<?php
require __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../src/SecurityHeaders.php';
require __DIR__ . '/../src/Csrf.php';
require __DIR__ . '/../src/Db.php';
require __DIR__ . '/../src/Mailer.php';

SecurityHeaders::applyNoIndex();
Csrf::startSession();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  http_response_code(405); exit('Method Not Allowed');
}

if (!Csrf::verify($_POST['csrf'] ?? '')) {
  http_response_code(400); exit('CSRF error');
}

// Honeypot (botok ellen): ennek üresnek kell lennie
if (!empty($_POST['hp'] ?? '')) {
  http_response_code(200); exit('OK');
}

// Minimum kitöltési idő (botok ellen)
$started = (int)($_POST['started_at'] ?? 0);
if ($started > 0 && (time() - $started) < 3) {
  http_response_code(429);
  header('Content-Type: text/plain; charset=utf-8');
  exit('Ez túl gyorsan történt!');
}

$email = trim((string)($_POST['email'] ?? ''));
$orderRef = trim((string)($_POST['order_ref'] ?? ''));
$category = trim((string)($_POST['category'] ?? ''));
$deviceCount = (int)($_POST['device_count'] ?? 0);

$contactPhone = trim((string)($_POST['contact_phone'] ?? ''));

$pcCount = (int)($_POST['pc_count'] ?? 0);
$phoneCount = (int)($_POST['phone_count'] ?? 0);
$otherCount = (int)($_POST['other_count'] ?? 0);

$otherNote = trim((string)($_POST['other_note'] ?? ''));



$allowedCategories = ['A','B','C'];
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
  http_response_code(200); exit('Ha az email helyes, küldtünk megerősítő linket.');
}
if ($orderRef === '' || mb_strlen($orderRef) > 100) {
  http_response_code(200); exit('Ha az email helyes, küldtünk megerősítő linket.');
}
if (!in_array($category, $allowedCategories, true)) {
  http_response_code(200); exit('Ha az email helyes, küldtünk megerősítő linket.');
}
if (($pcCount + $phoneCount + $otherCount) === 0) {
  http_response_code(200); exit('Ha az adatok helyesek, küldtünk megerősítő linket.');
}

if (mb_strlen($otherNote) > 2000) {
  http_response_code(200);
  exit('A megjegyzés túl hosszú (max 2000 karakter).');
}

$pdo = Db::pdo();
$now = (new DateTimeImmutable())->format('Y-m-d H:i:s');

$ip = $_SERVER['REMOTE_ADDR'] ?? null;
$ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);

$pdo->beginTransaction();
try {
$stmt = $pdo->prepare("
  INSERT INTO requests (
    email, contact_phone, order_ref, category,
    pc_count, phone_count, other_count, other_note,
    status, created_ip, user_agent, created_at, updated_at
  ) VALUES (
    ?, ?, ?, ?,
    ?, ?, ?, ?,
    'PENDING_EMAIL', ?, ?, ?, ?
  )
");

$stmt->execute([
  $email, $contactPhone, $orderRef, $category,
  $pcCount, $phoneCount, $otherCount, $otherNote,
  $ip, $ua, $now, $now
]);
  $requestId = (int)$pdo->lastInsertId();

  $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
  $pepper = getenv('INVITE_PEPPER') ?: '';
  $tokenHash = hash('sha256', $token . $pepper);
  $expiresAt = (new DateTimeImmutable('+60 minutes'))->format('Y-m-d H:i:s');

  $stmt2 = $pdo->prepare("INSERT INTO request_verifications (request_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)");
  $stmt2->execute([$requestId, $tokenHash, $expiresAt, $now]);

  $pdo->commit();

  $appUrl = rtrim(getenv('APP_URL') ?: 'http://localhost:8080', '/');
  $verifyUrl = $appUrl . "/request_verify.php?token=" . urlencode($token);

  Mailer::sendVerifyLink($email, $verifyUrl);

} catch (Throwable $e) {
  $pdo->rollBack();
  http_response_code(500);
  header('Content-Type: text/plain; charset=utf-8');
  exit("Hiba történt: " . $e->getMessage());
}
