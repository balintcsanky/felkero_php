<?php
require __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../src/SecurityHeaders.php';
require __DIR__ . '/../src/Csrf.php';
require __DIR__ . '/../src/Db.php';
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

// Előellenőrzés (email + telefon) kötelező a beküldéshez
$preverified = !empty($_SESSION['preverified']) && !empty($_SESSION['verified_email']) && !empty($_SESSION['verified_phone']);
$preverifiedAt = (int)($_SESSION['preverified_at'] ?? 0);
if (!$preverified || $preverifiedAt <= 0 || (time() - $preverifiedAt) > 1800) {
  http_response_code(200);
  header('Content-Type: text/plain; charset=utf-8');
  exit('Kérjük, erősítsd meg az email címed és a telefonszámod a beküldés előtt.');
}

$email = trim((string)($_POST['email'] ?? ''));
$orderRef = trim((string)($_POST['order_ref'] ?? ''));
$category = trim((string)($_POST['category'] ?? ''));
$deviceCount = (int)($_POST['device_count'] ?? 0);

$contactPhone = trim((string)($_POST['contact_phone'] ?? ''));

// A kliens oldalon readonly, de szerver oldalon is ellenőrzünk
$sessEmail = (string)($_SESSION['verified_email'] ?? '');
$sessPhone = (string)($_SESSION['verified_phone'] ?? '');
if ($sessEmail === '' || $sessPhone === '' || strcasecmp($email, $sessEmail) !== 0 || $contactPhone !== $sessPhone) {
  http_response_code(200);
  header('Content-Type: text/plain; charset=utf-8');
  exit('Érvénytelen beküldés. Kérjük, indítsd újra az igénybejelentést.');
}

$pcCount = (int)($_POST['pc_count'] ?? 0);
$phoneCount = (int)($_POST['phone_count'] ?? 0);
$otherCount = (int)($_POST['other_count'] ?? 0);

$otherNote = trim((string)($_POST['other_note'] ?? ''));

$allowedCategories = ['A','B','C'];
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
  http_response_code(200); exit('Ha az adatok helyesek, igényed feldolgozás alá kerül.');
}
if ($orderRef === '' || mb_strlen($orderRef) > 100) {
  http_response_code(200); exit('Ha az adatok helyesek, igényed feldolgozás alá kerül.');
}
if (!in_array($category, $allowedCategories, true)) {
  http_response_code(200); exit('Ha az adatok helyesek, igényed feldolgozás alá kerül.');
}
if (($pcCount + $phoneCount + $otherCount) === 0) {
  http_response_code(200); exit('Ha az adatok helyesek, igényed feldolgozás alá kerül.');
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
      status, email_verified_at, created_ip, user_agent, created_at, updated_at
    ) VALUES (
      ?, ?, ?, ?,
      ?, ?, ?, ?,
      'PENDING_REVIEW', ?, ?, ?, ?, ?
    )
  ");

  $stmt->execute([
    $email, $contactPhone, $orderRef, $category,
    $pcCount, $phoneCount, $otherCount, $otherNote,
    $now, $ip, $ua, $now, $now
  ]);

  $requestId = (int)$pdo->lastInsertId();
  $pdo->commit();

  // Biztonság: pre-verified státusz egyszer használatos (opcionális)
  unset($_SESSION['preverified'], $_SESSION['preverified_at'], $_SESSION['verified_email'], $_SESSION['verified_phone']);

  header('Content-Type: text/plain; charset=utf-8');
  echo "Köszönjük! Az igénybejelentést rögzítettük.";
  exit;

} catch (Throwable $e) {
  $pdo->rollBack();
  http_response_code(500);
  header('Content-Type: text/plain; charset=utf-8');
  exit("Hiba történt: " . $e->getMessage());
}
