<?php
require __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../src/SecurityHeaders.php';
require __DIR__ . '/../src/Db.php';

SecurityHeaders::applyNoIndex();

$token = (string)($_GET['token'] ?? '');
if ($token === '') { http_response_code(400); exit('Invalid token'); }

$pepper = getenv('INVITE_PEPPER') ?: '';
$tokenHash = hash('sha256', $token . $pepper);

$pdo = Db::pdo();
$now = (new DateTimeImmutable())->format('Y-m-d H:i:s');

$pdo->beginTransaction();
try {
  $stmt = $pdo->prepare("SELECT id, request_id, expires_at, used_at FROM request_verifications WHERE token_hash = ? FOR UPDATE");
  $stmt->execute([$tokenHash]);
  $row = $stmt->fetch();

  if (!$row) { throw new RuntimeException('not found'); }
  if ($row['used_at'] !== null) { throw new RuntimeException('used'); }
  if (strtotime($row['expires_at']) < time()) { throw new RuntimeException('expired'); }

  $stmt2 = $pdo->prepare("UPDATE request_verifications SET used_at = ? WHERE id = ?");
  $stmt2->execute([$now, $row['id']]);

  $stmt3 = $pdo->prepare("UPDATE requests SET email_verified_at = ?, status = 'PENDING_REVIEW', updated_at = ? WHERE id = ?");
  $stmt3->execute([$now, $now, $row['request_id']]);

  $pdo->commit();
  echo "Email megerősítve. Igényed feldolgozás alatt (PENDING_REVIEW).";

} catch (Throwable $e) {
  $pdo->rollBack();
  http_response_code(400);
  echo "A megerősítő link érvénytelen vagy lejárt.";
}
