<?php
require __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../src/SecurityHeaders.php';
require __DIR__ . '/../src/Csrf.php';

SecurityHeaders::applyNoIndex();
Csrf::startSession();

// Pre-verifikáció ellenőrzés (email + telefon)
$preverified = !empty($_SESSION['preverified']) && !empty($_SESSION['verified_email']) && !empty($_SESSION['verified_phone']);
$preverifiedAt = (int)($_SESSION['preverified_at'] ?? 0);
if (!$preverified || $preverifiedAt <= 0 || (time() - $preverifiedAt) > 1800) {
  header('Location: /verify_contact.php', true, 302);
  exit;
}

$lockedEmail = (string)$_SESSION['verified_email'];
$lockedPhone = (string)$_SESSION['verified_phone'];

$_SESSION['form_started_at'] = time();

$categories = ['A', 'B', 'C']; // TODO: valós kategóriák

$csrf = Csrf::token();
?>
<!doctype html>
<html lang="hu">
<head>
  <meta charset="utf-8">
  <meta name="robots" content="noindex,nofollow">
  <title>Igénybejelentés</title>
</head>
<body>
  <h1>Igénybejelentés</h1>

  <form method="post" action="/request_submit.php">
    <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
    <input type="hidden" name="hp" value="">
    <input type="hidden" name="started_at" value="<?= (int)($_SESSION['form_started_at'] ?? time()) ?>">

    <div>
      <label>Céges email</label><br>
      <input type="email" name="email" required readonly value="<?= htmlspecialchars($lockedEmail) ?>" style="background:#f2f2f2;">
    </div>

    <div>
      <label>Telefonszám</label><br>
      <input type="tel" name="contact_phone" required readonly maxlength="30"
            placeholder="+36 30 123 4567" value="<?= htmlspecialchars($lockedPhone) ?>" style="background:#f2f2f2;">
    </div>

    <div>
      <label>Megrendelés száma</label><br>
      <input type="text" name="order_ref" required maxlength="100">
    </div>

    <div>
      <label>Kategória</label><br>
      <select name="category" required>
        <?php foreach ($categories as $c): ?>
          <option value="<?= htmlspecialchars($c) ?>"><?= htmlspecialchars($c) ?></option>
        <?php endforeach; ?>
      </select>
    </div>

    <fieldset style="margin-top: 12px;">
      <legend>Eszközök darabszáma</legend>

      <div>
        <label>PC</label><br>
        <input type="number" name="pc_count" required min="0" step="1" value="0">
      </div>

      <div>
        <label>Telefon</label><br>
        <input type="number" name="phone_count" required min="0" step="1" value="0">
      </div>

      <div>
        <label>Egyéb</label><br>
        <input type="number" name="other_count" required min="0" step="1" value="0">
      </div>

      <div style="margin-top: 12px;">
        <label>Egyéb megjegyzés</label><br>
        <textarea name="other_note" rows="4" cols="50" maxlength="2048"
            placeholder="Egyéb információk..."></textarea>
      </div>

    </fieldset>

    <button type="submit">Beküldés</button>
  </form>
</body>
</html>
