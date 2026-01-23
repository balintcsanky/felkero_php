<?php
require __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../src/SecurityHeaders.php';
require __DIR__ . '/../src/Csrf.php';
require __DIR__ . '/../src/Mailer.php';

SecurityHeaders::applyNoIndex();
Csrf::startSession();

$csrf = Csrf::token();

const OTP_TTL_SECONDS = 600;         // 10 perc
const OTP_RESEND_COOLDOWN = 30;      // 30 mp
const OTP_MAX_ATTEMPTS = 5;          // 5 próbálkozás
const PREVERIFIED_MAX_AGE = 1800;    // 30 perc

function normalize_phone(string $phone): string {
  $p = trim($phone);
  $p = preg_replace('/[ \t\r\n\-]/', '', $p) ?? $p;
  return $p;
}

function otp_hash(string $code): string {
  $pepper = getenv('OTP_PEPPER') ?: (getenv('INVITE_PEPPER') ?: '');
  return hash('sha256', $code . $pepper);
}

function gen_code6(): string {
  return str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
}

function can_resend(?int $sentAt): bool {
  if (!$sentAt) return true;
  return (time() - $sentAt) >= OTP_RESEND_COOLDOWN;
}

function is_code_valid(?int $sentAt): bool {
  if (!$sentAt) return false;
  return (time() - $sentAt) <= OTP_TTL_SECONDS;
}

function reset_phone_flow(): void {
  unset(
    $_SESSION['pv_phone'], $_SESSION['pv_phone_otp_hash'], $_SESSION['pv_phone_sent_at'], $_SESSION['pv_phone_attempts'],
    $_SESSION['pv_phone_ok'], $_SESSION['verified_phone'],
    $_SESSION['preverified'], $_SESSION['preverified_at']
  );
}

function reset_email_flow(): void {
  unset(
    $_SESSION['pv_email'], $_SESSION['pv_email_otp_hash'], $_SESSION['pv_email_sent_at'], $_SESSION['pv_email_attempts'],
    $_SESSION['pv_email_ok'], $_SESSION['verified_email']
  );
  reset_phone_flow();
}

$msg = null;
$err = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  if (!Csrf::verify($_POST['csrf'] ?? '')) {
    http_response_code(400);
    $err = 'CSRF hiba. Kérlek frissítsd az oldalt.';
  } else {
    $action = (string)($_POST['action'] ?? '');

    // 1) EMAIL KÓD KÜLDÉS
    if ($action === 'send_email') {
      $email = trim((string)($_POST['email'] ?? ''));
      if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $err = 'Kérlek, adj meg egy érvényes email címet.';
      } else {
        // ha változik az email, reseteljük az email+telefon folyamatot
        if (strcasecmp((string)($_SESSION['pv_email'] ?? ''), $email) !== 0 || strcasecmp((string)($_SESSION['verified_email'] ?? ''), $email) !== 0) {
          reset_email_flow();
        }

        $sentAt = (int)($_SESSION['pv_email_sent_at'] ?? 0);
        if (!can_resend($sentAt)) {
          $err = 'Túl gyorsan kérted újra. Próbáld meg pár másodperc múlva.';
        } else {
          $code = gen_code6();
          $_SESSION['pv_email'] = $email;
          $_SESSION['pv_email_otp_hash'] = otp_hash($code);
          $_SESSION['pv_email_sent_at'] = time();
          $_SESSION['pv_email_attempts'] = 0;
          $_SESSION['pv_email_ok'] = false;

          Mailer::sendOtpCode($email, 'Email ellenőrző kód - Felkérő Portal', $code);
          $msg = 'Az email ellenőrző kódot elküldtük (Mailhog).';
        }
      }
    }

    // 2) EMAIL KÓD ELLENŐRZÉS
    elseif ($action === 'verify_email') {
      $code = trim((string)($_POST['email_otp'] ?? ''));
      $email = (string)($_SESSION['pv_email'] ?? '');
      $hash = (string)($_SESSION['pv_email_otp_hash'] ?? '');
      $sentAt = (int)($_SESSION['pv_email_sent_at'] ?? 0);
      $attempts = (int)($_SESSION['pv_email_attempts'] ?? 0);

      if (!$email || !$hash) {
        $err = 'Előbb kérj email kódot.';
      } elseif (!is_code_valid($sentAt)) {
        $err = 'Az email kód lejárt. Kérj újat.';
      } elseif ($attempts >= OTP_MAX_ATTEMPTS) {
        $err = 'Túl sok próbálkozás. Kérj új kódot.';
      } else {
        if (hash_equals($hash, otp_hash($code))) {
          $_SESSION['pv_email_ok'] = true;
          $_SESSION['verified_email'] = $email;

          // email OTP adatok törlése
          unset($_SESSION['pv_email_otp_hash'], $_SESSION['pv_email_sent_at'], $_SESSION['pv_email_attempts']);

          $msg = 'Email sikeresen ellenőrizve.';
        } else {
          $_SESSION['pv_email_attempts'] = $attempts + 1;
          $err = 'Hibás email kód.';
        }
      }
    }

    // 3) TELEFON KÓD KÜLDÉS (csak sikeres email után)
    elseif ($action === 'send_phone') {
      if (empty($_SESSION['pv_email_ok']) || empty($_SESSION['verified_email'])) {
        $err = 'Előbb ellenőrizd az email címedet.';
      } else {
        $phone = normalize_phone((string)($_POST['contact_phone'] ?? ''));
        if ($phone === '' || mb_strlen($phone) > 30) {
          $err = 'Kérlek, adj meg egy érvényes telefonszámot.';
        } else {
          // ha változik a telefon, reseteljük a telefon folyamatot
          if (($phone !== (string)($_SESSION['pv_phone'] ?? '')) || ($phone !== (string)($_SESSION['verified_phone'] ?? ''))) {
            reset_phone_flow();
          }

          $sentAt = (int)($_SESSION['pv_phone_sent_at'] ?? 0);
          if (!can_resend($sentAt)) {
            $err = 'Túl gyorsan kérted újra. Próbáld meg pár másodperc múlva.';
          } else {
            $code = gen_code6();
            $_SESSION['pv_phone'] = $phone;
            $_SESSION['pv_phone_otp_hash'] = otp_hash($code);
            $_SESSION['pv_phone_sent_at'] = time();
            $_SESSION['pv_phone_attempts'] = 0;
            $_SESSION['pv_phone_ok'] = false;

            // SMS nincs: teszt módban emailben küldjük
            $email = (string)$_SESSION['verified_email'];
            Mailer::sendOtpCode($email, 'Telefon ellenőrző kód (teszt mód) - Felkérő Portal', $code);

            $msg = 'A telefon ellenőrző kódot teszt módban emailben elküldtük (Mailhog).';
          }
        }
      }
    }

    // 4) TELEFON KÓD ELLENŐRZÉS
    elseif ($action === 'verify_phone') {
      if (empty($_SESSION['pv_email_ok']) || empty($_SESSION['verified_email'])) {
        $err = 'Előbb ellenőrizd az email címedet.';
      } else {
        $code = trim((string)($_POST['phone_otp'] ?? ''));
        $phone = (string)($_SESSION['pv_phone'] ?? '');
        $hash = (string)($_SESSION['pv_phone_otp_hash'] ?? '');
        $sentAt = (int)($_SESSION['pv_phone_sent_at'] ?? 0);
        $attempts = (int)($_SESSION['pv_phone_attempts'] ?? 0);

        if (!$phone || !$hash) {
          $err = 'Előbb kérj telefon kódot.';
        } elseif (!is_code_valid($sentAt)) {
          $err = 'A telefon kód lejárt. Kérj újat.';
        } elseif ($attempts >= OTP_MAX_ATTEMPTS) {
          $err = 'Túl sok próbálkozás. Kérj új kódot.';
        } else {
          if (hash_equals($hash, otp_hash($code))) {
            $_SESSION['pv_phone_ok'] = true;
            $_SESSION['verified_phone'] = $phone;

            // teljes preverified állapot
            session_regenerate_id(true);
            $_SESSION['preverified'] = true;
            $_SESSION['preverified_at'] = time();

            // telefon OTP adatok törlése
            unset($_SESSION['pv_phone_otp_hash'], $_SESSION['pv_phone_sent_at'], $_SESSION['pv_phone_attempts']);

            $msg = 'Telefonszám sikeresen ellenőrizve.';
          } else {
            $_SESSION['pv_phone_attempts'] = $attempts + 1;
            $err = 'Hibás telefon kód.';
          }
        }
      }
    } else {
      http_response_code(400);
      $err = 'Ismeretlen művelet.';
    }
  }
}

// lejárt preverified ablak esetén törlés
if (!empty($_SESSION['preverified']) && (int)($_SESSION['preverified_at'] ?? 0) > 0) {
  if ((time() - (int)$_SESSION['preverified_at']) > PREVERIFIED_MAX_AGE) {
    unset($_SESSION['preverified'], $_SESSION['preverified_at'], $_SESSION['verified_email'], $_SESSION['verified_phone']);
    $_SESSION['pv_email_ok'] = false;
    $_SESSION['pv_phone_ok'] = false;
  }
}

$pvEmail = htmlspecialchars((string)($_SESSION['pv_email'] ?? ''), ENT_QUOTES, 'UTF-8');
$pvPhone = htmlspecialchars((string)($_SESSION['pv_phone'] ?? ''), ENT_QUOTES, 'UTF-8');

$emailSent = !empty($_SESSION['pv_email_otp_hash']);
$emailOk   = !empty($_SESSION['pv_email_ok']) && !empty($_SESSION['verified_email']);

$phoneVisible = $emailOk;
$phoneSent = !empty($_SESSION['pv_phone_otp_hash']);
$phoneOk   = !empty($_SESSION['pv_phone_ok']) && !empty($_SESSION['verified_phone']);

$canContinue = !empty($_SESSION['preverified']) && $emailOk && $phoneOk;
?>
<!doctype html>
<html lang="hu">
<head>
  <meta charset="utf-8">
  <meta name="robots" content="noindex,nofollow">
  <link rel="stylesheet" href="/assets/app.css?v=1">
  <title>Igénybejelentés</title>

  <script>
    (function () {
    try {
        const navEntry = performance.getEntriesByType && performance.getEntriesByType("navigation")[0];
        const isReload = navEntry ? (navEntry.type === "reload")
        : (performance.navigation && performance.navigation.type === 1);

        if (isReload && !location.search.includes("reset=1")) {
        location.replace("/verify_contact.php?reset=1");
        }
    } catch (e) { /* no-op */ }
    })();
    </script>

</head>

<body>
  <main class="page">
    <section class="card">

      <header class="card__header">
        <h1 class="title">Igénybejelentés</h1>
        <p class="subtitle">
          Kétlépcsős ellenőrzés (Email és telefon). Ellenőrzés után lehet folytatni.
        </p>

        <div class="steps">
          <span class="step <?= $emailOk ? 'step--ok' : 'step--active' ?>">1) Email</span>
          <span class="step <?= $phoneOk ? 'step--ok' : ($emailOk ? 'step--active' : '') ?>">2) Telefon</span>
          <span class="step <?= $canContinue ? 'step--active' : '' ?>">3) Tovább</span>
        </div>
      </header>

      <div class="card__body">

        <?php if ($msg): ?>
          <div class="alert alert--ok">
            <div class="alert__title">Siker</div>
            <div class="alert__text"><?= htmlspecialchars($msg) ?></div>
          </div>
        <?php endif; ?>

        <?php if ($err): ?>
          <div class="alert alert--err">
            <div class="alert__title">Hiba</div>
            <div class="alert__text"><?= htmlspecialchars($err) ?></div>
          </div>
        <?php endif; ?>

        <!-- EMAIL szekció -->
        <div class="section">
          <p class="section__title">Email ellenőrzés</p>

          <form method="post" action="/verify_contact.php" class="row" autocomplete="off">
            <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
            <input type="hidden" name="action" value="send_email">

            <div class="field">
              <label class="label">Céges Email cím</label>
              <input class="input" type="email" name="email" required
                     value="<?= $pvEmail ?>"
                     <?= $emailOk ? 'readonly' : '' ?>
                     placeholder="pelda@nvsz.hu">
            </div>

            <div class="actions">
              <button class="btn btn--primary" type="submit" <?= $emailOk ? 'disabled' : '' ?>>
                Ellenőrző kód küldése
              </button>
            </div>
          </form>

          <?php if ($emailSent && !$emailOk): ?>
            <form method="post" action="/verify_contact.php" class="row" autocomplete="off">
              <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
              <input type="hidden" name="action" value="verify_email">

              <div class="field">
                <label class="label">Egyszer használatos email kód</label>
                <input class="input" type="text" name="email_otp" inputmode="numeric"
                       pattern="[0-9]{6}" maxlength="6" placeholder="6 számjegy" required>
              </div>

              <div class="actions">
                <button class="btn" type="submit">Email ellenőrzése</button>
              </div>
            </form>
          <?php endif; ?>

          <?php if ($emailOk): ?>
            <div class="help">
              Ellenőrizve: <strong><?= htmlspecialchars((string)$_SESSION['verified_email']) ?></strong>
            </div>
          <?php endif; ?>
        </div>

        <!-- TELEFON szekció (csak email után) -->
        <?php if ($phoneVisible): ?>
          <div class="section">
            <p class="section__title">Telefonszám ellenőrzés</p>

            <form method="post" action="/verify_contact.php" class="row" autocomplete="off">
              <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
              <input type="hidden" name="action" value="send_phone">

              <div class="field">
                <label class="label">Céges Telefonszám</label>
                <input class="input" type="tel" name="contact_phone" required maxlength="30"
                       placeholder="+36 30 123 4567" value="<?= $pvPhone ?>"
                       <?= $phoneOk ? 'readonly' : '' ?>>
              </div>

              <div class="actions">
                <button class="btn btn--primary" type="submit" <?= $phoneOk ? 'disabled' : '' ?>>
                  Ellenőrző kód küldése
                </button>
              </div>


            </form>

            <?php if ($phoneSent && !$phoneOk): ?>
              <form method="post" action="/verify_contact.php" class="row" autocomplete="off">
                <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
                <input type="hidden" name="action" value="verify_phone">

                <div class="field">
                  <label class="label">Egyszer használatos telefon kód</label>
                  <input class="input" type="text" name="phone_otp" inputmode="numeric"
                         pattern="[0-9]{6}" maxlength="6" placeholder="6 számjegy" required>
                </div>

                <div class="actions">
                  <button class="btn" type="submit">Telefon ellenőrzése</button>
                </div>
              </form>
            <?php endif; ?>

            <?php if ($phoneOk): ?>
              <div class="help">
                Ellenőrizve: <strong><?= htmlspecialchars((string)$_SESSION['verified_phone']) ?></strong>
              </div>
            <?php endif; ?>
          </div>

          <?php if ($canContinue): ?>
            <div class="actions">
              <a class="link" href="/request.php">
                <button class="btn btn--primary" type="button">Tovább az igénybejelentéshez</button>
              </a>
            </div>
          <?php endif; ?>
        <?php endif; ?>

      </div>

      <footer class="footer">
        <span>Kód érvényesség: 10 perc</span>
        <a class="link" href="/verify_contact.php?reset=1">Újrakezdés</a>
      </footer>

    </section>
  </main>
</body>

</html>
