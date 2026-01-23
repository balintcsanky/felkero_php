<?php
declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../src/SecurityHeaders.php';
require __DIR__ . '/../src/Csrf.php';

SecurityHeaders::applyNoIndex();
Csrf::startSession();

/**
 * Csak akkor lehessen elérni, ha email + telefon előellenőrzés megtörtént.
 * (verify_contact.php állítja be ezeket)
 */
$preverified   = !empty($_SESSION['preverified']) && !empty($_SESSION['verified_email']) && !empty($_SESSION['verified_phone']);
$preverifiedAt = (int)($_SESSION['preverified_at'] ?? 0);

if (!$preverified || $preverifiedAt <= 0 || (time() - $preverifiedAt) > 1800) {
  header('Location: /verify_contact.php?reset=1', true, 302);
  exit;
}

$lockedEmail = (string)$_SESSION['verified_email'];
$lockedPhone = (string)$_SESSION['verified_phone'];

// Botvédelem: minimális kitöltési idő
$_SESSION['form_started_at'] = time();

$csrf = Csrf::token();

// TODO: ha nálad dinamikus kategóriák vannak, innen töltsd
$categories = ['A', 'B', 'C'];
?>
<!doctype html>
<html lang="hu">
<head>
  <meta charset="utf-8">
  <meta name="robots" content="noindex,nofollow">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Igénybejelentés</title>

  <link rel="stylesheet" href="/assets/app.css?v=1">
</head>
<body>
  <main class="page">
    <section class="card">

      <header class="card__header">
        <h1 class="title">Igénybejelentés</h1>
        <p class="subtitle">
          Add meg az igény leadásához szükséges adatokat. Az email cím és a telefonszám ellenőrzött, nem módosítható.
        </p>
      </header>

      <div class="card__body">

        <form method="post" action="/request_submit.php" autocomplete="off">
          <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
          <input type="hidden" name="hp" value="">
          <input type="hidden" name="started_at" value="<?= (int)($_SESSION['form_started_at'] ?? time()) ?>">

          <!-- Alap adatok -->
          <div class="section">
            <p class="section__title">Alap adatok</p>

            <div class="field">
              <label class="label">Céges email</label>
              <input class="input" type="email" name="email" required readonly
                     value="<?= htmlspecialchars($lockedEmail, ENT_QUOTES, 'UTF-8') ?>">
            </div>

            <div class="field">
              <label class="label">Telefonszám</label>
              <input class="input" type="tel" name="contact_phone" required readonly maxlength="30"
                     value="<?= htmlspecialchars($lockedPhone, ENT_QUOTES, 'UTF-8') ?>">
            </div>

            <div class="field">
              <label class="label">Ügy száma</label>
              <input class="input" type="text" name="order_ref" required maxlength="100"
                     placeholder="Pl. 12345-67-2026">
            </div>

            <div class="field">
              <label class="label">Kategória</label>
              <select class="input" name="category" required>
                <?php foreach ($categories as $c): ?>
                  <option value="<?= htmlspecialchars($c, ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars($c, ENT_QUOTES, 'UTF-8') ?></option>
                <?php endforeach; ?>
              </select>
            </div>
          </div>

          <!-- Igény típusa -->
          <div class="section">
            <p class="section__title">Igény típusa</p>

            <div class="segmented" role="group" aria-label="Igény típusa">
              <label class="segmented__item">
                <input type="radio" name="request_kind" value="DEVICES" checked>
                <span>Eszközök mentése</span>
              </label>

              <label class="segmented__item">
                <input type="radio" name="request_kind" value="SEARCH">
                <span>Felkérés házkutatásra</span>
              </label>
            </div>

            <!--<p class="help">
              
            </p> -->
          </div>

          <!-- DEVICES blokk -->
          <div id="block-devices" class="section">
            <p class="section__title">Eszközök darabszáma</p>

            <div class="row row--3">
              <div class="field">
                <label class="label">PC</label>
                <input class="input" type="number" name="pc_count" min="0" step="1" value="0" required>
              </div>

              <div class="field">
                <label class="label">Telefon</label>
                <input class="input" type="number" name="phone_count" min="0" step="1" value="0" required>
              </div>

              <div class="field">
                <label class="label">Egyéb</label>
                <input class="input" type="number" name="other_count" min="0" step="1" value="0" required>
              </div>
            </div>

            <div class="field">
              <label class="label">Egyéb megjegyzés</label>
              <textarea class="input" name="other_note" rows="4" maxlength="2000"
                        placeholder="Egyéb információk..."></textarea>
            </div>
          </div>

          <!-- SEARCH blokk -->
          <div id="block-search" class="section is-hidden">
            <p class="section__title">Felkérés házkutatásra</p>

            <div class="row row--2">
              <div class="field">
                <label class="label">Kapcsolattartó neve</label>
                <input class="input" type="text" name="search_contact_name" maxlength="120"
                       placeholder="Pl. Teszt Elek">
              </div>

              <div class="field">
                <label class="label">Kapcsolattartó telefonszáma</label>
                <input class="input" type="tel" name="search_contact_phone" maxlength="30"
                       placeholder="+36 30 123 4567">
              </div>
            </div>

            <div class="row row--2">
              <div class="field">
                <label class="label">Kutatás időpontja</label>
                <input class="input" type="date" name="search_date" placeholder="yyyy-mm-dd">
              </div>

              <div class="field">
                <label class="label">Kutatás helyszíne</label>
                <input class="input" type="text" name="search_location" maxlength="200"
                       placeholder="Pl. 1101 Budapest, Kerepesi út 47-49.">
              </div>
            </div>

            <div class="field">
              <label class="label">Egyéb megjegyzés</label>
              <textarea class="input" name="search_note" rows="5" maxlength="2000"
                        placeholder="Minden további lényeges információ... Például: Várható eszközök száma"></textarea>
            </div>
          </div>

          <div class="actions">
            <button class="btn btn--primary" type="submit">Beküldés</button>
          </div>
        </form>

      </div>

      <footer class="footer">
        <span>Nemzeti Védelmi Szolgálat</span>
        <a class="link" href="/verify_contact.php?reset=1">Újrakezdés</a>
      </footer>

    </section>
  </main>

  <script>
  (function(){
    const devices = document.getElementById('block-devices');
    const search  = document.getElementById('block-search');

    const pc = document.querySelector('input[name="pc_count"]');
    const ph = document.querySelector('input[name="phone_count"]');
    const ot = document.querySelector('input[name="other_count"]');
    const otherNote = document.querySelector('textarea[name="other_note"]');

    const searchName  = document.querySelector('input[name="search_contact_name"]');
    const searchPhone = document.querySelector('input[name="search_contact_phone"]');
    const searchDate  = document.querySelector('input[name="search_date"]');
    const searchLoc   = document.querySelector('input[name="search_location"]');
    const searchNote  = document.querySelector('textarea[name="search_note"]');

    function setDisabled(el, disabled){
      if (!el) return;
      el.disabled = disabled;
      if (disabled) el.value = '';
    }

    function sync(){
      const kind = document.querySelector('input[name="request_kind"]:checked')?.value || 'DEVICES';

      if (kind === 'DEVICES') {
        devices.classList.remove('is-hidden');
        search.classList.add('is-hidden');

        // DEVICES kötelező
        pc.required = ph.required = ot.required = true;

        // SEARCH nem kötelező
        [searchName, searchPhone, searchDate, searchLoc, searchNote].forEach(el => { if (el) el.required = false; });

        setDisabled(pc, false); setDisabled(ph, false); setDisabled(ot, false); setDisabled(otherNote, false);
        [searchName, searchPhone, searchDate, searchLoc, searchNote].forEach(el => setDisabled(el, true));

      } else {
        devices.classList.add('is-hidden');
        search.classList.remove('is-hidden');

        // SEARCH kötelező mezők
        pc.required = ph.required = ot.required = false;

        if (searchName)  searchName.required  = true;
        if (searchPhone) searchPhone.required = true;
        if (searchDate)  searchDate.required  = true;
        if (searchLoc)   searchLoc.required   = true;
        if (searchNote)  searchNote.required  = false; // megjegyzés opcionális

        setDisabled(pc, true); setDisabled(ph, true); setDisabled(ot, true); setDisabled(otherNote, true);
        [searchName, searchPhone, searchDate, searchLoc, searchNote].forEach(el => setDisabled(el, false));
      }
    }

    document.querySelectorAll('input[name="request_kind"]').forEach(r => r.addEventListener('change', sync));
    sync();
  })();
  </script>
</body>
</html>
