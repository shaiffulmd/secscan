<?php
// ================================================================
//  updates.php — SecScan public release notes
// ================================================================

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/src/Changelog.php';

if (!headers_sent()) {
    header_remove('X-Powered-By');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    header("Content-Security-Policy: default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com data:; style-src 'self' https://fonts.googleapis.com; script-src 'self'; form-action 'self'");
    secscan_send_operational_security_headers();
    if (secscan_is_https()) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

$appVersion = secscan_app_version();
$e = static fn(string $value): string => htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="ms">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"/>
  <meta name="description" content="Kemas kini terbaharu SecScan, termasuk pengesanan baharu dan perubahan yang perlu anda ambil tindakan."/>
  <title>Kemas Kini SecScan</title>
  <link rel="icon" type="image/svg+xml" href="favicon.svg"/>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&amp;family=Lora:wght@500;600&amp;family=JetBrains+Mono:wght@400;500&amp;display=swap" rel="stylesheet"/>
  <link rel="stylesheet" href="assets/app.css?v=<?= rawurlencode((string)filemtime(__DIR__ . '/assets/app.css')) ?>"/>
  <link rel="stylesheet" href="assets/enterprise.css?v=<?= rawurlencode((string)filemtime(__DIR__ . '/assets/enterprise.css')) ?>"/>
  <script src="assets/theme.js?v=<?= rawurlencode((string)filemtime(__DIR__ . '/assets/theme.js')) ?>"></script>
</head>
<body class="enterprise-ui about-page">
  <div class="app">
    <header class="header">
      <div class="header-inner">
        <a href="index.php" class="logo">
          <div class="logo-icon"><img src="secscan-logo.svg" alt=""></div>
          <div>
            <div class="logo-name">SecScan</div>
            <div class="logo-sub">Pengimbas Keselamatan Enterprise</div>
          </div>
        </a>
        <div class="header-actions">
          <a class="dashboard-link" href="index.php">Scanner</a>
          <a class="dashboard-link" href="faqs.php">FAQ</a>
          <a class="dashboard-link" href="about.php">Tentang</a>
          <button type="button" class="theme-toggle" id="themeToggle" aria-label="Tukar tema">◐</button>
        </div>
      </div>
    </header>

    <main class="about-main updates-main">
      <section class="about-hero">
        <p class="faq-eyebrow">KEMAS KINI</p>
        <h1>Apa yang baharu dalam SecScan.</h1>
        <p>Setiap keluaran disenaraikan di sini, termasuk pengesanan baharu dan perkara yang perlu anda ambil tindakan.</p>
      </section>

      <div class="updates-list">
        <?php foreach (Changelog::ENTRIES as $entry): ?>
          <article class="updates-entry">
            <p class="updates-meta">
              <span class="updates-version">Versi <?= $e($entry['version']) ?></span>
              <time datetime="<?= $e($entry['date']) ?>"><?= $e(Changelog::formatDate($entry['date'])) ?></time>
            </p>
            <h2><?= $e($entry['title']) ?></h2>
            <ul>
              <?php foreach ($entry['items'] as $item): ?>
                <li><?= $e($item) ?></li>
              <?php endforeach; ?>
            </ul>
            <?php if (!empty($entry['action'])): ?>
              <p class="updates-action"><strong>Tindakan diperlukan:</strong> <?= $e($entry['action']) ?></p>
            <?php endif; ?>
          </article>
        <?php endforeach; ?>
      </div>
    </main>

    <footer class="footer">
      <span>© 2026 SecScan Enterprise. Hak cipta terpelihara.</span>
      <span class="footer-version">Versi <?= $e($appVersion) ?></span>
      <nav class="footer-links" aria-label="Pautan SecScan">
        <a href="index.php">Scanner</a>
        <a href="faqs.php">FAQ</a>
        <a href="about.php">Tentang</a>
        <a href="server-audit.php">Audit Server</a>
      </nav>
    </footer>
  </div>
</body>
</html>
