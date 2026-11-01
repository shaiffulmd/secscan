<?php
// ================================================================
//  server-audit.php — SecScan Ubuntu Server Audit helper page
// ================================================================

require_once __DIR__ . '/config.php';

if (!headers_sent()) {
    header_remove('X-Powered-By');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    header("Content-Security-Policy: default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com data:; style-src 'self' https://fonts.googleapis.com; script-src 'self'; report-to default; report-uri /reporting.php");
    secscan_send_operational_security_headers();
    if (secscan_is_https()) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
    }
}

$scheme = secscan_is_https() ? 'https' : 'http';
$host   = $_SERVER['HTTP_HOST'] ?? 'your-server.com';
$base   = $scheme . '://' . preg_replace('/[^A-Za-z0-9.\-:]/', '', $host);
$auditHash = hash_file('sha256', __DIR__ . '/audit.sh') ?: '';
?>
<!DOCTYPE html>
<html lang="ms">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"/>
  <meta name="theme-color" content="#F4F7FB" media="(prefers-color-scheme: light)"/>
  <meta name="theme-color" content="#080D14" media="(prefers-color-scheme: dark)"/>
  <title>Audit Pelayan Ubuntu — SecScan</title>
  <link rel="icon" type="image/svg+xml" href="favicon.svg"/>
  <link rel="shortcut icon" href="favicon.svg"/>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&amp;family=Lora:wght@500;600&amp;family=JetBrains+Mono:wght@400;500&amp;display=swap" rel="stylesheet"/>
  <link rel="stylesheet" href="assets/app.css?v=<?= rawurlencode((string)filemtime(__DIR__ . '/assets/app.css')) ?>"/>
  <link rel="stylesheet" href="assets/enterprise.css?v=<?= rawurlencode((string)filemtime(__DIR__ . '/assets/enterprise.css')) ?>"/>
  <script src="assets/theme.js?v=<?= rawurlencode((string)filemtime(__DIR__ . '/assets/theme.js')) ?>"></script>
</head>
<body class="enterprise-ui audit-page">
  <div class="app">
    <header class="header">
      <div class="header-inner">
        <a href="index.php" class="logo">
          <div class="logo-icon"><img src="secscan-logo.svg" alt="" aria-hidden="true"/></div>
          <div>
            <div class="logo-name">SecScan</div>
            <div class="logo-sub">Pengimbas Keselamatan Enterprise</div>
          </div>
        </a>
        <div class="header-actions">
          <a class="dashboard-link" href="index.php">Scanner</a>
          <a class="dashboard-link" href="faqs.php">FAQ</a>
          <a class="dashboard-link" href="dashboard.php">Papan Pemuka</a>
          <button type="button" class="theme-toggle" id="themeToggle" aria-label="Tukar tema">
            <svg class="icon-moon" width="16" height="16" viewBox="0 0 24 24" fill="none">
              <path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            <svg class="icon-sun" width="16" height="16" viewBox="0 0 24 24" fill="none">
              <circle cx="12" cy="12" r="4" stroke="currentColor" stroke-width="1.8"/>
              <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
            </svg>
          </button>
        </div>
      </div>
    </header>

    <main>
      <section class="server-audit audit-page-section">
        <div class="sa-head">
          <div class="sa-kicker">Alat tambahan</div>
          <h1 class="sa-title">Audit keselamatan pelayan Ubuntu</h1>
          <p class="sa-sub">Skrip bash <strong>read-only</strong> yang menyemak firewall, SSH, pengguna, kemas kini, port terbuka dan keizinan fail — kemudian menjana laporan HTML dengan cadangan pembetulan. Tiada perubahan dibuat pada sistem anda.</p>
        </div>

        <div class="sa-card">
          <div class="sa-step">
            <span class="sa-num">1</span>
            <span class="sa-step-label">Muat turun, semak, dan jalankan pada pelayan anda</span>
            <span class="sa-badge">Disyorkan</span>
          </div>
          <div class="sa-terminal">
            <div class="sa-terminal-bar">
              <span class="sa-tdot" aria-hidden="true">&#8203;</span><span class="sa-tdot" aria-hidden="true">&#8203;</span><span class="sa-tdot" aria-hidden="true">&#8203;</span>
              <span class="sa-terminal-title">bash</span>
              <button type="button" class="sa-copy" id="saCopyBtn" aria-label="Salin arahan">
                <svg class="sa-copy-ic" width="14" height="14" viewBox="0 0 24 24" fill="none">
                  <rect x="9" y="9" width="11" height="11" rx="2" stroke="currentColor" stroke-width="1.7"/>
                  <path d="M6 15H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v1" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>
                </svg>
                <span class="sa-copy-txt">Salin</span>
              </button>
            </div>
            <div class="sa-terminal-body">
              <span class="sa-prompt">$</span>
              <code id="saCurl">curl -fsSLO <?= htmlspecialchars($base, ENT_QUOTES) ?>/audit.sh</code>
            </div>
          </div>
          <p class="sa-tip">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.7"/>
              <path d="M12 11v5" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"/>
              <circle cx="12" cy="7.6" r="1" fill="currentColor"/>
            </svg>
            <span>Amalan selamat: baca skrip dahulu, sahkan checksum, kemudian jalankan sebagai root. Jangan pipe skrip rangkaian terus ke <code>sudo bash</code>.</span>
          </p>

          <?php if ($auditHash !== ''): ?>
          <div class="sa-run">Sahkan: <code>echo "<?= htmlspecialchars($auditHash, ENT_QUOTES) ?>  audit.sh" | sha256sum -c -</code></div>
          <?php endif; ?>

          <div class="sa-divider"><span>atau</span></div>

          <div class="sa-step">
            <span class="sa-num">2</span>
            <span class="sa-step-label">Muat turun dan semak dahulu</span>
          </div>
          <div class="sa-download-row">
            <a class="sa-download" href="audit.sh" download>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
                <path d="M12 3v12m0 0 4-4m-4 4-4-4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                <path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
              </svg>
              Muat turun audit.sh
            </a>
            <div class="sa-run">Selepas semak kandungan dan checksum, jalankan <code>sudo bash audit.sh</code></div>
          </div>
        </div>
      </section>
    </main>

    <footer class="footer">
      <span>&copy; 2026 SecScan Enterprise. Hak cipta terpelihara.</span>
      <nav class="footer-links" aria-label="Pautan SecScan">
        <a href="index.php">Scanner</a>
        <a href="updates.php">Kemas Kini</a>
        <a href="faqs.php">FAQ</a>
        <a href="dashboard.php">Papan Pemuka</a>
      </nav>
    </footer>
  </div>
</body>
</html>
