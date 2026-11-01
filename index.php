<?php
// ================================================================
//  index.php — SecScan (backend handler + frontend shell)
// ================================================================

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/src/RateLimiter.php';
require_once __DIR__ . '/src/UrlGuard.php';

header_remove('X-Powered-By');
$requestMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if (!in_array($requestMethod, ['GET', 'HEAD', 'POST'], true)) {
    header('Allow: GET, HEAD, POST');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store');
    http_response_code(405);
    exit;
}

$sendSecurityHeaders = static function (): void {
    if (headers_sent()) {
        return;
    }

    header_remove('X-Powered-By');

    $csp = implode('; ', [
        "default-src 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "connect-src 'self' https://cloudflareinsights.com",
        "img-src 'self' data: blob:",
        "font-src 'self' https://fonts.gstatic.com data:",
        "style-src 'self' https://fonts.googleapis.com 'sha256-VTbasa/FRHDnKoVUg8hQBJH4DUC4uJn/GGJL6yp/T4U='",
        "style-src-elem 'self' https://fonts.googleapis.com 'sha256-VTbasa/FRHDnKoVUg8hQBJH4DUC4uJn/GGJL6yp/T4U='",
        "style-src-attr 'none'",
        "script-src 'self' https://static.cloudflareinsights.com",
        "script-src-attr 'none'",
        "frame-src 'self' blob:",
        "worker-src 'none'",
        "manifest-src 'self'",
        'report-to default',
        'report-uri /reporting.php',
        'upgrade-insecure-requests',
    ]);

    header('Content-Security-Policy: ' . $csp);
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), fullscreen=(self)');
    header('Cache-Control: no-store, private, max-age=0, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Embedder-Policy: require-corp');
    header('Cross-Origin-Resource-Policy: same-origin');
    secscan_send_operational_security_headers();

    $isHttps = secscan_is_https();

    if ($isHttps) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
    }
};


// Handle AJAX scan request — guna scanner.php penuh (30+ checks), bukan mini scanner 12 checks
if ($requestMethod === 'POST' && strtolower($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') === 'xmlhttprequest') {
    set_time_limit(120);
    ini_set('max_execution_time', '120');
    ob_start();

    set_error_handler(static function (int $errno, string $errstr, string $errfile = '', int $errline = 0): bool {
        error_log("[SecScan index.php] PHP error ({$errno}): {$errstr} in {$errfile}:{$errline}");
        return true;
    });

    $sendSecurityHeaders();
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');

    $sendJson = static function (array $payload, int $status = 200): void {
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
        http_response_code($status);
        echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        exit;
    };

    $enforceScanRateLimit = static function () use ($sendJson): void {
        $clientIp = secscan_client_ip();
        if (secscan_is_owner_bypass_ip($clientIp)) {
            header('X-RateLimit-Bypass: owner-ip');
            header('X-RateLimit-Limit: bypass');
            header('X-RateLimit-Remaining: bypass');
            return;
        }

        $rate = RateLimiter::consume(
            'scan_v5',
            $clientIp,
            (int)secscan_config('scan_rate_limit'),
            (int)secscan_config('scan_rate_window')
        );

        header('X-RateLimit-Limit: ' . $rate['limit']);
        header('X-RateLimit-Remaining: ' . $rate['remaining']);
        header('X-RateLimit-Reset: ' . $rate['reset']);

        if (!empty($rate['storage_failed'])) {
            $sendJson(['error' => 'Perkhidmatan rate limit tidak tersedia. Cuba semula kemudian.'], 503);
        }

        if (!$rate['allowed']) {
            header('Retry-After: ' . $rate['retry_after']);
            $limit = (int)secscan_config('scan_rate_limit');
            $window = (int)secscan_config('scan_rate_window');
            $sendJson([
                'error'       => "Had scan telah dicapai. Maksimum {$limit} scan sahaja bagi setiap IP dalam tempoh {$window} saat.",
                'limit'       => $limit,
                'window'      => $window,
                'retry_after' => $rate['retry_after'],
                'client_ip'   => $clientIp,
            ], 429);
        }
    };

    $rawBody = secscan_read_request_body();
    if ($rawBody === null) {
        $sendJson(['error' => 'Request terlalu besar.'], 413);
    }
    $input = $rawBody !== '' ? json_decode($rawBody, true) : [];
    if (!is_array($input) || ($rawBody !== '' && json_last_error() !== JSON_ERROR_NONE)) {
        if ($_POST === []) {
            $sendJson(['error' => 'Request JSON tidak sah.'], 400);
        }
        $input = [];
    }
    $target  = UrlGuard::normalizeAndValidate((string)($input['url'] ?? $_POST['url'] ?? $_GET['url'] ?? ''));
    if (!$target['ok']) {
        $sendJson(['error' => $target['error']], (int)$target['status']);
    }

    // Kuota hanya dibakar selepas URL sah.
    $enforceScanRateLimit();

    try {
        // Authenticated scanning (opt-in via SECSCAN_ALLOW_AUTH_SCAN=1).
        $authCookie = '';
        $authHeaders = [];
        if (secscan_config('allow_auth_scan')) {
            $authCookie = trim((string)($input['auth_cookie'] ?? ''));
            $authHeaders = $input['auth_headers'] ?? [];
            if (!is_array($authHeaders)) $authHeaders = [];
            if ($authCookie !== '' || $authHeaders !== []) {
                if (($target['scheme'] ?? '') !== 'https') {
                    $sendJson(['error' => 'Authenticated scan memerlukan URL HTTPS yang sah.'], 400);
                }
            }
        }

        if (secscan_config('scanner_mode') === 'remote') {
            require_once __DIR__ . '/src/RemoteScannerClient.php';
            $client = new RemoteScannerClient(
                (string)secscan_config('worker_url'),
                (string)secscan_config('worker_shared_secret'),
                (int)secscan_config('worker_timeout'),
                (int)secscan_config('worker_max_response_bytes')
            );
            $result = $client->scan((string)$target['url'], $authHeaders, $authCookie);
        } else {
            $scannerPath = __DIR__ . '/scanner.php';
            if (!is_file($scannerPath)) {
                $sendJson(['error' => 'scanner.php tidak dijumpai dalam folder yang sama dengan index.php.'], 500);
            }
            require_once $scannerPath;
            if (!class_exists('SecurityScanner')) {
                $sendJson(['error' => 'Class SecurityScanner tidak dijumpai dalam scanner.php.'], 500);
            }
            $scanner = new SecurityScanner((string)$target['url']);
            if ($authCookie !== '' || $authHeaders !== []) {
                $scanner->setAuth($authHeaders, $authCookie);
            }
            $result = $scanner->scan();
        }

        if (!is_array($result)) {
            $sendJson(['error' => 'scanner.php tidak memulangkan array result yang sah.'], 500);
        }

        $clientIp = secscan_client_ip();
        $result['scan_client_ip'] = $clientIp;
        $result['request'] = [
            'client_ip' => $clientIp,
        ];
        $result['scanner_identity'] = secscan_scanner_identity();

        // Log scan ke SQLite untuk dashboard
        try {
            $loggerPath = __DIR__ . '/logger.php';
            if (is_file($loggerPath)) {
                require_once $loggerPath;
                (new ScanLogger())->log($result, $clientIp);
            }
        } catch (Throwable $logEx) {
            error_log('[SecScan] Logger failed (non-fatal): ' . $logEx->getMessage());
        }

        $result['target'] = [
            'name'     => $target['hostname'],
            'hostname' => $target['hostname'],
            'scheme'   => $target['scheme'],
            'url'      => $target['url'],
            'ipv4'     => $target['ipv4'],
            'ipv6'     => $target['ipv6'],
        ];
        $result['resolved_ips'] = [
            'ipv4' => $target['ipv4'],
            'ipv6' => $target['ipv6'],
        ];

        $sendJson($result);
    } catch (Throwable $e) {
        error_log(sprintf(
            '[SecScan index.php] %s for %s | %s in %s:%d | Trace: %s',
            get_class($e),
            $target['url'],
            $e->getMessage(),
            $e->getFile(),
            $e->getLine(),
            str_replace("\n", ' ', $e->getTraceAsString())
        ));
        $sendJson(['error' => 'Ralat dalaman semasa scan. Semak PHP error_log untuk detail.'], 500);
    }
}

$sendSecurityHeaders();
$scannerIdentity = secscan_scanner_identity();
$scannerAllowlistConfigured = !empty($scannerIdentity['configured']);
$scannerAllowlistText = (string)($scannerIdentity['allowlist_text'] ?? '');
$appVersion = secscan_app_version();
?>
<!DOCTYPE html>
<html lang="ms">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"/>
  <meta name="theme-color" content="#F4F7FB" media="(prefers-color-scheme: light)"/>
  <meta name="theme-color" content="#080D14" media="(prefers-color-scheme: dark)"/>
  <title>SecScan — Platform Risikan Keselamatan</title>
  <link rel="icon" type="image/svg+xml" href="favicon.svg"/>
  <link rel="shortcut icon" href="favicon.svg"/>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&amp;family=Lora:wght@500;600&amp;family=JetBrains+Mono:wght@400;500&amp;display=swap" rel="stylesheet"/>
  <link rel="stylesheet" href="assets/app.css?v=<?= rawurlencode((string)filemtime(__DIR__ . '/assets/app.css')) ?>"/>
  <link rel="stylesheet" href="assets/enterprise.css?v=<?= rawurlencode((string)filemtime(__DIR__ . '/assets/enterprise.css')) ?>"/>
  <script src="assets/theme.js?v=<?= rawurlencode((string)filemtime(__DIR__ . '/assets/theme.js')) ?>"></script>
</head>
<body class="enterprise-ui">
  <div class="app">

    <!-- HEADER -->
    <header class="header">
      <div class="header-inner">
        <a href="/" class="logo">
          <div class="logo-icon"><img src="secscan-logo.svg" alt="" aria-hidden="true"/></div>
          <div>
            <div class="logo-name">SecScan</div>
            <div class="logo-sub">Pengimbas Keselamatan Enterprise</div>
          </div>
        </a>
        <div class="header-actions">
          <a class="dashboard-link" href="faqs.php">FAQ</a>
          <a class="dashboard-link" href="about.php">Tentang</a>
          <a class="dashboard-link" href="server-audit.php">Audit Server</a>
          <a class="dashboard-link" href="dashboard.php">Papan Pemuka</a>
          <div class="live-badge">
              <span class="live-dot" aria-hidden="true">&#8203;</span>
            Audit IP aktif
          </div>
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
      <section class="hero">
        <div class="hero-layout">
          <div class="hero-main">

        <div class="eyebrow">
          <span class="eyebrow-dot" aria-hidden="true">&#8203;</span>
          Imbasan keselamatan web dibenarkan
        </div>

        <h1 class="hero-title">
          <span>Imbasan keselamatan</span>
          <span>web organisasi, dibina</span>
          <span>untuk pasukan bertanggungjawab.</span>
        </h1>

        <p class="hero-sub">
          Nilai posture laman web, kenal pasti CMS, kesan captcha atau WAF block, dan hasilkan bukti audit yang mudah dibaca.
        </p>

        <!-- Scan Console -->
        <div class="scan-console">
          <div class="console-head">
            <span><span class="status-dot" aria-hidden="true">&#8203;</span>Endpoint pengimbas sedia</span>
            <span>Audit IP aktif</span>
          </div>
        <form id="scanForm" class="scan-form" autocomplete="off" novalidate>
          <div class="scan-card">
            <span class="scan-input-icon">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
                <circle cx="11" cy="11" r="8" stroke="currentColor" stroke-width="1.8"/>
                <path d="M21 21l-4.35-4.35" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
              </svg>
            </span>
            <input
              type="text"
              id="urlInput"
              class="scan-input"
              placeholder="https://xxxxxxx.my"
              inputmode="url"
              autocapitalize="off"
              spellcheck="false"
              required
            />
            <button type="submit" class="scan-btn" id="scanBtn">
              <span class="btn-text">Mula Scan Sah</span>
              <span class="btn-spinner" aria-hidden="true">&#8203;</span>
            </button>
          </div>
          <div class="scan-status" id="termStatus"></div>

<?php if ($scannerAllowlistConfigured): ?>
          <details class="allowlist-panel">
            <summary class="allowlist-toggle">
              <span class="allowlist-toggle-show">Tunjuk allowlist sebelum scan</span>
              <span class="allowlist-toggle-hide">Sembunyikan allowlist sebelum scan</span>
              <svg class="allowlist-toggle-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path d="m8 10 4 4 4-4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
              </svg>
            </summary>
            <div class="allowlist-content">
              <div class="allowlist-grid">
                <div class="allowlist-item">
                  <span>Domain scanner</span>
                  <strong><?= htmlspecialchars((string)($scannerIdentity['domain'] ?? '') ?: 'Belum dikonfigurasi', ENT_QUOTES, 'UTF-8') ?></strong>
                </div>
                <div class="allowlist-item">
                  <span>IP server scanner</span>
                  <strong><?= htmlspecialchars(!empty($scannerIdentity['ips']) ? implode(', ', $scannerIdentity['ips']) : 'Belum dikonfigurasi', ENT_QUOTES, 'UTF-8') ?></strong>
                </div>
              </div>
              <div class="allowlist-note">
                Minta pemilik target allowlist nilai ini pada WAF/firewall sebelum scan jika target ada bot protection.
                <?php if ($scannerAllowlistText !== ''): ?>
                  <button type="button" class="allowlist-copy" data-copy="<?= htmlspecialchars($scannerAllowlistText, ENT_QUOTES, 'UTF-8') ?>">Salin</button>
                <?php endif; ?>
              </div>
            </div>
          </details>
<?php endif; ?>

<?php if (secscan_config('allow_auth_scan')): ?>
          <!-- Scan berautentikasi (lanjutan) -->
          <details class="auth-panel" id="authPanel">
            <summary>Scan berautentikasi (lanjutan)</summary>
            <p class="auth-note">Scan di belakang log masuk. Kredensial hanya dihantar kepada hos sasaran. Scan sistem yang anda miliki sahaja.</p>
            <label class="auth-label" for="authCookie">Pengepala cookie</label>
            <input type="text" id="authCookie" class="auth-input" placeholder="sessionid=abc123; csrftoken=xyz" autocapitalize="off" spellcheck="false" />
            <label class="auth-label" for="authHeaders">Pengepala tambahan (satu setiap baris, contoh <code>Authorization: Bearer ...</code>)</label>
            <textarea id="authHeaders" class="auth-input" rows="3" placeholder="Authorization: Bearer eyJ...&#10;X-Api-Key: ..."></textarea>
          </details>
<?php endif; ?>

          <!-- Error -->
          <div class="error-box" id="errorBox">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
              <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.8"/>
              <path d="M12 8v4M12 16h.01" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
            </svg>
            <span id="errorMsg">URL tidak sah.</span>
          </div>
        </form>

        <div class="scan-disclaimer">
          <strong>Penggunaan sah sahaja.</strong> Dengan meneruskan scan, pengguna mengesahkan target berada bawah pemilikan, pengurusan, atau kebenaran rasmi. Persetujuan boleh disimpan selama 30 hari.
        </div>
        </div><!-- /scan-console -->

        <div class="terms-modal" id="termsModal" role="dialog" aria-modal="true" aria-labelledby="termsTitle" hidden>
          <div class="terms-card">
            <div class="terms-icon" aria-hidden="true">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
                <path d="M12 2.8 4 6.4v5.8c0 5 3.3 9.2 8 10.6 4.7-1.4 8-5.6 8-10.6V6.4l-8-3.6Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>
                <path d="M9 12.2 11.1 14.3 15.5 9.8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
              </svg>
            </div>
            <div class="terms-body">
              <h2 id="termsTitle">Setuju terma penggunaan SecScan</h2>
              <p>Gunakan SecScan hanya untuk domain atau sistem yang anda miliki, urus, atau mendapat kebenaran jelas untuk diuji.</p>
              <ul>
                <li>Anda bertanggungjawab terhadap semua aktiviti scan yang dimulakan.</li>
                <li>IP pengguna scan akan direkod untuk audit dan pencegahan penyalahgunaan.</li>
                <li>Jangan gunakan SecScan untuk menguji sistem pihak ketiga tanpa izin.</li>
              </ul>
              <div class="terms-note">Persetujuan ini disimpan sebagai kuki selama 30 hari pada pelayar ini.</div>
              <div class="terms-actions">
                <button type="button" class="terms-btn" id="termsCancelBtn">Batal</button>
                <button type="button" class="terms-btn primary" id="termsAgreeBtn">Saya setuju &amp; mula scan</button>
              </div>
            </div>
          </div>
        </div>

        <!-- Progress -->
        <div class="progress-section" id="progressSection">
          <div class="progress-label">
            <span id="progressLabel">Menganalisa…</span>
            <span id="progressPct">0%</span>
          </div>
          <div class="progress-bar-wrap">
            <div class="progress-bar-fill" id="progressFill"></div>
          </div>
          <div class="progress-stage-current" id="progressStageCurrent">Fasa aktif: Sambungan server</div>
          <div class="progress-steps" id="progressSteps" aria-label="Fasa scan sedang berjalan"></div>
          <div class="progress-text" id="progressText">Menyambung ke server...</div>
        </div>

          </div>

          <!-- Risikan pendedahan langsung (diisi selepas scan) -->
          <aside class="hero-intel" id="heroIntel" aria-label="Risikan pendedahan langsung">
            <div class="intel-top">
              <div class="intel-title">Risikan Pendedahan Langsung</div>
              <span class="intel-badge" id="intelWaf">Menunggu scan</span>
            </div>
            <div class="radar" id="intelRadar" aria-hidden="true">
              <span class="radar-point p1">&#8203;</span>
              <span class="radar-point p2">&#8203;</span>
              <span class="radar-point p3">&#8203;</span>
            </div>
            <div class="security-grade-card" id="intelGradeCard">
              <div class="security-grade-mark" id="intelGrade">&ndash;</div>
              <div class="security-grade-meta">
                <h2 id="intelGradeTitle">Gred Keselamatan: &mdash;</h2>
                <p id="intelGradeDesc">Masukkan URL dan jalankan scan untuk melihat gred keselamatan, CMS, dan status WAF secara langsung.</p>
                <div class="security-grade-scale" id="intelScale" aria-hidden="true">
                  <span>&#8203;</span><span>&#8203;</span><span>&#8203;</span><span>&#8203;</span><span>&#8203;</span>
                </div>
              </div>
            </div>
            <div class="intel-list">
              <div class="intel-row"><span>Cap jari CMS</span><strong id="intelCms">&mdash;</strong></div>
              <div class="intel-row"><span>Semakan aktif</span><strong id="intelProbe">&mdash;</strong></div>
              <div class="intel-row"><span>IP pengimbas</span><strong id="intelIp">&mdash;</strong></div>
            </div>
          </aside>

        </div>

        <!-- Capabilities -->
        <div class="section-grid" aria-label="Keupayaan SecScan">
          <article class="capability">
            <div class="cap-icon">ID</div>
            <h2>Pengenalan CMS</h2>
            <p>Kenal pasti Joomla, WordPress, penanda sumber, aset, tag penjana, dan pilihan semakan bila semakan aktif disekat.</p>
          </article>
          <article class="capability">
            <div class="cap-icon">WF</div>
            <h2>Kesedaran WAF &amp; Captcha</h2>
            <p>Pengimbas terus memaklumkan bila scan disekat dan memberi langkah penyelesaian seperti senarai dibenarkan atau tetingkap scan.</p>
          </article>
          <article class="capability">
            <div class="cap-icon">AU</div>
            <h2>Jejak Audit</h2>
            <p>Papan pemuka memaparkan IP pengguna, sejarah scan, gred, status, dan bukti untuk tadbir urus dalaman.</p>
          </article>
        </div>

      </section>

      <!-- RESULTS -->
      <section class="results-section" id="resultsSection">

        <div class="target-banner">
          <div class="target-main">
            <div class="target-kicker">Sasaran scan</div>
            <div class="target-name" id="targetName">—</div>
            <div class="target-url" id="targetUrl">—</div>
          </div>

          <div class="target-meta-grid" id="targetMetaGrid"></div>

          <div class="report-actions">
            <button type="button" class="report-btn primary" id="printA4Btn">Cetak A4</button>
            <button type="button" class="report-btn" id="saveA4Btn">Simpan HTML</button>
            <button type="button" class="report-btn" id="copyResultBtn">Salin hasil</button>
          </div>
        </div>

        <div class="result-tabs">
          <button type="button" class="result-tab active" id="tabSecurity" data-tab="security">
            <span>Scan keselamatan</span>
            <strong id="tabSecurityBadge">—</strong>
          </button>
          <button type="button" class="result-tab" id="tabPci" data-tab="pci">
            <span>PCI DSS Lite</span>
            <strong id="tabPciBadge">10</strong>
          </button>
        </div>

        <div class="tab-content active" id="securityTabPanel">
          <div class="assessment-panel compact-panel">
            <div class="assessment-header">
              <div>
                <div class="assessment-kicker">Ringkasan</div>
                <h3 class="assessment-title">Keputusan scan keselamatan</h3>
              </div>
              <div class="assessment-mini-meta" id="securityMiniMeta">—</div>
            </div>
            <div class="assessment-body" id="securityOverview"></div>
          </div>

          <div id="recommendationsContainer"></div>

          <div id="categoryScoresContainer"></div>

          <div class="results-block">
            <div class="results-block-head">
              <div class="findings-title">Keputusan scan mengikut kategori</div>
            </div>
            <div id="findingsContainer"></div>
          </div>
        </div>

        <div class="tab-content" id="pciTabPanel">
          <div class="assessment-panel compact-panel">
            <div class="assessment-header">
              <div>
                <div class="assessment-kicker">Paparan pematuhan</div>
                <h3 class="assessment-title">Keputusan PCI DSS Lite</h3>
              </div>
              <div class="assessment-mini-meta" id="pciMiniMeta">10 kawalan</div>
            </div>
            <div class="assessment-body" id="pciOverview"></div>
          </div>

          <div class="results-block">
            <div class="results-block-head">
              <div class="findings-title">Kawalan PCI DSS Lite</div>
            </div>
            <div id="pciControlsContainer"></div>
          </div>
        </div>

      </section>
      <!-- SERVER AUDIT LINK -->
      <section class="audit-teaser" aria-labelledby="auditTeaserTitle">
        <div>
          <div class="sa-kicker">Alat tambahan</div>
          <h2 id="auditTeaserTitle">Audit keselamatan pelayan Ubuntu</h2>
          <p>Skrip audit read-only kini diletakkan pada halaman khusus supaya scanner utama kekal ringkas.</p>
        </div>
        <a class="audit-teaser-link" href="server-audit.php">Buka audit server</a>
      </section>

    </main>

    <footer class="footer">
      <span>© 2026 SecScan Enterprise. Hak cipta terpelihara.</span>
      <span class="footer-version">Versi <?= htmlspecialchars($appVersion, ENT_QUOTES, 'UTF-8') ?></span>
      <nav class="footer-links" aria-label="Pautan legal SecScan">
        <a href="#terma" data-legal-modal="terms">Terma</a>
        <a href="#privasi" data-legal-modal="privacy">Privasi</a>
        <a href="#penafian" data-legal-modal="disclaimer">Penafian</a>
        <a href="faqs.php">FAQ</a>
        <a href="about.php">Tentang</a>
        <a href="server-audit.php">Audit Server</a>
        <a href="dashboard.php">Papan Pemuka</a>
      </nav>
    </footer>

    <div class="terms-modal legal-modal" id="legalModal" role="dialog" aria-modal="true" aria-labelledby="legalModalTitle" hidden>
      <div class="terms-card legal-card">
        <div class="terms-icon" aria-hidden="true">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
            <path d="M7 3h7l5 5v13H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>
            <path d="M14 3v6h5M8.5 13h7M8.5 16.5h7M8.5 9.5h2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
          </svg>
        </div>
        <div class="terms-body legal-body">
          <h2 id="legalModalTitle">Terma</h2>
          <div id="legalModalBody"></div>
          <div class="terms-actions">
            <button type="button" class="terms-btn primary" id="legalModalCloseBtn">Tutup</button>
          </div>
        </div>
      </div>
    </div>

  </div>

  <script src="assets/app.js?v=<?= rawurlencode((string)filemtime(__DIR__ . '/assets/app.js')) ?>"></script>
</body>
</html>
