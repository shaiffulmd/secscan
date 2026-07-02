<?php
// ================================================================
//  index.php — SecScan (backend handler + frontend shell)
// ================================================================

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/src/RateLimiter.php';
require_once __DIR__ . '/src/UrlGuard.php';

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
        "connect-src 'self'",
        "img-src 'self' data: blob:",
        "font-src 'self' https://fonts.gstatic.com data:",
        "style-src 'self' https://fonts.googleapis.com",
        "style-src-elem 'self' https://fonts.googleapis.com",
        "style-src-attr 'none'",
        "script-src 'self'",
        "script-src-attr 'none'",
        "frame-src 'self' blob:",
        "worker-src 'none'",
        "manifest-src 'self'",
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

    $isHttps = secscan_is_https();

    if ($isHttps) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
    }
};


// Handle AJAX scan request — guna scanner.php penuh (30+ checks), bukan mini scanner 12 checks
if ($_SERVER['REQUEST_METHOD'] === 'POST' && strtolower($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') === 'xmlhttprequest') {
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
        $rate = RateLimiter::consume(
            'scan_v4',
            $clientIp,
            (int)secscan_config('scan_rate_limit'),
            (int)secscan_config('scan_rate_window')
        );

        header('X-RateLimit-Limit: ' . $rate['limit']);
        header('X-RateLimit-Remaining: ' . $rate['remaining']);
        header('X-RateLimit-Reset: ' . $rate['reset']);

        if (!$rate['allowed']) {
            header('Retry-After: ' . $rate['retry_after']);
            $sendJson([
                'error'       => 'Had scan telah dicapai. Maksimum 50 scan sahaja bagi setiap IP dalam 24 jam.',
                'limit'       => $rate['limit'],
                'window'      => (int)secscan_config('scan_rate_window'),
                'retry_after' => $rate['retry_after'],
                'client_ip'   => $clientIp,
            ], 429);
        }
    };

    $rawBody = file_get_contents('php://input') ?: '';
    $input   = json_decode($rawBody, true);
    $target  = UrlGuard::normalizeAndValidate((string)($input['url'] ?? $_POST['url'] ?? $_GET['url'] ?? ''));
    if (!$target['ok']) {
        $sendJson(['error' => $target['error']], (int)$target['status']);
    }

    // Kuota hanya dibakar selepas URL sah.
    $enforceScanRateLimit();

    try {
        $scannerPath = __DIR__ . '/scanner.php';
        if (!is_file($scannerPath)) {
            $sendJson(['error' => 'scanner.php tidak dijumpai dalam folder yang sama dengan index.php.'], 500);
        }

        require_once $scannerPath;

        if (!class_exists('SecurityScanner')) {
            $sendJson(['error' => 'Class SecurityScanner tidak dijumpai dalam scanner.php.'], 500);
        }

        $scanner = new SecurityScanner($target['url']);

        // Authenticated scanning (opt-in via SECSCAN_ALLOW_AUTH_SCAN=1).
        if (secscan_config('allow_auth_scan')) {
            $authCookie  = trim((string)($input['auth_cookie'] ?? ''));
            $authHeaders = $input['auth_headers'] ?? [];
            if (!is_array($authHeaders)) $authHeaders = [];
            if ($authCookie !== '' || $authHeaders !== []) {
                $scanner->setAuth($authHeaders, $authCookie);
            }
        }

        $result  = $scanner->scan();

        if (!is_array($result)) {
            $sendJson(['error' => 'scanner.php tidak memulangkan array result yang sah.'], 500);
        }

        // Log scan ke SQLite untuk dashboard
        try {
            $loggerPath = __DIR__ . '/logger.php';
            if (is_file($loggerPath)) {
                require_once $loggerPath;
                (new ScanLogger())->log($result, secscan_client_ip());
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
?>
<!DOCTYPE html>
<html lang="ms">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"/>
  <meta name="theme-color" content="#FAF9F5" media="(prefers-color-scheme: light)"/>
  <meta name="theme-color" content="#262624" media="(prefers-color-scheme: dark)"/>
  <title>SecScan — Security Intelligence Platform</title>
  <link rel="icon" type="image/svg+xml" href="security-icon.svg"/>
  <link rel="shortcut icon" href="security-icon.svg"/>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Lora:wght@500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet"/>
  <link rel="stylesheet" href="assets/app.css?v=<?= rawurlencode((string)filemtime(__DIR__ . '/assets/app.css')) ?>"/>
  <script src="assets/theme.js?v=<?= rawurlencode((string)filemtime(__DIR__ . '/assets/theme.js')) ?>"></script>
</head>
<body>
  <div class="app">

    <!-- HEADER -->
    <header class="header">
      <div class="header-inner">
        <a href="/" class="logo">
          <div class="logo-icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.35C16.5 22.15 20 17.25 20 12V6L12 2z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>
              <path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </div>
          <div>
            <div class="logo-name">SecScan</div>
            <div class="logo-sub">Security intelligence</div>
          </div>
        </a>
        <div class="header-actions">
          <div class="live-badge">
            <span class="live-dot"></span>
            Live
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

        <div class="eyebrow">
          <span class="eyebrow-dot"></span>
          Analisis keselamatan full-stack
        </div>

        <h1 class="hero-title">
          Kenal pasti risiko keselamatan<br>
          <span class="accent">sebelum ia jadi masalah.</span>
        </h1>

        <p class="hero-sub">
          Scan mana-mana domain untuk vulnerabilities, misconfigurations, dan exposure risks — dalam beberapa saat.
        </p>

        <!-- Scan Form -->
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
              placeholder="example.com atau https://..."
              inputmode="url"
              autocapitalize="off"
              spellcheck="false"
              required
            />
            <button type="submit" class="scan-btn" id="scanBtn">
              <span class="btn-text">Mula scan</span>
              <div class="btn-spinner"></div>
            </button>
          </div>
          <div class="scan-status" id="termStatus"></div>

<?php if (secscan_config('allow_auth_scan')): ?>
          <!-- Authenticated scan (advanced) -->
          <details class="auth-panel" id="authPanel">
            <summary>Authenticated scan (advanced)</summary>
            <p class="auth-note">Scan behind a login. Credentials are sent only to the target host. Only scan systems you own.</p>
            <label class="auth-label" for="authCookie">Cookie header</label>
            <input type="text" id="authCookie" class="auth-input" placeholder="sessionid=abc123; csrftoken=xyz" autocapitalize="off" spellcheck="false" />
            <label class="auth-label" for="authHeaders">Extra headers (one per line, e.g. <code>Authorization: Bearer …</code>)</label>
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

        <!-- Stats -->
        <div class="stats-row">
          <div class="stat-card"><div class="stat-val">30+</div><div class="stat-label">Semakan keselamatan</div></div>
          <div class="stat-card"><div class="stat-val">&lt;15s</div><div class="stat-label">Purata masa scan</div></div>
          <div class="stat-card"><div class="stat-val">A–F</div><div class="stat-label">Gred keseluruhan</div></div>
        </div>

        <!-- Features -->
        <div class="features-row">
          <span class="feat-pill">SSL / TLS</span>
          <span class="feat-pill">HTTP Headers</span>
          <span class="feat-pill">DNS Records</span>
          <span class="feat-pill">SPF / DMARC</span>
          <span class="feat-pill">Info Disclosure</span>
          <span class="feat-pill">security.txt</span>
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
              <div class="assessment-mini-meta" id="pciMiniMeta">10 controls</div>
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
    </main>

    <footer class="footer">
      © 2025 SecScan · Platform analisis keselamatan
    </footer>

  </div>

  <script src="assets/app.js?v=<?= rawurlencode((string)filemtime(__DIR__ . '/assets/app.js')) ?>"></script>
</body>
</html>
