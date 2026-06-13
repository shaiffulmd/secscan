<?php
// ================================================================
//  index.php — SecScan (Frontend + Backend dalam satu fail)
// ================================================================

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/src/RateLimiter.php';
require_once __DIR__ . '/src/UrlGuard.php';

// Generate one-time nonce for this response. Required because this single-file
// page uses inline CSS and JavaScript.
try {
    $cspNonce = rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');
} catch (Throwable $e) {
    $cspNonce = bin2hex(random_bytes(16));
}

$sendSecurityHeaders = static function (string $nonce): void {
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
        "style-src 'self' 'nonce-{$nonce}' https://fonts.googleapis.com",
        "style-src-elem 'self' 'nonce-{$nonce}' https://fonts.googleapis.com",
        "style-src-attr 'none'",
        "script-src 'self' 'nonce-{$nonce}'",
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

    $isHttps = (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https')
        || (($_SERVER['HTTP_CF_VISITOR'] ?? '') && str_contains((string)$_SERVER['HTTP_CF_VISITOR'], 'https'));

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

    $sendSecurityHeaders($cspNonce);
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

$sendSecurityHeaders($cspNonce);
?>
<!DOCTYPE html>
<html lang="ms">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"/>
  <meta name="theme-color" content="#060c14"/>
  <title>SecScan — Security Intelligence Platform</title>
  <link rel="icon" type="image/svg+xml" href="security-icon.svg"/>
  <link rel="shortcut icon" href="security-icon.svg"/>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet"/>
  <style nonce="<?= htmlspecialchars($cspNonce, ENT_QUOTES, 'UTF-8') ?>">
    :root {
      --void:     #020508;
      --base:     #050d18;
      --surface:  #091525;
      --elevated: #0e1f33;
      --high:     #132840;
      --border:   rgba(0,220,180,.08);
      --border2:  rgba(0,220,180,.18);
      --border3:  rgba(0,220,180,.32);
      --t1: #cde8f8; --t2: #5a8aaa; --t3: #2a4560;
      --mint:  #00ffcc; --mint2: rgba(0,255,204,.08); --mint3: rgba(0,255,204,.20);
      --sky:   #38bdf8; --rose:  #f43f5e; --amber: #f59e0b; --green: #22c55e;
      --f-title: 'Plus Jakarta Sans', sans-serif;
      --f-mono:  'JetBrains Mono', monospace;
      --r-sm: 6px; --r-md: 12px; --r-lg: 18px;
      --ease: cubic-bezier(.4,0,.2,1);
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { font-size: 16px; scroll-behavior: smooth; }
    body { font-family: var(--f-mono); background: var(--base); color: var(--t1); min-height: 100vh; overflow-x: hidden; }
    input, button { font-family: inherit; }
    button { cursor: pointer; border: none; background: none; }
    a { text-decoration: none; }

    .bg-grid {
      position: fixed; inset: 0; z-index: 0; pointer-events: none;
      background-image: radial-gradient(rgba(0,255,204,.04) 1px, transparent 1px);
      background-size: 30px 30px;
      mask-image: radial-gradient(ellipse 85% 85% at 50% 40%, black 30%, transparent 100%);
    }
    .bg-glow {
      position: fixed; inset: 0; z-index: 0; pointer-events: none;
      background:
        radial-gradient(ellipse 70% 55% at 50% -5%, rgba(0,255,204,.055) 0%, transparent 65%),
        radial-gradient(ellipse 45% 35% at 85% 95%, rgba(56,189,248,.045) 0%, transparent 65%);
    }
    .app { position: relative; z-index: 1; max-width: 1000px; margin: 0 auto; padding: 0 20px 100px; }

    /* HEADER */
    .header { position: sticky; top: 0; z-index: 100; background: rgba(5,13,24,.85); backdrop-filter: blur(16px); border-bottom: 1px solid var(--border); }
    .header-inner { max-width: 1000px; margin: 0 auto; padding: 0 20px; height: 58px; display: flex; align-items: center; justify-content: space-between; }
    .logo { display: flex; align-items: center; gap: 10px; }
    .logo-icon { width: 34px; height: 34px; background: var(--mint2); border: 1px solid var(--border2); border-radius: var(--r-sm); display: grid; place-items: center; box-shadow: 0 0 16px rgba(0,255,204,.10); }
    .logo-name { font-family: var(--f-title); font-weight: 800; font-size: 1rem; letter-spacing: .04em; }
    .logo-sub  { font-size: .5rem; letter-spacing: .2em; color: var(--mint); font-family: var(--f-title); font-weight: 600; margin-top: 2px; opacity: .7; }
    .live-badge { display: flex; align-items: center; gap: 6px; font-family: var(--f-title); font-weight: 700; font-size: .58rem; letter-spacing: .18em; color: var(--mint); background: var(--mint2); border: 1px solid var(--border2); border-radius: 999px; padding: 4px 10px; }
    .live-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--mint); box-shadow: 0 0 8px var(--mint); animation: blink 1.8s ease-in-out infinite; }
    @keyframes blink { 0%,100%{opacity:1}50%{opacity:.3} }

    /* HERO */
    .hero { padding: 64px 0 48px; text-align: center; display: flex; flex-direction: column; align-items: center; }
    .eyebrow { display: inline-flex; align-items: center; gap: 8px; font-size: .62rem; letter-spacing: .18em; color: var(--mint); font-family: var(--f-title); font-weight: 700; background: var(--mint2); border: 1px solid var(--border2); border-radius: 999px; padding: 5px 16px; margin-bottom: 24px; }
    .eyebrow-dot { width: 5px; height: 5px; border-radius: 50%; background: var(--mint); }
    .hero-title { font-family: var(--f-title); font-weight: 800; font-size: clamp(2rem, 6vw, 3.5rem); line-height: 1.1; letter-spacing: -.02em; margin-bottom: 16px; max-width: 680px; }
    .hero-title .accent { background: linear-gradient(90deg, var(--mint), var(--sky)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
    .hero-sub { font-size: clamp(.78rem, 2.2vw, .9rem); color: var(--t2); line-height: 1.7; max-width: 500px; margin-bottom: 40px; }

    #scanForm { width: 100%; max-width: 680px; }

    /* SCAN CARD */
    .scan-card { width: 100%; max-width: 680px; background: var(--surface); border: 1px solid var(--border2); border-radius: var(--r-lg); overflow: hidden; box-shadow: 0 24px 48px rgba(0,0,0,.4), 0 0 80px rgba(0,255,204,.04); transition: border-color .3s, box-shadow .3s; }
    .scan-card:focus-within { border-color: var(--border3); box-shadow: 0 24px 48px rgba(0,0,0,.5), 0 0 80px rgba(0,255,204,.10); }
    .term-bar { display: flex; align-items: center; gap: 8px; padding: 11px 16px; background: var(--elevated); border-bottom: 1px solid var(--border); }
    .t-dot { width: 10px; height: 10px; border-radius: 50%; }
    .t-red{background:#ff5f57} .t-amber{background:#febc2e} .t-green{background:#28c840}
    .term-label { font-size: .58rem; letter-spacing: .18em; color: var(--t3); font-family: var(--f-title); font-weight: 700; margin-left: 6px; }
    .term-spacer { flex: 1; }
    .term-status { font-size: .58rem; letter-spacing: .12em; color: var(--mint); opacity: .6; }
    .term-body { display: flex; align-items: center; padding: 16px 20px; gap: 10px; }
    .term-prompt { font-size: .78rem; color: var(--mint); white-space: nowrap; flex-shrink: 0; opacity: .85; }
    .term-prompt .cmd { color: var(--sky); }
    .term-input { flex: 1; min-width: 0; background: transparent; border: none; outline: none; font-family: var(--f-mono); font-size: .88rem; color: var(--t1); caret-color: var(--mint); }
    .term-input::placeholder { color: var(--t3); }

    /* SCAN BTN */
    .scan-btn { display: flex; align-items: center; justify-content: center; gap: 8px; width: 100%; max-width: 680px; padding: 14px 24px; font-family: var(--f-title); font-weight: 700; font-size: .8rem; letter-spacing: .12em; color: #020508; background: linear-gradient(135deg, var(--mint), #00d4aa); border-radius: var(--r-md); margin-top: 12px; min-height: 50px; box-shadow: 0 0 24px rgba(0,255,204,.20), 0 4px 12px rgba(0,0,0,.3); transition: all .2s var(--ease); position: relative; overflow: hidden; }
    .scan-btn:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 0 40px rgba(0,255,204,.35), 0 8px 20px rgba(0,0,0,.35); }
    .scan-btn:disabled { opacity: .6; cursor: not-allowed; transform: none; }
    .btn-spinner { display: none; width: 16px; height: 16px; border: 2px solid rgba(0,0,0,.3); border-top-color: #020508; border-radius: 50%; animation: spin .7s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .scan-btn.loading .btn-text { display: none; }
    .scan-btn.loading .btn-icon { display: none; }
    .scan-btn.loading .btn-spinner { display: block; }

    /* ERROR */
    .error-box { display: none; align-items: flex-start; gap: 10px; background: rgba(244,63,94,.08); border: 1px solid rgba(244,63,94,.22); border-radius: var(--r-md); padding: 14px 16px; margin-top: 12px; font-size: .8rem; color: #fda4af; width: 100%; max-width: 680px; }
    .error-box.show { display: flex; }

    /* PROGRESS */
    .progress-section { display: none; width: 100%; max-width: 680px; margin-top: 20px; }
    .progress-section.show { display: block; }
    .progress-label { font-size: .65rem; letter-spacing: .12em; color: var(--t2); margin-bottom: 8px; display: flex; justify-content: space-between; }
    .progress-bar-wrap { height: 4px; background: var(--elevated); border-radius: 999px; overflow: hidden; }
    .progress-bar-fill { height: 100%; background: linear-gradient(90deg, var(--mint), var(--sky)); border-radius: 999px; width: 0%; transition: width .4s var(--ease); }
    .progress-text { font-size: .62rem; color: var(--t3); margin-top: 8px; letter-spacing: .08em; }

    /* RESULTS */
    .results-section { display: none; width: 100%; margin-top: 40px; }
    .results-section.show { display: block; }

    /* Score Card */
    .score-card { background: var(--surface); border: 1px solid var(--border2); border-radius: var(--r-lg); padding: 32px; display: flex; align-items: center; gap: 28px; margin-bottom: 24px; flex-wrap: wrap; }
    .score-grade-wrap { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 14px; min-width: 160px; }
    .score-grade { font-family: var(--f-title); font-weight: 800; font-size: 5rem; line-height: 1; min-width: 100px; text-align: center; }
    .grade-A\+ { color: var(--mint); text-shadow: 0 0 30px rgba(0,255,204,.4); }
    .grade-A  { color: var(--mint); text-shadow: 0 0 20px rgba(0,255,204,.3); }
    .grade-B  { color: var(--sky);  text-shadow: 0 0 20px rgba(56,189,248,.3); }
    .grade-C  { color: var(--amber);}
    .grade-D  { color: #fb923c; }
    .grade-F  { color: var(--rose); text-shadow: 0 0 20px rgba(244,63,94,.3); }
    .score-info { flex: 1; }
    .score-host { font-family: var(--f-title); font-weight: 700; font-size: 1.1rem; margin-bottom: 6px; }
    .score-meta { font-size: .65rem; color: var(--t3); letter-spacing: .1em; margin-bottom: 16px; }
    .score-bar-wrap { height: 6px; background: var(--elevated); border-radius: 999px; overflow: hidden; margin-bottom: 8px; }
    .score-bar-fill { height: 100%; border-radius: 999px; transition: width 1s var(--ease); }
    .score-num { font-size: .7rem; color: var(--t2); letter-spacing: .08em; }

    /* Summary pills */
    .summary-pills { display: flex; flex-wrap: wrap; gap: 10px; margin: 0; align-items: center; justify-content: center; }
    .s-pill { display: inline-flex; align-items: center; justify-content: center; gap: 6px; font-family: var(--f-title); font-size: .68rem; font-weight: 800; letter-spacing: .08em; padding: 10px 16px; border-radius: 999px; border: 1px solid; box-shadow: inset 0 1px 0 rgba(255,255,255,.04), 0 10px 24px rgba(0,0,0,.14); }
    .s-pill.critical { color: #ffd5db; background: linear-gradient(180deg, rgba(127,29,29,.46), rgba(69,10,10,.32)); border-color: rgba(251,113,133,.55); }
    .s-pill.high     { color: #ffdfc1; background: linear-gradient(180deg, rgba(124,45,18,.46), rgba(67,20,7,.32)); border-color: rgba(251,146,60,.55); }
    .s-pill.medium   { color: #fff0b3; background: linear-gradient(180deg, rgba(120,53,15,.40), rgba(69,26,3,.28)); border-color: rgba(245,158,11,.58); }
    .s-pill.warning  { color: #fff0b3; background: linear-gradient(180deg, rgba(120,53,15,.40), rgba(69,26,3,.28)); border-color: rgba(245,158,11,.58); }
    .s-pill.info     { color: #d8eeff; background: linear-gradient(180deg, rgba(8,47,73,.46), rgba(12,27,51,.32)); border-color: rgba(56,189,248,.55); }
    .s-pill.low      { color: #d8eeff; background: linear-gradient(180deg, rgba(8,47,73,.46), rgba(12,27,51,.32)); border-color: rgba(56,189,248,.55); }
    .s-pill.pass     { color: #d5ffe8; background: linear-gradient(180deg, rgba(20,83,45,.46), rgba(5,46,22,.32)); border-color: rgba(34,197,94,.55); }

    /* Findings */
    .findings-title { font-family: var(--f-title); font-weight: 700; font-size: .7rem; letter-spacing: .15em; color: var(--t3); margin-bottom: 12px; }
    .finding-item { background: var(--surface); border: 1px solid var(--border); border-radius: var(--r-md); padding: 16px; margin-bottom: 8px; display: flex; gap: 14px; align-items: flex-start; transition: border-color .2s; }
    .finding-item:hover { border-color: var(--border2); }
    .finding-badge { flex-shrink: 0; font-family: var(--f-title); font-weight: 700; font-size: .55rem; letter-spacing: .12em; padding: 3px 8px; border-radius: var(--r-sm); border: 1px solid; white-space: nowrap; margin-top: 2px; }
    .badge-critical { color: #fca5a5; background: rgba(244,63,94,.12); border-color: rgba(244,63,94,.3); }
    .badge-high     { color: #fdba74; background: rgba(251,146,60,.12); border-color: rgba(251,146,60,.3); }
    .badge-medium   { color: #fde68a; background: rgba(245,158,11,.12); border-color: rgba(245,158,11,.3); }
    .badge-warning  { color: #fde68a; background: rgba(245,158,11,.12); border-color: rgba(245,158,11,.3); }
    .badge-low      { color: #bfdbfe; background: rgba(56,189,248,.12); border-color: rgba(56,189,248,.3); }
    .badge-pass     { color: #86efac; background: rgba(34,197,94,.12); border-color: rgba(34,197,94,.3); }
    .badge-info     { color: var(--t2); background: var(--elevated); border-color: var(--border2); }
    .finding-body { flex: 1; min-width: 0; }
    .finding-check { font-family: var(--f-title); font-weight: 700; font-size: .78rem; margin-bottom: 4px; }
    .finding-cat   { font-size: .58rem; color: var(--t3); letter-spacing: .1em; margin-bottom: 6px; }
    .finding-msg   { font-size: .75rem; color: var(--t2); line-height: 1.6; }
    .finding-rec   { font-size: .7rem; color: var(--sky); margin-top: 8px; padding: 8px 12px; background: rgba(56,189,248,.06); border-left: 2px solid rgba(56,189,248,.3); border-radius: 0 var(--r-sm) var(--r-sm) 0; line-height: 1.5; }
    .finding-refs  { font-size: .68rem; color: var(--muted, #94a3b8); margin-top: 6px; line-height: 1.5; }
    .finding-refs a { color: var(--sky); text-decoration: none; border-bottom: 1px dotted rgba(56,189,248,.4); }
    .finding-refs a:hover { border-bottom-style: solid; }

    /* Prioritized recommendations + category scores panels */
    .recs-panel { background: rgba(9,21,37,.72); border: 1px solid var(--border); border-radius: var(--r-lg, 14px); margin-bottom: 16px; overflow: hidden; }
    .recs-head { display: flex; align-items: center; gap: 10px; padding: 14px 18px; border-bottom: 1px solid var(--border); }
    .recs-icon { font-size: 1.05rem; }
    .recs-title { font-size: .8rem; font-weight: 700; letter-spacing: .06em; color: #e2e8f0; }
    .recs-count { margin-left: auto; font-size: .7rem; color: var(--muted, #94a3b8); }
    .recs-empty { padding: 16px 18px; font-size: .82rem; color: var(--muted, #94a3b8); }
    .recs-clean .recs-head { border-bottom: none; }
    .recs-body { padding: 6px 0; }
    .rec-row { display: flex; gap: 12px; padding: 12px 18px; border-bottom: 1px solid rgba(148,163,184,.08); }
    .rec-row:last-child { border-bottom: none; }
    .rec-rank { flex: 0 0 26px; height: 26px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: .72rem; font-weight: 700; color: #0b1525; background: #cbd5e1; }
    .rec-critical .rec-rank { background: #f87171; color: #2a0808; }
    .rec-warning .rec-rank { background: #fbbf24; color: #2a1a00; }
    .rec-main { min-width: 0; flex: 1; }
    .rec-line1 { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 4px; }
    .rec-check { font-size: .82rem; font-weight: 600; color: #f1f5f9; }
    .rec-cat { font-size: .66rem; color: var(--muted, #94a3b8); padding: 1px 7px; border: 1px solid var(--border); border-radius: 999px; }
    .rec-quickwin { font-size: .64rem; color: #34d399; padding: 1px 7px; border: 1px solid rgba(52,211,153,.4); border-radius: 999px; }
    .rec-issue { font-size: .76rem; color: #cbd5e1; line-height: 1.5; overflow-wrap: anywhere; }
    .rec-action { font-size: .72rem; color: var(--sky); margin-top: 5px; line-height: 1.5; overflow-wrap: anywhere; }
    .rec-refs { font-size: .68rem; color: var(--muted, #94a3b8); margin-top: 5px; }
    .rec-refs a { color: var(--sky); text-decoration: none; border-bottom: 1px dotted rgba(56,189,248,.4); }
    .rec-refs a:hover { border-bottom-style: solid; }
    .catscore-body { padding: 12px 18px; }
    .catscore-row { display: flex; align-items: center; gap: 12px; padding: 7px 0; }
    .catscore-name { flex: 0 0 38%; max-width: 38%; font-size: .76rem; color: #e2e8f0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .catscore-track { flex: 1; height: 8px; background: rgba(148,163,184,.12); border-radius: 999px; overflow: hidden; }
    .catscore-fill { height: 100%; border-radius: 999px; transition: width .6s ease; }
    .catscore-val { flex: 0 0 auto; display: flex; align-items: center; gap: 8px; font-size: .72rem; color: #cbd5e1; }
    .catscore-grade { font-weight: 700; }
    .catscore-checks { color: var(--muted, #94a3b8); font-size: .66rem; }


    /* Categorized findings */
    .category-group {
      background: rgba(9,21,37,.72);
      border: 1px solid var(--border);
      border-radius: var(--r-lg);
      margin-bottom: 16px;
      overflow: hidden;
      box-shadow: 0 18px 50px rgba(0,0,0,.16);
    }
    .category-header {
      width: 100%;
      border: 0;
      background: linear-gradient(180deg, rgba(14,31,51,.95), rgba(9,21,37,.82));
      color: var(--t1);
      padding: 15px 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
      text-align: left;
      cursor: pointer;
      border-bottom: 1px solid var(--border);
      font-family: var(--f-title);
    }
    .category-header:hover { background: linear-gradient(180deg, rgba(19,40,64,.95), rgba(9,21,37,.9)); }
    .category-heading { min-width: 0; display: flex; align-items: center; gap: 10px; }
    .category-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--mint); box-shadow: 0 0 16px rgba(0,255,204,.5); flex: 0 0 auto; }
    .category-title {
      font-weight: 800;
      font-size: .78rem;
      letter-spacing: .14em;
      text-transform: uppercase;
      overflow-wrap: anywhere;
    }
    .category-count {
      font-size: .6rem;
      color: var(--t3);
      letter-spacing: .12em;
      margin-top: 3px;
      font-family: var(--f-mono);
    }
    .category-right { display: flex; align-items: center; gap: 8px; flex: 0 0 auto; }
    .category-badges { display: flex; align-items: center; justify-content: flex-end; gap: 6px; flex-wrap: wrap; }
    .cat-pill {
      font-size: .52rem;
      font-weight: 800;
      letter-spacing: .08em;
      border: 1px solid;
      border-radius: 999px;
      padding: 3px 7px;
      white-space: nowrap;
    }
    .cat-pill.critical { color: #fca5a5; background: rgba(244,63,94,.12); border-color: rgba(244,63,94,.30); }
    .cat-pill.warning, .cat-pill.medium, .cat-pill.high { color: #fde68a; background: rgba(245,158,11,.12); border-color: rgba(245,158,11,.30); }
    .cat-pill.info, .cat-pill.low { color: #bfdbfe; background: rgba(56,189,248,.10); border-color: rgba(56,189,248,.25); }
    .cat-pill.pass { color: #86efac; background: rgba(34,197,94,.10); border-color: rgba(34,197,94,.25); }
    .category-chevron { color: var(--t3); transition: transform .22s var(--ease), color .22s var(--ease); }
    .category-group.collapsed .category-chevron { transform: rotate(-90deg); }
    .category-group:not(.collapsed) .category-chevron { color: var(--mint); }
    .category-body { padding: 12px; }
    .category-group.collapsed .category-body { display: none; }
    .category-body .finding-item { margin-bottom: 10px; background: rgba(5,13,24,.62); }
    .category-body .finding-item:last-child { margin-bottom: 0; }

    /* Stats row */
    .stats-row { display: grid; grid-template-columns: repeat(3,1fr); gap: 10px; max-width: 680px; width: 100%; margin-top: 40px; }
    .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--r-md); padding: 16px; text-align: center; transition: border-color .2s, background .2s; }
    .stat-card:hover { background: var(--elevated); border-color: var(--border2); }
    .stat-val { font-family: var(--f-title); font-weight: 800; font-size: 1.4rem; color: var(--mint); line-height: 1; }
    .stat-label { font-size: .58rem; color: var(--t3); letter-spacing: .12em; margin-top: 5px; font-family: var(--f-title); font-weight: 600; }

    /* Features */
    .features-row { display: flex; flex-wrap: wrap; justify-content: center; gap: 8px; max-width: 680px; width: 100%; margin-top: 28px; }
    .feat-pill { display: flex; align-items: center; gap: 6px; font-family: var(--f-title); font-size: .6rem; font-weight: 600; letter-spacing: .1em; color: var(--t2); background: var(--surface); border: 1px solid var(--border); border-radius: 999px; padding: 5px 14px; transition: all .2s; }
    .feat-pill:hover { color: var(--t1); border-color: var(--border2); background: var(--elevated); }

    .footer { border-top: 1px solid var(--border); margin-top: 80px; padding: 24px 0; text-align: center; font-size: .58rem; color: var(--t3); letter-spacing: .1em; }

    .hidden { display: none !important; }
    @media (max-width: 540px) {
      .score-card { flex-direction: column; gap: 20px; }
      .score-grade { font-size: 4rem; }
      .stats-row { gap: 8px; }
      .stat-val { font-size: 1.1rem; }
    }
  
    /* ══════════════════════════════════════
       MOBILE-READY PERMANENT GUARD
       Keep this block LAST inside <style>.
    ══════════════════════════════════════ */

    html,
    body {
      width: 100%;
      max-width: 100%;
      overflow-x: hidden !important;
      -webkit-text-size-adjust: 100%;
      text-size-adjust: 100%;
    }

    body {
      min-width: 0;
      padding-left: env(safe-area-inset-left, 0px);
      padding-right: env(safe-area-inset-right, 0px);
    }

    img,
    svg,
    canvas,
    video,
    iframe {
      max-width: 100%;
    }

    input,
    button {
      max-width: 100%;
      -webkit-tap-highlight-color: transparent;
    }

    .app {
      width: min(1000px, 100%) !important;
      max-width: 100% !important;
      padding-inline: clamp(12px, 4vw, 20px) !important;
      padding-bottom: calc(80px + env(safe-area-inset-bottom, 0px)) !important;
      overflow-x: clip !important;
    }

    .header,
    .header-inner,
    main,
    section,
    form {
      max-width: 100%;
      min-width: 0;
    }

    .header-inner {
      width: min(1000px, 100%) !important;
      height: auto !important;
      min-height: 58px;
      padding-inline: clamp(12px, 4vw, 20px) !important;
      padding-top: max(8px, env(safe-area-inset-top, 0px)) !important;
      padding-bottom: 8px !important;
      gap: 10px;
    }

    .logo {
      min-width: 0;
      flex: 1 1 auto;
      text-decoration: none;
      color: inherit;
    }

    .logo > div:last-child {
      min-width: 0;
    }

    .logo-name,
    .logo-sub,
    .term-label,
    .term-status {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .live-badge {
      flex: 0 0 auto;
    }

    .hero {
      width: 100%;
      max-width: 100%;
      padding-top: clamp(36px, 10vw, 64px) !important;
      padding-bottom: clamp(34px, 9vw, 48px) !important;
    }

    .eyebrow,
    .hero-title,
    .hero-sub {
      max-width: 100%;
      overflow-wrap: anywhere;
    }

    .hero-title {
      font-size: clamp(1.85rem, 10vw, 3.5rem) !important;
      line-height: 1.08 !important;
    }

    .hero-sub {
      padding-inline: 4px;
    }

    #scanForm {
      width: min(680px, 100%) !important;
      max-width: 100% !important;
      margin-inline: auto !important;
      display: flex !important;
      flex-direction: column !important;
      align-items: center !important;
      gap: 12px !important;
    }

    .scan-card {
      width: 100% !important;
      max-width: 100% !important;
      min-width: 0 !important;
    }

    .term-bar,
    .term-body {
      min-width: 0;
      max-width: 100%;
    }

    .term-body {
      width: 100%;
      overflow: hidden;
    }

    .term-prompt {
      min-width: 0;
      max-width: 46%;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .term-input {
      width: 100% !important;
      min-width: 0 !important;
      overflow: hidden;
      text-overflow: ellipsis;
      -webkit-appearance: none;
      appearance: none;
    }

    .scan-btn {
      width: min(220px, 100%) !important;
      max-width: 220px !important;
      min-height: 44px !important;
      margin-top: 0 !important;
      padding: 10px 18px !important;
      align-self: center !important;
      justify-self: center !important;
      white-space: nowrap;
      font-size: clamp(.68rem, 2.7vw, .76rem) !important;
      letter-spacing: .13em !important;
      touch-action: manipulation;
    }

    .progress-section {
      width: min(680px, calc(100% - 24px)) !important;
      max-width: 680px !important;
      margin: clamp(14px, 4vw, 24px) auto clamp(28px, 7vw, 52px) !important;
    }

    .progress-label,
    .progress-steps,
    .progress-step-text {
      min-width: 0;
      max-width: 100%;
      overflow-wrap: anywhere;
    }

    .error-box,
    .results-section,
    .history-section,
    .score-card,
    .results-grid,
    .result-card,
    .stats-row,
    .features-row {
      max-width: 100% !important;
      min-width: 0;
    }

    .error-box {
      overflow-wrap: anywhere;
    }

    .score-card {
      overflow: hidden;
    }

    .score-info,
    .score-breakdown,
    .result-card,
    .stat-card {
      min-width: 0;
    }

    .score-target,
    .score-meta,
    .result-title,
    .result-message,
    .result-recommendation,
    .finding-title,
    .finding-msg,
    .finding-rec {
      min-width: 0;
      overflow-wrap: anywhere !important;
      word-break: break-word;
    }

    .results-grid {
      grid-template-columns: repeat(auto-fit, minmax(min(260px, 100%), 1fr)) !important;
    }

    @media (max-width: 760px) {
      .app {
        padding-inline: clamp(12px, 4vw, 16px) !important;
      }

      .header-inner {
        flex-wrap: nowrap;
      }

      .hero {
        padding-top: 42px !important;
      }

      .hero-title {
        font-size: clamp(1.85rem, 9.4vw, 2.35rem) !important;
      }

      .scan-card {
        border-radius: 14px !important;
      }

      .term-body {
        padding: 14px 16px !important;
        gap: 8px !important;
      }

      .score-card {
        flex-direction: column !important;
        align-items: stretch !important;
        gap: 20px !important;
        padding: 24px 18px !important;
      }

      .score-grade {
        min-width: 0 !important;
        text-align: center;
      }

      .stats-row {
        grid-template-columns: repeat(3, minmax(0, 1fr)) !important;
      }

      .features-row {
        justify-content: center;
      }
    }

    @media (max-width: 540px) {
      .logo-icon {
        width: 32px !important;
        height: 32px !important;
      }

      .logo-sub {
        display: none !important;
      }

      .live-badge {
        padding: 4px 8px !important;
        font-size: .56rem !important;
        letter-spacing: .11em !important;
      }

      .eyebrow {
        font-size: .55rem !important;
        padding-inline: 12px !important;
      }

      .hero-sub {
        display: none !important;
      }

      .term-label {
        max-width: 66%;
      }

      .term-status {
        display: none;
      }

      .term-prompt {
        max-width: 90px !important;
        font-size: .7rem !important;
      }

      .term-input {
        font-size: .82rem !important;
      }

      .scan-btn {
        width: min(200px, 100%) !important;
        max-width: 200px !important;
        min-height: 42px !important;
        padding: 9px 14px !important;
      }

      .progress-section {
        width: min(100%, calc(100% - 8px)) !important;
      }

      .progress-steps {
        grid-template-columns: repeat(2, minmax(0, 1fr)) !important;
      }

      .stats-row {
        grid-template-columns: repeat(1, minmax(0, 1fr)) !important;
      }

      .feat-pill {
        flex: 1 1 calc(50% - 8px);
        justify-content: center;
      }


      .category-header {
        align-items: flex-start !important;
        flex-direction: column !important;
        gap: 10px !important;
      }

      .category-right {
        width: 100%;
        justify-content: space-between;
      }

      .category-badges {
        justify-content: flex-start;
      }

      .finding-item {
        flex-direction: column !important;
        gap: 10px !important;
      }

      .finding-badge {
        align-self: flex-start;
      }
    }

    @media (max-width: 360px) {
      .app {
        padding-inline: 10px !important;
      }

      .hero-title {
        font-size: 1.7rem !important;
      }

      .term-body {
        padding: 12px !important;
      }

      .term-prompt {
        max-width: 74px !important;
      }

      .scan-btn {
        width: min(188px, 100%) !important;
        font-size: .64rem !important;
      }

      .score-grade {
        font-size: 3.25rem !important;
      }
    }

    /* RESULT SUMMARY NEXT TO GRADE */
    .score-card { align-items: center; }
    .score-grade-wrap {
      display: grid !important;
      grid-template-columns: auto auto;
      align-items: center;
      gap: 18px;
      min-width: 300px;
      flex: 0 0 auto;
    }
    .summary-pills {
      display: flex;
      flex-direction: column;
      align-items: stretch;
      justify-content: center;
      gap: 10px;
      min-width: 156px;
    }
    .s-pill {
      min-width: 156px;
      justify-content: space-between;
      padding: 10px 14px;
      font-size: .72rem;
      letter-spacing: .07em;
      font-weight: 800;
      box-shadow: inset 0 1px 0 rgba(255,255,255,.05), 0 12px 28px rgba(0,0,0,.18);
    }
    .s-pill.critical { color: #ffe1e7; background: linear-gradient(180deg, rgba(190,24,93,.30), rgba(127,29,29,.42)); border-color: rgba(251,113,133,.75); }
    .s-pill.warning,
    .s-pill.medium,
    .s-pill.high { color: #fff1b8; background: linear-gradient(180deg, rgba(180,83,9,.28), rgba(120,53,15,.42)); border-color: rgba(250,204,21,.72); }
    .s-pill.info,
    .s-pill.low { color: #e0f2fe; background: linear-gradient(180deg, rgba(2,132,199,.22), rgba(8,47,73,.40)); border-color: rgba(56,189,248,.72); }
    .s-pill.pass { color: #dcfce7; background: linear-gradient(180deg, rgba(22,163,74,.22), rgba(20,83,45,.40)); border-color: rgba(74,222,128,.72); }

    @media (max-width: 760px) {
      .score-grade-wrap {
        grid-template-columns: 1fr !important;
        justify-items: center;
        min-width: 0;
        width: 100%;
      }
      .summary-pills {
        min-width: 0;
        width: 100%;
        flex-direction: row;
        flex-wrap: wrap;
        justify-content: center;
      }
      .s-pill {
        min-width: 124px;
      }
    }

    @media (max-width: 540px) {
      .summary-pills {
        gap: 8px;
      }
      .s-pill {
        min-width: calc(50% - 6px);
        font-size: .64rem;
        padding: 9px 12px;
      }
    }

    @media (max-width: 360px) {
      .s-pill {
        min-width: 100%;
      }
    }
  
    /* PRO RESULT CARD UPGRADE */
    .score-card {
      position: relative;
      display: grid;
      grid-template-columns: minmax(0, 1.2fr) minmax(240px, .8fr);
      align-items: center;
      gap: 24px;
      padding: 28px;
      background: linear-gradient(180deg, rgba(9,21,37,.96), rgba(5,13,24,.96));
      box-shadow: 0 24px 60px rgba(0,0,0,.24), inset 0 1px 0 rgba(255,255,255,.03);
    }
    .score-grade-wrap {
      display: grid !important;
      grid-template-columns: minmax(150px, 172px) minmax(280px, 1fr);
      align-items: stretch;
      gap: 16px;
      min-width: 0;
      width: 100%;
    }
    .grade-panel {
      display: flex;
      flex-direction: column;
      align-items: stretch;
      justify-content: center;
      gap: 10px;
      padding: 18px 14px;
      border-radius: 18px;
      border: 1px solid rgba(0,220,180,.16);
      background: radial-gradient(circle at top, rgba(0,255,204,.08), rgba(0,255,204,0) 55%), rgba(7,18,30,.95);
      min-height: 100%;
      text-align: center;
      box-shadow: inset 0 1px 0 rgba(255,255,255,.03);
    }
    .grade-kicker {
      font-family: var(--f-title);
      font-size: .54rem;
      font-weight: 800;
      letter-spacing: .18em;
      color: var(--t2);
      text-align: center;
    }
    .score-grade {
      font-size: clamp(3.5rem, 5vw, 4.8rem);
      min-width: 0;
      line-height: .95;
    }
    .score-percent {
      align-self: center;
      font-family: var(--f-title);
      font-weight: 800;
      font-size: 1.08rem;
      letter-spacing: .04em;
      color: var(--t1);
      padding: 8px 14px;
      border-radius: 999px;
      border: 1px solid rgba(56,189,248,.26);
      background: linear-gradient(180deg, rgba(56,189,248,.12), rgba(56,189,248,.04));
      box-shadow: inset 0 1px 0 rgba(255,255,255,.03);
    }
    .grade-meter {
      margin-top: 4px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .grade-meter-label {
      font-family: var(--f-title);
      font-size: .56rem;
      font-weight: 800;
      letter-spacing: .14em;
      color: #6f94af;
    }
    .grade-bar-wrap {
      height: 10px;
      background: rgba(14,31,51,.96);
      margin-bottom: 0;
      border: 1px solid rgba(0,220,180,.09);
      box-shadow: inset 0 1px 6px rgba(0,0,0,.18);
    }
    .score-info {
      min-width: 0;
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-self: stretch;
      padding: 18px 20px;
      border-radius: 18px;
      border: 1px solid rgba(0,220,180,.10);
      background: linear-gradient(180deg, rgba(8,19,33,.78), rgba(5,13,24,.64));
    }
    .score-host {
      font-size: clamp(1.08rem, 2vw, 1.6rem);
      margin-bottom: 8px;
      overflow-wrap: anywhere;
    }
    .score-meta {
      margin-bottom: 0;
      color: #6c90ab;
      line-height: 1.9;
    }
    .score-num {
      font-family: var(--f-title);
      font-size: .8rem;
      font-weight: 800;
      letter-spacing: .06em;
      color: #b7e6ff;
    }
    .summary-pills {
      display: grid !important;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
      align-content: stretch;
      min-width: 0;
      margin: 0;
    }
    .s-pill {
      min-width: 0;
      min-height: 118px;
      border-radius: 18px;
      padding: 14px 16px;
      display: flex;
      flex-direction: column;
      align-items: flex-start;
      justify-content: space-between;
      gap: 4px;
      text-align: left;
      box-shadow: 0 14px 24px rgba(0,0,0,.18), inset 0 1px 0 rgba(255,255,255,.03);
    }
    .pill-top {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      min-width: 0;
    }
    .pill-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: currentColor;
      box-shadow: 0 0 14px currentColor;
      flex: 0 0 auto;
    }
    .pill-label {
      font-family: var(--f-title);
      font-size: .64rem;
      font-weight: 800;
      letter-spacing: .1em;
      text-transform: uppercase;
    }
    .pill-main {
      font-family: var(--f-title);
      font-size: 2rem;
      font-weight: 800;
      line-height: 1;
    }
    .pill-sub {
      font-size: .58rem;
      font-weight: 700;
      letter-spacing: .04em;
      color: rgba(235,248,255,.76);
      line-height: 1.35;
    }
    .s-pill.critical { color: #ffd4df; background: linear-gradient(180deg, rgba(190,24,93,.26), rgba(127,29,29,.36)); border-color: rgba(251,113,133,.48); }
    .s-pill.warning  { color: #fff2b8; background: linear-gradient(180deg, rgba(180,83,9,.22), rgba(120,53,15,.34)); border-color: rgba(250,204,21,.42); }
    .s-pill.info     { color: #d8f0ff; background: linear-gradient(180deg, rgba(2,132,199,.18), rgba(8,47,73,.34)); border-color: rgba(56,189,248,.42); }
    .s-pill.pass     { color: #d7ffe6; background: linear-gradient(180deg, rgba(22,163,74,.18), rgba(20,83,45,.34)); border-color: rgba(74,222,128,.42); }

    @media (max-width: 980px) {
      .score-card {
        grid-template-columns: 1fr;
      }
      .score-grade-wrap {
        grid-template-columns: 1fr;
        width: 100%;
      }
      .grade-panel {
        padding: 18px;
      }
      .summary-pills {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
    }
    @media (max-width: 540px) {
      .score-card {
        padding: 20px 16px;
        gap: 16px;
      }
      .summary-pills {
        grid-template-columns: 1fr 1fr;
        gap: 10px;
      }
      .s-pill {
        min-height: 110px;
        padding: 12px;
      }
      .pill-main {
        font-size: 1.7rem;
      }
      .score-percent {
        font-size: .95rem;
      }
    }
    @media (max-width: 380px) {
      .summary-pills {
        grid-template-columns: 1fr;
      }
    }


    /* PRO UPGRADE V2: SCORE RING + ICON CARDS */
    .grade-panel {
      position: relative;
      --ring-color: #00ffcc;
    }
    .score-ring {
      --score: 0;
      --ring-color: #00ffcc;
      width: 122px;
      height: 122px;
      margin: 0 auto;
      border-radius: 50%;
      padding: 10px;
      background:
        radial-gradient(circle at center, rgba(255,255,255,.06) 0, rgba(255,255,255,0) 62%),
        conic-gradient(var(--ring-color) calc(var(--score) * 1%), rgba(255,255,255,.08) 0);
      box-shadow: 0 0 24px color-mix(in srgb, var(--ring-color) 28%, transparent);
      position: relative;
    }
    .score-ring::after {
      content: "";
      position: absolute;
      inset: 7px;
      border-radius: 50%;
      background: linear-gradient(180deg, rgba(9,21,37,.98), rgba(5,13,24,.98));
      border: 1px solid rgba(255,255,255,.05);
    }
    .score-ring-inner {
      position: absolute;
      inset: 0;
      z-index: 1;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      gap: 4px;
    }
    .score-ring-sub {
      font-family: var(--f-title);
      font-size: .52rem;
      font-weight: 800;
      letter-spacing: .16em;
      color: var(--t2);
    }
    .score-percent {
      align-self: center;
      min-width: 84px;
      text-align: center;
      background: linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.015));
    }
    .grade-meter {
      margin-top: 2px;
      gap: 6px;
    }
    .grade-meter-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
    }
    .grade-meter-label { margin: 0; }
    .grade-bar-wrap { margin-top: 0; }
    .summary-pills {
      align-content: stretch;
    }
    .pill-top {
      gap: 10px;
    }
    .pill-icon {
      width: 26px;
      height: 26px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border-radius: 999px;
      background: rgba(255,255,255,.08);
      border: 1px solid rgba(255,255,255,.14);
      box-shadow: inset 0 1px 0 rgba(255,255,255,.06);
      flex: 0 0 auto;
    }
    .pill-icon svg {
      width: 15px;
      height: 15px;
      display: block;
    }
    .pill-dot { display: none; }
    .s-pill {
      overflow: hidden;
      position: relative;
    }
    .s-pill::after {
      content: "";
      position: absolute;
      right: -18px;
      bottom: -18px;
      width: 64px;
      height: 64px;
      border-radius: 50%;
      background: rgba(255,255,255,.05);
      filter: blur(2px);
    }
    @media (max-width: 540px) {
      .score-ring {
        width: 112px;
        height: 112px;
      }
      .grade-meter-head {
        flex-direction: column;
        align-items: stretch;
        gap: 4px;
      }
      .score-num {
        text-align: left;
      }
    }


    /* REPORT ACTION TOOLBAR */
    .report-toolbar {
      display: grid;
      gap: 14px;
      padding: 18px;
      margin: 0 0 18px;
      border-radius: var(--r-lg);
      border: 1px solid rgba(56,189,248,.16);
      background: linear-gradient(180deg, rgba(8,19,33,.90), rgba(5,13,24,.86));
      box-shadow: 0 18px 46px rgba(0,0,0,.16), inset 0 1px 0 rgba(255,255,255,.03);
    }
    .report-toolbar-head {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 14px;
      min-width: 0;
    }
    .report-kicker {
      font-family: var(--f-title);
      font-size: .55rem;
      font-weight: 800;
      letter-spacing: .18em;
      color: var(--sky);
      margin-bottom: 6px;
    }
    .report-title {
      font-family: var(--f-title);
      font-size: .92rem;
      font-weight: 800;
      color: var(--t1);
      line-height: 1.35;
    }
    .report-status {
      min-height: 28px;
      display: inline-flex;
      align-items: center;
      justify-content: flex-end;
      font-family: var(--f-title);
      font-size: .62rem;
      font-weight: 800;
      letter-spacing: .05em;
      color: #7da4bf;
      text-align: right;
    }
    .report-status.ok { color: #86efac; }
    .report-status.warn { color: #fde68a; }
    .report-status.error { color: #fca5a5; }
    .report-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }
    .report-btn {
      appearance: none;
      border: 1px solid rgba(56,189,248,.20);
      background: rgba(56,189,248,.055);
      color: #cde8f8;
      border-radius: 999px;
      min-height: 40px;
      padding: 9px 14px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      font-family: var(--f-title);
      font-size: .66rem;
      font-weight: 800;
      letter-spacing: .08em;
      text-transform: uppercase;
      cursor: pointer;
      transition: transform .2s var(--ease), border-color .2s, background .2s, color .2s;
    }
    .report-btn:hover {
      transform: translateY(-1px);
      color: #ffffff;
      border-color: rgba(56,189,248,.42);
      background: rgba(56,189,248,.10);
    }
    .report-btn.primary {
      color: #061016;
      background: linear-gradient(135deg, var(--mint), #38bdf8);
      border-color: rgba(0,255,204,.50);
      box-shadow: 0 14px 30px rgba(0,255,204,.12);
    }
    .report-btn svg {
      width: 15px;
      height: 15px;
      flex: 0 0 auto;
    }
    @media (max-width: 640px) {
      .report-toolbar-head { flex-direction: column; }
      .report-status { justify-content: flex-start; text-align: left; }
      .report-actions { display: grid; grid-template-columns: 1fr; }
      .report-btn { width: 100%; }
    }
    @media print {
      .no-print, .header, .hero, .footer, .bg-grid, .bg-glow { display: none !important; }
      body { background: #fff !important; color: #111827 !important; }
      .app { width: 100% !important; max-width: none !important; padding: 0 !important; }
      .results-section { display: block !important; margin: 0 !important; }
      .target-card, .score-card, .category-group { box-shadow: none !important; break-inside: avoid; }
    }

    /* TARGET IDENTITY + PROGRESS PHASE UI */
    .target-card {
      display: grid;
      gap: 18px;
      padding: 22px;
      margin-bottom: 18px;
      border-radius: var(--r-lg);
      border: 1px solid rgba(0,220,180,.18);
      background: linear-gradient(180deg, rgba(9,21,37,.92), rgba(5,13,24,.92));
      box-shadow: 0 18px 46px rgba(0,0,0,.20), inset 0 1px 0 rgba(255,255,255,.03);
    }
    .target-head {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 18px;
      min-width: 0;
    }
    .target-kicker {
      font-family: var(--f-title);
      font-size: .56rem;
      font-weight: 800;
      letter-spacing: .18em;
      color: var(--mint);
      margin-bottom: 8px;
    }
    .target-name {
      font-family: var(--f-title);
      font-size: clamp(1.2rem, 2.4vw, 1.75rem);
      font-weight: 800;
      color: var(--t1);
      overflow-wrap: anywhere;
      line-height: 1.2;
    }
    .target-url {
      margin-top: 6px;
      font-size: .72rem;
      color: #6c90ab;
      overflow-wrap: anywhere;
      line-height: 1.5;
    }
    .target-protocol {
      flex: 0 0 auto;
      font-family: var(--f-title);
      font-size: .68rem;
      font-weight: 800;
      letter-spacing: .12em;
      padding: 8px 12px;
      border-radius: 999px;
      color: #d7fff6;
      background: rgba(0,255,204,.08);
      border: 1px solid rgba(0,255,204,.28);
      box-shadow: 0 0 20px rgba(0,255,204,.10);
    }
    .target-ip-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }
    .target-ip-box {
      min-width: 0;
      padding: 14px;
      border-radius: 15px;
      border: 1px solid rgba(56,189,248,.14);
      background: rgba(8,19,33,.72);
    }
    .target-ip-label {
      font-family: var(--f-title);
      font-size: .58rem;
      font-weight: 800;
      letter-spacing: .16em;
      color: #77a8c8;
      margin-bottom: 10px;
    }
    .target-ip-list {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      min-width: 0;
    }
    .ip-chip,
    .ip-empty {
      display: inline-flex;
      max-width: 100%;
      align-items: center;
      min-height: 30px;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: .68rem;
      line-height: 1.2;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    .ip-chip {
      color: #d8f0ff;
      background: rgba(56,189,248,.09);
      border: 1px solid rgba(56,189,248,.24);
    }
    .ip-empty {
      color: #607e96;
      background: rgba(255,255,255,.025);
      border: 1px dashed rgba(255,255,255,.08);
    }
    .progress-stage-current {
      margin-top: 10px;
      font-family: var(--f-title);
      font-size: .68rem;
      font-weight: 700;
      color: #9ad1f3;
      letter-spacing: .04em;
      line-height: 1.5;
    }
    .progress-steps {
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap: 8px;
      margin-top: 12px;
    }
    .progress-step {
      min-width: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      padding: 8px 7px;
      border-radius: 999px;
      border: 1px solid rgba(56,189,248,.12);
      background: rgba(8,19,33,.72);
      color: #41637d;
      font-family: var(--f-title);
      font-size: .54rem;
      font-weight: 800;
      letter-spacing: .08em;
      white-space: nowrap;
      transition: .22s var(--ease);
    }
    .progress-step-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: currentColor;
      opacity: .7;
      flex: 0 0 auto;
    }
    .progress-step.active {
      color: var(--mint);
      border-color: rgba(0,255,204,.38);
      background: rgba(0,255,204,.08);
      box-shadow: 0 0 20px rgba(0,255,204,.08);
    }
    .progress-step.active .progress-step-dot {
      opacity: 1;
      box-shadow: 0 0 14px currentColor;
    }
    .progress-step.done {
      color: #86efac;
      border-color: rgba(34,197,94,.22);
      background: rgba(34,197,94,.055);
    }
    @media (max-width: 760px) {
      .target-head { flex-direction: column; }
      .target-ip-grid { grid-template-columns: 1fr; }
      .progress-steps { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    }
    @media (max-width: 420px) {
      .target-card { padding: 16px; }
      .progress-steps { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .progress-step { font-size: .5rem; padding-inline: 6px; }
    }



    /* FINAL COMPACT TABS + A4 ACTIONS */
    .target-banner {
      display: grid;
      grid-template-columns: minmax(0, 1.2fr) minmax(300px, .9fr) auto;
      gap: 14px;
      align-items: stretch;
      background: linear-gradient(180deg, rgba(9,21,37,.96), rgba(5,13,24,.96));
      border: 1px solid var(--border2);
      border-radius: 22px;
      padding: 16px;
      margin-bottom: 16px;
      box-shadow: 0 20px 46px rgba(0,0,0,.22), inset 0 1px 0 rgba(255,255,255,.03);
    }
    .target-main { min-width: 0; }
    .target-kicker, .assessment-kicker {
      font-family: var(--f-title);
      font-size: .58rem;
      font-weight: 800;
      letter-spacing: .18em;
      color: var(--t2);
    }
    .target-name {
      font-family: var(--f-title);
      font-size: clamp(1.15rem, 2.5vw, 1.6rem);
      font-weight: 800;
      line-height: 1.15;
      margin-top: 6px;
      overflow-wrap: anywhere;
    }
    .target-url {
      color: #8ab7d3;
      margin-top: 6px;
      font-size: .75rem;
      overflow-wrap: anywhere;
    }
    .target-meta-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0,1fr));
      gap: 8px;
      min-width: 0;
    }
    .target-chip {
      background: rgba(255,255,255,.02);
      border: 1px solid var(--border);
      border-radius: 13px;
      padding: 9px 11px;
      min-width: 0;
    }
    .target-chip-label {
      font-family: var(--f-title);
      font-size: .52rem;
      font-weight: 800;
      letter-spacing: .13em;
      color: var(--t2);
      margin-bottom: 5px;
    }
    .target-chip-value {
      font-size: .72rem;
      font-weight: 700;
      color: var(--t1);
      overflow-wrap: anywhere;
      line-height: 1.35;
    }
    .report-actions {
      display: flex;
      flex-direction: column;
      gap: 8px;
      min-width: 118px;
    }
    .report-btn {
      font-family: var(--f-title);
      font-size: .58rem;
      font-weight: 800;
      letter-spacing: .08em;
      color: #9dc0d8;
      background: rgba(255,255,255,.03);
      border: 1px solid var(--border2);
      border-radius: 12px;
      padding: 10px 12px;
      white-space: nowrap;
      transition: all .2s var(--ease);
    }
    .report-btn:hover { color: var(--t1); border-color: var(--border3); transform: translateY(-1px); }
    .report-btn.primary {
      color: #03120f;
      background: linear-gradient(135deg, var(--mint), #38bdf8);
      border-color: transparent;
    }

    .result-tabs {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      margin: 0 auto 16px;
      max-width: 820px;
    }
    .result-tab {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      min-width: 0;
      padding: 12px 15px;
      border-radius: 16px;
      border: 1px solid var(--border2);
      background: rgba(9,21,37,.78);
      color: #6f94af;
      font-family: var(--f-title);
      font-size: .68rem;
      font-weight: 800;
      letter-spacing: .1em;
      transition: all .2s var(--ease);
    }
    .result-tab:hover { border-color: var(--border3); color: var(--t1); }
    .result-tab.active {
      color: var(--mint);
      background: linear-gradient(180deg, rgba(0,255,204,.12), rgba(0,255,204,.04));
      border-color: rgba(0,255,204,.35);
      box-shadow: 0 0 28px rgba(0,255,204,.06);
    }
    .result-tab strong {
      display: inline-grid;
      place-items: center;
      min-width: 30px;
      height: 24px;
      border-radius: 999px;
      font-size: .68rem;
      background: rgba(255,255,255,.06);
      border: 1px solid rgba(255,255,255,.10);
      color: inherit;
    }
    .tab-content { display: none; }
    .tab-content.active { display: block; }

    .compact-panel {
      max-width: 860px;
      margin: 0 auto 18px;
      padding: 14px;
      border-radius: 22px;
      background: linear-gradient(180deg, rgba(9,21,37,.96), rgba(5,13,24,.96));
      border: 1px solid var(--border2);
      box-shadow: 0 20px 46px rgba(0,0,0,.20), inset 0 1px 0 rgba(255,255,255,.03);
    }
    .assessment-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      margin-bottom: 12px;
      padding: 0 2px;
    }
    .assessment-title {
      font-family: var(--f-title);
      font-size: .98rem;
      font-weight: 800;
      margin-top: 3px;
    }
    .assessment-mini-meta {
      font-size: .68rem;
      color: #87acc5;
      text-align: right;
      line-height: 1.5;
    }
    .assessment-body {
      display: grid;
      grid-template-columns: 180px minmax(0, 1fr);
      gap: 12px;
      align-items: stretch;
    }
    .grade-card {
      border-radius: 18px;
      border: 1px solid var(--border2);
      background: radial-gradient(circle at top, rgba(56,189,248,.10), rgba(56,189,248,0) 46%), rgba(6,18,30,.94);
      padding: 14px 12px;
      display: flex;
      flex-direction: column;
      align-items: center;
      text-align: center;
      min-width: 0;
    }
    .grade-card-title {
      font-family: var(--f-title);
      font-size: .62rem;
      font-weight: 800;
      letter-spacing: .15em;
      color: #7aa9cb;
      margin-bottom: 10px;
    }
    .score-ring {
      --score: 0;
      --ring-color: #38bdf8;
      width: 126px;
      height: 126px;
      border-radius: 50%;
      position: relative;
      display: grid;
      place-items: center;
      background:
        radial-gradient(circle at center, rgba(255,255,255,.08) 0, rgba(255,255,255,0) 58%),
        conic-gradient(var(--ring-color) calc(var(--score) * 1%), rgba(26,53,73,.92) 0);
      box-shadow: 0 0 24px color-mix(in srgb, var(--ring-color) 20%, transparent);
      margin-bottom: 10px;
    }
    .score-ring::after {
      content: "";
      position: absolute;
      inset: 8px;
      border-radius: 50%;
      background: linear-gradient(180deg, rgba(5,15,28,.98), rgba(5,12,22,.98));
      border: 1px solid rgba(255,255,255,.04);
    }
    .score-ring-inner {
      position: relative;
      z-index: 1;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      gap: 4px;
    }
    .score-grade {
      font-family: var(--f-title);
      font-size: 3.1rem;
      font-weight: 800;
      line-height: .95;
      letter-spacing: -.04em;
    }
    .score-ring-sub {
      font-family: var(--f-title);
      font-size: .52rem;
      font-weight: 800;
      letter-spacing: .15em;
      color: #6da1c8;
    }
    .score-pill {
      min-width: 94px;
      border-radius: 999px;
      border: 1px solid rgba(56,189,248,.35);
      background: linear-gradient(180deg, rgba(56,189,248,.10), rgba(56,189,248,.03));
      padding: 7px 13px;
      font-family: var(--f-title);
      font-size: .92rem;
      font-weight: 800;
    }
    .grade-stats {
      width: 100%;
      margin-top: 11px;
    }
    .grade-stats-row {
      display: flex;
      justify-content: space-between;
      gap: 8px;
      align-items: flex-end;
      margin-bottom: 7px;
    }
    .grade-stat-label {
      font-family: var(--f-title);
      font-size: .55rem;
      font-weight: 800;
      letter-spacing: .12em;
      color: #7aa2c5;
      text-align: left;
    }
    .grade-stat-value {
      font-family: var(--f-title);
      font-size: .78rem;
      font-weight: 800;
      text-align: right;
    }
    .grade-progress {
      height: 10px;
      border-radius: 999px;
      overflow: hidden;
      background: rgba(13,32,52,.96);
      border: 1px solid rgba(56,189,248,.12);
    }
    .grade-progress-fill {
      height: 100%;
      width: 0%;
      border-radius: inherit;
      transition: width .7s var(--ease);
    }

    .status-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0,1fr));
      gap: 11px;
      min-width: 0;
    }
    .metric-card {
      border-radius: 18px;
      padding: 15px 15px 13px;
      min-height: 132px;
      border: 1px solid rgba(255,255,255,.08);
      position: relative;
      overflow: hidden;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .metric-card::after {
      content: "";
      position: absolute;
      right: -14px;
      bottom: -14px;
      width: 70px;
      height: 70px;
      border-radius: 50%;
      background: rgba(255,255,255,.05);
      filter: blur(2px);
    }
    .metric-head {
      display: flex;
      align-items: center;
      gap: 9px;
      position: relative;
      z-index: 1;
    }
    .metric-icon {
      width: 32px;
      height: 32px;
      border-radius: 50%;
      border: 1px solid rgba(255,255,255,.18);
      background: rgba(255,255,255,.06);
      display: grid;
      place-items: center;
      flex: 0 0 auto;
    }
    .metric-icon svg { width: 15px; height: 15px; }
    .metric-label {
      font-family: var(--f-title);
      font-size: .68rem;
      font-weight: 800;
      letter-spacing: .08em;
    }
    .metric-main {
      position: relative;
      z-index: 1;
      margin-top: 10px;
    }
    .metric-value {
      font-family: var(--f-title);
      font-size: 2rem;
      font-weight: 800;
      line-height: 1;
    }
    .metric-sub {
      margin-top: 9px;
      font-size: .68rem;
      font-weight: 700;
      color: rgba(240,248,255,.82);
      line-height: 1.3;
    }
    .metric-card.critical { color:#ffd9e2; background: linear-gradient(180deg, rgba(129,17,62,.78), rgba(74,16,40,.78)); border-color: rgba(251,113,133,.58); }
    .metric-card.warning  { color:#fff2be; background: linear-gradient(180deg, rgba(108,67,15,.78), rgba(81,47,12,.78)); border-color: rgba(250,204,21,.48); }
    .metric-card.info     { color:#d7efff; background: linear-gradient(180deg, rgba(3,79,130,.78), rgba(3,57,97,.78)); border-color: rgba(56,189,248,.46); }
    .metric-card.pass     { color:#d9ffe9; background: linear-gradient(180deg, rgba(7,89,67,.78), rgba(9,66,46,.78)); border-color: rgba(74,222,128,.44); }

    .results-block {
      max-width: 860px;
      margin: 18px auto 0;
      background: linear-gradient(180deg, rgba(9,21,37,.96), rgba(5,13,24,.96));
      border: 1px solid var(--border2);
      border-radius: 20px;
      padding: 16px;
    }
    .results-block-head { margin-bottom: 12px; }
    .category-card {
      border: 1px solid var(--border);
      border-radius: 16px;
      overflow: hidden;
      background: rgba(255,255,255,.015);
    }
    .category-card + .category-card, .pci-control-card + .pci-control-card { margin-top: 12px; }
    .category-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
      padding: 12px 14px;
      border-bottom: 1px solid var(--border);
      background: rgba(255,255,255,.018);
    }
    .category-title-wrap { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .category-title { font-family: var(--f-title); font-size: .85rem; font-weight: 800; }
    .category-meta { color:#81a8c4; font-size: .68rem; }
    .severity-dots { display:flex; flex-wrap:wrap; gap:7px; justify-content:flex-end; }
    .severity-dot {
      border-radius:999px;
      padding: 5px 9px;
      font-family: var(--f-title);
      font-size:.56rem;
      font-weight:800;
      letter-spacing:.08em;
      border:1px solid transparent;
    }
    .severity-dot.critical { background: rgba(244,63,94,.10); color:#ffb4c3; border-color: rgba(244,63,94,.28); }
    .severity-dot.warning { background: rgba(245,158,11,.10); color:#ffd986; border-color: rgba(245,158,11,.28); }
    .severity-dot.info { background: rgba(56,189,248,.10); color:#b3e8ff; border-color: rgba(56,189,248,.28); }
    .severity-dot.pass { background: rgba(34,197,94,.10); color:#b9ffd1; border-color: rgba(34,197,94,.28); }
    .category-body { padding: 8px 9px 9px; }
    .finding-row, .pci-control-card {
      display:flex;
      align-items:flex-start;
      gap: 10px;
      padding: 10px;
      border-radius: 13px;
      background: rgba(255,255,255,.02);
    }
    .finding-row + .finding-row { margin-top: 8px; }
    .finding-badge, .pci-control-badge {
      min-width: 76px;
      text-align:center;
      padding: 7px 9px;
      border-radius: 999px;
      font-family: var(--f-title);
      font-size: .58rem;
      font-weight: 800;
      letter-spacing: .08em;
    }
    .finding-content, .pci-control-body { min-width:0; flex:1; }
    .finding-check, .pci-control-title { font-family: var(--f-title); font-size: .82rem; font-weight: 800; }
    .finding-msg, .pci-control-msg { margin-top: 6px; color:#9dc0d8; line-height: 1.55; font-size: .76rem; }
    .finding-rec, .pci-control-rec { margin-top: 7px; color:#d8edf8; font-size: .74rem; line-height: 1.45; }

    .badge-critical, .pci-control-badge.critical { background: rgba(244,63,94,.10); color:#ffb4c3; border:1px solid rgba(244,63,94,.28); }
    .badge-warning, .pci-control-badge.warning { background: rgba(245,158,11,.10); color:#ffd986; border:1px solid rgba(245,158,11,.28); }
    .badge-info, .pci-control-badge.info { background: rgba(56,189,248,.10); color:#b3e8ff; border:1px solid rgba(56,189,248,.28); }
    .badge-pass, .pci-control-badge.pass { background: rgba(34,197,94,.10); color:#b9ffd1; border:1px solid rgba(34,197,94,.28); }

    @media (max-width: 920px) {
      .target-banner { grid-template-columns: 1fr; }
      .report-actions { flex-direction: row; flex-wrap: wrap; }
      .report-btn { flex: 1; }
    }
    @media (max-width: 760px) {
      .assessment-body { grid-template-columns: 1fr; }
      .status-grid { grid-template-columns: repeat(2, minmax(0,1fr)); }
      .result-tabs { grid-template-columns: 1fr; }
    }
    @media (max-width: 520px) {
      .target-meta-grid, .status-grid { grid-template-columns: 1fr; }
      .target-banner, .compact-panel, .results-block { padding: 13px; border-radius: 18px; }
      .metric-card { min-height: 116px; }
      .finding-row, .pci-control-card { flex-direction: column; }
      .finding-badge, .pci-control-badge { min-width: 0; }
    }

  </style>
</head>
<body>
  <div class="bg-grid" aria-hidden="true"></div>
  <div class="bg-glow" aria-hidden="true"></div>

  <div class="app">

    <!-- HEADER -->
    <header class="header">
      <div class="header-inner">
        <a href="/" class="logo">
          <div class="logo-icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.35C16.5 22.15 20 17.25 20 12V6L12 2z" stroke="#00ffcc" stroke-width="1.8" stroke-linejoin="round"/>
              <path d="M9 12l2 2 4-4" stroke="#00ffcc" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </div>
          <div>
            <div class="logo-name">SecScan</div>
            <div class="logo-sub">SECURITY INTELLIGENCE</div>
          </div>
        </a>
        <div class="live-badge">
          <span class="live-dot"></span>
          LIVE
        </div>
      </div>
    </header>

    <main>
      <section class="hero">

        <div class="eyebrow">
          <span class="eyebrow-dot"></span>
          FULL-STACK SECURITY ANALYSIS ENGINE
        </div>

        <h1 class="hero-title">
          Identify. Analyze.<br>
          <span class="accent">Eliminate Threats.</span>
        </h1>

        <p class="hero-sub">
          Scan mana-mana domain untuk vulnerabilities, misconfigurations, dan exposure risks — dalam beberapa saat.
        </p>

        <!-- Scan Form -->
        <form id="scanForm" class="scan-form" autocomplete="off" novalidate>
          <div class="scan-card">
            <div class="term-bar">
              <span class="t-dot t-red"></span>
              <span class="t-dot t-amber"></span>
              <span class="t-dot t-green"></span>
              <span class="term-label">SECSCAN CONSOLE</span>
              <span class="term-spacer"></span>
              <span class="term-status" id="termStatus">READY</span>
            </div>
            <div class="term-body">
              <span class="term-prompt">root@secscan:~&nbsp;<span class="cmd">scan</span>&nbsp;</span>
              <input
                type="text"
                id="urlInput"
                class="term-input"
                placeholder="example.com atau https://..."
                inputmode="url"
                autocapitalize="off"
                spellcheck="false"
                required
              />
            </div>
          </div>

          <!-- Error -->
          <div class="error-box" id="errorBox">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" flex-shrink="0">
              <circle cx="12" cy="12" r="10" stroke="#f43f5e" stroke-width="1.8"/>
              <path d="M12 8v4M12 16h.01" stroke="#f43f5e" stroke-width="1.8" stroke-linecap="round"/>
            </svg>
            <span id="errorMsg">URL tidak sah.</span>
          </div>

          <!-- Scan Button -->
          <button type="submit" class="scan-btn" id="scanBtn">
            <svg class="btn-icon" width="15" height="15" viewBox="0 0 24 24" fill="none">
              <circle cx="11" cy="11" r="8" stroke="currentColor" stroke-width="2"/>
              <path d="M21 21l-4.35-4.35" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
            </svg>
            <span class="btn-text">MULA SCAN KESELAMATAN</span>
            <div class="btn-spinner"></div>
          </button>
        </form>

        <!-- Progress -->
        <div class="progress-section" id="progressSection">
          <div class="progress-label">
            <span id="progressLabel">MENGANALISA...</span>
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
          <div class="stat-card"><div class="stat-val">30+</div><div class="stat-label">CHECKS</div></div>
          <div class="stat-card"><div class="stat-val">&lt;15s</div><div class="stat-label">AVG SCAN</div></div>
          <div class="stat-card"><div class="stat-val">A–F</div><div class="stat-label">GRADING</div></div>
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
            <div class="target-kicker">TARGET SCAN</div>
            <div class="target-name" id="targetName">—</div>
            <div class="target-url" id="targetUrl">—</div>
          </div>

          <div class="target-meta-grid" id="targetMetaGrid"></div>

          <div class="report-actions">
            <button type="button" class="report-btn primary" id="printA4Btn">PRINT A4</button>
            <button type="button" class="report-btn" id="saveA4Btn">SAVE HTML</button>
            <button type="button" class="report-btn" id="copyResultBtn">COPY RESULT</button>
          </div>
        </div>

        <div class="result-tabs">
          <button type="button" class="result-tab active" id="tabSecurity" data-tab="security">
            <span>SCAN KESELAMATAN</span>
            <strong id="tabSecurityBadge">—</strong>
          </button>
          <button type="button" class="result-tab" id="tabPci" data-tab="pci">
            <span>PCI DSS LITE</span>
            <strong id="tabPciBadge">10</strong>
          </button>
        </div>

        <div class="tab-content active" id="securityTabPanel">
          <div class="assessment-panel compact-panel">
            <div class="assessment-header">
              <div>
                <div class="assessment-kicker">OVERVIEW</div>
                <h3 class="assessment-title">Keputusan Scan Keselamatan</h3>
              </div>
              <div class="assessment-mini-meta" id="securityMiniMeta">—</div>
            </div>
            <div class="assessment-body" id="securityOverview"></div>
          </div>

          <div id="recommendationsContainer"></div>

          <div id="categoryScoresContainer"></div>

          <div class="results-block">
            <div class="results-block-head">
              <div class="findings-title">KEPUTUSAN SCAN MENGIKUT KATEGORI</div>
            </div>
            <div id="findingsContainer"></div>
          </div>
        </div>

        <div class="tab-content" id="pciTabPanel">
          <div class="assessment-panel compact-panel">
            <div class="assessment-header">
              <div>
                <div class="assessment-kicker">COMPLIANCE VIEW</div>
                <h3 class="assessment-title">Keputusan PCI DSS Lite</h3>
              </div>
              <div class="assessment-mini-meta" id="pciMiniMeta">10 controls</div>
            </div>
            <div class="assessment-body" id="pciOverview"></div>
          </div>

          <div class="results-block">
            <div class="results-block-head">
              <div class="findings-title">PCI DSS LITE CONTROLS</div>
            </div>
            <div id="pciControlsContainer"></div>
          </div>
        </div>

      </section>
    </main>

    <footer class="footer">
      © 2025 SECSCAN · SECURITY INTELLIGENCE PLATFORM · ALL RIGHTS RESERVED
    </footer>

  </div>

  <script nonce="<?= htmlspecialchars($cspNonce, ENT_QUOTES, 'UTF-8') ?>">
  (function () {
    'use strict';

    const scanForm       = document.getElementById('scanForm');
    const urlInput       = document.getElementById('urlInput');
    const scanBtn        = document.getElementById('scanBtn');
    const termStatus     = document.getElementById('termStatus');
    const errorBox       = document.getElementById('errorBox');
    const errorMsg       = document.getElementById('errorMsg');
    const progressSec    = document.getElementById('progressSection');
    const progressFill   = document.getElementById('progressFill');
    const progressLabel  = document.getElementById('progressLabel');
    const progressPct    = document.getElementById('progressPct');
    const progressText   = document.getElementById('progressText');
    const resultsSec     = document.getElementById('resultsSection');

    const targetName     = document.getElementById('targetName');
    const targetUrl      = document.getElementById('targetUrl');
    const targetMetaGrid = document.getElementById('targetMetaGrid');

    const tabSecurity    = document.getElementById('tabSecurity');
    const tabPci         = document.getElementById('tabPci');
    const printA4Btn     = document.getElementById('printA4Btn');
    const saveA4Btn      = document.getElementById('saveA4Btn');
    const copyResultBtn  = document.getElementById('copyResultBtn');
    const tabSecurityBadge = document.getElementById('tabSecurityBadge');
    const tabPciBadge      = document.getElementById('tabPciBadge');
    const securityTabPanel = document.getElementById('securityTabPanel');
    const pciTabPanel      = document.getElementById('pciTabPanel');

    const securityMiniMeta = document.getElementById('securityMiniMeta');
    const pciMiniMeta      = document.getElementById('pciMiniMeta');
    const securityOverview = document.getElementById('securityOverview');
    const pciOverview      = document.getElementById('pciOverview');
    const findingsCont     = document.getElementById('findingsContainer');
    const recommendationsCont = document.getElementById('recommendationsContainer');
    const categoryScoresCont  = document.getElementById('categoryScoresContainer');
    const pciControlsCont  = document.getElementById('pciControlsContainer');

    let isScanning = false;
    let progressInterval = null;
    let lastReport = null;

    function switchResultTab(tab) {
      const isSecurity = tab === 'security';
      tabSecurity.classList.toggle('active', isSecurity);
      tabPci.classList.toggle('active', !isSecurity);
      securityTabPanel.classList.toggle('active', isSecurity);
      pciTabPanel.classList.toggle('active', !isSecurity);
    }

    function copyResults() {
      if (!lastReport) { showError('Tiada result untuk disalin.'); return; }
      const text = buildPlainReport(lastReport.data, lastReport.pci);
      copyToClipboard(text);
    }

    function saveA4Report() {
      if (!lastReport) { showError('Tiada result untuk disimpan.'); return; }
      const html = buildA4Html(lastReport.data, lastReport.pci);
      const filename = 'secscan-report-' + safeFilename(lastReport.data.hostname || 'target') + '.html';
      const blobUrl = URL.createObjectURL(new Blob([html], { type: 'text/html;charset=utf-8' }));
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(blobUrl), 1200);
    }

    function printA4Report() {
      if (!lastReport) { showError('Tiada result untuk dicetak.'); return; }

      // Elak popup blocker: jangan guna window.open().
      // Hidden iframe lebih stabil kerana tidak mencipta tab/window baharu.
      const html = buildA4Html(lastReport.data, lastReport.pci, true);
      const oldFrame = document.getElementById('secscanPrintFrame');
      if (oldFrame) oldFrame.remove();

      const frame = document.createElement('iframe');
      frame.id = 'secscanPrintFrame';
      frame.title = 'SecScan A4 Print Frame';
      frame.setAttribute('aria-hidden', 'true');
      frame.style.position = 'fixed';
      frame.style.right = '0';
      frame.style.bottom = '0';
      frame.style.width = '0';
      frame.style.height = '0';
      frame.style.border = '0';
      frame.style.opacity = '0';
      frame.style.pointerEvents = 'none';
      document.body.appendChild(frame);

      let printBlobUrl = '';
      try {
        printBlobUrl = URL.createObjectURL(new Blob([html], { type: 'text/html;charset=utf-8' }));
        frame.src = printBlobUrl;
      } catch (err) {
        frame.remove();
        showError('Gagal menyediakan dokumen cetakan. Cuba SAVE HTML dan print manual.');
        return;
      }

      let printed = false;
      const cleanup = () => {
        setTimeout(() => {
          const f = document.getElementById('secscanPrintFrame');
          if (f) f.remove();
          if (printBlobUrl) URL.revokeObjectURL(printBlobUrl);
        }, 1200);
      };

      const doPrint = () => {
        if (printed) return;
        printed = true;
        try {
          frame.contentWindow.focus();
          frame.contentWindow.print();
          cleanup();
        } catch (err) {
          console.error(err);
          cleanup();
          showError('Gagal buka dialog print. Cuba SAVE HTML dan print manual.');
        }
      };

      // Beri masa CSS @page A4 dan table layout render sebelum dialog print.
      frame.onload = () => setTimeout(doPrint, 250);
      setTimeout(doPrint, 700); // fallback untuk browser yang tidak trigger iframe onload
    }

    tabSecurity.addEventListener('click', () => switchResultTab('security'));
    tabPci.addEventListener('click', () => switchResultTab('pci'));
    printA4Btn.addEventListener('click', printA4Report);
    saveA4Btn.addEventListener('click', saveA4Report);
    copyResultBtn.addEventListener('click', copyResults);

    urlInput.addEventListener('input', () => {
      hideError();
      termStatus.textContent = urlInput.value.trim() ? 'TYPING...' : 'READY';
    });

    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' && !isScanning) {
        urlInput.value = '';
        hideError();
        termStatus.textContent = 'READY';
        urlInput.focus();
      }
    });

    scanForm.addEventListener('submit', function (e) {
      e.preventDefault();
      if (isScanning) return;
      const url = urlInput.value.trim();
      if (!url) { showError('Sila masukkan URL atau domain.'); return; }
      startScan(url);
    });

    function startScan(url) {
      isScanning = true;
      scanBtn.classList.add('loading');
      scanBtn.disabled = true;
      hideError();
      hideResults();
      showProgress();
      termStatus.textContent = 'SCANNING...';

      let pct = 0;
      const steps = [
        'Menyambung ke server...',
        'Memeriksa TLS dan sijil...',
        'Menganalisa security headers...',
        'Semak DNS, SPF dan DMARC...',
        'Mengesan exposure dan open ports...',
        'Menyusun laporan akhir...'
      ];
      let stepIdx = 0;
      progressInterval = setInterval(() => {
        pct = Math.min(pct + Math.random() * 11, 92);
        setProgress(pct, steps[stepIdx] || 'Memproses...');
        stepIdx = Math.min(stepIdx + 1, steps.length - 1);
      }, 650);

      fetch(window.location.pathname, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        body: JSON.stringify({ url })
      })
      .then(async r => {
        let data;
        try { data = await r.json(); }
        catch (_) { throw new Error('Response bukan JSON yang sah.'); }
        if (!r.ok && !data.error) throw new Error('HTTP ' + r.status);
        return data;
      })
      .then(data => {
        clearInterval(progressInterval);
        setProgress(100, 'Selesai!');
        setTimeout(() => {
          hideProgress();
          if (data.error) showError(data.error);
          else renderResults(data);
          resetBtn();
        }, 450);
      })
      .catch(err => {
        clearInterval(progressInterval);
        hideProgress();
        showError('Ralat rangkaian / render: ' + err.message);
        resetBtn();
      });
    }

    function resetBtn() {
      isScanning = false;
      scanBtn.classList.remove('loading');
      scanBtn.disabled = false;
      termStatus.textContent = 'READY';
    }

    function showProgress() { progressSec.classList.add('show'); setProgress(0, 'Memulakan scan...'); }
    function hideProgress() { progressSec.classList.remove('show'); }
    function setProgress(pct, text) {
      progressFill.style.width = pct + '%';
      progressLabel.textContent = 'SCANNING';
      progressPct.textContent = Math.round(pct) + '%';
      progressText.textContent = text;
    }

    function showError(msg) { errorMsg.textContent = msg; errorBox.classList.add('show'); }
    function hideError() { errorBox.classList.remove('show'); }
    function hideResults() { resultsSec.classList.remove('show'); lastReport = null; }

    function renderResults(raw) {
      const data = normalizeScannerResult(raw || {});
      const pci = buildPciModel(data);
      lastReport = { data, pci, raw };

      renderTargetBanner(data);
      securityMiniMeta.textContent = `${data.duration || '-'} · ${data.total_checks} checks`;
      pciMiniMeta.textContent = `${pci.total} controls · ${pci.status}`;
      tabSecurityBadge.textContent = data.total_checks;
      tabPciBadge.textContent = pci.total;

      securityOverview.innerHTML = renderAssessmentBody({
        label: 'GRED KESELAMATAN',
        score: data.score,
        grade: data.grade,
        counts: { critical: data.critical, warning: data.warnings, info: data.info, pass: data.passed },
        total: data.total_checks,
        scoreLabel: `Skor: ${data.score}/100`,
        barLabel: 'SKOR'
      });

      pciOverview.innerHTML = renderAssessmentBody({
        label: 'PCI DSS LITE',
        score: pci.score,
        grade: pci.grade,
        counts: pci.counts,
        total: pci.total,
        scoreLabel: `Skor: ${pci.score}/100`,
        barLabel: 'ALIGNMENT'
      });

      animateAssessment(securityOverview, data.score);
      animateAssessment(pciOverview, pci.score);

      recommendationsCont.innerHTML = renderRecommendations(data.recommendations);
      categoryScoresCont.innerHTML = renderCategoryScores(data.category_scores);
      findingsCont.innerHTML = renderCategoryCards(data.categories);
      pciControlsCont.innerHTML = renderPciControls(pci.controls);

      switchResultTab('security');
      resultsSec.classList.add('show');
      resultsSec.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function renderTargetBanner(data) {
      targetName.textContent = data.hostname || data.url || '—';
      targetUrl.textContent = data.url || '—';
      const target = data.target || {};
      const ipv4 = (target.ipv4 || []).length ? target.ipv4.join(', ') : 'Tidak dikesan';
      const ipv6 = (target.ipv6 || []).length ? target.ipv6.join(', ') : 'Tidak dikesan';
      const items = [
        ['PROTOKOL', (target.scheme || '').toUpperCase() || detectScheme(data.url)],
        ['MASA SCAN', data.scan_time || '—'],
        ['IPv4', ipv4],
        ['IPv6', ipv6],
      ];
      targetMetaGrid.innerHTML = items.map(([label,value]) => `
        <div class="target-chip">
          <div class="target-chip-label">${escHtml(label)}</div>
          <div class="target-chip-value">${escHtml(value)}</div>
        </div>
      `).join('');
    }

    function renderAssessmentBody(model) {
      const counts = model.counts || {};
      const total = Math.max(1, Number(model.total || 1));
      const cards = ['critical','warning','info','pass'].map(key => {
        const count = Number(counts[key] || 0);
        const pct = ((count / total) * 100).toFixed(1).replace('.0','');
        return `
          <div class="metric-card ${key}">
            <div class="metric-head">
              <div class="metric-icon">${severityIcon(key)}</div>
              <div class="metric-label">${key.toUpperCase()}</div>
            </div>
            <div class="metric-main">
              <div class="metric-value">${count}</div>
              <div class="metric-sub">${pct}% daripada checks</div>
            </div>
          </div>`;
      }).join('');

      const safeScore = Math.max(0, Math.min(100, Number(model.score || 0)));
      return `
        <div class="grade-card" data-score="${safeScore}">
          <div class="grade-card-title">${escHtml(model.label || 'GRADE')}</div>
          <div class="score-ring">
            <div class="score-ring-inner">
              <div class="score-grade">${escHtml(model.grade || 'F')}</div>
              <div class="score-ring-sub">GRADE</div>
            </div>
          </div>
          <div class="score-pill">${safeScore}%</div>
          <div class="grade-stats">
            <div class="grade-stats-row">
              <div class="grade-stat-label">${escHtml(model.barLabel || 'SKOR')}</div>
              <div class="grade-stat-value">${escHtml(model.scoreLabel || '')}</div>
            </div>
            <div class="grade-progress"><div class="grade-progress-fill"></div></div>
          </div>
        </div>
        <div class="status-grid">${cards}</div>
      `;
    }

    function animateAssessment(container, score) {
      const ring = container.querySelector('.score-ring');
      const bar = container.querySelector('.grade-progress-fill');
      const safeScore = Math.max(0, Math.min(100, Number(score || 0)));
      setTimeout(() => {
        if (ring) {
          ring.style.setProperty('--score', safeScore);
          ring.style.setProperty('--ring-color', ringColor(safeScore));
          const grade = ring.querySelector('.score-grade');
          if (grade) grade.style.color = ringColor(safeScore);
        }
        if (bar) {
          bar.style.width = safeScore + '%';
          bar.style.background = barGradient(safeScore);
        }
      }, 80);
    }

    function renderRecommendations(recs) {
      const list = Array.isArray(recs) ? recs : [];
      if (!list.length) {
        return `
          <div class="recs-panel recs-clean">
            <div class="recs-head"><span class="recs-icon">✅</span><span class="recs-title">UTAMAKAN PEMBETULAN INI</span></div>
            <div class="recs-empty">Tiada isu critical atau warning dikesan. Bagus!</div>
          </div>`;
      }
      const rows = list.map(r => {
        const sev = normalizeSeverity(r.severity);
        const refs = (Array.isArray(r.references) && r.references.length)
          ? `<div class="rec-refs">📖 ${r.references.map((u, i) => `<a href="${escHtml(u)}" target="_blank" rel="noopener noreferrer">Rujukan ${i + 1}</a>`).join(' · ')}</div>`
          : '';
        const quick = r.quick_win ? `<span class="rec-quickwin">⚡ Quick win</span>` : '';
        return `
          <div class="rec-row rec-${sev}">
            <div class="rec-rank">${Number(r.priority) || ''}</div>
            <div class="rec-main">
              <div class="rec-line1">
                <span class="finding-badge badge-${sev}">${sev.toUpperCase()}</span>
                <span class="rec-check">${escHtml(r.check || '')}</span>
                <span class="rec-cat">${escHtml(r.category || '')}</span>
                ${quick}
              </div>
              <div class="rec-issue">${escHtml(r.issue || '')}</div>
              <div class="rec-action">💡 ${escHtml(r.action || '')}</div>
              ${refs}
            </div>
          </div>`;
      }).join('');
      return `
        <div class="recs-panel">
          <div class="recs-head"><span class="recs-icon">🎯</span><span class="recs-title">UTAMAKAN PEMBETULAN INI</span><span class="recs-count">${list.length} isu</span></div>
          <div class="recs-body">${rows}</div>
        </div>`;
    }

    function renderCategoryScores(scores) {
      const entries = Object.entries(scores || {});
      if (!entries.length) return '';
      const rows = entries.map(([cat, info]) => {
        const sc = Number(info && info.score) || 0;
        const grade = (info && info.grade) || gradeFromScore(sc);
        const checks = Number(info && info.checks) || 0;
        return `
          <div class="catscore-row">
            <div class="catscore-name">${escHtml(cat)}</div>
            <div class="catscore-track"><div class="catscore-fill" style="width:${sc}%;background:${barGradient(sc)}"></div></div>
            <div class="catscore-val"><strong>${sc}</strong><span class="catscore-grade grade-${String(grade).replace('+','plus')}">${escHtml(grade)}</span><span class="catscore-checks">${checks} checks</span></div>
          </div>`;
      }).join('');
      return `
        <div class="recs-panel">
          <div class="recs-head"><span class="recs-icon">📊</span><span class="recs-title">SKOR MENGIKUT KATEGORI</span></div>
          <div class="catscore-body">${rows}</div>
        </div>`;
    }

    function renderCategoryCards(categories) {
      const severityOrder = { critical: 0, warning: 1, info: 2, pass: 3 };
      const entries = Object.entries(categories || {});
      if (!entries.length) return '<div class="category-card"><div class="category-body"><div class="finding-msg">Tiada findings diterima daripada scanner.</div></div></div>';

      return entries.map(([category, list]) => {
        const counts = { critical:0, warning:0, info:0, pass:0 };
        (list || []).forEach(f => counts[normalizeSeverity(f.severity)]++);
        const rows = [...(list || [])].sort((a,b) => (severityOrder[normalizeSeverity(a.severity)] ?? 9) - (severityOrder[normalizeSeverity(b.severity)] ?? 9)).map(f => {
          const sev = normalizeSeverity(f.severity);
          return `
            <div class="finding-row">
              <div class="finding-badge badge-${sev}">${sev.toUpperCase()}</div>
              <div class="finding-content">
                <div class="finding-check">${escHtml(f.check || 'Unknown check')}</div>
                <div class="finding-msg">${escHtml(f.message || '')}</div>
                ${f.recommendation ? `<div class="finding-rec">💡 ${escHtml(f.recommendation)}</div>` : ''}
                ${(Array.isArray(f.references) && f.references.length) ? `<div class="finding-refs">📖 ${f.references.map((u, i) => `<a href="${escHtml(u)}" target="_blank" rel="noopener noreferrer">Rujukan ${i + 1}</a>`).join(' · ')}</div>` : ''}
              </div>
            </div>`;
        }).join('');

        const dots = ['critical','warning','info','pass']
          .filter(k => counts[k] > 0)
          .map(k => `<span class="severity-dot ${k}">${counts[k]} ${k.toUpperCase()}</span>`)
          .join('');

        return `
          <div class="category-card">
            <div class="category-head">
              <div class="category-title-wrap">
                <div class="category-title">${escHtml(category)}</div>
                <div class="category-meta">${(list || []).length} checks</div>
              </div>
              <div class="severity-dots">${dots}</div>
            </div>
            <div class="category-body">${rows}</div>
          </div>`;
      }).join('');
    }

    function renderPciControls(controls) {
      return (controls || []).map(c => `
        <div class="pci-control-card">
          <div class="pci-control-badge ${c.severity}">${c.severity.toUpperCase()}</div>
          <div class="pci-control-body">
            <div class="pci-control-title">${escHtml(c.title)}</div>
            <div class="pci-control-msg">${escHtml(c.message)}</div>
            ${c.recommendation ? `<div class="pci-control-rec">💡 ${escHtml(c.recommendation)}</div>` : ''}
          </div>
        </div>`).join('');
    }

    function normalizeScannerResult(data) {
      const categories = data.categories && typeof data.categories === 'object'
        ? data.categories
        : groupLegacyFindings(Array.isArray(data.findings) ? data.findings : []);

      const normalizedCategories = {};
      const findings = [];
      Object.keys(categories || {}).forEach(category => {
        const list = Array.isArray(categories[category]) ? categories[category] : [];
        normalizedCategories[category] = list.map(f => ({
          category,
          check: f.check || 'Unknown check',
          severity: normalizeSeverity(f.severity),
          message: f.message || '',
          recommendation: f.recommendation || '',
          references: Array.isArray(f.references) ? f.references : []
        }));
        findings.push(...normalizedCategories[category]);
      });

      const counts = { critical:0, warnings:0, info:0, passed:0 };
      findings.forEach(f => {
        if (f.severity === 'critical') counts.critical++;
        else if (f.severity === 'warning') counts.warnings++;
        else if (f.severity === 'pass') counts.passed++;
        else counts.info++;
      });

      const target = data.target || {};
      const serverIp = data.server_ip || {};
      target.ipv4 = Array.isArray(target.ipv4) ? target.ipv4 : (Array.isArray(serverIp.ipv4) ? serverIp.ipv4 : []);
      target.ipv6 = Array.isArray(target.ipv6) ? target.ipv6 : (Array.isArray(serverIp.ipv6) ? serverIp.ipv6 : []);
      target.scheme = target.scheme || (String(data.url || '').startsWith('https://') ? 'https' : 'http');
      target.hostname = target.hostname || data.hostname || data.host || '';

      return {
        url: data.url || target.url || '',
        hostname: data.hostname || data.host || target.hostname || '—',
        score: Number(data.score ?? 0),
        grade: String(data.grade || gradeFromScore(Number(data.score || 0))),
        total_checks: Number(data.total_checks || findings.length || 0),
        passed: Number(data.passed ?? counts.passed),
        info: Number(data.info ?? counts.info),
        warnings: Number(data.warnings ?? data.warning ?? counts.warnings),
        critical: Number(data.critical ?? counts.critical),
        scan_time: data.scan_time || data.scanTime || '',
        duration: data.duration || '',
        categories: normalizedCategories,
        category_scores: (data.category_scores && typeof data.category_scores === 'object') ? data.category_scores : {},
        recommendations: Array.isArray(data.recommendations) ? data.recommendations : [],
        findings,
        target
      };
    }

    function buildPciModel(data) {
      const findings = Array.isArray(data.findings) ? data.findings : [];
      const controls = [
        makePciControl('Secure Transmission (HTTPS/TLS)', matchFindings(findings, f => ['Transport','TLS/SSL'].includes(f.category) || /HTTPS|HSTS|Certificate|Protocol|Cipher|TLS|SSL/i.test(f.check)), 'Pastikan semua data dihantar melalui HTTPS/TLS yang kuat.'),
        makePciControl('Browser Security Headers', matchFindings(findings, f => f.category === 'Headers' && /Content-Security-Policy|Strict-Transport-Security|X-Frame-Options|X-Content-Type-Options|Referrer-Policy|Permissions-Policy/i.test(f.check)), 'Aktifkan security headers yang sesuai untuk payment page.'),
        makePciControl('Cookie & Session Hygiene', matchFindings(findings, f => /Cookie/i.test(f.check) || /HttpOnly|SameSite|Secure/i.test(f.message)), 'Gunakan Secure, HttpOnly dan SameSite pada session cookies.'),
        makePciControl('Client-side / Payment Page Hardening', matchFindings(findings, f => f.category === 'HTML' && /Mixed Content|Subresource Integrity|Insecure Form Action|Meta CSP/i.test(f.check)), 'Kuatkan payment page daripada mixed content dan skrip tidak terkawal.'),
        makePciControl('CORS Access Control', matchFindings(findings, f => f.category === 'CORS'), 'Hadkan akses cross-origin kepada origin yang dipercayai sahaja.'),
        makePciControl('DNS / Email Domain Protection', matchFindings(findings, f => f.category === 'DNS'), 'Kuatkan DNS, SPF dan DMARC untuk kurangkan risiko spoofing.'),
        makePciControl('Sensitive File Exposure', matchFindings(findings, f => f.category === 'Exposed Files'), 'Pastikan fail sensitif, backup dan config tidak boleh dicapai awam.'),
        makePciControl('Public Service / Port Exposure', matchFindings(findings, f => f.category === 'Ports'), 'Tutup port awam yang tidak perlu dan lindungi akses service.'),
        makePciControl('Information Disclosure', matchFindings(findings, f => /Server|Technology|Version|Leak/i.test(f.check) || /Server Leak/i.test(f.category)), 'Kurangkan maklumat server/teknologi yang terdedah.'),
        makePciControl('Security Operations Readiness', matchFindings(findings, f => /security.txt|Robots|HTTP Versions|Reachability/i.test(f.check) || ['Connection'].includes(f.category)), 'Pastikan operasi security, disclosure channel dan surface management jelas.'),
      ];

      const counts = { critical:0, warning:0, info:0, pass:0 };
      controls.forEach(c => counts[c.severity]++);
      const weights = { pass: 100, info: 70, warning: 35, critical: 0 };
      const score = Math.round(controls.reduce((sum, c) => sum + weights[c.severity], 0) / Math.max(1, controls.length));
      return {
        controls,
        total: controls.length,
        counts,
        score,
        grade: gradeFromScore(score),
        status: score >= 85 ? 'Good alignment' : (score >= 65 ? 'Partial alignment' : 'Action required')
      };
    }

    function makePciControl(title, relatedFindings, defaultRecommendation) {
      if (!relatedFindings.length) {
        return {
          title,
          severity: 'pass',
          message: 'Tiada signal negatif dikesan untuk kawalan ini berdasarkan scan luaran semasa.',
          recommendation: defaultRecommendation
        };
      }
      const sorted = [...relatedFindings].sort((a,b) => severityRank(a.severity) - severityRank(b.severity));
      const top = sorted[0];
      return {
        title,
        severity: normalizeSeverity(top.severity),
        message: top.message || 'Signal kawalan memerlukan perhatian.',
        recommendation: top.recommendation || defaultRecommendation
      };
    }

    function buildPlainReport(data, pci) {
      const lines = [];
      lines.push('SECSCAN REPORT');
      lines.push('Target: ' + (data.hostname || '-'));
      lines.push('URL: ' + (data.url || '-'));
      lines.push('Scan Time: ' + (data.scan_time || '-'));
      lines.push('Duration: ' + (data.duration || '-'));
      lines.push('');
      lines.push('SCAN KESELAMATAN');
      lines.push(`Score: ${data.score}/100 | Grade: ${data.grade} | Checks: ${data.total_checks}`);
      lines.push(`Critical: ${data.critical} | Warning: ${data.warnings} | Info: ${data.info} | Pass: ${data.passed}`);
      lines.push('');
      lines.push('PCI DSS LITE');
      lines.push(`Score: ${pci.score}/100 | Grade: ${pci.grade} | Status: ${pci.status}`);
      lines.push(`Critical: ${pci.counts.critical} | Warning: ${pci.counts.warning} | Info: ${pci.counts.info} | Pass: ${pci.counts.pass}`);
      lines.push('');
      lines.push('FINDINGS');
      Object.entries(data.categories || {}).forEach(([cat, list]) => {
        lines.push('');
        lines.push('[' + cat + ']');
        (list || []).forEach(f => {
          lines.push(`- ${String(f.severity || '').toUpperCase()} | ${f.check}: ${f.message}`);
          if (f.recommendation) lines.push(`  Cadangan: ${f.recommendation}`);
        });
      });
      lines.push('');
      lines.push('PCI CONTROLS');
      (pci.controls || []).forEach(c => {
        lines.push(`- ${c.severity.toUpperCase()} | ${c.title}: ${c.message}`);
        if (c.recommendation) lines.push(`  Cadangan: ${c.recommendation}`);
      });
      return lines.join('\n');
    }

    function buildA4Html(data, pci, autoPrint = false) {
      const securityRows = Object.entries(data.categories || {}).flatMap(([cat, list]) =>
        (list || []).map(f => `<tr><td>${escHtml(cat)}</td><td>${escHtml(String(f.severity || '').toUpperCase())}</td><td><strong>${escHtml(f.check)}</strong><br>${escHtml(f.message)}${f.recommendation ? '<br><em>Cadangan: ' + escHtml(f.recommendation) + '</em>' : ''}</td></tr>`)
      ).join('');

      const pciRows = (pci.controls || []).map(c =>
        `<tr><td>${escHtml(String(c.severity || '').toUpperCase())}</td><td><strong>${escHtml(c.title)}</strong><br>${escHtml(c.message)}${c.recommendation ? '<br><em>Cadangan: ' + escHtml(c.recommendation) + '</em>' : ''}</td></tr>`
      ).join('');

      const ip4 = (data.target?.ipv4 || []).join(', ') || '-';
      const ip6 = (data.target?.ipv6 || []).join(', ') || '-';

      return `<!doctype html>
<html lang="ms">
<head>
<meta charset="utf-8">
<title>SecScan Report - ${escHtml(data.hostname)}</title>
<style>
  @page { size: A4; margin: 10mm; }
  * { box-sizing: border-box; }
  body { font-family: Arial, Helvetica, sans-serif; color:#111827; margin:0; font-size:10px; line-height:1.35; }
  h1 { font-size:16px; margin:0 0 3px; }
  h2 { font-size:12px; margin:12px 0 6px; border-bottom:1px solid #111827; padding-bottom:3px; }
  .muted { color:#4b5563; }
  .top { display:flex; justify-content:space-between; gap:12px; border-bottom:2px solid #111827; padding-bottom:8px; margin-bottom:8px; }
  .boxgrid { display:grid; grid-template-columns: repeat(4, 1fr); gap:5px; margin:6px 0 8px; }
  .box { border:1px solid #d1d5db; padding:5px 6px; border-radius:4px; min-height:34px; }
  .box b { display:block; font-size:11px; }
  .summary { display:grid; grid-template-columns: 1fr 1fr; gap:8px; }
  table { width:100%; border-collapse:collapse; page-break-inside:auto; }
  tr { page-break-inside:avoid; page-break-after:auto; }
  th,td { border:1px solid #d1d5db; padding:4px 5px; vertical-align:top; }
  th { background:#f3f4f6; text-align:left; font-size:9px; text-transform:uppercase; letter-spacing:.04em; }
  em { color:#374151; }
  .small { font-size:9px; }
  .footer { margin-top:10px; font-size:9px; color:#6b7280; border-top:1px solid #d1d5db; padding-top:5px; }
</style>
</head>
<body>
  <div class="top">
    <div>
      <h1>SecScan Report</h1>
      <div class="muted">${escHtml(data.hostname || '-')}</div>
      <div class="small">${escHtml(data.url || '-')}</div>
    </div>
    <div class="small">
      Scan: ${escHtml(data.scan_time || '-')}<br>
      Duration: ${escHtml(data.duration || '-')}<br>
      IPv4: ${escHtml(ip4)}<br>
      IPv6: ${escHtml(ip6)}
    </div>
  </div>

  <div class="summary">
    <div>
      <h2>Scan Keselamatan</h2>
      <div class="boxgrid">
        <div class="box"><span>Grade</span><b>${escHtml(data.grade)}</b></div>
        <div class="box"><span>Score</span><b>${data.score}/100</b></div>
        <div class="box"><span>Checks</span><b>${data.total_checks}</b></div>
        <div class="box"><span>Pass</span><b>${data.passed}</b></div>
      </div>
      <div class="boxgrid">
        <div class="box"><span>Critical</span><b>${data.critical}</b></div>
        <div class="box"><span>Warning</span><b>${data.warnings}</b></div>
        <div class="box"><span>Info</span><b>${data.info}</b></div>
        <div class="box"><span>Pass</span><b>${data.passed}</b></div>
      </div>
    </div>
    <div>
      <h2>PCI DSS Lite</h2>
      <div class="boxgrid">
        <div class="box"><span>Grade</span><b>${escHtml(pci.grade)}</b></div>
        <div class="box"><span>Score</span><b>${pci.score}/100</b></div>
        <div class="box"><span>Controls</span><b>${pci.total}</b></div>
        <div class="box"><span>Status</span><b>${escHtml(pci.status)}</b></div>
      </div>
      <div class="boxgrid">
        <div class="box"><span>Critical</span><b>${pci.counts.critical}</b></div>
        <div class="box"><span>Warning</span><b>${pci.counts.warning}</b></div>
        <div class="box"><span>Info</span><b>${pci.counts.info}</b></div>
        <div class="box"><span>Pass</span><b>${pci.counts.pass}</b></div>
      </div>
    </div>
  </div>

  <h2>Findings Keselamatan</h2>
  <table>
    <thead><tr><th style="width:18%">Kategori</th><th style="width:12%">Severity</th><th>Dapatan & Cadangan</th></tr></thead>
    <tbody>${securityRows || '<tr><td colspan="3">Tiada findings.</td></tr>'}</tbody>
  </table>

  <h2>PCI DSS Lite Controls</h2>
  <table>
    <thead><tr><th style="width:12%">Severity</th><th>Kawalan & Cadangan</th></tr></thead>
    <tbody>${pciRows || '<tr><td colspan="2">Tiada controls.</td></tr>'}</tbody>
  </table>

  <div class="footer">Nota: PCI DSS Lite ialah signal luaran ringkas, bukan pensijilan PCI rasmi / ASV / QSA assessment.</div>
</body>
</html>`;
    }

    function copyToClipboard(text) {
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text)
          .then(() => alert('Result berjaya disalin.'))
          .catch(() => fallbackCopy(text));
      } else {
        fallbackCopy(text);
      }
    }

    function fallbackCopy(text) {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      try {
        document.execCommand('copy');
        alert('Result berjaya disalin.');
      } catch (_) {
        alert('Gagal salin. Sila copy manual.');
      }
      document.body.removeChild(ta);
    }

    function matchFindings(findings, predicate) { return findings.filter(predicate); }
    function severityRank(sev) {
      const map = { critical:0, warning:1, info:2, pass:3 };
      return map[normalizeSeverity(sev)] ?? 9;
    }
    function gradeFromScore(score) {
      score = Number(score || 0);
      if (score >= 90) return 'A+';
      if (score >= 80) return 'A';
      if (score >= 70) return 'B';
      if (score >= 60) return 'C';
      if (score >= 45) return 'D';
      return 'F';
    }
    function groupLegacyFindings(findings) {
      return findings.reduce((acc, f) => {
        const category = f.category || 'General';
        if (!acc[category]) acc[category] = [];
        acc[category].push(f);
        return acc;
      }, {});
    }
    function normalizeSeverity(severity) {
      severity = String(severity || 'info').toLowerCase();
      if (['high', 'medium', 'low', 'warn', 'warning'].includes(severity)) return 'warning';
      if (['ok', 'success', 'passed'].includes(severity)) return 'pass';
      if (severity === 'critical' || severity === 'pass' || severity === 'info') return severity;
      return 'info';
    }
    function severityIcon(type) {
      const icons = {
        critical: '<svg viewBox="0 0 24 24" fill="none"><path d="M12 8v5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="16.5" r="1.2" fill="currentColor"/><path d="M10.4 3.8 3.8 15.1a2 2 0 0 0 1.72 3h13a2 2 0 0 0 1.73-3L13.6 3.8a2 2 0 0 0-3.2 0Z" stroke="currentColor" stroke-width="1.8" fill="none" stroke-linejoin="round"/></svg>',
        warning: '<svg viewBox="0 0 24 24" fill="none"><path d="M12 8v5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="16.5" r="1.2" fill="currentColor"/><path d="M10.4 3.8 3.8 15.1a2 2 0 0 0 1.72 3h13a2 2 0 0 0 1.73-3L13.6 3.8a2 2 0 0 0-3.2 0Z" stroke="currentColor" stroke-width="1.8" fill="none" stroke-linejoin="round"/></svg>',
        info: '<svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="8.5" stroke="currentColor" stroke-width="1.8"/><circle cx="12" cy="8.2" r="1.1" fill="currentColor"/><path d="M12 11v5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
        pass: '<svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="8.5" stroke="currentColor" stroke-width="1.8"/><path d="M7.5 12.5 10.5 15.4 16.7 9.2" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>'
      };
      return icons[type] || icons.info;
    }
    function barGradient(score) {
      score = Number(score || 0);
      if (score >= 80) return 'linear-gradient(90deg,#38bdf8,#60a5fa,#6366f1)';
      if (score >= 60) return 'linear-gradient(90deg,#38bdf8,#8b5cf6)';
      if (score >= 40) return 'linear-gradient(90deg,#f59e0b,#fb923c)';
      return 'linear-gradient(90deg,#f43f5e,#dc2626)';
    }
    function ringColor(score) {
      score = Number(score || 0);
      if (score >= 80) return '#38bdf8';
      if (score >= 60) return '#60a5fa';
      if (score >= 40) return '#f59e0b';
      return '#f43f5e';
    }
    function detectScheme(url) {
      return String(url || '').toLowerCase().startsWith('https://') ? 'HTTPS' : 'HTTP';
    }
    function safeFilename(str) {
      return String(str || 'target').replace(/[^a-z0-9.-]+/gi, '-').replace(/^-+|-+$/g, '').toLowerCase() || 'target';
    }
    function escHtml(str) {
      return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }
  })();
  </script>
</body>
</html>
