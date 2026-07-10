<?php

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/src/RateLimiter.php';
require_once __DIR__ . '/src/UrlGuard.php';

set_time_limit(120);
ini_set('max_execution_time', '120');
ob_start();

set_error_handler(static function (int $errno, string $errstr, string $errfile = '', int $errline = 0): bool {
    error_log("[SecScan API] PHP error ({$errno}): {$errstr} in {$errfile}:{$errline}");
    return true;
});

$sendJson = static function (array $payload, int $status = 200): void {
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    http_response_code($status);
    echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
};

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
secscan_send_operational_security_headers();

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

if (!in_array($_SERVER['REQUEST_METHOD'], ['GET', 'POST'], true)) {
    $sendJson(['error' => 'Method not allowed.'], 405);
}

$rawBody = $_SERVER['REQUEST_METHOD'] === 'POST' ? secscan_read_request_body() : '';
if ($rawBody === null) {
    $sendJson(['error' => 'Request body is too large.'], 413);
}
$input = $rawBody !== '' ? (json_decode($rawBody, true) ?: []) : [];
$urlInput = trim((string)($input['url'] ?? $_POST['url'] ?? $_GET['url'] ?? ''));

$target = UrlGuard::normalizeAndValidate($urlInput);
if (!$target['ok']) {
    $sendJson(['error' => $target['error']], (int)$target['status']);
}

$clientIp = secscan_client_ip();
if (secscan_is_owner_bypass_ip($clientIp)) {
    $rate = ['allowed' => true, 'limit' => 'bypass', 'remaining' => 'bypass', 'reset' => time(), 'retry_after' => 0, 'storage_failed' => false];
    header('X-RateLimit-Bypass: owner-ip');
} else {
    $rate = RateLimiter::consume(
        'scan_v5',
        $clientIp,
        (int)secscan_config('scan_rate_limit'),
        (int)secscan_config('scan_rate_window')
    );
}

header('X-RateLimit-Limit: ' . $rate['limit']);
header('X-RateLimit-Remaining: ' . $rate['remaining']);
header('X-RateLimit-Reset: ' . $rate['reset']);

if (!empty($rate['storage_failed'])) {
    $sendJson(['error' => 'Rate-limit service is unavailable. Please try again later.'], 503);
}

if (!$rate['allowed']) {
    header('Retry-After: ' . $rate['retry_after']);
    $sendJson([
        'error' => 'Rate limit exceeded. Please wait before scanning again.',
        'retry_after' => $rate['retry_after'],
    ], 429);
}

require_once __DIR__ . '/scanner.php';

try {
    $scanner = new SecurityScanner($target['url']);

    // Authenticated scanning (opt-in via SECSCAN_ALLOW_AUTH_SCAN=1). Accepts a
    // raw Cookie value and/or a header map so scans can run behind a login.
    if (secscan_config('allow_auth_scan')) {
        $authCookie  = trim((string)($input['auth_cookie'] ?? ''));
        $authHeaders = $input['auth_headers'] ?? [];
        if (!is_array($authHeaders)) $authHeaders = [];
        if ($authCookie !== '' || $authHeaders !== []) {
            if (($target['scheme'] ?? '') !== 'https') {
                $sendJson(['error' => 'Authenticated scanning requires a valid HTTPS URL.'], 400);
            }
            $scanner->setAuth($authHeaders, $authCookie);
        }
    }

    $result = $scanner->scan();

    try {
        $loggerPath = __DIR__ . '/logger.php';
        if (is_file($loggerPath)) {
            require_once $loggerPath;
            (new ScanLogger())->log($result, $clientIp);
        }
    } catch (Throwable $logEx) {
        error_log('[SecScan API] Logger failed (non-fatal): ' . $logEx->getMessage());
    }

    $result['target'] = [
        'name' => $target['hostname'],
        'hostname' => $target['hostname'],
        'scheme' => $target['scheme'],
        'url' => $target['url'],
        'ipv4' => $target['ipv4'],
        'ipv6' => $target['ipv6'],
    ];
    $result['resolved_ips'] = [
        'ipv4' => $target['ipv4'],
        'ipv6' => $target['ipv6'],
    ];
    $result['scan_client_ip'] = $clientIp;
    $result['request'] = [
        'client_ip' => $clientIp,
    ];
    $result['scanner_identity'] = secscan_scanner_identity();

    $sendJson($result);
} catch (Throwable $e) {
    error_log(sprintf(
        '[SecScan API] %s for %s | %s in %s:%d | Trace: %s',
        get_class($e),
        $target['url'],
        $e->getMessage(),
        $e->getFile(),
        $e->getLine(),
        str_replace("\n", ' ', $e->getTraceAsString())
    ));
    $sendJson(['error' => 'An internal error occurred during the scan.'], 500);
}
