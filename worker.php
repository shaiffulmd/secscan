<?php

// Deploy this file together with scanner.php, config.php, and src/ on the VPS.
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/src/UrlGuard.php';
require_once __DIR__ . '/src/WorkerProtocol.php';

header_remove('X-Powered-By');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, private, max-age=0');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'");

/**
 * @param array<string,mixed> $payload
 */
$send = static function (array $payload, int $status, string $secret, string $nonce): void {
    $body = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if (!is_string($body)) $body = '{"error":"Worker response encoding failed."}';
    if ($nonce !== '' && $secret !== '') {
        header('X-SecScan-Job-Nonce: ' . $nonce);
        header('X-SecScan-Response-Signature: ' . WorkerProtocol::responseSignature($secret, $nonce, $body));
    }
    http_response_code($status);
    echo $body;
    exit;
};

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    $send(['error' => 'Method not allowed.'], 405, '', '');
}

$secret = trim((string)secscan_config('worker_shared_secret'));
$timestamp = trim((string)($_SERVER['HTTP_X_SECSCAN_TIMESTAMP'] ?? ''));
$nonce = trim((string)($_SERVER['HTTP_X_SECSCAN_NONCE'] ?? ''));
$signature = trim((string)($_SERVER['HTTP_X_SECSCAN_SIGNATURE'] ?? ''));
if (strlen($secret) < 32 || !WorkerProtocol::isFreshTimestamp($timestamp)
    || !WorkerProtocol::isValidNonce($nonce) || !preg_match('/^[a-f0-9]{64}$/i', $signature)) {
    $send(['error' => 'Worker authentication failed.'], 401, '', '');
}

$allowedCallers = trim((string)secscan_config('worker_allowed_callers'));
if ($allowedCallers !== '' && !secscan_ip_in_ranges(secscan_client_ip(), $allowedCallers)) {
    $send(['error' => 'Worker caller is not allowed.'], 403, $secret, $nonce);
}

$rawBody = secscan_read_request_body();
if ($rawBody === null) {
    $send(['error' => 'Request terlalu besar.'], 413, $secret, $nonce);
}
$expected = WorkerProtocol::requestSignature($secret, $timestamp, $nonce, $rawBody);
if (!hash_equals($expected, $signature)) {
    $send(['error' => 'Worker request signature is invalid.'], 401, $secret, $nonce);
}

// Store seen nonces for five minutes to reject replayed scan jobs.
$nonceFile = rtrim((string)secscan_config('data_dir'), '/') . '/worker-nonces.json';
$nonceDir = dirname($nonceFile);
if (!is_dir($nonceDir) && !@mkdir($nonceDir, 0700, true) && !is_dir($nonceDir)) {
    $send(['error' => 'Worker nonce storage is unavailable.'], 503, $secret, $nonce);
}
$nonceHandle = @fopen($nonceFile, 'c+');
if ($nonceHandle === false || !flock($nonceHandle, LOCK_EX)) {
    if (is_resource($nonceHandle)) fclose($nonceHandle);
    $send(['error' => 'Worker nonce storage is unavailable.'], 503, $secret, $nonce);
}
@chmod($nonceFile, 0600);
if (!rewind($nonceHandle)) {
    flock($nonceHandle, LOCK_UN);
    fclose($nonceHandle);
    $send(['error' => 'Worker nonce storage is unavailable.'], 503, $secret, $nonce);
}
$existing = stream_get_contents($nonceHandle);
if ($existing === false) {
    flock($nonceHandle, LOCK_UN);
    fclose($nonceHandle);
    $send(['error' => 'Worker nonce storage is unavailable.'], 503, $secret, $nonce);
}
$seen = [];
if ($existing !== '') {
    $decoded = json_decode($existing, true);
    if (!is_array($decoded) || json_last_error() !== JSON_ERROR_NONE) {
        flock($nonceHandle, LOCK_UN);
        fclose($nonceHandle);
        $send(['error' => 'Worker nonce storage is unavailable.'], 503, $secret, $nonce);
    }
    $seen = $decoded;
}
$now = time();
$seen = array_filter($seen, static fn($seenAt): bool => is_int($seenAt) && $seenAt >= $now - 300);
if (isset($seen[$nonce])) {
    flock($nonceHandle, LOCK_UN);
    fclose($nonceHandle);
    $send(['error' => 'Worker request replay detected.'], 409, $secret, $nonce);
}
$seen[$nonce] = $now;
$seenPayload = json_encode($seen, JSON_UNESCAPED_SLASHES);
$noncePersisted = is_string($seenPayload)
    && ftruncate($nonceHandle, 0)
    && rewind($nonceHandle)
    && fwrite($nonceHandle, $seenPayload) === strlen($seenPayload)
    && fflush($nonceHandle);
flock($nonceHandle, LOCK_UN);
fclose($nonceHandle);
if (!$noncePersisted) {
    $send(['error' => 'Worker nonce storage is unavailable.'], 503, $secret, $nonce);
}

$input = json_decode($rawBody, true);
if (!is_array($input)) {
    $send(['error' => 'Invalid JSON request.'], 400, $secret, $nonce);
}
$target = UrlGuard::normalizeAndValidate((string)($input['url'] ?? ''));
if (!($target['ok'] ?? false)) {
    $send(['error' => (string)($target['error'] ?? 'Invalid target.')], (int)($target['status'] ?? 400), $secret, $nonce);
}

try {
    set_time_limit(max(60, (int)secscan_config('worker_scan_timeout')));
    require_once __DIR__ . '/scanner.php';
    $scanner = new SecurityScanner((string)$target['url']);
    if (secscan_config('allow_auth_scan')) {
        $headers = $input['auth_headers'] ?? [];
        $cookie = trim((string)($input['auth_cookie'] ?? ''));
        if (is_array($headers) && ($headers !== [] || $cookie !== '')) {
            if (($target['scheme'] ?? '') !== 'https') {
                $send(['error' => 'Authenticated scan memerlukan URL HTTPS.'], 400, $secret, $nonce);
            }
            $scanner->setAuth($headers, $cookie);
        }
    }
    $result = $scanner->scan();
    if (!is_array($result)) throw new RuntimeException('Scanner returned an invalid result.');
    $result['worker'] = ['mode' => 'remote', 'completed_at' => gmdate('c')];
    $send($result, 200, $secret, $nonce);
} catch (Throwable $e) {
    error_log('[SecScan Worker] ' . get_class($e) . ': ' . $e->getMessage());
    $send(['error' => 'Worker scanner gagal menjalankan scan.'], 500, $secret, $nonce);
}
