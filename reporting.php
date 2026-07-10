<?php

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/src/RateLimiter.php';

if (!headers_sent()) {
    header_remove('X-Powered-By');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    secscan_send_operational_security_headers();
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method === 'OPTIONS') {
    http_response_code(204);
    exit;
}

if ($method !== 'POST') {
    http_response_code(405);
    header('Allow: POST, OPTIONS');
    exit;
}

$body = secscan_read_request_body();
if ($body === null) {
    http_response_code(413);
    exit;
}

$reports = json_decode($body, true);
if (!is_array($reports)) {
    http_response_code(400);
    exit;
}

// Reporting endpoints are public by design, so protect the retained telemetry
// from high-volume spoofed submissions as well as from oversized bodies.
$rate = RateLimiter::consume(
    'security_reports_v1',
    secscan_client_ip(),
    (int)secscan_config('report_rate_limit'),
    (int)secscan_config('report_rate_window')
);
if (!empty($rate['storage_failed'])) {
    http_response_code(503);
    exit;
}
if (!$rate['allowed']) {
    header('Retry-After: ' . $rate['retry_after']);
    http_response_code(429);
    exit;
}

if (array_is_list($reports) && count($reports) > 20) {
    http_response_code(400);
    exit;
}

$dataDir = (string)secscan_config('data_dir');
if ($dataDir !== '' && (is_dir($dataDir) || @mkdir($dataDir, 0750, true))) {
    $entry = [
        'time' => gmdate('c'),
        'ip' => secscan_client_ip(),
        'user_agent' => substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 300),
        'reports' => $reports,
    ];
    $line = json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if (is_string($line)) {
        $path = rtrim($dataDir, '/\\') . '/security-reports.ndjson';
        $fp = @fopen($path, 'c+');
        if ($fp !== false) {
            flock($fp, LOCK_EX);
            $size = (int)(fstat($fp)['size'] ?? 0);
            $entry = $line . "\n";
            // A bounded circular log prevents unauthenticated reports from
            // exhausting disk. Export it externally if longer retention is needed.
            if ($size + strlen($entry) > (int)secscan_config('report_log_max_bytes')) {
                ftruncate($fp, 0);
                rewind($fp);
            } else {
                fseek($fp, 0, SEEK_END);
            }
            fwrite($fp, $entry);
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }
}

http_response_code(204);
