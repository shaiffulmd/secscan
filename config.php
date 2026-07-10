<?php

/**
 * Central SecScan configuration.
 *
 * Environment variables override these defaults. For production, set at least:
 * SECSCAN_DASHBOARD_PASSWORD_HASH and SECSCAN_IP_HASH_SALT.
 */

/**
 * Load a local .env file into the process environment.
 *
 * The app reads config via getenv(); on hosts where you cannot set FPM/systemd
 * environment variables (shared/cPanel hosting) this lets a .env file supply
 * them. Lookup order: $SECSCAN_ENV_FILE, then ./.env next to this file, then
 * ../.env one level above the web root (the safest place — not web-reachable).
 *
 * Real environment variables ALWAYS win — a .env value never overrides one that
 * is already set. Values are read literally (no shell/`$` expansion), so bcrypt
 * hashes are safe. The file is also denied by .htaccess when kept in the root.
 */
function secscan_load_dotenv(): void
{
    static $loaded = false;
    if ($loaded) {
        return;
    }
    $loaded = true;

    $candidates = [];
    $explicit = getenv('SECSCAN_ENV_FILE');
    if (is_string($explicit) && $explicit !== '') {
        $candidates[] = $explicit;
    }
    $candidates[] = __DIR__ . '/.env';
    $candidates[] = dirname(__DIR__) . '/.env';
    // Explicit deployment location (this server keeps .env above the web root).
    $candidates[] = '/home/security/.env';

    $path = null;
    foreach ($candidates as $candidate) {
        if (is_string($candidate) && $candidate !== '' && is_readable($candidate)) {
            $path = $candidate;
            break;
        }
    }
    if ($path === null) {
        return;
    }

    $lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) {
        return;
    }

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') {
            continue;
        }
        if (strncmp($line, 'export ', 7) === 0) {
            $line = ltrim(substr($line, 7));
        }
        $eq = strpos($line, '=');
        if ($eq === false) {
            continue;
        }
        $key = trim(substr($line, 0, $eq));
        if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $key)) {
            continue;
        }
        // Never override an environment variable that is already set.
        if (getenv($key) !== false || array_key_exists($key, $_ENV) || array_key_exists($key, $_SERVER)) {
            continue;
        }
        $value = trim(substr($line, $eq + 1));
        if (strlen($value) >= 2) {
            $q = $value[0];
            if (($q === '"' || $q === "'") && $value[strlen($value) - 1] === $q) {
                $value = substr($value, 1, -1);
            }
        }
        putenv("{$key}={$value}");
        $_ENV[$key] = $value;
    }
}

secscan_load_dotenv();

function secscan_env(string $key, ?string $default = null): ?string
{
    $value = getenv($key);
    if ($value === false || $value === '') {
        return $default;
    }
    return $value;
}

/**
 * Application version shown in the scanner footer and dashboard. Set
 * SECSCAN_APP_VERSION to override a deployment, otherwise update the VERSION
 * file as part of every release.
 */
function secscan_app_version(): string
{
    static $version = null;
    if ($version !== null) {
        return $version;
    }

    $candidate = trim((string)secscan_env('SECSCAN_APP_VERSION', ''));
    if ($candidate === '') {
        $raw = @file_get_contents(__DIR__ . '/VERSION');
        $candidate = is_string($raw) ? trim($raw) : '';
    }

    return $version = preg_match('/^v?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$/', $candidate)
        ? ltrim($candidate, 'v')
        : 'dev';
}

function secscan_config(?string $key = null)
{
    static $config = null;

    if ($config === null) {
        $dataDir = secscan_env('SECSCAN_DATA_DIR', __DIR__ . '/data');

        $config = [
            'data_dir' => $dataDir,
            'database_path' => secscan_env('SECSCAN_DB_PATH', $dataDir . '/secscan.db'),
            'ip_hash_salt' => secscan_env('SECSCAN_IP_HASH_SALT', 'change-this-salt-before-production'),
            'dashboard_password_hash' => secscan_env('SECSCAN_DASHBOARD_PASSWORD_HASH', ''),
            'scan_rate_limit' => (int)secscan_env('SECSCAN_SCAN_RATE_LIMIT', '50'),
            'scan_rate_window' => (int)secscan_env('SECSCAN_SCAN_RATE_WINDOW', '86400'),
            'max_request_bytes' => max(1024, (int)secscan_env('SECSCAN_MAX_REQUEST_BYTES', '65536')),
            'rate_limit_max_keys' => max(100, (int)secscan_env('SECSCAN_RATE_LIMIT_MAX_KEYS', '10000')),
            'report_rate_limit' => max(1, (int)secscan_env('SECSCAN_REPORT_RATE_LIMIT', '30')),
            'report_rate_window' => max(1, (int)secscan_env('SECSCAN_REPORT_RATE_WINDOW', '60')),
            'report_log_max_bytes' => max(65536, (int)secscan_env('SECSCAN_REPORT_LOG_MAX_BYTES', '5242880')),
            // Owner/admin IP allowlist that may scan without consuming the public
            // per-IP scan quota. Comma-separated IPs or CIDR ranges.
            'owner_bypass_ips' => secscan_env('SECSCAN_OWNER_BYPASS_IPS', ''),
            // Successful dashboard logins can grant a temporary scan-quota bypass
            // for the admin's current IP. Default follows the dashboard session.
            'owner_bypass_ttl' => max(60, (int)secscan_env('SECSCAN_OWNER_BYPASS_TTL', '3600')),
            'api_rate_limit' => (int)secscan_env('SECSCAN_API_RATE_LIMIT', '5'),
            'api_rate_window' => (int)secscan_env('SECSCAN_API_RATE_WINDOW', '60'),
            'max_url_length' => (int)secscan_env('SECSCAN_MAX_URL_LENGTH', '2048'),
            // Reverse proxies / load balancers whose forwarded client-IP headers
            // may be trusted. Comma-separated list of IPs or CIDR ranges (v4/v6).
            // Empty = trust nothing (forwarded headers ignored; REMOTE_ADDR used).
            'trusted_proxies' => secscan_env('SECSCAN_TRUSTED_PROXIES', ''),
            // Set to "1" to additionally trust Cloudflare's published edge ranges.
            'trust_cloudflare' => secscan_env('SECSCAN_TRUST_CLOUDFLARE', '0'),
            // Public scanner identity shown to users so target owners can
            // allowlist this scanner in their WAF/firewall before scanning.
            'scanner_public_domain' => secscan_env('SECSCAN_SCANNER_PUBLIC_DOMAIN', ''),
            'scanner_public_ips' => secscan_env('SECSCAN_SCANNER_PUBLIC_IPS', ''),
            // Authenticated scanning: accept per-request session cookies / auth
            // headers so scans can run behind a login. OFF by default because a
            // public, unauthenticated API endpoint that forwards arbitrary
            // credentials to arbitrary hosts is an abuse vector — enable this
            // only on access-controlled deployments.
            'allow_auth_scan' => secscan_env('SECSCAN_ALLOW_AUTH_SCAN', '0') === '1',
        ];
    }

    if ($key === null) {
        return $config;
    }

    return $config[$key] ?? null;
}

/** Read a request body without permitting an unbounded PHP allocation. */
function secscan_read_request_body(?int $maxBytes = null): ?string
{
    $maxBytes = $maxBytes ?? (int)secscan_config('max_request_bytes');
    $contentLength = $_SERVER['CONTENT_LENGTH'] ?? '';
    if (is_string($contentLength) && ctype_digit($contentLength) && (int)$contentLength > $maxBytes) {
        return null;
    }

    $body = file_get_contents('php://input', false, null, 0, $maxBytes + 1);
    return is_string($body) && strlen($body) <= $maxBytes ? $body : null;
}

function secscan_scanner_identity(): array
{
    $configuredDomain = trim((string)secscan_config('scanner_public_domain'));
    $configuredIps = trim((string)secscan_config('scanner_public_ips'));
    $configured = $configuredDomain !== '' || $configuredIps !== '';

    $domain = $configuredDomain;
    if ($domain === '') {
        $domain = trim((string)($_SERVER['HTTP_HOST'] ?? ''));
        $domain = preg_replace('/:\d+$/', '', $domain) ?: '';
    }

    $ips = array_values(array_unique(array_filter(array_map(
        static fn($ip): string => trim((string)$ip),
        explode(',', (string)secscan_config('scanner_public_ips'))
    ))));
    if ($ips === []) {
        $serverAddr = trim((string)($_SERVER['SERVER_ADDR'] ?? ''));
        if (filter_var($serverAddr, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            $ips[] = $serverAddr;
        }
    }

    return [
        'configured' => $configured,
        'domain' => $domain,
        'ips' => $ips,
        'allowlist_text' => trim(implode(', ', array_filter([
            $domain,
            implode(', ', $ips),
        ]))),
    ];
}

/**
 * Best-effort client IP for rate limiting and analytics.
 *
 * SECURITY: Forwarded headers (CF-Connecting-IP, X-Real-IP, X-Forwarded-For) are
 * trivially spoofable by the client. They are ONLY honoured when the direct peer
 * (REMOTE_ADDR) is a configured trusted proxy; otherwise REMOTE_ADDR is used.
 * Trusting these headers unconditionally would let anyone forge an IP per request
 * to bypass per-IP rate limits or poison the dashboard's unique-IP counts.
 */
function secscan_client_ip(): string
{
    $remote = trim((string)($_SERVER['REMOTE_ADDR'] ?? ''));
    $fallback = filter_var($remote, FILTER_VALIDATE_IP) ? $remote : 'unknown';

    if (!secscan_is_trusted_proxy($remote)) {
        return $fallback;
    }

    foreach ([
        $_SERVER['HTTP_CF_CONNECTING_IP'] ?? '',
        $_SERVER['HTTP_X_REAL_IP'] ?? '',
        $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '',
    ] as $candidate) {
        $candidate = trim((string)$candidate);
        if ($candidate === '') {
            continue;
        }
        if (str_contains($candidate, ',')) {
            // X-Forwarded-For: the original client is the left-most entry.
            $candidate = trim(explode(',', $candidate)[0]);
        }
        if (filter_var($candidate, FILTER_VALIDATE_IP)) {
            return $candidate;
        }
    }

    return $fallback;
}

/**
 * Is the request's direct peer one of the configured trusted reverse proxies?
 * Reads SECSCAN_TRUSTED_PROXIES (comma-separated IPs/CIDRs) plus, when
 * SECSCAN_TRUST_CLOUDFLARE=1, Cloudflare's published edge ranges.
 */
function secscan_is_trusted_proxy(string $ip): bool
{
    if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }

    $ranges = array_filter(array_map('trim', explode(',', (string)secscan_config('trusted_proxies'))));

    if ((string)secscan_config('trust_cloudflare') === '1') {
        $ranges = array_merge($ranges, secscan_cloudflare_ranges());
    }

    foreach ($ranges as $range) {
        if (secscan_ip_in_cidr($ip, $range)) {
            return true;
        }
    }

    return false;
}

/**
 * True if $ip falls within $range. $range may be a bare IP (exact match) or a
 * CIDR block. Works for both IPv4 and IPv6 via binary prefix comparison.
 */
function secscan_ip_in_cidr(string $ip, string $range): bool
{
    $ip = trim($ip);
    $range = trim($range);
    if ($ip === '' || $range === '') {
        return false;
    }

    if (!str_contains($range, '/')) {
        return $ip === $range;
    }

    [$subnet, $maskLen] = explode('/', $range, 2);
    $maskLen = (int)$maskLen;

    $ipBin     = @inet_pton($ip);
    $subnetBin = @inet_pton(trim($subnet));
    if ($ipBin === false || $subnetBin === false) {
        return false;
    }
    // Address families must match (4 bytes for v4, 16 for v6).
    if (strlen($ipBin) !== strlen($subnetBin)) {
        return false;
    }

    $maxBits = strlen($ipBin) * 8;
    if ($maskLen < 0 || $maskLen > $maxBits) {
        return false;
    }

    $fullBytes = intdiv($maskLen, 8);
    $remBits   = $maskLen % 8;

    if ($fullBytes > 0 && strncmp($ipBin, $subnetBin, $fullBytes) !== 0) {
        return false;
    }
    if ($remBits === 0) {
        return true;
    }
    $mask = chr((0xFF << (8 - $remBits)) & 0xFF);
    return (ord($ipBin[$fullBytes]) & ord($mask)) === (ord($subnetBin[$fullBytes]) & ord($mask));
}

function secscan_ip_in_ranges(string $ip, string $ranges): bool
{
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }

    foreach (array_filter(array_map('trim', explode(',', $ranges))) as $range) {
        if (secscan_ip_in_cidr($ip, $range)) {
            return true;
        }
    }

    return false;
}

function secscan_is_owner_bypass_ip(string $ip): bool
{
    if (secscan_ip_in_ranges($ip, (string)secscan_config('owner_bypass_ips'))) {
        return true;
    }

    $entries = secscan_auto_owner_bypass_entries();
    return isset($entries[$ip]) && (int)$entries[$ip] >= time();
}

function secscan_owner_bypass_file(): string
{
    $dataDir = (string)secscan_config('data_dir');
    if ($dataDir === '') {
        return '';
    }
    if (!is_dir($dataDir) && !@mkdir($dataDir, 0750, true) && !is_dir($dataDir)) {
        return '';
    }
    if (!is_writable($dataDir)) {
        return '';
    }
    return rtrim($dataDir, '/\\') . '/owner_bypass_ips.json';
}

function secscan_auto_owner_bypass_entries(): array
{
    $file = secscan_owner_bypass_file();
    if ($file === '') {
        return [];
    }

    $fp = @fopen($file, 'c+');
    if (!$fp) {
        return [];
    }

    flock($fp, LOCK_EX);
    rewind($fp);
    $raw = stream_get_contents($fp);
    $entries = is_string($raw) && $raw !== '' ? (json_decode($raw, true) ?: []) : [];
    $now = time();
    $clean = [];
    foreach ($entries as $ip => $expires) {
        if (filter_var((string)$ip, FILTER_VALIDATE_IP) && (int)$expires >= $now) {
            $clean[(string)$ip] = (int)$expires;
        }
    }
    if ($clean !== $entries) {
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode($clean, JSON_UNESCAPED_SLASHES));
    }
    flock($fp, LOCK_UN);
    fclose($fp);

    return $clean;
}

function secscan_remember_owner_bypass_ip(string $ip, ?int $ttl = null): bool
{
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }
    $file = secscan_owner_bypass_file();
    if ($file === '') {
        return false;
    }

    $ttl = $ttl ?? (int)secscan_config('owner_bypass_ttl');
    $expires = time() + max(60, $ttl);

    $fp = @fopen($file, 'c+');
    if (!$fp) {
        return false;
    }

    flock($fp, LOCK_EX);
    rewind($fp);
    $raw = stream_get_contents($fp);
    $entries = is_string($raw) && $raw !== '' ? (json_decode($raw, true) ?: []) : [];
    $now = time();
    $clean = [];
    foreach ($entries as $entryIp => $entryExpires) {
        if (filter_var((string)$entryIp, FILTER_VALIDATE_IP) && (int)$entryExpires >= $now) {
            $clean[(string)$entryIp] = (int)$entryExpires;
        }
    }
    $clean[$ip] = $expires;
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($clean, JSON_UNESCAPED_SLASHES));
    flock($fp, LOCK_UN);
    fclose($fp);

    return true;
}

function secscan_forget_owner_bypass_ip(string $ip): void
{
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return;
    }
    $file = secscan_owner_bypass_file();
    if ($file === '' || !is_file($file)) {
        return;
    }

    $fp = @fopen($file, 'c+');
    if (!$fp) {
        return;
    }

    flock($fp, LOCK_EX);
    rewind($fp);
    $raw = stream_get_contents($fp);
    $entries = is_string($raw) && $raw !== '' ? (json_decode($raw, true) ?: []) : [];
    unset($entries[$ip]);
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($entries, JSON_UNESCAPED_SLASHES));
    flock($fp, LOCK_UN);
    fclose($fp);
}

/**
 * Cloudflare's published edge IP ranges. See https://www.cloudflare.com/ips/
 * Used only when SECSCAN_TRUST_CLOUDFLARE=1.
 */
function secscan_cloudflare_ranges(): array
{
    return [
        // IPv4
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        // IPv6
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
        '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
    ];
}

/**
 * Reliable HTTPS detection. Direct server signals (HTTPS, SERVER_PORT) are always
 * trusted; spoofable forwarded scheme headers only when behind a trusted proxy.
 */
function secscan_is_https(): bool
{
    if (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') {
        return true;
    }
    if ((string)($_SERVER['SERVER_PORT'] ?? '') === '443') {
        return true;
    }
    if (secscan_is_trusted_proxy(trim((string)($_SERVER['REMOTE_ADDR'] ?? '')))) {
        if (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https') {
            return true;
        }
        $cfVisitor = (string)($_SERVER['HTTP_CF_VISITOR'] ?? '');
        if ($cfVisitor !== '' && str_contains($cfVisitor, 'https')) {
            return true;
        }
    }
    return false;
}

function secscan_request_origin(): string
{
    $scheme = secscan_is_https() ? 'https' : 'http';
    $host = trim((string)($_SERVER['HTTP_HOST'] ?? 'security.apasaja.my'));
    $host = preg_replace('/[\r\n].*$/', '', $host) ?: 'security.apasaja.my';
    $host = preg_replace('/[^A-Za-z0-9.\-:\[\]]/', '', $host) ?: 'security.apasaja.my';

    return $scheme . '://' . $host;
}

function secscan_reporting_endpoint(): string
{
    $configured = trim((string)secscan_env('SECSCAN_REPORTING_ENDPOINT', ''));
    if ($configured !== '') {
        if (preg_match('#^https?://#i', $configured)) {
            return $configured;
        }
        if ($configured[0] === '/') {
            return secscan_request_origin() . $configured;
        }
    }

    return secscan_request_origin() . '/reporting.php';
}

function secscan_send_operational_security_headers(): void
{
    if (headers_sent()) {
        return;
    }

    $endpoint = secscan_reporting_endpoint();

    header('Origin-Agent-Cluster: ?1');
    header('Reporting-Endpoints: default=' . json_encode($endpoint, JSON_UNESCAPED_SLASHES));
    header('Report-To: ' . json_encode([
        'group' => 'default',
        'max_age' => 86400,
        'endpoints' => [
            ['url' => $endpoint],
        ],
        'include_subdomains' => true,
    ], JSON_UNESCAPED_SLASHES));
    header('NEL: ' . json_encode([
        'report_to' => 'default',
        'max_age' => 86400,
        'include_subdomains' => true,
    ], JSON_UNESCAPED_SLASHES));
}
