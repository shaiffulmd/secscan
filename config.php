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
            'api_rate_limit' => (int)secscan_env('SECSCAN_API_RATE_LIMIT', '5'),
            'api_rate_window' => (int)secscan_env('SECSCAN_API_RATE_WINDOW', '60'),
            'max_url_length' => (int)secscan_env('SECSCAN_MAX_URL_LENGTH', '2048'),
            // Reverse proxies / load balancers whose forwarded client-IP headers
            // may be trusted. Comma-separated list of IPs or CIDR ranges (v4/v6).
            // Empty = trust nothing (forwarded headers ignored; REMOTE_ADDR used).
            'trusted_proxies' => secscan_env('SECSCAN_TRUSTED_PROXIES', ''),
            // Set to "1" to additionally trust Cloudflare's published edge ranges.
            'trust_cloudflare' => secscan_env('SECSCAN_TRUST_CLOUDFLARE', '0'),
        ];
    }

    if ($key === null) {
        return $config;
    }

    return $config[$key] ?? null;
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
