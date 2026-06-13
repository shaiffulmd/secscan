<?php

/**
 * Central SecScan configuration.
 *
 * Environment variables override these defaults. For production, set at least:
 * SECSCAN_DASHBOARD_PASSWORD_HASH and SECSCAN_IP_HASH_SALT.
 */
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
        ];
    }

    if ($key === null) {
        return $config;
    }

    return $config[$key] ?? null;
}

function secscan_client_ip(): string
{
    foreach ([
        $_SERVER['HTTP_CF_CONNECTING_IP'] ?? '',
        $_SERVER['HTTP_X_REAL_IP'] ?? '',
        $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '',
        $_SERVER['REMOTE_ADDR'] ?? '',
    ] as $candidate) {
        $candidate = trim((string)$candidate);
        if ($candidate === '') {
            continue;
        }
        if (str_contains($candidate, ',')) {
            $candidate = trim(explode(',', $candidate)[0]);
        }
        if (filter_var($candidate, FILTER_VALIDATE_IP)) {
            return $candidate;
        }
    }

    return 'unknown';
}
