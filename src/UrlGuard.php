<?php

class UrlGuard
{
    private const BLOCKED_IP_RANGES = [
        // IPv4 special-use ranges not consistently covered by PHP's filters.
        '0.0.0.0/8',
        '10.0.0.0/8',
        '100.64.0.0/10',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '172.16.0.0/12',
        '192.0.0.0/24',
        '192.0.2.0/24',
        '192.88.99.0/24',
        '192.168.0.0/16',
        '198.18.0.0/15',
        '198.51.100.0/24',
        '203.0.113.0/24',
        '224.0.0.0/4',
        '240.0.0.0/4',
        '255.255.255.255/32',
        // IPv6 loopback, link-local, unique-local, multicast, documentation, and transition ranges.
        '::/128',
        '::1/128',
        '::ffff:0:0/96',
        '64:ff9b::/96',
        '100::/64',
        '2001::/23',
        '2001:db8::/32',
        '2002::/16',
        'fc00::/7',
        'fe80::/10',
        'ff00::/8',
    ];

    public static function normalizeAndValidate(string $input): array
    {
        $url = trim($input);
        if ($url === '') {
            return self::error('URL diperlukan.', 400);
        }

        if (strlen($url) > (int)secscan_config('max_url_length')) {
            return self::error('URL terlalu panjang. Maksimum 2048 aksara.', 400);
        }

        if (!preg_match('#^https?://#i', $url)) {
            $url = 'https://' . $url;
        }

        $parsed = parse_url($url);
        if (!$parsed || empty($parsed['host'])) {
            return self::error('URL tidak sah.', 400);
        }

        $scheme = strtolower((string)($parsed['scheme'] ?? ''));
        if (!in_array($scheme, ['http', 'https'], true)) {
            return self::error('Hanya URL http/https dibenarkan.', 400);
        }

        if (isset($parsed['user']) || isset($parsed['pass'])) {
            return self::error('URL tidak boleh mengandungi username atau password.', 400);
        }

        $host = (string)$parsed['host'];
        if ($host === '' || strlen($host) > 253) {
            return self::error('Hostname tidak sah.', 400);
        }

        $hostForLookup = trim($host, '[]');
        $public = self::publicResolution($hostForLookup);
        if (!$public['allowed']) {
            return self::error($public['error'], 403);
        }

        return [
            'ok' => true,
            'url' => $url,
            'scheme' => $scheme,
            'host' => $host,
            'hostname' => $hostForLookup,
            'ipv4' => $public['ipv4'],
            'ipv6' => $public['ipv6'],
        ];
    }

    public static function isPublicUrl(string $url): bool
    {
        $parsed = parse_url($url);
        if (!$parsed || empty($parsed['host'])) {
            return false;
        }

        $scheme = strtolower((string)($parsed['scheme'] ?? ''));
        if (!in_array($scheme, ['http', 'https'], true)) {
            return false;
        }

        return self::publicResolution(trim((string)$parsed['host'], '[]'))['allowed'];
    }

    public static function isPublicHost(string $host): bool
    {
        return self::publicResolution(trim($host, '[]'))['allowed'];
    }

    private static function publicResolution(string $host): array
    {
        if (self::isBlockedHostname($host)) {
            return self::blockedResult('IP private/reserved tidak dibenarkan.');
        }

        $ipv4 = [];
        $ipv6 = [];

        if (filter_var($host, FILTER_VALIDATE_IP)) {
            if (!self::isPublicIp($host)) {
                return self::blockedResult('IP private/reserved tidak dibenarkan.');
            }

            if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $ipv6[] = $host;
            } else {
                $ipv4[] = $host;
            }

            return ['allowed' => true, 'error' => '', 'ipv4' => $ipv4, 'ipv6' => $ipv6];
        }

        if (!preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])\.?$/i', $host)) {
            return self::blockedResult('Hostname tidak sah.');
        }

        $records = @dns_get_record(rtrim($host, '.'), DNS_A + DNS_AAAA) ?: [];
        foreach ($records as $record) {
            $ip = $record['ip'] ?? $record['ipv6'] ?? '';
            if ($ip === '') {
                continue;
            }
            if (!self::isPublicIp($ip)) {
                return self::blockedResult('Domain resolve kepada IP private/reserved. Scan tidak dibenarkan.');
            }
            if (!empty($record['ip'])) {
                $ipv4[] = $record['ip'];
            }
            if (!empty($record['ipv6'])) {
                $ipv6[] = $record['ipv6'];
            }
        }

        if (empty($ipv4) && empty($ipv6)) {
            return self::blockedResult('Domain tidak mempunyai rekod A/AAAA public. Scan tidak dibenarkan.');
        }

        return [
            'allowed' => true,
            'error' => '',
            'ipv4' => array_values(array_unique($ipv4)),
            'ipv6' => array_values(array_unique($ipv6)),
        ];
    }

    public static function isPublicIp(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return false;
        }

        foreach (self::BLOCKED_IP_RANGES as $range) {
            if (self::ipInCidr($ip, $range)) {
                return false;
            }
        }

        return true;
    }

    private static function ipInCidr(string $ip, string $range): bool
    {
        [$subnet, $maskLen] = explode('/', $range, 2);
        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);
        if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }

        $maskLen = (int)$maskLen;
        $maxBits = strlen($ipBin) * 8;
        if ($maskLen < 0 || $maskLen > $maxBits) {
            return false;
        }

        $fullBytes = intdiv($maskLen, 8);
        $remainingBits = $maskLen % 8;

        if ($fullBytes > 0 && strncmp($ipBin, $subnetBin, $fullBytes) !== 0) {
            return false;
        }
        if ($remainingBits === 0) {
            return true;
        }

        $mask = chr((0xFF << (8 - $remainingBits)) & 0xFF);
        return (ord($ipBin[$fullBytes]) & ord($mask)) === (ord($subnetBin[$fullBytes]) & ord($mask));
    }

    private static function isBlockedHostname(string $host): bool
    {
        $host = strtolower(rtrim($host, '.'));
        if (in_array($host, ['localhost', 'localhost.localdomain'], true)) {
            return true;
        }

        return (bool)preg_match('/\.(localhost|local|internal|lan|home|corp)$/i', $host);
    }

    private static function blockedResult(string $error): array
    {
        return ['allowed' => false, 'error' => $error, 'ipv4' => [], 'ipv6' => []];
    }

    private static function error(string $message, int $status): array
    {
        return ['ok' => false, 'error' => $message, 'status' => $status];
    }
}
