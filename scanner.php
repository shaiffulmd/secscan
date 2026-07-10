<?php

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/src/UrlGuard.php';
require_once __DIR__ . '/src/JoomlaFingerprint.php';

class SecurityFinding
{
    public string $category;
    public string $check;
    public string $severity;
    public string $message;
    public string $recommendation;
    /** @var string[] Documentation/standard references (OWASP, MDN, RFC, …). */
    public array $references;
    public bool $scoreable;

    public function __construct(string $category, string $check, string $severity, string $message, string $recommendation = '', array $references = [], bool $scoreable = true)
    {
        $this->category = $category;
        $this->check = $check;
        $this->severity = $severity;
        $this->message = $message;
        $this->recommendation = $recommendation;
        $this->references = $references;
        $this->scoreable = $scoreable;
    }
}

class SecurityScanner
{
    private string $url;
    private string $hostname;
    private string $scheme;
    private int $port;
    private array $findings = [];
    private array $responseHeaders = [];
    private string $responseBody = '';
    private array $cookies = [];
    private array $primaryResponseHeaders = [];
    private string $primaryResponseBody = '';
    private array $primaryCookies = [];
    private int $httpCode = 0;
    private float $scanStart;
    private array $resolvedIpv4 = [];
    private array $resolvedIpv6 = [];

    // Memoised DNS results, keyed by "name|type" — see dnsQuery().
    private array $dnsCache = [];

    // Soft-404 / catch-all baseline — populated by getBaseline() on first use.
    private array $baselineProbe = ['done' => false, 'catchall' => false, 'samples' => []];

    // Negotiated TLS metadata captured once in checkTLS() and reused by
    // later checks to avoid TLS 1.3 / CDN false positives.
    private string $negotiatedTlsProtocol = '';
    private string $negotiatedCipherName = '';
    private int $negotiatedCipherBits = 0;
    private string $negotiatedCipherVersion = '';

    // Set by checkCMSDetection() and consumed by checkCMSVulnerabilities()
    // to look up published CVEs for the detected platform.
    private string $detectedCms = '';
    private string $detectedCmsVersion = '';
    private array $detectedCmsSignals = [];
    private array $scanBlocked = [];
    private array $detectedWafVendors = [];
    private array $detectedWafSignals = [];

    // Weighted score from the passive Joomla fingerprint layer. Drives the
    // active safety-net probe: a hardened Joomla site can score 0 passively,
    // so probeJoomlaEndpoints() confirms it via Joomla-only endpoints.
    private int $joomlaPassiveScore = 0;

    // Installed WordPress plugins fingerprinted from the target:
    //   slug => ['version' => ?string, 'confirmed' => bool]
    private array $installedPlugins = [];

    // Installed Joomla extensions fingerprinted from front-end asset paths:
    //   slug (e.g. "com_sppagebuilder") => normalised token used for matching
    private array $installedExtensions = [];

    // Optional authenticated-scan credentials, applied ONLY to same-host target
    // requests (never across a redirect to a different host) so session tokens
    // cannot leak cross-origin. Populated via setAuth(); empty by default.
    private array $authHeaders = [];   // ['Authorization: Bearer …', 'X-Api-Key: …']
    private string $authCookie = '';    // raw Cookie header value, e.g. 'sid=abc; csrf=xyz'
    private bool $authEnabled = false;
    private string $authOrigin = '';

    private const WEAK_CIPHERS = [
        'RC4', 'DES-CBC', '3DES', 'DES-CBC3', 'NULL',
        'EXPORT', 'anon', 'ADH', 'AECDH', 'MD5',
        'SEED', 'IDEA', 'CAMELLIA'
    ];

    private const STRONG_KEY_EXCHANGES = ['ECDHE', 'DHE', 'X25519', 'X448', 'CECPQ'];
    private const STRONG_AEAD_CIPHERS  = ['GCM', 'CHACHA20', 'POLY1305', 'CCM'];
    private const PFS_CIPHERS          = ['ECDHE', 'DHE', 'ECDH'];
    private const TARGET_USER_AGENT    = 'Mozilla/5.0 (compatible; SecScan/2.0; +https://security.apasaja.my)';

    public function __construct(string $url)
    {
        if (!preg_match('#^https?://#i', $url)) $url = 'https://' . $url;
        $url = rtrim($url, '/');
        $this->url = $url;

        $parsed = parse_url($url);
        $this->hostname  = $parsed['host'] ?? '';
        $this->scheme    = $parsed['scheme'] ?? 'https';
        $this->port      = (int)($parsed['port'] ?? ($this->scheme === 'https' ? 443 : 80));
        $this->scanStart = microtime(true);

        try {
            $ipv4 = @dns_get_record($this->hostname, DNS_A) ?: [];
            foreach ($ipv4 as $r) { if (isset($r['ip'])) $this->resolvedIpv4[] = $r['ip']; }
            $ipv6 = @dns_get_record($this->hostname, DNS_AAAA) ?: [];
            foreach ($ipv6 as $r) { if (isset($r['ipv6'])) $this->resolvedIpv6[] = $r['ipv6']; }
        } catch (Throwable $e) {
            error_log("[SecScan] DNS resolution failed for {$this->hostname}: " . $e->getMessage());
        }
    }

    private function addFinding(string $category, string $check, string $severity, string $message, string $recommendation = '', array $references = [], bool $scoreable = true): void
    {
        // Auto-attach standard references when the caller didn't supply any.
        if (empty($references)) {
            $references = $this->referencesFor($category, $check);
        }
        $this->findings[] = new SecurityFinding($category, $check, $severity, $message, $recommendation, $references, $scoreable);
    }

    /**
     * Supply credentials so checks can scan behind a login (authenticated scan).
     *
     * $headers accepts either a list of "Name: value" strings or a name=>value
     * map. Only a safe subset is honoured (Authorization, Cookie, and any X-*
     * header); everything else is dropped. CR/LF is stripped to prevent header
     * injection. Any 'Cookie' header is merged into the cookie jar. These
     * credentials are sent ONLY to the original target host — withAuth()
     * checks each request URL so tokens never leak after a cross-host redirect.
     *
     * @param array<int|string,string> $headers
     */
    public function setAuth(array $headers = [], string $cookie = ''): void
    {
        $safe        = [];
        $cookieParts = [];
        $rawCookie   = trim($cookie);
        if ($rawCookie !== '') $cookieParts[] = $rawCookie;

        foreach ($headers as $k => $v) {
            if (is_int($k)) {
                $line = trim((string)$v);
                if ($line === '' || strpos($line, ':') === false) continue;
                [$name, $val] = explode(':', $line, 2);
            } else {
                $name = (string)$k;
                $val  = (string)$v;
            }
            $name = preg_replace('/[\r\n]/', '', trim($name));
            $val  = preg_replace('/[\r\n]/', '', trim($val));
            if ($name === '' || $val === '') continue;
            if (!$this->isAllowedAuthHeader($name)) continue;

            if (strcasecmp($name, 'Cookie') === 0) {
                $cookieParts[] = $val;
                continue;
            }
            $safe[] = "{$name}: {$val}";
        }

        $this->authHeaders = $safe;
        $this->authCookie  = implode('; ', $cookieParts);
        $this->authEnabled = !empty($this->authHeaders) || $this->authCookie !== '';
        $this->authOrigin = $this->originForUrl(isset($this->url) ? $this->url : '');
        // Supports isolated unit tests that instantiate without the constructor.
        if ($this->authOrigin === '' && isset($this->hostname)) {
            $scheme = isset($this->scheme) ? $this->scheme : 'https';
            $port = isset($this->port) ? $this->port : (strtolower($scheme) === 'https' ? 443 : 80);
            $this->authOrigin = $this->formatOrigin($scheme, $this->hostname, $port);
        }
    }

    /** Allow-list of request headers that are meaningful for an authenticated scan. */
    private function isAllowedAuthHeader(string $name): bool
    {
        $n = strtolower($name);
        if ($n === 'authorization' || $n === 'cookie') return true;
        return str_starts_with($n, 'x-'); // API keys, CSRF tokens, tenant IDs, …
    }

    public function isAuthenticated(): bool
    {
        return $this->authEnabled;
    }

    /**
     * Merge authenticated-scan credentials into a cURL option array. Callers
     * wrap their per-request option array with this so every same-origin target
     * request carries the session. Preserves any CURLOPT_HTTPHEADER the caller
     * already set (e.g. Origin/Content-Type probes).
     */
    private function withAuth(array $opts): array
    {
        if (!$this->authEnabled) return $opts;
        if (!$this->authRequestMatchesOrigin($opts)) return $opts;
        // Session credentials must never travel over plaintext HTTP or a TLS
        // connection whose certificate is not verified. This intentionally
        // overrides permissive probe defaults used for anonymous scans.
        $scheme = strtolower((string)parse_url((string)$opts[CURLOPT_URL], PHP_URL_SCHEME));
        if ($scheme !== 'https') return $opts;
        $opts[CURLOPT_SSL_VERIFYPEER] = true;
        $opts[CURLOPT_SSL_VERIFYHOST] = 2;
        if ($this->authCookie !== '') {
            $opts[CURLOPT_COOKIE] = $this->authCookie;
        }
        if (!empty($this->authHeaders)) {
            $existing = $opts[CURLOPT_HTTPHEADER] ?? [];
            $opts[CURLOPT_HTTPHEADER] = array_merge($existing, $this->authHeaders);
        }
        return $opts;
    }

    private function authRequestMatchesOrigin(array $opts): bool
    {
        $url = (string)($opts[CURLOPT_URL] ?? '');
        return $url !== '' && $this->authOrigin !== ''
            && hash_equals($this->authOrigin, $this->originForUrl($url));
    }

    /**
     * Memoised DNS lookups. Several checks (SPF, DMARC, CAA, MTA-STS, BIMI,
     * subdomain-takeover) hit the resolver for the same names; caching avoids
     * redundant network round-trips and speeds up the overall scan.
     */
    private function dnsQuery(string $name, int $type): array
    {
        $key = $name . '|' . $type;
        if (array_key_exists($key, $this->dnsCache)) {
            return $this->dnsCache[$key];
        }
        $records = @dns_get_record($name, $type) ?: [];
        return $this->dnsCache[$key] = $records;
    }

    /**
     * PHP 8.5 deprecates curl_close() for CurlHandle objects because the call
     * has had no effect since PHP 8.0. Keep compatibility with old PHP 7.x
     * resource handles without producing deprecation noise on PHP 8+.
     */
    private function closeCurl($ch): void
    {
        if (PHP_VERSION_ID < 80000 && is_resource($ch)) {
            curl_close($ch);
        }
    }

    // ================================================================
    //  SSRF HARDENING — pin connections to validated public IPs
    // ================================================================
    //
    // UrlGuard validates that the hostname resolves to a public IP *before* the
    // scan. Without pinning, every cURL/socket call below re-resolves the name,
    // so an attacker controlling DNS (low-TTL "rebinding") could return a public
    // IP at validation time and a private/loopback/cloud-metadata IP at fetch
    // time (classic TOCTOU SSRF). We resolve once and force all outbound
    // connections to the validated public IP(s).

    private ?array $pinnedIps = null;

    /** Validated public IPs for the target hostname (IPv4 preferred first). */
    private function pinnedIps(): array
    {
        if ($this->pinnedIps !== null) {
            return $this->pinnedIps;
        }

        $ips = [];
        foreach (array_merge($this->resolvedIpv4, $this->resolvedIpv6) as $ip) {
            if (UrlGuard::isPublicIp($ip)) {
                $ips[] = $ip;
            }
        }

        // Literal-IP targets: already validated upstream as public.
        if (!$ips && filter_var($this->hostname, FILTER_VALIDATE_IP) && UrlGuard::isPublicIp($this->hostname)) {
            $ips[] = $this->hostname;
        }

        return $this->pinnedIps = array_values(array_unique($ips));
    }

    /**
     * CURLOPT_RESOLVE entries locking the hostname to its validated public IP(s)
     * on every port this scanner touches. Empty array = no override (host is a
     * literal IP, or local resolution failed and UrlGuard remains the gate).
     */
    private function pinResolve(): array
    {
        return $this->pinResolveForHost(
            $this->hostname,
            $this->port,
            $this->resolvedIpv4,
            $this->resolvedIpv6,
            [80, 443]
        );
    }

    private function pinResolveForHost(string $host, int $port, array $ipv4, array $ipv6, array $extraPorts = []): array
    {
        $host = trim($host, '[]');
        if ($host === '' || filter_var($host, FILTER_VALIDATE_IP)) {
            return [];
        }

        $ips = [];
        foreach (array_merge($ipv4, $ipv6) as $ip) {
            if (is_string($ip) && UrlGuard::isPublicIp($ip)) {
                $ips[] = $ip;
            }
        }
        $ips = array_values(array_unique($ips));
        if (!$ips) {
            return [];
        }

        $joined = implode(',', $ips);
        $out = [];
        foreach (array_unique(array_map('intval', array_merge([$port], $extraPorts))) as $p) {
            if ($p > 0 && $p <= 65535) {
                $out[] = "{$host}:{$p}:{$joined}";
            }
        }
        return $out;
    }

    private function portForUrl(string $url, string $scheme): int
    {
        $port = parse_url($url, PHP_URL_PORT);
        if (is_int($port) && $port > 0 && $port <= 65535) {
            return $port;
        }
        return strtolower($scheme) === 'https' ? 443 : 80;
    }

    /** Canonical scheme/host/effective-port tuple used for auth and probes. */
    private function originForUrl(string $url): string
    {
        $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));
        $host = (string)parse_url($url, PHP_URL_HOST);
        if ($scheme === '' || $host === '' || !in_array($scheme, ['http', 'https'], true)) {
            return '';
        }
        return $this->formatOrigin($scheme, $host, $this->portForUrl($url, $scheme));
    }

    private function formatOrigin(string $scheme, string $host, int $port): string
    {
        $host = strtolower(trim($host, '[]'));
        if ($host === '' || $port < 1 || $port > 65535) return '';
        $authority = str_contains($host, ':') ? '[' . $host . ']' : $host;
        return strtolower($scheme) . '://' . $authority . ':' . $port;
    }

    /** Base URL for target-relative probes; preserves a non-default port. */
    private function originBase(): string
    {
        return $this->formatOrigin($this->scheme, $this->hostname, $this->port);
    }

    private function applyValidatedTarget(string $url, array $target): void
    {
        $this->url = rtrim($url, '/');
        $this->scheme = (string)($target['scheme'] ?? $this->scheme);
        $this->hostname = (string)($target['hostname'] ?? $this->hostname);
        $this->port = $this->portForUrl($url, $this->scheme);
        $this->resolvedIpv4 = array_values(array_unique($target['ipv4'] ?? []));
        $this->resolvedIpv6 = array_values(array_unique($target['ipv6'] ?? []));
        $this->pinnedIps = null;
        $this->dnsCache = [];
        $this->baselineProbe = ['done' => false, 'catchall' => false, 'samples' => []];
    }

    /**
     * Host token for raw socket transport strings. Prefers the validated public
     * IP so stream_socket_client() cannot be rebound; SNI and certificate
     * verification still use $this->hostname via the context's peer_name option.
     */
    private function connectHost(): string
    {
        $ips = $this->pinnedIps();
        if (!$ips) {
            return $this->hostname;
        }
        $ip = $ips[0];
        return str_contains($ip, ':') ? '[' . $ip . ']' : $ip; // bracket IPv6 literals
    }

    /** Belt-and-suspenders: true if cURL actually connected to a non-public IP. */
    private function curlHitPrivateIp($ch): bool
    {
        $ip = (string)curl_getinfo($ch, CURLINFO_PRIMARY_IP);
        return $ip !== '' && !UrlGuard::isPublicIp($ip);
    }

    // ================================================================
    //  MAIN SCAN ENTRY
    // ================================================================

    public function scan(): array
    {
        if (empty($this->hostname)) {
            $this->addFinding('Connection', 'URL Parsing', 'critical', 'Could not parse the provided URL.');
            return $this->buildResult();
        }

        if (!UrlGuard::isPublicHost($this->hostname)) {
            $this->addFinding(
                'Connection',
                'Target Safety',
                'critical',
                'Refused to scan a private, reserved, or local network target.',
                'Use a public hostname or IP address.'
            );
            return $this->buildResult();
        }

        if (!$this->fetchUrl()) return $this->buildResult();

        // Run each check independently — one failure won't abort the entire scan
        $checks = [
            'checkCSP', 'checkHSTS', 'checkXContentType', 'checkXFrameOptions',
            'checkReferrerPolicy', 'checkPermissionsPolicy', 'checkXXSSProtection',
            'checkCacheControl', 'checkCrossOriginHeaders',
            'checkServerLeakage',
            'checkHTTPMethods',
            'checkCookies',
            'checkHTTPSRedirect',
            'checkTLS', 'checkDeprecatedProtocols', 'checkCipherStrength',
            'checkECDHESupport', 'checkPerfectForwardSecrecy', 'checkCertificateChain',
            'checkCORS', 'checkCORSReflection', 'checkCrossDomainPolicy',
            'checkMixedContent', 'checkSRI', 'checkInsecureForms', 'checkMetaCSP',
            'checkClientSideDependencies',
            'checkCsrfProtection',
            'checkExposedSecrets',
            'checkHTTPVersions',
            'checkDNSSecurity',
            'checkEmailAuthHardening',
            'checkZoneTransfer',
            'checkApiGraphQL',
            'checkCMSDetection',
            'checkCMSVulnerabilities',
            'checkCmsHardening',
            'checkWAF',
            'checkOutdatedSoftware',
            'checkSubdomainTakeover',
            'checkExposedFiles',
            'checkDirectoryListing',
            'checkSecurityTxt', 'checkRobotsTxt',
            'checkOpenPorts',
            'checkAdminEndpoints',
            'checkCAA',
            'checkMTASTS',
            'checkBIMI',
            'checkModernHeaders',
        ];

        foreach ($checks as $method) {
            try {
                $this->$method();
            } catch (Throwable $e) {
                // Log which check failed and why — check error_log for details
                error_log("[SecScan] {$method} failed for {$this->hostname}: " . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
                // Add a graceful finding so the scan still returns useful results
                $category = match(true) {
                    str_contains($method, 'TLS') || str_contains($method, 'Cipher') || str_contains($method, 'Protocol') || str_contains($method, 'Certificate') || str_contains($method, 'PFS') || str_contains($method, 'ECDHE') => 'TLS/SSL',
                    str_contains($method, 'DNS') || str_contains($method, 'DNSSEC') => 'DNS',
                    str_contains($method, 'Port') => 'Ports',
                    str_contains($method, 'CMS') || str_contains($method, 'Tech') || str_contains($method, 'Software') || str_contains($method, 'WAF') => 'Technology',
                    str_contains($method, 'Subdomain') => 'DNS',
                    str_contains($method, 'Method') => 'Headers',
                    str_contains($method, 'Secret') => 'Information Leakage',
                    str_contains($method, 'Csrf') => 'HTML',
                    str_contains($method, 'Email') || str_contains($method, 'GraphQL') => str_contains($method, 'GraphQL') ? 'API' : 'DNS',
                    str_contains($method, 'File') || str_contains($method, 'Admin') => 'Exposed Files',
                    str_contains($method, 'Robots') || str_contains($method, 'Security') => 'Security',
                    str_contains($method, 'CAA') || str_contains($method, 'MTA') || str_contains($method, 'BIMI') => 'DNS',
                    str_contains($method, 'Modern') => 'Headers',
                    default => 'Checks',
                };
                $this->addFinding($category, $method, 'info',
                    "Check could not complete: " . $e->getMessage(),
                    'See server error_log for details.');
            }
        }

        return $this->buildResult();
    }

    // ================================================================
    //  HTTP FETCH
    // ================================================================

    private function fetchUrl(): bool
    {
        $currentUrl = $this->url;
        $maxRedirects = 5;

        for ($redirects = 0; $redirects <= $maxRedirects; $redirects++) {
            $target = UrlGuard::normalizeAndValidate($currentUrl);
            if (!($target['ok'] ?? false)) {
                $this->addFinding(
                    'Connection',
                    'Redirect Safety',
                    'critical',
                    'Refused to follow an unsafe redirect target: ' . ($target['error'] ?? 'invalid URL') . '.',
                    'Ensure redirects only point to public http/https URLs.'
                );
                return false;
            }

            $currentUrl = (string)$target['url'];
            $currentPort = $this->portForUrl($currentUrl, (string)$target['scheme']);
            $ch = curl_init();
            $headers = [];

            $opts = [
                CURLOPT_URL            => $currentUrl,
                CURLOPT_RESOLVE        => $this->pinResolveForHost(
                    (string)$target['hostname'],
                    $currentPort,
                    $target['ipv4'] ?? [],
                    $target['ipv6'] ?? [],
                    [80, 443]
                ),
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_TIMEOUT        => 20,
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_USERAGENT      => self::TARGET_USER_AGENT,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_1_1,
                CURLOPT_ENCODING       => '',
                CURLOPT_HEADERFUNCTION => function ($ch, $header) use (&$headers) {
                    $len = strlen($header);
                    $parts = explode(':', $header, 2);
                    if (count($parts) === 2) {
                        $name  = strtolower(trim($parts[0]));
                        $value = trim($parts[1]);
                        $headers[$name][] = $value;
                    }
                    if (stripos($header, 'Set-Cookie:') === 0) {
                        $this->cookies[] = trim(substr($header, 11));
                    }
                    return $len;
                },
            ];

            // Only attach authenticated-scan credentials when the current hop is
            // still the original target host — never leak them across a redirect
            // to a different host.
            if (strcasecmp((string)($target['hostname'] ?? ''), $this->hostname) === 0) {
                $opts = $this->withAuth($opts);
            }
            curl_setopt_array($ch, $opts);

            $body           = curl_exec($ch);
            $this->httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $error          = curl_error($ch);
            $errno          = curl_errno($ch);
            $hitPrivate     = $this->curlHitPrivateIp($ch);
            $this->closeCurl($ch);

            // DNS-rebinding guard: refuse if the connection landed on a non-public IP.
            if ($hitPrivate) {
                $this->addFinding(
                    'Connection',
                    'Target Safety',
                    'critical',
                    'Refused: the host resolved to a private, reserved, or local IP at connection time (possible DNS rebinding).',
                    'Only public hosts may be scanned.'
                );
                return false;
            }

            if ($body === false || $this->httpCode === 0) {
                $msg = $error ?: "cURL error #{$errno}";
                $recommendation = 'Verify the URL is correct and the server is running.';
                $this->applyWafOverride('reachability_failure', $msg);
                if (
                    $errno === 60
                    || stripos($msg, 'SSL certificate') !== false
                    || stripos($msg, 'unable to get local issuer certificate') !== false
                    || stripos($msg, 'unable to verify the first certificate') !== false
                ) {
                    $recommendation = 'Server is reachable, but the TLS certificate chain is incomplete or untrusted. Install the missing intermediate CA certificate on the web server, then scan again.';
                }
                $this->addFinding('Connection', 'Reachability', 'critical',
                    "Could not connect to {$currentUrl}: {$msg}",
                    $recommendation);
                $this->capturePassiveCmsAfterFetchFailure($currentUrl, $target, $msg);
                return false;
            }

            $location = $headers['location'][0] ?? null;
            if ($this->httpCode >= 300 && $this->httpCode < 400 && $location) {
                $nextUrl = $this->absoluteUrl($currentUrl, $location);
                if ($nextUrl === null) {
                    $this->addFinding('Connection', 'Redirect Safety', 'critical',
                        "Refused invalid redirect location: {$location}",
                        'Return an absolute or valid relative http/https redirect.');
                    return false;
                }
                $currentUrl = $nextUrl;
                continue;
            }

            $this->applyValidatedTarget($currentUrl, $target);
            $this->responseHeaders = $headers;
            $this->responseBody    = (string)$body;
            $this->primaryResponseHeaders = $headers;
            $this->primaryResponseBody = (string)$body;
            $this->primaryCookies = $this->cookies;
            $this->addFinding('Connection', 'Reachability', 'pass', "Successfully connected — HTTP {$this->httpCode}.");
            return true;
        }

        $this->addFinding('Connection', 'Redirect Limit', 'warning',
            "Too many redirects while fetching {$this->url}.",
            'Reduce redirect chains to five or fewer hops.');
        return false;
    }

    private function absoluteUrl(string $baseUrl, string $location): ?string
    {
        $location = trim($location);
        if ($location === '') {
            return null;
        }

        if (preg_match('#^https?://#i', $location)) {
            return $location;
        }

        if (str_starts_with($location, '//')) {
            $scheme = parse_url($baseUrl, PHP_URL_SCHEME) ?: 'https';
            return $scheme . ':' . $location;
        }

        $base = parse_url($baseUrl);
        if (!$base || empty($base['scheme']) || empty($base['host'])) {
            return null;
        }

        $origin = $base['scheme'] . '://' . $base['host'] . (isset($base['port']) ? ':' . $base['port'] : '');
        if (str_starts_with($location, '/')) {
            return $origin . $location;
        }

        $path = $base['path'] ?? '/';
        $dir = preg_replace('#/[^/]*$#', '/', $path) ?: '/';
        return $origin . $dir . $location;
    }

    private function getHeader(string $name): ?string
    {
        return $this->responseHeaders[strtolower($name)][0] ?? null;
    }

    private function getAllHeaders(string $name): array
    {
        return $this->responseHeaders[strtolower($name)] ?? [];
    }


    private function isCloudflareEdge(): bool
    {
        $server = strtolower($this->getHeader('server') ?? '');
        return $server === 'cloudflare'
            || $this->getHeader('cf-ray') !== null
            || $this->getHeader('cf-cache-status') !== null
            || $this->getHeader('cf-request-id') !== null;
    }

    private function hasNegotiatedTls13(): bool
    {
        return stripos($this->negotiatedTlsProtocol, 'TLSv1.3') !== false
            || stripos($this->negotiatedCipherVersion, 'TLSv1.3') !== false
            || str_starts_with(strtoupper($this->negotiatedCipherName), 'TLS_');
    }

    private function isTls13Cipher(string $cipherName, string $version = ''): bool
    {
        return str_starts_with(strtoupper($cipherName), 'TLS_')
            || stripos($version, 'TLSv1.3') !== false
            || stripos($this->negotiatedTlsProtocol, 'TLSv1.3') !== false;
    }

    // ================================================================
    //  1. HTTP SECURITY HEADERS
    // ================================================================

    private function checkCSP(): void
    {
        $csp = $this->getHeader('Content-Security-Policy');
        if (!$csp) {
            $ro = $this->getHeader('Content-Security-Policy-Report-Only');
            if ($ro) {
                $this->addFinding('Headers', 'Content-Security-Policy', 'warning',
                    'Only a CSP Report-Only header is present — the policy is not enforced.',
                    'Move the policy to the enforcing Content-Security-Policy header once validated.');
            } else {
                $this->addFinding('Headers', 'Content-Security-Policy', 'critical',
                    'Content-Security-Policy header is missing entirely.',
                    "Implement a CSP. Example: default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; upgrade-insecure-requests;");
            }
            return;
        }

        $issues = [];

        // A nonce, hash, or 'strict-dynamic' source causes CSP2+ browsers to
        // IGNORE 'unsafe-inline' for scripts — it only remains as a fallback for
        // ancient browsers. Flagging it in that case is a false positive, so we
        // only warn about 'unsafe-inline' when nothing neutralises it.
        $hasNonceOrHash = (bool) preg_match("/'(nonce-[^']+|sha(?:256|384|512)-[^']+)'/i", $csp);
        $hasStrictDynamic = strpos($csp, "'strict-dynamic'") !== false;
        if (strpos($csp, "'unsafe-inline'") !== false) {
            if ($hasNonceOrHash || $hasStrictDynamic) {
                // Neutralised — note it as advisory rather than a scored issue.
                $this->addFinding('Headers', 'CSP unsafe-inline Fallback', 'info',
                    "CSP lists 'unsafe-inline' but a " . ($hasStrictDynamic ? "'strict-dynamic'" : 'nonce/hash') .
                    " source is present, so modern browsers ignore 'unsafe-inline'. It only affects legacy browsers.",
                    "Optional: drop 'unsafe-inline' once you no longer support pre-CSP2 browsers.",
                    [], false);
            } else {
                $issues[] = "allows 'unsafe-inline' (XSS risk)";
            }
        }
        if (strpos($csp, "'unsafe-eval'") !== false)   $issues[] = "allows 'unsafe-eval' (code injection risk)";
        if (strpos($csp, 'default-src') === false)     $issues[] = 'missing default-src fallback directive';
        if (preg_match('/(?:^|[\s;])\*(?:$|[\s;])/', $csp)) $issues[] = 'contains wildcard (*) source';
        if (strpos($csp, 'frame-ancestors') === false)         $issues[] = 'missing frame-ancestors (clickjacking risk)';
        if (strpos($csp, 'upgrade-insecure-requests') === false) $issues[] = 'missing upgrade-insecure-requests';
        if (strpos($csp, 'base-uri') === false)   $issues[] = 'missing base-uri directive';
        if (strpos($csp, 'form-action') === false) $issues[] = 'missing form-action directive';
        if (preg_match('/script-src[^;]*data:/', $csp)) $issues[] = "script-src allows data: URIs";
        if (preg_match('/script-src[^;]*http:/', $csp)) $issues[] = "script-src allows http: sources";

        if ($issues) {
            $this->addFinding('Headers', 'Content-Security-Policy', 'warning',
                'CSP present but has issues: ' . implode('; ', $issues) . '.',
                'Tighten the policy by removing unsafe directives and adding missing ones.');
        } else {
            $this->addFinding('Headers', 'Content-Security-Policy', 'pass',
                'Content-Security-Policy is present and well configured.');
        }
    }

    private function checkHSTS(): void
    {
        $hsts = $this->getHeader('Strict-Transport-Security');
        if (!$hsts) {
            $this->addFinding('Headers', 'Strict-Transport-Security', 'critical',
                'HSTS header is missing.',
                'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
            return;
        }
        $issues = [];
        if (preg_match('/max-age=(\d+)/i', $hsts, $m)) {
            if ((int)$m[1] < 31536000) $issues[] = "max-age is {$m[1]}s — should be >= 31536000";
            if ((int)$m[1] === 0)      $issues[] = "max-age=0 effectively disables HSTS";
        } else { $issues[] = 'max-age directive missing'; }
        if (stripos($hsts, 'includeSubDomains') === false) $issues[] = 'missing includeSubDomains';
        if (stripos($hsts, 'preload') === false)           $issues[] = 'missing preload flag';

        if ($issues) {
            $this->addFinding('Headers', 'Strict-Transport-Security', 'warning',
                'HSTS present but: ' . implode('; ', $issues) . '.',
                'Use: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
        } else {
            $this->addFinding('Headers', 'Strict-Transport-Security', 'pass',
                'HSTS is properly configured with includeSubDomains and preload.');
        }
    }

    private function checkXContentType(): void
    {
        $val = $this->getHeader('X-Content-Type-Options');
        if ($val && strtolower(trim($val)) === 'nosniff') {
            $this->addFinding('Headers', 'X-Content-Type-Options', 'pass', "Set to 'nosniff'.");
        } else {
            $this->addFinding('Headers', 'X-Content-Type-Options', 'warning',
                'X-Content-Type-Options header is missing or misconfigured.',
                'Add: X-Content-Type-Options: nosniff');
        }
    }

    private function checkXFrameOptions(): void
    {
        $val = $this->getHeader('X-Frame-Options');
        if ($val && in_array(strtoupper(trim($val)), ['DENY', 'SAMEORIGIN'])) {
            $this->addFinding('Headers', 'X-Frame-Options', 'pass', 'Set to ' . strtoupper(trim($val)) . '.');
        } else {
            $this->addFinding('Headers', 'X-Frame-Options', 'warning',
                'X-Frame-Options header is missing or misconfigured.',
                'Add: X-Frame-Options: DENY — or use CSP frame-ancestors.');
        }
    }

    private function checkReferrerPolicy(): void
    {
        $val  = $this->getHeader('Referrer-Policy');
        $safe = ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin', 'same-origin'];
        if ($val && in_array(strtolower(trim($val)), $safe)) {
            $this->addFinding('Headers', 'Referrer-Policy', 'pass', "Set to '{$val}'.");
        } elseif ($val) {
            $this->addFinding('Headers', 'Referrer-Policy', 'info',
                "Set to '{$val}' — consider a stricter value.", 'Recommended: strict-origin-when-cross-origin');
        } else {
            $this->addFinding('Headers', 'Referrer-Policy', 'warning',
                'Referrer-Policy header is missing.', 'Add: Referrer-Policy: strict-origin-when-cross-origin');
        }
    }

    private function checkPermissionsPolicy(): void
    {
        $val    = $this->getHeader('Permissions-Policy');
        $legacy = $this->getHeader('Feature-Policy');
        if ($val) {
            $this->addFinding('Headers', 'Permissions-Policy', 'pass', 'Permissions-Policy header is present.');
        } elseif ($legacy) {
            $this->addFinding('Headers', 'Permissions-Policy', 'info',
                'Legacy Feature-Policy found but Permissions-Policy is missing.',
                'Migrate from Feature-Policy to Permissions-Policy.');
        } else {
            $this->addFinding('Headers', 'Permissions-Policy', 'info',
                'Permissions-Policy header is missing.',
                'Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');
        }
    }

    private function checkXXSSProtection(): void
    {
        $val = $this->getHeader('X-XSS-Protection');
        if ($val && strpos($val, '1') === 0 && stripos($val, 'block') !== false) {
            $this->addFinding('Headers', 'X-XSS-Protection', 'pass', 'Enabled with mode=block.');
        } elseif ($val === '0') {
            $this->addFinding('Headers', 'X-XSS-Protection', 'info',
                'Explicitly disabled (acceptable with strong CSP).');
        } else {
            $this->addFinding('Headers', 'X-XSS-Protection', 'info',
                'Missing (deprecated in modern browsers).', 'Rely on a strong CSP instead.');
        }
    }

    private function checkCacheControl(): void
    {
        $cc     = strtolower($this->getHeader('Cache-Control') ?? '');
        $pragma = strtolower($this->getHeader('Pragma') ?? '');
        if (strpos($cc, 'no-store') !== false) {
            $this->addFinding('Headers', 'Cache-Control', 'pass', 'Cache-Control includes no-store.');
        } elseif (strpos($cc, 'private') !== false) {
            $this->addFinding('Headers', 'Cache-Control', 'pass', 'Cache-Control set to private.');
        } elseif (strpos($pragma, 'no-cache') !== false) {
            $this->addFinding('Headers', 'Cache-Control', 'info',
                'Pragma: no-cache found — prefer Cache-Control.', 'Add: Cache-Control: no-store, private');
        } else {
            $this->addFinding('Headers', 'Cache-Control', 'info',
                'Cache-Control may allow caching.', 'For sensitive pages: Cache-Control: no-store, private');
        }
    }

    private function checkCrossOriginHeaders(): void
    {
        $coep = $this->getHeader('Cross-Origin-Embedder-Policy');
        $coop = $this->getHeader('Cross-Origin-Opener-Policy');
        $corp = $this->getHeader('Cross-Origin-Resource-Policy');

        $this->addFinding('Headers', 'Cross-Origin-Embedder-Policy',
            $coep ? 'pass' : 'info',
            $coep ? "COEP set to: {$coep}" : 'COEP missing.',
            $coep ? '' : 'Consider: Cross-Origin-Embedder-Policy: require-corp');

        $this->addFinding('Headers', 'Cross-Origin-Opener-Policy',
            $coop ? 'pass' : 'info',
            $coop ? "COOP set to: {$coop}" : 'COOP missing.',
            $coop ? '' : 'Consider: Cross-Origin-Opener-Policy: same-origin');

        $this->addFinding('Headers', 'Cross-Origin-Resource-Policy',
            $corp ? 'pass' : 'info',
            $corp ? "CORP set to: {$corp}" : 'CORP missing.',
            $corp ? '' : 'Consider: Cross-Origin-Resource-Policy: same-origin');
    }

    // ================================================================
    //  2. INFORMATION LEAKAGE
    // ================================================================

    private function checkServerLeakage(): void
    {
        $leakHeaders = [
            'Server'              => 'Server software/version',
            'X-Powered-By'        => 'Backend technology',
            'X-AspNet-Version'    => 'ASP.NET version',
            'X-AspNetMvc-Version' => 'ASP.NET MVC version',
            'X-Generator'         => 'Site generator',
            'X-Drupal-Cache'      => 'Drupal CMS',
            'X-Varnish'           => 'Varnish cache',
            'Via'                 => 'Proxy information',
        ];

        $found = false;
        foreach ($leakHeaders as $header => $desc) {
            $val = $this->getHeader($header);
            if (!$val) continue;

            $found = true;
            $headerLower = strtolower($header);
            $valueLower  = strtolower(trim($val));

            // Cloudflare injects its own Server header at the edge. This is not
            // an origin Server header leak and should not reduce the score.
            if ($headerLower === 'server' && $valueLower === 'cloudflare') {
                $this->addFinding(
                    'Information Leakage',
                    $header,
                    'info',
                    "'Server: cloudflare' is a CDN/WAF edge fingerprint, not an origin server version leak.",
                    'No origin fix required. Do not treat this as a security failure.'
                );
                continue;
            }

            // Generic Server header without a version is low-value fingerprinting,
            // not enough to justify a warning.
            if ($headerLower === 'server' && !preg_match('/\d+(?:\.\d+)+/', $val)) {
                $this->addFinding(
                    'Information Leakage',
                    $header,
                    'info',
                    "'{$header}' exposes a generic server fingerprint: '{$val}'.",
                    'Optional: remove/genericize if your stack allows it.'
                );
                continue;
            }

            $this->addFinding(
                'Information Leakage',
                $header,
                'warning',
                "'{$header}' exposes {$desc}: '{$val}'.",
                "Remove or genericize the {$header} header."
            );
        }

        if (!$found) {
            $this->addFinding('Information Leakage', 'Server Headers', 'pass',
                'No common information leakage headers detected.');
        }
    }

    // ================================================================
    //  3. COOKIES
    // ================================================================

    private function checkCookies(): void
    {
        if (empty($this->cookies)) {
            $this->addFinding('Cookies', 'Presence', 'info', 'No cookies were set on the scanned page.');
            return;
        }
        foreach ($this->cookies as $cookieStr) {
            $parts   = explode(';', $cookieStr);
            $nameVal = trim($parts[0]);
            $eqPos   = strpos($nameVal, '=');
            $name    = $eqPos !== false ? substr($nameVal, 0, $eqPos) : $nameVal;
            $lower   = strtolower($cookieStr);
            $issues  = [];
            if (strpos($lower, 'secure') === false)   $issues[] = 'missing Secure flag';
            if (strpos($lower, 'httponly') === false)  $issues[] = 'missing HttpOnly flag';
            if (strpos($lower, 'samesite') === false)  $issues[] = 'missing SameSite attribute';
            if (preg_match('/samesite\s*=\s*none/i', $cookieStr) && strpos($lower, 'secure') === false)
                $issues[] = 'SameSite=None requires Secure flag';
            if (stripos($name, '__Host-') === 0 && (strpos($lower, 'secure') === false || strpos($lower, 'path=/') === false))
                $issues[] = '__Host- prefix requires Secure and Path=/';

            if ($issues) {
                $this->addFinding('Cookies', "Cookie: {$name}", 'warning',
                    "Cookie '{$name}' — " . implode('; ', $issues) . '.',
                    'Set: Secure; HttpOnly; SameSite=Lax on all sensitive cookies.');
            } else {
                $this->addFinding('Cookies', "Cookie: {$name}", 'pass',
                    "Cookie '{$name}' has proper security attributes.");
            }
        }
    }

    // ================================================================
    //  4. TRANSPORT
    // ================================================================

    private function checkHTTPSRedirect(): void
    {
        if ($this->scheme !== 'https') {
            $this->addFinding('Transport', 'HTTPS', 'critical',
                'The site is served over plain HTTP.',
                'Obtain a TLS certificate and redirect all HTTP to HTTPS.');
            return;
        }
        $httpUrl = preg_replace('#^https://#', 'http://', $this->url);
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $httpUrl,
            CURLOPT_RESOLVE        => $this->pinResolve(),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT        => 8,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_USERAGENT => self::TARGET_USER_AGENT,
            CURLOPT_NOBODY         => true,
            CURLOPT_HEADER         => true,
        ]);
        $response = curl_exec($ch);
        $code     = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $this->closeCurl($ch);

        if ($response === false || $code === 0) {
            $this->addFinding('Transport', 'HTTP → HTTPS Redirect', 'info',
                'Could not connect on port 80 — HTTP may be disabled (good).');
            return;
        }
        if (in_array($code, [301, 302, 307, 308])) {
            $loc = '';
            if (preg_match('/Location:\s*(.+)/i', $response, $lm)) $loc = trim($lm[1]);
            if ($loc && stripos($loc, 'https://') === 0) {
                $this->addFinding('Transport', 'HTTP → HTTPS Redirect',
                    $code === 301 ? 'pass' : 'info',
                    $code === 301 ? 'HTTP permanently redirects (301) to HTTPS.'
                                 : "HTTP redirects ({$code}) to HTTPS — prefer 301.",
                    $code !== 301 ? 'Use a 301 permanent redirect.' : '');
            } else {
                $this->addFinding('Transport', 'HTTP → HTTPS Redirect', 'warning',
                    'HTTP redirects but not to an HTTPS URL.', 'Ensure redirect target uses https://.');
            }
        } else {
            $this->addFinding('Transport', 'HTTP → HTTPS Redirect', 'warning',
                "HTTP returns {$code} without redirecting to HTTPS.",
                'Configure server to 301-redirect all HTTP to HTTPS.');
        }
    }

    // ================================================================
    //  5. TLS / SSL
    // ================================================================

    private function checkTLS(): void
    {
        if (empty($this->hostname)) return;
        $ctx = stream_context_create(['ssl' => [
            'capture_peer_cert'       => true,
            'capture_peer_cert_chain' => true,
            'verify_peer'             => true,
            'verify_peer_name'        => true,
            'SNI_enabled'             => true,
            'peer_name'               => $this->hostname,
        ]]);
        $errno = 0; $errstr = '';
        $client = @stream_socket_client("ssl://{$this->connectHost()}:{$this->port}", $errno, $errstr, 15, STREAM_CLIENT_CONNECT, $ctx);
        if (!$client) {
            $this->addFinding('TLS/SSL', 'Connection', 'critical',
                "TLS connection failed: {$errstr} (errno {$errno})",
                'Verify the server has a valid TLS certificate on port ' . $this->port . '.');
            return;
        }

        $params = stream_context_get_params($client);
        $meta   = stream_get_meta_data($client);
        $crypto = $meta['crypto'] ?? [];
        $proto  = (string)($crypto['protocol'] ?? 'unknown');

        $this->negotiatedTlsProtocol   = $proto;
        $this->negotiatedCipherName    = (string)($crypto['cipher_name'] ?? '');
        $this->negotiatedCipherBits    = (int)($crypto['cipher_bits'] ?? 0);
        $this->negotiatedCipherVersion = (string)($crypto['cipher_version'] ?? $proto);

        if (stripos($proto, 'TLSv1.3') !== false) {
            $this->addFinding('TLS/SSL', 'Protocol Version', 'pass', "Negotiated TLSv1.3 (best).");
        } elseif (stripos($proto, 'TLSv1.2') !== false) {
            $this->addFinding('TLS/SSL', 'Protocol Version', 'pass', "Negotiated TLSv1.2.");
        } elseif (stripos($proto, 'TLSv1.1') !== false) {
            $this->addFinding('TLS/SSL', 'Protocol Version', 'critical', "Deprecated TLSv1.1.", 'Disable TLS 1.1, allow TLS 1.2+ only.');
        } elseif (stripos($proto, 'TLSv1') !== false) {
            $this->addFinding('TLS/SSL', 'Protocol Version', 'critical', "Deprecated TLSv1.0.", 'Disable TLS 1.0, allow TLS 1.2+ only.');
        } else {
            $this->addFinding('TLS/SSL', 'Protocol Version', 'warning', "Negotiated: {$proto}.");
        }

        if ($this->negotiatedCipherName !== '') {
            $this->analyzeCipher($this->negotiatedCipherName, $this->negotiatedCipherBits, $this->negotiatedCipherVersion ?: $proto);
        }

        if (isset($params['options']['ssl']['peer_certificate'])) {
            $this->analyzeCertificate($params['options']['ssl']['peer_certificate'], $params['options']['ssl']['peer_certificate_chain'] ?? []);
        }

        fclose($client);
    }

    private function analyzeCipher(string $cipherName, int $bits, string $version): void
    {
        $upper   = strtoupper($cipherName);
        $isTls13 = $this->isTls13Cipher($cipherName, $version);

        $isAEAD = false;
        foreach (self::STRONG_AEAD_CIPHERS as $a) {
            if (strpos($upper, strtoupper($a)) !== false) { $isAEAD = true; break; }
        }

        // TLS 1.3 cipher suite names intentionally do not encode the key exchange
        // algorithm. Do not flag "KX Unknown" for names like TLS_AES_256_GCM_SHA384.
        if ($isTls13) {
            $details = [
                "Cipher: {$cipherName}",
                "Protocol: TLSv1.3",
                'KX: negotiated via TLS 1.3 key_share (not encoded in cipher suite name)',
                'Bits: ' . ($bits > 0 ? (string)$bits : 'unknown'),
                'AEAD: ' . ($isAEAD ? 'Yes' : 'Unknown'),
            ];

            if ($bits > 0 && $bits < 128) {
                $this->addFinding('TLS/SSL', 'Cipher Suite Analysis', 'critical',
                    implode(' | ', $details) . '. Issues: less than 128-bit security.',
                    'Use standard TLS 1.3 AEAD cipher suites.');
                return;
            }

            $this->addFinding('TLS/SSL', 'Cipher Suite Analysis', 'pass',
                implode(' | ', $details) . '. TLS 1.3 KX is not inferred from the cipher name.');
            return;
        }

        $weakFound = [];
        foreach (self::WEAK_CIPHERS as $w) {
            if (strpos($upper, strtoupper($w)) !== false) $weakFound[] = $w;
        }
        if (!empty($weakFound)) {
            $this->addFinding('TLS/SSL', 'Cipher Suite', 'critical',
                "Weak cipher: {$cipherName} (" . implode(', ', $weakFound) . ").",
                'Use ECDHE+AESGCM or CHACHA20-POLY1305 suites.');
            return;
        }

        $kx = 'Unknown';
        foreach (self::STRONG_KEY_EXCHANGES as $skx) {
            if (strpos($upper, strtoupper($skx)) !== false) { $kx = $skx; break; }
        }

        $details  = ["Cipher: {$cipherName}", "KX: {$kx}", "Bits: {$bits}", "AEAD: " . ($isAEAD ? 'Yes' : 'No')];
        $severity = 'pass';
        $issues   = [];

        if ($bits > 0 && $bits < 128) { $severity = 'critical'; $issues[] = "only {$bits} bits"; }
        if (!$isAEAD) { $severity = $severity === 'critical' ? 'critical' : 'warning'; $issues[] = 'not AEAD'; }
        if ($kx === 'Unknown') { $severity = $severity === 'critical' ? 'critical' : 'warning'; $issues[] = 'unknown KX'; }

        if ($issues) {
            $this->addFinding('TLS/SSL', 'Cipher Suite Analysis', $severity,
                implode(' | ', $details) . '. Issues: ' . implode('; ', $issues) . '.',
                'Prefer ECDHE+AES-256-GCM or CHACHA20-POLY1305.');
        } else {
            $this->addFinding('TLS/SSL', 'Cipher Suite Analysis', 'pass', implode(' | ', $details) . '.');
        }
    }

    private function analyzeCertificate($certResource, array $chain = []): void
    {
        $cert = openssl_x509_parse($certResource);
        if (!$cert) { $this->addFinding('TLS/SSL', 'Certificate', 'critical', 'Could not parse certificate.'); return; }

        $notAfter = $cert['validTo_time_t'] ?? 0;
        $notBefore = $cert['validFrom_time_t'] ?? 0;
        $daysLeft  = (int)(($notAfter - time()) / 86400);
        $totalDays = (int)(($notAfter - $notBefore) / 86400);

        if ($daysLeft < 0)  $this->addFinding('TLS/SSL', 'Certificate Expiry', 'critical', 'Certificate EXPIRED ' . abs($daysLeft) . ' day(s) ago!', 'Renew immediately.');
        elseif ($daysLeft < 7)  $this->addFinding('TLS/SSL', 'Certificate Expiry', 'critical', "Expires in {$daysLeft} day(s)!", 'Renew urgently.');
        elseif ($daysLeft < 30) $this->addFinding('TLS/SSL', 'Certificate Expiry', 'warning', "Expires in {$daysLeft} day(s).", 'Renew soon.');
        else $this->addFinding('TLS/SSL', 'Certificate Expiry', 'pass', "Valid for {$daysLeft} more day(s).");

        if ($totalDays > 398) $this->addFinding('TLS/SSL', 'Certificate Validity Period', 'warning', "Validity {$totalDays} days (exceeds 398-day standard).", 'Use max 398-day certificates.');
        else $this->addFinding('TLS/SSL', 'Certificate Validity Period', 'pass', "Validity period: {$totalDays} days.");

        $cn  = $cert['subject']['CN'] ?? 'N/A';
        $san = [];
        if (isset($cert['extensions']['subjectAltName'])) {
            preg_match_all('/DNS:([^,\s]+)/', $cert['extensions']['subjectAltName'], $sm);
            $san = $sm[1] ?? [];
        }
        $match = false;
        foreach (array_merge([$cn], $san) as $n) { if ($this->matchHostname($n, $this->hostname)) { $match = true; break; } }
        if ($match) $this->addFinding('TLS/SSL', 'Certificate Hostname', 'pass', "Certificate matches '{$this->hostname}'.");
        else $this->addFinding('TLS/SSL', 'Certificate Hostname', 'critical', "CN={$cn} does not match '{$this->hostname}'.", 'Obtain a certificate covering this hostname.');

        $sanDisplay = array_slice($san, 0, 8);
        $this->addFinding('TLS/SSL', 'Certificate Subject', 'info',
            "CN={$cn} | SANs: " . (empty($sanDisplay) ? 'none' : implode(', ', $sanDisplay)) . (count($san) > 8 ? ' (+' . (count($san)-8) . ' more)' : ''));

        $pubKey = openssl_pkey_get_public($certResource);
        if ($pubKey) {
            $det = openssl_pkey_get_details($pubKey);
            $bits = $det['bits'] ?? 0;
            $kt   = $det['type'] ?? -1;
            $ktn  = match($kt) { OPENSSL_KEYTYPE_RSA => 'RSA', OPENSSL_KEYTYPE_EC => 'EC', OPENSSL_KEYTYPE_DSA => 'DSA', default => 'Unknown' };
            $minB = match($kt) { OPENSSL_KEYTYPE_RSA => 2048, OPENSSL_KEYTYPE_EC => 256, default => 2048 };
            if ($bits >= $minB) $this->addFinding('TLS/SSL', 'Key Strength', 'pass', "Public key: {$ktn} {$bits}-bit.");
            else $this->addFinding('TLS/SSL', 'Key Strength', 'critical', "Public key: {$ktn} {$bits}-bit (min: {$minB}).", "Use at least {$minB}-bit {$ktn} key.");
            if ($kt === OPENSSL_KEYTYPE_RSA && $bits <= 2048)
                $this->addFinding('TLS/SSL', 'Key Type', 'info', 'Consider upgrading to ECDSA for better performance.', 'Use EC P-256/P-384 certificate.');
        }

        $sigAlg = $cert['signatureTypeSN'] ?? $cert['signatureTypeLN'] ?? '';
        $weak = stripos($sigAlg, 'md5') !== false || stripos($sigAlg, 'md2') !== false
             || (stripos($sigAlg, 'sha1') !== false);
        if ($weak) $this->addFinding('TLS/SSL', 'Signature Algorithm', 'critical', "Weak algorithm: {$sigAlg}.", 'Use SHA-256 or SHA-384.');
        else $this->addFinding('TLS/SSL', 'Signature Algorithm', 'pass', "Algorithm: {$sigAlg}.");
    }

    private function checkDeprecatedProtocols(): void
    {
        if (empty($this->hostname)) return;
        $deprecated = [];
        if (defined('STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT')) $deprecated['TLSv1.0'] = STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT;
        if (defined('STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT')) $deprecated['TLSv1.1'] = STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT;

        foreach ($deprecated as $name => $method) {
            $r = $this->testProtocol($method);
            if ($r === true) {
                $this->addFinding('TLS/SSL', "Deprecated: {$name}", 'critical', "Server accepts {$name}.", "Disable {$name}.");
            } elseif ($r === false) {
                $this->addFinding('TLS/SSL', "Deprecated: {$name}", 'pass', "{$name} is disabled.");
            } else {
                $this->addFinding('TLS/SSL', "Deprecated: {$name}", 'info', "Could not determine {$name} support.");
            }
        }

        if (defined('STREAM_CRYPTO_METHOD_SSLv3_CLIENT')) {
            $r = $this->testProtocol(STREAM_CRYPTO_METHOD_SSLv3_CLIENT);
            if ($r === true) {
                if ($this->isCloudflareEdge()) {
                    $this->addFinding(
                        'TLS/SSL',
                        'Deprecated: SSLv3',
                        'info',
                        'Scanner probe reported SSLv3 against a Cloudflare edge. Treating as suspected false positive because this does not prove origin SSLv3 support.',
                        'Verify externally with openssl s_client -ssl3. Do not fail the grade unless a real SSLv3 handshake is confirmed.'
                    );
                } else {
                    $this->addFinding('TLS/SSL', 'Deprecated: SSLv3', 'critical', 'Server accepts SSLv3 (POODLE).', 'Disable SSLv3 immediately.');
                }
            } else {
                $this->addFinding('TLS/SSL', 'Deprecated: SSLv3', 'pass', 'SSLv3 is disabled.');
            }
        } else {
            $this->addFinding('TLS/SSL', 'Deprecated: SSLv3', 'info', 'SSLv3 probe not available in this PHP/OpenSSL build.');
        }
    }

    private function testProtocol(int $method): ?bool
    {
        $ctx = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false, 'crypto_method' => $method, 'SNI_enabled' => true, 'peer_name' => $this->hostname]]);
        $errno = 0; $errstr = '';
        $client = @stream_socket_client("tcp://{$this->connectHost()}:{$this->port}", $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $ctx);
        if (!$client) return null;
        $success = @stream_socket_enable_crypto($client, true, $method);
        fclose($client);
        return $success === true;
    }

    private function checkCipherStrength(): void
    {
        if (empty($this->hostname)) return;
        $tests = [
            'RC4'     => 'RC4',
            'DES-CBC' => 'DES',
            '3DES'    => 'Triple DES',
            'NULL'    => 'NULL ciphers',
            'EXPORT'  => 'EXPORT ciphers',
            'aNULL'   => 'Anonymous auth',
        ];

        $weak = [];
        foreach ($tests as $cs => $desc) {
            // Force TLS 1.2 when enumerating legacy OpenSSL cipher strings.
            // Otherwise TLS 1.3 can connect successfully while ignoring the ciphers option,
            // producing false positives for NULL/aNULL/EXPORT/RC4.
            if ($this->testCipherGroup($cs, true)) $weak[$cs] = $desc;
        }

        if (!empty($weak)) {
            $severity = $this->isCloudflareEdge() ? 'info' : 'critical';
            $message  = 'Server appears to accept weak TLS<=1.2 cipher groups: ' . implode(', ', array_map(fn($d,$c) => "{$d} ({$c})", $weak, array_keys($weak))) . '.';
            if ($this->isCloudflareEdge()) {
                $message .= ' Target is behind Cloudflare; treat this as suspected false positive unless reproduced with a real TLS<=1.2 handshake.';
            }
            $this->addFinding('TLS/SSL', 'Weak Cipher Support', $severity,
                $message,
                'Disable all weak ciphers. Use: ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!3DES:!RC4');
        } else {
            $this->addFinding('TLS/SSL', 'Weak Cipher Support', 'pass', 'No weak TLS<=1.2 cipher suites accepted.');
        }
    }

    private function checkECDHESupport(): void
    {
        if (empty($this->hostname)) return;

        if ($this->hasNegotiatedTls13()) {
            $this->addFinding('TLS/SSL', 'ECDHE Support', 'pass',
                'TLS 1.3 negotiated. Key exchange is handled through TLS 1.3 key_share and is not encoded in the cipher suite name.');
            return;
        }

        $ecdheTests = [
            'ECDHE-RSA-AES256-GCM-SHA384'   => 'ECDHE-RSA+AES-256-GCM',
            'ECDHE-RSA-AES128-GCM-SHA256'   => 'ECDHE-RSA+AES-128-GCM',
            'ECDHE-ECDSA-AES256-GCM-SHA384' => 'ECDHE-ECDSA+AES-256-GCM',
            'ECDHE-RSA-CHACHA20-POLY1305'   => 'ECDHE-RSA+CHACHA20',
            'ECDHE-ECDSA-CHACHA20-POLY1305' => 'ECDHE-ECDSA+CHACHA20',
        ];
        $supported = [];
        foreach ($ecdheTests as $c => $d) { if ($this->testCipherGroup($c, true)) $supported[] = $d; }
        if (!empty($supported)) {
            $this->addFinding('TLS/SSL', 'ECDHE Support', 'pass',
                'ECDHE supported: ' . implode(', ', array_slice($supported, 0, 3)) . (count($supported) > 3 ? '...' : '') . '.');
        } else {
            $this->addFinding('TLS/SSL', 'ECDHE Support', 'warning',
                'No TLS 1.2 ECDHE cipher suites found.', 'Enable ECDHE cipher suites for forward secrecy on TLS 1.2.');
        }
    }

    private function checkPerfectForwardSecrecy(): void
    {
        if (empty($this->hostname)) return;

        if ($this->hasNegotiatedTls13()) {
            $this->addFinding('TLS/SSL', 'Perfect Forward Secrecy', 'pass',
                'TLS 1.3 negotiated. Forward secrecy is provided for normal certificate/(EC)DHE handshakes; cipher name does not include ECDHE/DHE.');
            return;
        }

        $pfs = false;
        $ctx = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false, 'SNI_enabled' => true, 'peer_name' => $this->hostname]]);
        $errno = 0; $errstr = '';
        $client = @stream_socket_client("ssl://{$this->connectHost()}:{$this->port}", $errno, $errstr, 8, STREAM_CLIENT_CONNECT, $ctx);
        if ($client) {
            $meta = stream_get_meta_data($client);
            $neg  = strtoupper($meta['crypto']['cipher_name'] ?? '');
            fclose($client);
            foreach (self::PFS_CIPHERS as $p) { if (strpos($neg, strtoupper($p)) !== false) { $pfs = true; break; } }
        }
        if ($pfs) $this->addFinding('TLS/SSL', 'Perfect Forward Secrecy', 'pass', 'PFS supported via ephemeral key exchange.');
        else $this->addFinding('TLS/SSL', 'Perfect Forward Secrecy', 'warning', 'PFS may not be supported for TLS 1.2 or below.', 'Enable ECDHE or DHE cipher suites.');
    }

    private function checkCertificateChain(): void
    {
        if (empty($this->hostname)) return;
        $ctx = stream_context_create(['ssl' => ['capture_peer_cert_chain' => true, 'verify_peer' => false, 'verify_peer_name' => false, 'SNI_enabled' => true, 'peer_name' => $this->hostname]]);
        $errno = 0; $errstr = '';
        $client = @stream_socket_client("ssl://{$this->connectHost()}:{$this->port}", $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $ctx);
        if (!$client) return;
        $params = stream_context_get_params($client);
        fclose($client);
        $chain = $params['options']['ssl']['peer_certificate_chain'] ?? [];
        $len   = count($chain);
        if ($len === 0) $this->addFinding('TLS/SSL', 'Certificate Chain', 'warning', 'Could not retrieve chain.', 'Ensure intermediates are configured.');
        elseif ($len === 1) $this->addFinding('TLS/SSL', 'Certificate Chain', 'warning', 'Only leaf cert sent — intermediates may be missing.', 'Send full chain.');
        else $this->addFinding('TLS/SSL', 'Certificate Chain', 'pass', "Chain contains {$len} certificate(s).");
        foreach ($chain as $idx => $cc) {
            $p = openssl_x509_parse($cc);
            if (!$p) continue;
            $cn = $p['subject']['CN'] ?? 'Unknown';
            if (stripos($p['signatureTypeSN'] ?? '', 'sha1') !== false && $idx > 0)
                $this->addFinding('TLS/SSL', 'Chain: SHA-1 Intermediate', 'warning', "Intermediate '{$cn}' uses SHA-1.", 'Replace with SHA-256 signed intermediate.');
        }
    }

    private function testCipherGroup(string $cs, bool $forceTls12 = false): bool
    {
        $ssl = [
            'verify_peer'      => false,
            'verify_peer_name' => false,
            'ciphers'          => $cs,
            'SNI_enabled'      => true,
            'peer_name'        => $this->hostname,
        ];

        if ($forceTls12 && defined('STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT')) {
            $ssl['crypto_method'] = STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
        }

        $ctx = stream_context_create(['ssl' => $ssl]);
        $errno = 0; $errstr = '';
        $client = @stream_socket_client("ssl://{$this->connectHost()}:{$this->port}", $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $ctx);
        if (!$client) return false;

        $meta   = stream_get_meta_data($client);
        $crypto = $meta['crypto'] ?? [];
        $cipher = (string)($crypto['cipher_name'] ?? '');
        $proto  = (string)($crypto['protocol'] ?? '');
        fclose($client);

        // If OpenSSL ignored the legacy cipher string and negotiated TLS 1.3,
        // the test does not prove the requested TLS<=1.2 cipher group is accepted.
        if ($forceTls12 && (stripos($proto, 'TLSv1.3') !== false || str_starts_with(strtoupper($cipher), 'TLS_'))) {
            return false;
        }

        return true;
    }

    private function matchHostname(string $pattern, string $hostname): bool
    {
        $pattern = strtolower($pattern); $hostname = strtolower($hostname);
        if ($pattern === $hostname) return true;
        if (strpos($pattern, '*.') === 0) {
            $suffix = substr($pattern, 2);
            $parts  = explode('.', $hostname, 2);
            if (count($parts) === 2 && $parts[1] === $suffix) return true;
        }
        return false;
    }

    // ================================================================
    //  6. CORS
    // ================================================================

    private function checkCORS(): void
    {
        $acao = $this->getHeader('Access-Control-Allow-Origin');
        if (!$acao) { $this->addFinding('CORS', 'Access-Control-Allow-Origin', 'info', 'No CORS header (fine if not an API).'); return; }
        $acac = strtolower($this->getHeader('Access-Control-Allow-Credentials') ?? '');
        $acam = $this->getHeader('Access-Control-Allow-Methods') ?? '';
        if ($acao === '*') {
            if ($acac === 'true') $this->addFinding('CORS', 'CORS Misconfiguration', 'critical', 'Wildcard origin + credentials — severe misconfiguration.', 'Never use * with credentials. Whitelist origins.');
            else $this->addFinding('CORS', 'Access-Control-Allow-Origin', 'warning', 'CORS allows any origin (*).', 'Whitelist specific origins.');
        } elseif ($acao === 'null') {
            $this->addFinding('CORS', 'Access-Control-Allow-Origin', 'warning', "Origin 'null' can be exploited via sandboxed iframes.", 'Never allow null origin.');
        } else {
            $this->addFinding('CORS', 'Access-Control-Allow-Origin', 'pass', "CORS restricted to: {$acao}");
        }
        if ($acam && preg_match('/\*/i', $acam))
            $this->addFinding('CORS', 'Access-Control-Allow-Methods', 'warning', 'CORS allows all methods (*).', 'Specify only required methods.');
    }

    // ================================================================
    //  7. HTML BODY CHECKS
    // ================================================================

    private function checkMixedContent(): void
    {
        if (!$this->isHTML()) return;
        $body = substr($this->responseBody, 0, 100000);
        preg_match_all('/(?:src|href|action)\s*=\s*["\']http:\/\/[^"\']+/i', $body, $m);
        if (!empty($m[0])) {
            $this->addFinding('HTML', 'Mixed Content', 'warning',
                count($m[0]) . ' http:// reference(s). Examples: ' . implode(', ', array_slice($m[0], 0, 3)),
                'Change all resource URLs to https://.');
        } else {
            $this->addFinding('HTML', 'Mixed Content', 'pass', 'No mixed content detected.');
        }
    }

    private function checkSRI(): void
    {
        if (!$this->isHTML()) return;
        $body = substr($this->responseBody, 0, 100000);
        preg_match_all('/<script[^>]+src\s*=\s*["\']https?:\/\/[^"\']+["\'][^>]*>/i', $body, $m);
        if (empty($m[0])) return;
        $total = count($m[0]); $missing = 0; $examples = [];
        foreach ($m[0] as $tag) {
            if (stripos($tag, 'integrity=') === false) {
                $missing++;
                if (count($examples) < 2) { preg_match('/src\s*=\s*["\']([^"\']+)/i', $tag, $sm); if (isset($sm[1])) $examples[] = basename(parse_url($sm[1], PHP_URL_PATH) ?: $sm[1]); }
            }
        }
        if ($missing > 0) {
            $this->addFinding('HTML', 'Subresource Integrity', 'warning',
                "{$missing}/{$total} external script(s) lack SRI" . ($examples ? ' (e.g., ' . implode(', ', $examples) . ')' : '') . '.',
                "Add integrity='sha384-...' crossorigin='anonymous' to external scripts.");
        } else {
            $this->addFinding('HTML', 'Subresource Integrity', 'pass', 'All external scripts have SRI.');
        }
    }

    /**
     * Identify a small set of high-confidence JavaScript library/version pairs
     * from the delivered HTML. This is intentionally passive: it never fetches
     * third-party assets or claims an unversioned library is vulnerable.
     *
     * @return array<int,array{name:string,version:string,severity:string,note:string}>
     */
    public function analyzeClientSideDependencies(string $html): array
    {
        $sample = substr(html_entity_decode($html, ENT_QUOTES | ENT_HTML5, 'UTF-8'), 0, 500000);
        $patterns = [
            'jQuery' => '/(?:jquery(?:[-.]?(?:min|slim))?[-.]?v?|jquery\.js\?[^"\'\s>]*(?:ver|version)=)(\d+\.\d+(?:\.\d+)?)/i',
            'Lodash' => '/(?:lodash(?:\.min)?[-.]?v?|lodash\.js\?[^"\'\s>]*(?:ver|version)=)(\d+\.\d+(?:\.\d+)?)/i',
            'Bootstrap' => '/(?:bootstrap(?:\.bundle|\.min)?[-.]?v?|bootstrap(?:\.min)?\.css\?[^"\'\s>]*(?:ver|version)=)(\d+\.\d+(?:\.\d+)?)/i',
            'AngularJS' => '/(?:angular(?:\.min)?[-.]?v?|angular\.js\?[^"\'\s>]*(?:ver|version)=)(\d+\.\d+(?:\.\d+)?)/i',
        ];

        $out = [];
        foreach ($patterns as $name => $pattern) {
            if (!preg_match_all($pattern, $sample, $matches)) continue;
            foreach (array_values(array_unique($matches[1])) as $version) {
                $severity = '';
                $note = '';
                if ($name === 'jQuery' && version_compare($version, '3.5.0', '<')) {
                    $severity = 'warning';
                    $note = 'Known cross-site scripting fixes are missing in jQuery versions before 3.5.0.';
                } elseif ($name === 'Lodash' && version_compare($version, '4.17.21', '<')) {
                    $severity = 'critical';
                    $note = 'Known prototype-pollution and command-injection fixes are missing before Lodash 4.17.21.';
                } elseif ($name === 'Bootstrap' && (version_compare($version, '3.4.1', '<') || (str_starts_with($version, '4.') && version_compare($version, '4.3.1', '<')))) {
                    $severity = 'warning';
                    $note = 'Known cross-site scripting fixes are missing in this Bootstrap version.';
                } elseif ($name === 'AngularJS' && str_starts_with($version, '1.')) {
                    $severity = 'info';
                    $note = 'AngularJS is end-of-life; migrate to a supported framework.';
                }
                if ($severity !== '') {
                    $out["{$name}|{$version}"] = compact('name', 'version', 'severity', 'note');
                }
            }
        }

        return array_values($out);
    }

    private function checkClientSideDependencies(): void
    {
        if (!$this->isHTML()) return;
        $hits = $this->analyzeClientSideDependencies($this->responseBody);
        if ($hits === []) {
            $this->addFinding('Technology', 'Client-side Dependency CVE', 'pass',
                'No high-confidence vulnerable JavaScript library version was fingerprinted from the delivered HTML.');
            return;
        }

        foreach ($hits as $hit) {
            $this->addFinding('Technology', "{$hit['name']} {$hit['version']}", $hit['severity'],
                $hit['note'],
                "Upgrade {$hit['name']} to a supported patched release, then verify the deployed asset version.",
                ['https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities']);
        }
    }

    private function checkInsecureForms(): void
    {
        if (!$this->isHTML()) return;
        preg_match_all('/<form[^>]+action\s*=\s*["\']http:\/\/[^"\']+/i', substr($this->responseBody, 0, 100000), $m);
        if (!empty($m[0])) {
            $this->addFinding('HTML', 'Insecure Form Action', 'critical', count($m[0]) . ' form(s) submit to http://.', 'Change form actions to https://.');
        } else {
            $this->addFinding('HTML', 'Insecure Form Action', 'pass', 'No forms submitting over plain HTTP detected.');
        }
    }

    private function checkMetaCSP(): void
    {
        if (!$this->isHTML()) return;
        if (preg_match('/<meta[^>]+http-equiv\s*=\s*["\']Content-Security-Policy["\'][^>]*>/i', substr($this->responseBody, 0, 100000))) {
            $this->addFinding('HTML', 'Meta CSP', 'info',
                $this->getHeader('Content-Security-Policy')
                    ? 'CSP defined both via header and <meta> tag. Header takes precedence.'
                    : 'CSP via <meta> tag — HTTP header delivery is preferred.',
                'Deliver CSP via HTTP header for full coverage.');
        }
    }

    private function isHTML(): bool
    {
        return stripos($this->getHeader('Content-Type') ?? '', 'text/html') !== false;
    }

    // ================================================================
    //  EXPOSED SECRETS (credentials/keys leaked in the response body)
    // ================================================================

    /**
     * Scan an arbitrary text blob for high-confidence secret formats.
     *
     * Pure and side-effect free so it can be unit-tested offline. Only
     * well-known, structured token formats are matched to keep the false-
     * positive rate low. Returns a de-duplicated list of:
     *   ['type' => string, 'severity' => 'critical'|'warning', 'sample' => masked]
     *
     * @return array<int, array{type:string, severity:string, sample:string}>
     */
    public function scanBodyForSecrets(string $body): array
    {
        if ($body === '') return [];
        // Cap work on very large bodies; secrets near the top matter most.
        $body = substr($body, 0, 500000);

        // type => [regex, severity]. High-confidence structured formats only.
        $patterns = [
            'AWS Access Key ID'      => ['/\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b/',           'critical'],
            'AWS Secret Access Key'  => ['/\baws_secret_access_key\s*[:=]\s*["\']?[A-Za-z0-9\/+]{40}["\']?/i',  'critical'],
            'Google API Key'         => ['/\bAIza[0-9A-Za-z\-_]{35}\b/',                                        'critical'],
            'Stripe Secret Key'      => ['/\b(?:sk|rk)_live_[0-9a-zA-Z]{16,}\b/',                               'critical'],
            'GitHub Token'           => ['/\bgh[pousr]_[0-9A-Za-z]{36,}\b/',                                    'critical'],
            'Slack Token'            => ['/\bxox[baprs]-[0-9A-Za-z-]{10,}\b/',                                  'critical'],
            'Slack Webhook'          => ['#https://hooks\.slack\.com/services/[A-Za-z0-9/]+#',                  'critical'],
            'SendGrid API Key'       => ['/\bSG\.[\w-]{20,}\.[\w-]{30,}\b/',                                    'critical'],
            'Mailgun API Key'        => ['/\bkey-[0-9a-zA-Z]{32}\b/',                                           'critical'],
            'Twilio API Key'         => ['/\bSK[0-9a-fA-F]{32}\b/',                                             'critical'],
            'npm Token'              => ['/\bnpm_[0-9A-Za-z]{36}\b/',                                           'critical'],
            'Private Key Block'      => ['/-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/',       'critical'],
            'JSON Web Token (JWT)'   => ['/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/',   'warning'],
        ];

        $found = [];
        $seen  = [];
        foreach ($patterns as $type => [$regex, $severity]) {
            if (preg_match($regex, $body, $m)) {
                $key = $type;
                if (isset($seen[$key])) continue;
                $seen[$key] = true;
                $found[] = [
                    'type'     => $type,
                    'severity' => $severity,
                    'sample'   => $this->maskSecret($m[0]),
                ];
            }
        }
        return $found;
    }

    /** Redact the middle of a secret so the report never echoes it in full. */
    private function maskSecret(string $s): string
    {
        $s = trim($s);
        if (strlen($s) <= 12) return substr($s, 0, 3) . '…';
        return substr($s, 0, 6) . '…' . substr($s, -4);
    }

    private function checkExposedSecrets(): void
    {
        $hits = $this->scanBodyForSecrets($this->responseBody);
        if (empty($hits)) {
            $this->addFinding('Information Leakage', 'Exposed Secrets', 'pass',
                'No credentials, API keys, or private keys detected in the page source.');
            return;
        }
        foreach ($hits as $h) {
            $this->addFinding(
                'Information Leakage',
                'Exposed Secret: ' . $h['type'],
                $h['severity'],
                "Possible {$h['type']} exposed in the response body (redacted: {$h['sample']}).",
                'Remove the secret from client-delivered source, rotate/revoke it immediately, and move it to a server-side secret store.',
                ['https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url',
                 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html']
            );
        }
    }

    // ================================================================
    //  CSRF PROTECTION (state-changing forms lacking anti-CSRF tokens)
    // ================================================================

    /**
     * Inspect HTML for POST forms that carry no anti-CSRF token field.
     *
     * Pure/offline for unit testing. A page-level CSRF <meta> tag (Rails/Laravel
     * style, consumed by JS) counts as protection for all forms. Returns:
     *   ['post_forms' => int, 'unprotected' => int]
     *
     * @return array{post_forms:int, unprotected:int}
     */
    public function analyzeFormsForCsrf(string $html): array
    {
        if ($html === '') return ['post_forms' => 0, 'unprotected' => 0];
        $html = substr($html, 0, 300000);

        // Framework meta-token (e.g. <meta name="csrf-token" ...>) protects
        // AJAX/form submissions app-wide, so treat its presence as coverage.
        $hasMetaToken = (bool) preg_match(
            '/<meta[^>]+name\s*=\s*["\'](?:csrf-token|_csrf|xsrf-token|csrf-param)["\'][^>]*>/i',
            $html
        );

        preg_match_all('/<form\b[^>]*>(.*?)<\/form>/is', $html, $forms, PREG_SET_ORDER);
        $postForms = 0;
        $unprotected = 0;
        $tokenNameRe = '/name\s*=\s*["\'][^"\']*(?:csrf|xsrf|_token|authenticity_token|nonce|requestverification)[^"\']*["\']/i';

        foreach ($forms as $f) {
            $tag   = $f[0];
            $inner = $f[1] ?? '';
            // Only POST (state-changing) forms are relevant.
            if (!preg_match('/\bmethod\s*=\s*["\']?post["\']?/i', $tag)) continue;
            $postForms++;
            if ($hasMetaToken) continue;
            if (preg_match($tokenNameRe, $inner)) continue;      // hidden token field
            $unprotected++;
        }
        return ['post_forms' => $postForms, 'unprotected' => $unprotected];
    }

    private function checkCsrfProtection(): void
    {
        if (!$this->isHTML()) return;
        $r = $this->analyzeFormsForCsrf($this->responseBody);

        if ($r['post_forms'] === 0) {
            $this->addFinding('HTML', 'CSRF Token', 'info',
                'No POST forms found on the scanned page to assess for CSRF protection.',
                '', [], false);
            return;
        }
        if ($r['unprotected'] > 0) {
            $this->addFinding('HTML', 'CSRF Token', 'warning',
                "{$r['unprotected']} of {$r['post_forms']} POST form(s) have no visible anti-CSRF token field or page-level CSRF meta tag.",
                'Add a per-session anti-CSRF token (hidden field or framework meta tag) to state-changing forms, and set SameSite on session cookies.',
                ['https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html']);
        } else {
            $this->addFinding('HTML', 'CSRF Token', 'pass',
                "All {$r['post_forms']} POST form(s) carry an anti-CSRF token or the page exposes a CSRF meta tag.");
        }
    }

    // ================================================================
    //  8. HTTP/2 & HTTP/3
    // ================================================================

    private function checkHTTPVersions(): void
    {
        $ch = curl_init();
        curl_setopt_array($ch, [CURLOPT_URL => $this->url, CURLOPT_RESOLVE => $this->pinResolve(), CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10, CURLOPT_CONNECTTIMEOUT => 8, CURLOPT_USERAGENT => self::TARGET_USER_AGENT, CURLOPT_SSL_VERIFYPEER => false, CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_2_0]);
        curl_exec($ch);
        $ver = curl_getinfo($ch, CURLINFO_HTTP_VERSION);
        $this->closeCurl($ch);
        $h2 = defined('CURL_HTTP_VERSION_2') && $ver >= CURL_HTTP_VERSION_2;
        if ($h2) $this->addFinding('Transport', 'HTTP/2', 'pass', 'HTTP/2 supported — multiplexing active.');
        else $this->addFinding('Transport', 'HTTP/2', 'info', 'HTTP/2 not detected.', 'Enable HTTP/2 (h2) for better performance.');

        $altSvc = $this->getHeader('alt-svc') ?? '';
        if ($altSvc && preg_match('/h3[\-="]/i', $altSvc)) $this->addFinding('Transport', 'HTTP/3 (QUIC)', 'pass', "HTTP/3 advertised via Alt-Svc: {$altSvc}");
        else $this->addFinding('Transport', 'HTTP/3 (QUIC)', 'info', 'HTTP/3 not advertised.', 'Consider enabling QUIC/HTTP3 for better latency.');
    }

    // ================================================================
    //  9. DNS & EMAIL SECURITY
    // ================================================================


    /**
     * Some PHP builds do not expose DNS_DS / DNS_DNSKEY constants even though
     * the server can still query DNSSEC via BIND tools. This fallback uses dig
     * safely when available. It prevents the scanner from skipping DNSSEC just
     * because PHP was built without these constants.
     */
    private function canRunShellCommand(string $function): bool
    {
        if (!function_exists($function)) {
            return false;
        }

        $disabled = array_filter(array_map('trim', explode(',', (string)ini_get('disable_functions'))));
        return !in_array($function, $disabled, true);
    }

    private function getDigPath(): ?string
    {
        if (!$this->canRunShellCommand('shell_exec')) {
            return null;
        }

        $path = trim((string)@shell_exec('command -v dig 2>/dev/null'));
        if ($path === '') {
            return null;
        }

        return $path;
    }

    private function queryDnssecWithDig(string $domain): array
    {
        $domain = strtolower(rtrim(trim($domain), '.'));

        // Strict domain validation before shelling out. No IPs, underscores,
        // or shell metacharacters. This scanner only needs public DNS names here.
        if (!preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i', $domain)) {
            return [
                'available' => false,
                'error'     => 'Domain format is not suitable for dig DNSSEC lookup.',
                'ds'        => [],
                'dnskey'    => [],
            ];
        }

        $digPath = $this->getDigPath();
        if ($digPath === null) {
            return [
                'available' => false,
                'error'     => 'dig command is not available, or shell_exec is disabled.',
                'ds'        => [],
                'dnskey'    => [],
            ];
        }

        $dig = escapeshellcmd($digPath);
        $arg = escapeshellarg($domain);

        $dsRaw     = trim((string)@shell_exec("{$dig} +time=3 +tries=1 +dnssec +short {$arg} DS 2>/dev/null"));
        $dnskeyRaw = trim((string)@shell_exec("{$dig} +time=3 +tries=1 +dnssec +short {$arg} DNSKEY 2>/dev/null"));

        $ds = array_values(array_filter(array_map('trim', preg_split('/\R+/', $dsRaw) ?: [])));
        $dnskey = array_values(array_filter(array_map('trim', preg_split('/\R+/', $dnskeyRaw) ?: [])));

        return [
            'available' => true,
            'error'     => '',
            'ds'        => $ds,
            'dnskey'    => $dnskey,
        ];
    }

    private function checkDNSSecurity(): void
    {
        $host       = $this->hostname;
        $baseDomain = preg_replace('/^www\./i', '', $host);

        // SPF
        $spfFound = false;
        $txtRecs  = @dns_get_record($baseDomain, DNS_TXT) ?: [];
        foreach ($txtRecs as $r) {
            $txt = is_array($r['entries'] ?? null) ? implode('', $r['entries']) : ($r['txt'] ?? '');
            if (stripos($txt, 'v=spf1') === 0) {
                $spfFound = true;
                if (strpos($txt, '+all') !== false) $this->addFinding('DNS', 'SPF Record', 'critical', "SPF uses '+all' — anyone can send as your domain.", "Change to '-all'.");
                elseif (strpos($txt, '-all') !== false) $this->addFinding('DNS', 'SPF Record', 'pass', "SPF with strict -all.");
                elseif (strpos($txt, '~all') !== false) $this->addFinding('DNS', 'SPF Record', 'info', "SPF uses soft-fail (~all).", "Consider upgrading to -all.");
                else $this->addFinding('DNS', 'SPF Record', 'warning', "SPF found but no 'all' mechanism.", "Add '-all' at the end.");
                break;
            }
        }
        if (!$spfFound) $this->addFinding('DNS', 'SPF Record', 'warning', 'No SPF record — domain vulnerable to email spoofing.', "Add: v=spf1 include:provider.com -all");

        // DMARC
        $dmarcRecs = @dns_get_record("_dmarc.{$baseDomain}", DNS_TXT) ?: [];
        $dmarcFound = false;
        foreach ($dmarcRecs as $r) {
            $txt = is_array($r['entries'] ?? null) ? implode('', $r['entries']) : ($r['txt'] ?? '');
            if (stripos($txt, 'v=DMARC1') === 0) {
                $dmarcFound = true;
                if (strpos($txt, 'p=none') !== false)       $this->addFinding('DNS', 'DMARC Record', 'warning', "DMARC p=none (monitoring only).", "Upgrade to p=quarantine or p=reject.");
                elseif (strpos($txt, 'p=reject') !== false)     $this->addFinding('DNS', 'DMARC Record', 'pass', "DMARC p=reject (strict).");
                elseif (strpos($txt, 'p=quarantine') !== false)  $this->addFinding('DNS', 'DMARC Record', 'pass', "DMARC p=quarantine.");
                break;
            }
        }
        if (!$dmarcFound) $this->addFinding('DNS', 'DMARC Record', 'warning', 'No DMARC record.', "Add: _dmarc.{$baseDomain} TXT v=DMARC1; p=reject; rua=mailto:dmarc@{$baseDomain}");

        // DKIM
        $dkimSelectors = ['default', 'google', 'mail', 'dkim', 'selector1', 'selector2', 'k1', 'smtp', 'email', 'mx'];
        $dkimFound = false;
        foreach ($dkimSelectors as $sel) {
            $recs = @dns_get_record("{$sel}._domainkey.{$baseDomain}", DNS_TXT) ?: [];
            foreach ($recs as $r) {
                $txt = is_array($r['entries'] ?? null) ? implode('', $r['entries']) : ($r['txt'] ?? '');
                if (stripos($txt, 'v=DKIM1') !== false || stripos($txt, 'k=rsa') !== false || stripos($txt, 'p=') !== false) {
                    $dkimFound = true;
                    $this->addFinding('DNS', 'DKIM Record', 'pass', "DKIM found for selector '{$sel}'.");
                    break 2;
                }
            }
        }
        if (!$dkimFound) $this->addFinding('DNS', 'DKIM Record', 'info', 'No DKIM record found for common selectors.', 'Set up DKIM with your email provider.');

        // DNSSEC
        // Primary path: PHP constants, when exposed by this PHP build.
        // Fallback path: dig command, when the OS has bind/dnsutils installed.
        $ds  = defined('DNS_DS') ? (@dns_get_record($baseDomain, DNS_DS) ?: []) : [];
        $key = defined('DNS_DNSKEY') ? (@dns_get_record($baseDomain, DNS_DNSKEY) ?: []) : [];

        $digDnssec = $this->queryDnssecWithDig($baseDomain);
        $digHasDnssec = $digDnssec['available'] && (!empty($digDnssec['ds']) || !empty($digDnssec['dnskey']));

        if (!empty($ds) || !empty($key) || $digHasDnssec) {
            $source = (!empty($ds) || !empty($key)) ? 'PHP DNS resolver' : 'dig fallback';
            $detail = [];
            if (!empty($ds) || !empty($digDnssec['ds'])) {
                $detail[] = 'DS record found';
            }
            if (!empty($key) || !empty($digDnssec['dnskey'])) {
                $detail[] = 'DNSKEY record found';
            }

            $this->addFinding(
                'DNS',
                'DNSSEC',
                'pass',
                'DNSSEC detected for ' . $baseDomain . ' via ' . $source . ' — ' . implode(', ', $detail) . '.',
                'Verify the DS record at the registrar and ensure DNSSEC validation remains enabled after DNS changes.'
            );
        } elseif (!defined('DNS_DS') && !defined('DNS_DNSKEY') && !$digDnssec['available']) {
            $this->addFinding(
                'DNS',
                'DNSSEC',
                'info',
                'DNSSEC local check could not run because PHP does not expose DNS_DS / DNS_DNSKEY and dig fallback is unavailable.',
                'Install bind9-dnsutils/dnsutils so dig is available, or enable shell_exec, then scan again. Detail: ' . ($digDnssec['error'] ?: 'unknown reason')
            );
        } else {
            $this->addFinding(
                'DNS',
                'DNSSEC',
                'info',
                'DNSSEC not detected for ' . $baseDomain . '.',
                'Enable DNSSEC at the registrar/DNS provider, publish DS at the parent zone, then rescan.'
            );
        }

        // IPv6
        if (!empty($this->resolvedIpv6)) $this->addFinding('DNS', 'IPv6 Support', 'pass', 'IPv6 (AAAA) records: ' . implode(', ', array_slice($this->resolvedIpv6, 0, 3)));
        else $this->addFinding('DNS', 'IPv6 Support', 'info', 'No IPv6 AAAA records.', 'Consider adding IPv6 support.');
    }

    // ================================================================
    //  10. CMS & TECHNOLOGY DETECTION
    // ================================================================

    private function checkCMSDetection(): void
    {
        $bodySample = str_replace('\\/', '/', $this->cmsFingerprintBody());
        $lower      = strtolower($bodySample);
        $cmsBodyBlocked = $this->bodyLooksLikeValidationChallenge($bodySample);
        $headerHints = strtolower(implode(' ', array_filter(array_merge(
            $this->getAllHeaders('link'),
            $this->getAllHeaders('x-generator'),
            $this->getAllHeaders('x-drupal-cache'),
            $this->getAllHeaders('x-pingback')
        ))));

        $generator = $this->extractMetaContent($bodySample, 'generator');

        $candidates = [];
        $addSignal = static function (string $name, string $signal, string $version = '', int $weight = 3) use (&$candidates): void {
            if (!isset($candidates[$name])) {
                $candidates[$name] = ['signals' => [], 'version' => '', 'score' => 0];
            }
            if (!isset($candidates[$name]['signals'][$signal])) {
                $candidates[$name]['signals'][$signal] = true;
                $candidates[$name]['score'] += max(1, $weight);
            }
            if ($version !== '' && $candidates[$name]['version'] === '') {
                $candidates[$name]['version'] = $version;
            }
        };

        $cookieHints = strtolower(implode(' ', $this->cookies));
        $wpVersion = $this->detectWordPressVersion($bodySample, $headerHints);

        if (
            str_contains($lower, 'wp-includes/')
            || preg_match('#/wp-content/(?:themes|plugins|mu-plugins)/#i', $bodySample)
        ) {
            $addSignal('WordPress', 'WordPress asset paths', $wpVersion, 4);
        }
        if (
            str_contains($lower, 'wp-json')
            || str_contains($headerHints, 'api.w.org')
            || str_contains($headerHints, 'wp-json/oembed')
        ) {
            $addSignal('WordPress', 'WordPress REST API link', $wpVersion);
        }
        if (str_contains($lower, 'wp-emoji-release') || str_contains($lower, 'wp-block-library')) {
            $addSignal('WordPress', 'WordPress core frontend assets', $wpVersion);
        }
        if (preg_match('#/wp-includes/(?:css|js|blocks)/#i', $bodySample)) {
            $addSignal('WordPress', 'WordPress core asset paths', $wpVersion);
        }
        if (
            str_contains($cookieHints, 'pll_language=')
            || preg_match('/\bwordpress_(?:logged_in|sec|test_cookie)|\bwp-settings-\d+=|\bwp_lang=/i', $cookieHints)
        ) {
            $addSignal('WordPress', 'WordPress cookie/plugin marker', $wpVersion, 4);
        }
        if (stripos($generator, 'WordPress') !== false) {
            $version = preg_match('/WordPress\s*([0-9][0-9A-Za-z.\-]*)/i', $generator, $m) ? $m[1] : $wpVersion;
            $addSignal('WordPress', 'generator meta tag', $version);
        }
        if (str_contains($headerHints, 'wordpress')) {
            $addSignal('WordPress', 'HTTP generator/pingback header', $wpVersion);
        }

        // Joomla: layered multi-signal fingerprint (src/JoomlaFingerprint.php).
        // Independent signals survive partial hardening — removing one (e.g. the
        // generator tag) does not blind detection. Each matched signal is fed in
        // so the strongest CMS still wins the uasort() below.
        $joomla = JoomlaFingerprint::passiveSignals($bodySample, $headerHints, $generator);
        if ($joomla['score'] >= JoomlaFingerprint::THRESHOLD_DETECTED) {
            foreach ($joomla['signals'] as $sig) {
                $addSignal('Joomla', $sig['label'], $joomla['version'], (int)$sig['weight']);
            }
        }
        // Remember passive strength so the active safety-net probe can decide
        // whether it needs to run (see probeJoomlaEndpoints()).
        $this->joomlaPassiveScore = $joomla['score'];

        if (str_contains($lower, 'drupal-settings-json') || str_contains($lower, '/core/misc/drupal')) {
            $addSignal('Drupal', 'Drupal frontend assets');
        }
        if (str_contains($lower, '/sites/default/files') || str_contains($lower, '/sites/all/')) {
            $addSignal('Drupal', 'Drupal site file paths');
        }
        if (stripos($generator, 'Drupal') !== false || str_contains($headerHints, 'drupal')) {
            $version = preg_match('/Drupal\s*([0-9][0-9A-Za-z.\-]*)/i', $generator, $m) ? $m[1] : '';
            $addSignal('Drupal', $generator !== '' ? 'generator meta/header' : 'HTTP generator header', $version);
        }

        if (str_contains($lower, 'cdn.shopify.com') || str_contains($lower, 'shopify-section')) {
            $addSignal('Shopify', 'Shopify storefront assets');
        }
        if (str_contains($lower, 'wix.com') || str_contains($lower, 'wixstatic.com')) {
            $addSignal('Wix', 'Wix assets');
        }
        if (str_contains($lower, 'squarespace') || str_contains($lower, 'static1.squarespace.com')) {
            $addSignal('Squarespace', 'Squarespace assets');
        }
        if (str_contains($lower, 'ghost-') || str_contains($lower, 'ghost/api/')) {
            $addSignal('Ghost', 'Ghost assets/API');
        }

        if ($candidates) {
            uasort($candidates, static function ($a, $b): int {
                $byScore = ($b['score'] ?? 0) <=> ($a['score'] ?? 0);
                if ($byScore !== 0) return $byScore;
                return count($b['signals']) <=> count($a['signals']);
            });
            $cms = (string)array_key_first($candidates);
            $version = (string)($candidates[$cms]['version'] ?? '');
            $signals = array_keys($candidates[$cms]['signals']);

            $this->detectedCms = $cms;
            $this->detectedCmsVersion = $version;
            $this->detectedCmsSignals = $signals;

            $display = $cms . ($version !== '' ? " {$version}" : '');
            $detail = implode(', ', array_slice($signals, 0, 3));
            $this->addFinding(
                'Technology',
                'CMS Detected',
                'info',
                "CMS: {$display}. Signals: {$detail}.",
                'Keep CMS, themes, and plugins updated.'
            );
        } elseif (!$cmsBodyBlocked) {
            $this->addFinding('Technology', 'CMS Detection', 'pass', 'No common CMS fingerprint detected.');
        }

        // Active safety-net probe. A hardened Joomla site (generator tag + asset
        // paths stripped) can score 0 passively and be reported as "no CMS" — a
        // false negative for a site we are meant to protect. Confirm via
        // Joomla-only endpoints when nothing was detected, or when Joomla was
        // detected but no version was recovered (probe leaks the exact version
        // for CVE matching). Skip when another CMS is strongly fingerprinted.
        $shouldProbe = !$cmsBodyBlocked && (
            $this->detectedCms === ''
            || ($this->detectedCms === 'Joomla' && $this->detectedCmsVersion === '')
        );
        if ($shouldProbe) {
            $this->probeJoomlaEndpoints();
        }

        if ($cmsBodyBlocked && $this->detectedCms === '') {
            $this->scanBlocked = [
                'type' => 'captcha_validation',
                'title' => 'Scan disekat oleh captcha / validation page',
                'message' => 'Server memulangkan halaman captcha atau user validation, bukan HTML sebenar laman web. Keputusan CMS dan beberapa semakan HTML mungkin tidak lengkap.',
                'actions' => [
                    'Allowlist IP/server yang menjalankan SecScan di WAF, load balancer, atau bot protection.',
                    'Jalankan authenticated scan dengan cookie/session browser yang sudah melepasi captcha.',
                    'Semak semula selepas validation page dimatikan untuk endpoint scanner atau staging.',
                ],
            ];
            $this->addFinding(
                'Technology',
                'CMS Detection Blocked',
                'warning',
                'Homepage returned a bot/captcha validation page instead of the real site HTML, so CMS fingerprinting could not inspect the application source.',
                'Allowlist this scanner at the WAF/load balancer, run an authenticated scan, or provide a validation cookie/session so the scanner receives the same HTML a normal browser sees.'
            );
        }

        $server = $this->getHeader('server') ?? '';
        if (preg_match('/nginx\/([\d.]+)/i', $server, $m)) $this->addFinding('Technology', 'Server Version', 'warning', "Nginx version: {$m[1]}.", 'Add "server_tokens off;" in nginx.conf.');
        elseif (preg_match('/apache\/([\d.]+)/i', $server, $m)) $this->addFinding('Technology', 'Server Version', 'warning', "Apache version: {$m[1]}.", 'Add "ServerTokens Prod" in Apache config.');
        elseif (preg_match('/microsoft-iis\/([\d.]+)/i', $server, $m)) $this->addFinding('Technology', 'Server Version', 'warning', "IIS version: {$m[1]}.", 'Suppress version in IIS HTTP Response Headers.');

        $powered = $this->getHeader('x-powered-by') ?? '';
        if (preg_match('/PHP\/([\d.]+)/i', $powered, $m)) $this->addFinding('Technology', 'PHP Version', 'warning', "X-Powered-By exposes PHP {$m[1]}.", 'Set expose_php=Off in php.ini.');
        elseif ($powered) $this->addFinding('Technology', 'X-Powered-By', 'info', "X-Powered-By: {$powered}.", 'Remove header to reduce fingerprinting.');

        $frameworks = [];
        if (strpos($lower, 'laravel') !== false || $this->cookieNameExists('laravel_session') || $this->cookieNameExists('XSRF-TOKEN')) $frameworks[] = 'Laravel';
        if (strpos($lower, '_next/static') !== false) $frameworks[] = 'Next.js';
        if (strpos($lower, '__nuxt') !== false)       $frameworks[] = 'Nuxt.js';
        if (preg_match('/ng-version=["\'][\d.]+/i', $bodySample)) $frameworks[] = 'Angular';
        if (strpos($lower, 'django') !== false || $this->cookieNameExists('csrftoken')) $frameworks[] = 'Django';
        if ($frameworks) $this->addFinding('Technology', 'Framework', 'info', 'Detected: ' . implode(', ', $frameworks) . '.', 'Keep frameworks and dependencies updated.');

        $cdns = [];
        if ($this->getHeader('cf-ray'))              $cdns[] = 'Cloudflare';
        if ($this->getHeader('x-amz-cf-id'))         $cdns[] = 'AWS CloudFront';
        if ($this->getHeader('x-fastly-request-id')) $cdns[] = 'Fastly';
        if ($this->getHeader('x-azure-ref'))         $cdns[] = 'Azure CDN';
        if ($cdns) $this->addFinding('Technology', 'CDN/WAF', 'pass', 'Detected: ' . implode(', ', $cdns) . '.');
    }

    private function cmsFingerprintBody(): string
    {
        return $this->cmsFingerprintSample($this->responseBody);
    }

    private function cmsFingerprintSample(string $body): string
    {
        if (strlen($body) <= 2500000) {
            return $body;
        }

        return substr($body, 0, 1500000)
            . "\n<!-- secscan-cms-fingerprint-sample-boundary -->\n"
            . substr($body, -1000000);
    }

    private function detectWordPressVersion(string $html, string $headerHints = ''): string
    {
        foreach ([$html, $headerHints] as $source) {
            if (preg_match('/WordPress\s*([0-9][0-9A-Za-z.\-]*)/i', $source, $m)) {
                return $m[1];
            }
        }

        $coreVersionAssets = [
            '#wp-includes/js/wp-emoji-(?:release|loader)(?:\.min)?\.js[^"\'<>\s]*[?&](?:amp;)?ver=([0-9][0-9A-Za-z.\-]*)#i',
            '#wp-includes/css/(?:dashicons|classic-themes)(?:\.min)?\.css[^"\'<>\s]*[?&](?:amp;)?ver=([0-9][0-9A-Za-z.\-]*)#i',
            '#wp-includes/(?:blocks/[^"\'<>\s?]+/style(?:\.min)?\.css|css/dist/block-library/style(?:\.min)?\.css)[^"\'<>\s]*[?&](?:amp;)?ver=([0-9][0-9A-Za-z.\-]*)#i',
        ];
        foreach ($coreVersionAssets as $pattern) {
            if (preg_match_all($pattern, $html, $matches)) {
                foreach ($matches[1] as $candidate) {
                    if (preg_match('/^\d+(?:\.\d+){1,3}(?:[-.][A-Za-z0-9]+)?$/', $candidate)) {
                        return $candidate;
                    }
                }
            }
        }

        return '';
    }

    private function passiveCmsSnapshot(string $body, array $headers = [], array $cookies = []): array
    {
        $bodySample = str_replace('\\/', '/', $this->cmsFingerprintSample($body));
        $lower = strtolower($bodySample);
        $headerHints = strtolower(implode(' ', array_filter(array_merge(
            $headers['link'] ?? [],
            $headers['x-generator'] ?? [],
            $headers['x-drupal-cache'] ?? [],
            $headers['x-pingback'] ?? []
        ))));
        $cookieHints = strtolower(implode(' ', $cookies));
        $generator = $this->extractMetaContent($bodySample, 'generator');
        $wpVersion = $this->detectWordPressVersion($bodySample, $headerHints);

        $candidates = [];
        $addSignal = static function (string $name, string $signal, string $version = '', int $weight = 3) use (&$candidates): void {
            if (!isset($candidates[$name])) {
                $candidates[$name] = ['signals' => [], 'version' => '', 'score' => 0];
            }
            if (!isset($candidates[$name]['signals'][$signal])) {
                $candidates[$name]['signals'][$signal] = true;
                $candidates[$name]['score'] += max(1, $weight);
            }
            if ($version !== '' && $candidates[$name]['version'] === '') {
                $candidates[$name]['version'] = $version;
            }
        };

        if (
            str_contains($lower, 'wp-includes/')
            || preg_match('#/wp-content/(?:themes|plugins|mu-plugins)/#i', $bodySample)
        ) {
            $addSignal('WordPress', 'WordPress asset paths', $wpVersion, 4);
        }
        if (
            str_contains($lower, 'wp-json')
            || str_contains($headerHints, 'api.w.org')
            || str_contains($headerHints, 'wp-json/oembed')
        ) {
            $addSignal('WordPress', 'WordPress REST API link', $wpVersion);
        }
        if (str_contains($lower, 'wp-emoji-release') || str_contains($lower, 'wp-block-library')) {
            $addSignal('WordPress', 'WordPress core frontend assets', $wpVersion);
        }
        if (preg_match('#/wp-includes/(?:css|js|blocks)/#i', $bodySample)) {
            $addSignal('WordPress', 'WordPress core asset paths', $wpVersion);
        }
        if (
            str_contains($cookieHints, 'pll_language=')
            || preg_match('/\bwordpress_(?:logged_in|sec|test_cookie)|\bwp-settings-\d+=|\bwp_lang=/i', $cookieHints)
        ) {
            $addSignal('WordPress', 'WordPress cookie/plugin marker', $wpVersion, 4);
        }
        if (stripos($generator, 'WordPress') !== false) {
            $version = preg_match('/WordPress\s*([0-9][0-9A-Za-z.\-]*)/i', $generator, $m) ? $m[1] : $wpVersion;
            $addSignal('WordPress', 'generator meta tag', $version);
        }
        if (str_contains($headerHints, 'wordpress')) {
            $addSignal('WordPress', 'HTTP generator/pingback header', $wpVersion);
        }

        $joomla = JoomlaFingerprint::passiveSignals($bodySample, $headerHints, $generator);
        if ($joomla['score'] >= JoomlaFingerprint::THRESHOLD_DETECTED) {
            foreach ($joomla['signals'] as $sig) {
                $addSignal('Joomla', $sig['label'], $joomla['version'], (int)$sig['weight']);
            }
        }

        if (str_contains($lower, 'drupal-settings-json') || str_contains($lower, '/core/misc/drupal')) {
            $addSignal('Drupal', 'Drupal frontend assets');
        }
        if (str_contains($lower, '/sites/default/files') || str_contains($lower, '/sites/all/')) {
            $addSignal('Drupal', 'Drupal site file paths');
        }
        if (stripos($generator, 'Drupal') !== false || str_contains($headerHints, 'drupal')) {
            $version = preg_match('/Drupal\s*([0-9][0-9A-Za-z.\-]*)/i', $generator, $m) ? $m[1] : '';
            $addSignal('Drupal', $generator !== '' ? 'generator meta/header' : 'HTTP generator header', $version);
        }

        if (str_contains($lower, 'cdn.shopify.com') || str_contains($lower, 'shopify-section')) {
            $addSignal('Shopify', 'Shopify storefront assets');
        }
        if (str_contains($lower, 'wix.com') || str_contains($lower, 'wixstatic.com')) {
            $addSignal('Wix', 'Wix assets');
        }
        if (str_contains($lower, 'squarespace') || str_contains($lower, 'static1.squarespace.com')) {
            $addSignal('Squarespace', 'Squarespace assets');
        }
        if (str_contains($lower, 'ghost-') || str_contains($lower, 'ghost/api/')) {
            $addSignal('Ghost', 'Ghost assets/API');
        }

        if (!$candidates) {
            return ['cms' => '', 'version' => '', 'signals' => [], 'joomla_score' => $joomla['score']];
        }

        uasort($candidates, static function ($a, $b): int {
            $byScore = ($b['score'] ?? 0) <=> ($a['score'] ?? 0);
            if ($byScore !== 0) return $byScore;
            return count($b['signals']) <=> count($a['signals']);
        });

        $cms = (string)array_key_first($candidates);
        return [
            'cms' => $cms,
            'version' => (string)($candidates[$cms]['version'] ?? ''),
            'signals' => array_keys($candidates[$cms]['signals']),
            'joomla_score' => $joomla['score'],
        ];
    }

    private function capturePassiveCmsAfterFetchFailure(string $url, array $target, string $reason): void
    {
        if ($this->detectedCms !== '') {
            return;
        }

        $headers = [];
        $cookies = [];
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RESOLVE => $this->pinResolveForHost(
                (string)($target['hostname'] ?? $this->hostname),
                $this->portForUrl($url, (string)($target['scheme'] ?? $this->scheme)),
                $target['ipv4'] ?? [],
                $target['ipv6'] ?? [],
                [80, 443]
            ),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 8,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_USERAGENT => self::TARGET_USER_AGENT,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_ENCODING => '',
            CURLOPT_HEADERFUNCTION => static function ($ch, $header) use (&$headers, &$cookies) {
                $len = strlen($header);
                $parts = explode(':', $header, 2);
                if (count($parts) === 2) {
                    $name = strtolower(trim($parts[0]));
                    $value = trim($parts[1]);
                    $headers[$name][] = $value;
                }
                if (stripos($header, 'Set-Cookie:') === 0) {
                    $cookies[] = trim(substr($header, 11));
                }
                return $len;
            },
        ]);

        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $this->closeCurl($ch);

        if ($body === false || $code < 200 || $code >= 400) {
            return;
        }

        $snapshot = $this->passiveCmsSnapshot((string)$body, $headers, $cookies);
        if (($snapshot['cms'] ?? '') === '') {
            return;
        }

        $this->detectedCms = (string)$snapshot['cms'];
        $this->detectedCmsVersion = (string)($snapshot['version'] ?? '');
        $this->detectedCmsSignals = array_values(array_unique($snapshot['signals'] ?? []));

        $display = $this->detectedCms . ($this->detectedCmsVersion !== '' ? " {$this->detectedCmsVersion}" : '');
        $detail = implode(', ', array_slice($this->detectedCmsSignals, 0, 3));
        $this->addFinding(
            'Technology',
            'CMS Detected (fallback)',
            'info',
            "CMS: {$display}. Signals: {$detail}. Passive fallback ran after primary fetch failed: {$reason}.",
            'Fix the primary connection issue first; this fallback is only for CMS visibility and is not counted in the score.',
            [],
            false
        );
    }

    private function bodyLooksLikeValidationChallenge(string $body): bool
    {
        return (bool)preg_match(
            '/Validation request|User validation required|captcha_resp|captcha\.gif|BNIS_x-bni-jas|Web Page Blocked|browser to have javascript and cookie support enabled/i',
            $body
        );
    }

    private function extractMetaContent(string $html, string $name): string
    {
        if (!preg_match_all('/<meta\b[^>]*>/i', $html, $metaTags)) {
            return '';
        }

        foreach ($metaTags[0] as $tag) {
            $attrs = [];
            if (!preg_match_all('/([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'>`=]+))/i', $tag, $matches, PREG_SET_ORDER)) {
                continue;
            }
            foreach ($matches as $m) {
                $attrs[strtolower($m[1])] = html_entity_decode(trim($m[2] ?? $m[3] ?? $m[4] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8');
            }
            if (strcasecmp($attrs['name'] ?? '', $name) === 0) {
                return trim($attrs['content'] ?? '');
            }
        }

        return '';
    }

    /**
     * Active safety-net probe for Joomla. Fetches a small set of Joomla-only
     * endpoints (see JoomlaFingerprint::activeProbePaths()) that survive
     * front-end hardening, and confirms/upgrades detection from their responses.
     * Response validation is delegated to the pure JoomlaFingerprint::validateProbe()
     * so the logic stays unit-testable. Soft-404 / catch-all hosts are guarded
     * against with matchesBaseline(), same as the other endpoint checks.
     */
    private function probeJoomlaEndpoints(): void
    {
        $paths = array_keys(JoomlaFingerprint::activeProbePaths());
        $base  = $this->originBase();
        $mh      = curl_multi_init();
        $handles = [];

        foreach ($paths as $path) {
            $ch = curl_init();
            curl_setopt_array($ch, $this->withAuth([
                CURLOPT_URL            => $base . $path,
                CURLOPT_RESOLVE        => $this->pinResolve(),
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 6,
                CURLOPT_CONNECTTIMEOUT => 4,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_USERAGENT => self::TARGET_USER_AGENT,
                CURLOPT_SSL_VERIFYPEER => false,
            ]));
            $handles[$path] = $ch;
            curl_multi_add_handle($mh, $ch);
        }

        $running = null;
        do { curl_multi_exec($mh, $running); curl_multi_select($mh, 0.5); } while ($running > 0);

        $found   = [];   // human-readable labels
        $score   = 0;
        $version = '';
        $note    = '';

        foreach ($handles as $path => $ch) {
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $body = (string)(curl_multi_getcontent($ch) ?? '');
            curl_multi_remove_handle($mh, $ch);
            $this->closeCurl($ch);

            // Ignore soft-404 / catch-all bodies to avoid false positives.
            if ($body !== '' && $this->matchesBaseline($body)) {
                continue;
            }
            $res = JoomlaFingerprint::validateProbe($path, $code, $body);
            if (!$res['matched']) {
                continue;
            }
            $found[] = $res['label'] . ($res['note'] !== '' ? " ({$res['note']})" : '');
            $score  += $res['weight'];
            if ($version === '' && $res['version'] !== '') {
                $version = $res['version'];
            }
            if ($note === '' && $res['note'] !== '') {
                $note = $res['note'];
            }
        }
        curl_multi_close($mh);

        if ($score < JoomlaFingerprint::THRESHOLD_DETECTED && $version === '') {
            return; // Not enough active evidence — leave detection unchanged.
        }

        // Upgrade / confirm detection.
        $wasHidden = $this->detectedCms === '';
        $this->detectedCms = 'Joomla';
        if ($version !== '' && $this->detectedCmsVersion === '') {
            $this->detectedCmsVersion = $version;
        }
        $this->detectedCmsSignals = array_values(array_unique(array_merge($this->detectedCmsSignals, $found)));

        $display = 'Joomla' . ($this->detectedCmsVersion !== '' ? " {$this->detectedCmsVersion}" : '');
        $detail  = implode(', ', array_slice($found, 0, 3));

        // If the passive layer saw nothing, this is exactly the false-negative
        // case the probe exists for — flag it as a warning so the operator knows
        // the site is hardened at the surface but still fingerprintable.
        if ($wasHidden) {
            $this->addFinding(
                'Technology',
                'CMS Detected (active probe)',
                'warning',
                "CMS: {$display}, confirmed via Joomla-only endpoints despite hidden front-end fingerprints. Signals: {$detail}.",
                'Front-end hardening alone is insufficient. Restrict/remove the leaking endpoints: '
                . 'block /administrator/manifests/, /language/*/*.xml, README.txt, htaccess.txt, web.config.txt, '
                . 'and /api/ from public access, then keep core + extensions patched.'
            );
        } else {
            $this->addFinding(
                'Technology',
                'Joomla Version Disclosure',
                $version !== '' ? 'warning' : 'info',
                "Joomla confirmed via active probe" . ($version !== '' ? " — version {$version} disclosed" : '') . ". Signals: {$detail}.",
                'Remove version-leaking files (joomla.xml manifest, language XML, README.txt) from public reach.'
            );
        }
    }

    private function cookieNameExists(string $name): bool
    {
        foreach ($this->cookies as $c) { if (stripos(explode(';', $c)[0], $name . '=') !== false) return true; }
        return false;
    }

    // ================================================================
    //  10b. CMS CVE LOOKUP (NVD)
    // ================================================================

    /**
     * When checkCMSDetection() fingerprints a known CMS, query the NIST NVD
     * 2.0 API for recently-published CVEs that mention that platform (core,
     * plus the much larger universe of plugin/extension CVEs). Results are
     * sorted newest-first and surfaced as findings, with CVSS base severity
     * mapped onto SecScan's severity vocabulary.
     *
     * Notes:
     *  - Only runs for CMSes with strong NVD keyword coverage.
     *  - One outbound request per scan; set SECSCAN_NVD_API_KEY to raise the
     *    NVD rate limit (5 req/30s anonymous -> 50 req/30s with a key).
     *  - "terkini" window defaults to the last 120 days; override with
     *    SECSCAN_CVE_WINDOW_DAYS.
     */
    private function checkCMSVulnerabilities(): void
    {
        $cms = $this->detectedCms;
        if ($cms === '') return;

        $supported = ['WordPress', 'Joomla', 'Drupal'];
        if (!in_array($cms, $supported, true)) return;

        // Fingerprint actually-installed plugins so CVEs can be confirmed
        // against this site rather than just listed generically.
        if ($cms === 'WordPress') $this->detectInstalledPlugins();
        if ($cms === 'Joomla')    $this->detectJoomlaExtensions();

        $windowDays = (int)(getenv('SECSCAN_CVE_WINDOW_DAYS') ?: 120);
        if ($windowDays < 1 || $windowDays > 120) $windowDays = 120;

        $end   = new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $start = $end->sub(new DateInterval("P{$windowDays}D"));
        $fmt   = 'Y-m-d\TH:i:s.000';

        $params = http_build_query([
            'keywordSearch' => strtolower($cms),
            'pubStartDate'  => $start->format($fmt),
            'pubEndDate'    => $end->format($fmt),
            'resultsPerPage'=> 40,
        ]);
        $apiUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0?' . $params;

        $cacheTtl = (int)(getenv('SECSCAN_CVE_CACHE_TTL') ?: 86400);
        if ($cacheTtl < 300) {
            $cacheTtl = 300;
        }
        $json = $this->fetchCveFeed($apiUrl, $this->cveCachePath($cms, $windowDays), $cacheTtl);
        if ($json === null) {
            $this->addFinding('Technology', 'CMS CVE Lookup', 'info',
                "Could not reach the NVD CVE feed for {$cms}.",
                'Retry later, or check outbound HTTPS to services.nvd.nist.gov.',
                [],
                false);
            return;
        }

        $data = json_decode($json, true);
        $items = $data['vulnerabilities'] ?? null;
        if (!is_array($items)) {
            $this->addFinding('Technology', 'CMS CVE Lookup', 'info',
                "NVD returned no parseable data for {$cms}.",
                '',
                [],
                false);
            return;
        }

        if (count($items) === 0) {
            $this->addFinding('Technology', 'CMS CVEs', 'pass',
                "No {$cms}-related CVEs published in the last {$windowDays} days.",
                'Still keep core, themes/templates, and plugins/extensions updated.');
            return;
        }

        // Normalise + sort newest-first.
        $cves = [];
        foreach ($items as $entry) {
            $c = $entry['cve'] ?? null;
            if (!is_array($c) || empty($c['id'])) continue;
            $score = $this->cvssFrom($c['metrics'] ?? []);
            $desc  = '';
            foreach (($c['descriptions'] ?? []) as $d) {
                if (($d['lang'] ?? '') === 'en') { $desc = $d['value']; break; }
            }
            // Confirm against the fingerprinted install base for this CMS.
            $slug = ''; $installed = false;
            if ($cms === 'WordPress') {
                $slug      = $this->cvePluginSlug($c);
                $installed = ($slug !== '' && isset($this->installedPlugins[$slug]));
            } elseif ($cms === 'Joomla') {
                $slug      = $this->matchJoomlaExtension($c);
                $installed = ($slug !== '');
            }
            $cves[] = [
                'id'        => $c['id'],
                'published' => $c['published'] ?? '',
                'score'     => $score['score'],
                'sev'       => $score['severity'],
                'desc'      => $desc,
                'slug'      => $slug,
                'installed' => $installed,
            ];
        }
        // Confirmed-installed CVEs float to the top, then newest-first.
        usort($cves, function ($a, $b) {
            if ($a['installed'] !== $b['installed']) return $a['installed'] ? -1 : 1;
            return strcmp($b['published'], $a['published']);
        });

        $total    = count($cves);
        $critHigh = array_filter($cves, fn($v) => in_array($v['sev'], ['CRITICAL', 'HIGH'], true));

        // Summary finding: generic ecosystem CVEs are intelligence only. They
        // should not lower a site's grade unless this scan fingerprinted the
        // affected plugin/extension as installed.
        $matched = array_values(array_filter($cves, fn($v) => $v['installed']));
        $worst = 'info';
        foreach ($matched as $v) {
            $mapped = $this->mapCveSeverity($v['sev']);
            if ($mapped === 'critical') { $worst = 'critical'; break; }
            if ($mapped === 'warning') $worst = 'warning';
        }

        $verNote = $this->detectedCmsVersion !== ''
            ? " Detected version: {$cms} {$this->detectedCmsVersion} — confirm against each CVE's affected range."
            : '';
        $kindWord  = $cms === 'Joomla' ? 'extension' : 'plugin';
        $matchNote = $matched
            ? ' ' . count($matched) . " affect a {$kindWord} fingerprinted as INSTALLED on this site — see flagged items."
            : ' None matched a fingerprinted installed plugin/extension in this scan; listed CVEs are ecosystem intelligence only.';
        $this->addFinding('Technology', 'CMS CVEs', $worst,
            "{$total} {$cms}-related CVE(s) published in the last {$windowDays} days (" . count($critHigh) . " critical/high).{$matchNote}{$verNote}",
            $matched
                ? 'Review installed matches first and patch affected core/plugins/extensions immediately.'
                : 'Use this as inventory intelligence. Patch only if your installed core/plugins/extensions fall in an affected range.',
            ['https://nvd.nist.gov/vuln/search'],
            count($matched) > 0);

        // Surface the most recent CVEs, but never drop a confirmed-installed
        // match: show all matches plus enough recent ones to fill the cap.
        $cap   = max(12, count($matched));
        $shown = array_slice($cves, 0, $cap);
        foreach ($shown as $v) {
            $date  = substr($v['published'], 0, 10);
            $score = $v['score'] !== null ? sprintf('%.1f %s', $v['score'], $v['sev']) : $v['sev'];
            $snippet = $this->truncate($v['desc'], 220);
            if ($v['installed']) {
                $kind = $cms === 'Joomla' ? 'EXTENSION' : 'PLUGIN';
                $ver  = $this->installedPlugins[$v['slug']]['version'] ?? null;
                $vtxt = $ver ? " (you appear to run v{$ver})" : '';
                $msg  = "⚠ INSTALLED {$kind} '{$v['slug']}'{$vtxt} — [{$date}] CVSS {$score}. {$snippet}";
                $rec  = "This {$kind} was fingerprinted on your site. Compare your installed version to the affected range and update/remove immediately.";
                $sev  = $this->mapCveSeverity($v['sev']);
            } else {
                $msg  = "[{$date}] CVSS {$score}. Ecosystem CVE not confirmed installed on this site. {$snippet}";
                $rec  = 'Check your actual installed core/plugins/extensions against the affected range; update only if applicable.';
                $sev  = 'info';
            }
            $this->addFinding('Technology', $v['id'], $sev, $msg, $rec,
                ['https://nvd.nist.gov/vuln/detail/' . $v['id']],
                (bool)$v['installed']);
        }
    }

    // ================================================================
    //  10c. CMS-SPECIFIC HARDENING
    // ================================================================

    /** @return array{code:int,body:string}|null */
    private function cmsHardeningProbe(string $path): ?array
    {
        $ch = curl_init();
        curl_setopt_array($ch, $this->withAuth([
            CURLOPT_URL => $this->originBase() . $path,
            CURLOPT_RESOLVE => $this->pinResolve(), CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 8, CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => false, CURLOPT_USERAGENT => self::TARGET_USER_AGENT,
            CURLOPT_SSL_VERIFYPEER => false,
        ]));
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $hitPrivate = $this->curlHitPrivateIp($ch);
        $this->closeCurl($ch);
        if ($hitPrivate || !is_string($body)) return null;
        return ['code' => $code, 'body' => $body];
    }

    private function checkCmsHardening(): void
    {
        if ($this->detectedCms === 'WordPress') {
            $users = $this->cmsHardeningProbe('/wp-json/wp/v2/users?per_page=1&_fields=id,slug');
            $data = $users !== null ? json_decode($users['body'], true) : null;
            $first = is_array($data) && array_is_list($data) ? ($data[0] ?? null) : null;
            if (($users['code'] ?? 0) === 200 && is_array($first) && isset($first['id'], $first['slug'])) {
                $this->addFinding('Technology', 'WordPress REST User Enumeration', 'warning',
                    'The public WordPress REST API returns user identifiers and slugs.',
                    'Restrict unauthenticated access to /wp-json/wp/v2/users if public author enumeration is not required.');
            } else {
                $this->addFinding('Technology', 'WordPress REST User Enumeration', 'pass',
                    'The WordPress REST users endpoint did not expose a public user record.');
            }

            $registration = $this->cmsHardeningProbe('/wp-login.php?action=register');
            if (($registration['code'] ?? 0) === 200 && preg_match('/\bid=["\']registerform["\']|\bname=["\']user_login["\']/i', (string)($registration['body'] ?? ''))) {
                $this->addFinding('Technology', 'WordPress Public Registration', 'info',
                    'WordPress registration form is publicly reachable.',
                    'Disable public registration unless it is required, and add anti-spam, email verification, and role controls.');
            }
        }

        if ($this->detectedCms === 'Joomla') {
            $config = $this->cmsHardeningProbe('/api/index.php/v1/config/application');
            $body = (string)($config['body'] ?? '');
            if (($config['code'] ?? 0) === 200 && !$this->isHtmlBody($body)
                && preg_match('/"(?:dbprefix|mailfrom|debug|sitename)"\s*:/i', $body)) {
                $this->addFinding('Technology', 'Joomla Configuration API Exposure', 'warning',
                    'The Joomla Web Services configuration endpoint returned application configuration metadata without an authentication challenge.',
                    'Require authentication for configuration Web Services or disable the endpoint when it is not required.');
            } else {
                $this->addFinding('Technology', 'Joomla Configuration API Exposure', 'pass',
                    'The Joomla configuration API did not expose application configuration metadata.');
            }
        }
    }

    // ================================================================
    //  10d. INSTALLED WORDPRESS PLUGIN FINGERPRINTING
    // ================================================================

    /**
     * Black-box detection of installed WordPress plugins:
     *  1. PASSIVE — scrape the already-fetched homepage HTML for
     *     /wp-content/plugins/<slug>/ asset references and any "?ver=" tag.
     *  2. ACTIVE  — for each discovered slug (bounded), fetch the plugin's
     *     readme.txt and read its "Stable tag:" to confirm existence + version.
     * Soft-404 catch-all responses are filtered via the shared baseline so a
     * homepage returned for every path doesn't masquerade as a real readme.
     */
    private function detectInstalledPlugins(): void
    {
        $body = $this->responseBody;
        if ($body === '') return;

        // 1. Passive: slug + optional version from asset URLs.
        $found = [];
        if (preg_match_all(
                '#/wp-content/plugins/([a-z0-9][a-z0-9._-]*)/[^"\'\s)]*?(?:\?[^"\'\s)]*?\bver=([0-9][0-9A-Za-z.\-]*))?#i',
                $body, $m, PREG_SET_ORDER)) {
            foreach ($m as $hit) {
                $slug = strtolower($hit[1]);
                $ver  = $hit[2] ?? '';
                if (!isset($found[$slug]) || ($ver !== '' && ($found[$slug] === '' ))) {
                    $found[$slug] = $ver;
                }
            }
        }
        if (!$found) {
            $this->addFinding('Technology', 'Installed Plugins', 'info',
                'No WordPress plugin assets were referenced in the homepage HTML.',
                'Plugins may be bundled/minified; this is not proof none are installed.');
            return;
        }

        // 2. Active: confirm via readme.txt (cap requests to stay polite).
        $slugs = array_slice(array_keys($found), 0, 15);
        $base  = $this->originBase();
        $mh    = curl_multi_init();
        $handles = [];
        foreach ($slugs as $slug) {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => "{$base}/wp-content/plugins/{$slug}/readme.txt",
                CURLOPT_RESOLVE => $this->pinResolve(), CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 6, CURLOPT_CONNECTTIMEOUT => 4,
                CURLOPT_FOLLOWLOCATION => false, CURLOPT_USERAGENT => self::TARGET_USER_AGENT,
                CURLOPT_SSL_VERIFYPEER => false,
            ]);
            $handles[$slug] = $ch;
            curl_multi_add_handle($mh, $ch);
        }
        $running = null;
        do { curl_multi_exec($mh, $running); curl_multi_select($mh, 0.5); } while ($running > 0);

        foreach ($handles as $slug => $ch) {
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $rb   = (string)curl_multi_getcontent($ch);
            $confirmed = false;
            $version   = $found[$slug] !== '' ? $found[$slug] : null;
            if ($code === 200 && $rb !== '' && !$this->matchesBaseline($rb)
                && stripos($rb, '=== ') !== false) {
                $confirmed = true;
                if (preg_match('/Stable tag:\s*([0-9][0-9A-Za-z.\-]*)/i', $rb, $vm)) {
                    $version = $vm[1];
                }
            }
            $this->installedPlugins[$slug] = ['version' => $version, 'confirmed' => $confirmed];
            curl_multi_remove_handle($mh, $ch);
            $this->closeCurl($ch);
        }
        curl_multi_close($mh);

        // Report what was found.
        $lines = [];
        foreach ($this->installedPlugins as $slug => $info) {
            $v = $info['version'] ? " v{$info['version']}" : '';
            $c = $info['confirmed'] ? '' : ' (referenced, readme not public)';
            $lines[] = "{$slug}{$v}{$c}";
        }
        $this->addFinding('Technology', 'Installed Plugins', 'info',
            count($this->installedPlugins) . ' WordPress plugin(s) detected: ' . implode('; ', $lines) . '.',
            'Each becomes a CVE matching target below. Remove unused plugins; keep the rest updated.');
    }

    /**
     * Best-effort extraction of a WordPress plugin slug from a CVE record.
     * Wordfence/wpscan CVEs reference plugins.trac.wordpress.org/browser/<slug>/
     * or wordpress.org/plugins/<slug>/, which gives a reliable slug to match
     * against the fingerprinted install base.
     */
    private function cvePluginSlug(array $cve): string
    {
        foreach (($cve['references'] ?? []) as $ref) {
            $url = $ref['url'] ?? '';
            if (preg_match('#plugins\.trac\.wordpress\.org/browser/([a-z0-9][a-z0-9._-]*)/#i', $url, $m)
             || preg_match('#wordpress\.org/plugins/([a-z0-9][a-z0-9._-]*)/#i', $url, $m)
             || preg_match('#/plugins/([a-z0-9][a-z0-9._-]*)/tags/#i', $url, $m)) {
                return strtolower($m[1]);
            }
        }
        return '';
    }

    // ================================================================
    //  10d. INSTALLED JOOMLA EXTENSION FINGERPRINTING
    // ================================================================

    /**
     * Black-box detection of installed Joomla extensions. Joomla has no
     * readme.txt convention, but components/modules/plugins/templates expose
     * their asset directories in the front-end HTML:
     *   /components/com_<name>/   /modules/mod_<name>/
     *   /media/com_<name>/        /plugins/<group>/<name>/
     *   /templates/<name>/        /media/templates/site/<name>/
     * We harvest those slugs (no reliable public version source, so version is
     * left unknown) and match them to CVE product names below.
     */
    private function detectJoomlaExtensions(): void
    {
        $body = $this->responseBody;
        if ($body === '') return;

        $slugs = [];
        $patterns = [
            '#/components/(com_[a-z0-9_]+)/#i',
            '#/media/(com_[a-z0-9_]+)/#i',
            '#/modules/(mod_[a-z0-9_]+)/#i',
            '#/plugins/[a-z0-9_]+/([a-z0-9_]+)/#i',
            '#/templates/([a-z0-9_]+)/#i',
        ];
        // Joomla core slugs would produce generic-word tokens ("content",
        // "users", "media") that match unrelated CVE descriptions — skip them
        // so only third-party extensions are matched.
        $core = [
            'com_content','com_users','com_contact','com_banners','com_finder',
            'com_tags','com_media','com_fields','com_menus','com_modules',
            'com_plugins','com_templates','com_languages','com_cpanel','com_login',
            'com_admin','com_ajax','com_config','com_mailto','com_wrapper',
            'com_search','com_newsfeeds','com_categories','com_associations',
            'com_actionlogs','com_privacy','com_workflow','com_postinstall',
            'com_messages','com_redirect','com_checkin','com_installer',
            'com_joomlaupdate','com_scheduler','com_guidedtours',
            'mod_menu','mod_custom','mod_breadcrumbs','mod_search','mod_login',
            'mod_footer','mod_banners','mod_articles_news','mod_articles_latest',
            'system','content','index','cassiopeia','atum',
        ];
        foreach ($patterns as $re) {
            if (preg_match_all($re, $body, $m)) {
                foreach ($m[1] as $s) {
                    $s = strtolower($s);
                    if (in_array($s, $core, true)) continue;
                    $slugs[$s] = $this->normaliseExtToken($s);
                }
            }
        }

        if (!$slugs) {
            $this->addFinding('Technology', 'Installed Extensions', 'info',
                'No Joomla component/module/template asset paths were referenced in the homepage HTML.',
                'Assets may be combined/minified; this is not proof none are installed.');
            return;
        }

        $this->installedExtensions = $slugs;
        $this->addFinding('Technology', 'Installed Extensions', 'info',
            count($slugs) . ' Joomla extension(s)/template(s) detected: ' . implode('; ', array_keys($slugs)) . '.',
            'Each is matched against Joomla CVEs below. Remove unused extensions; keep the rest updated. '
            . 'Versions are not publicly exposed, so confirm each against the affected range manually.');
    }

    /**
     * If a Joomla CVE's product/description references a token matching one of
     * the fingerprinted extensions, return that extension slug; else ''.
     */
    private function matchJoomlaExtension(array $cve): string
    {
        if (!$this->installedExtensions) return '';

        // Build the haystack from affected product names + description.
        $hay = '';
        foreach (($cve['affected'] ?? []) as $aff) {
            foreach (($aff['affectedData'] ?? []) as $ad) {
                $hay .= ' ' . ($ad['product'] ?? '') . ' ' . ($ad['vendor'] ?? '');
            }
        }
        foreach (($cve['descriptions'] ?? []) as $d) {
            if (($d['lang'] ?? '') === 'en') { $hay .= ' ' . $d['value']; }
        }
        $hayNorm = $this->normaliseExtToken($hay);
        if ($hayNorm === '') return '';

        foreach ($this->installedExtensions as $slug => $token) {
            // Require a reasonably specific token to avoid noise matches.
            if (strlen($token) >= 5 && str_contains($hayNorm, $token)) {
                return $slug;
            }
        }
        return '';
    }

    /** Lowercase + strip com_/mod_/plg_ prefixes and all non-alphanumerics. */
    private function normaliseExtToken(string $s): string
    {
        $s = strtolower($s);
        $s = preg_replace('/\b(com_|mod_|plg_|tpl_)/', '', $s);
        return preg_replace('/[^a-z0-9]/', '', $s);
    }

    /** Pull the best available CVSS base score/severity from an NVD metrics block. */
    private function cvssFrom(array $metrics): array
    {
        foreach (['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'] as $key) {
            if (!empty($metrics[$key][0]['cvssData'])) {
                $d = $metrics[$key][0]['cvssData'];
                $score = isset($d['baseScore']) ? (float)$d['baseScore'] : null;
                $sev   = $d['baseSeverity'] ?? ($metrics[$key][0]['baseSeverity'] ?? $this->severityFromScore($score));
                return ['score' => $score, 'severity' => strtoupper((string)$sev)];
            }
        }
        return ['score' => null, 'severity' => 'UNKNOWN'];
    }

    private function severityFromScore(?float $s): string
    {
        if ($s === null) return 'UNKNOWN';
        if ($s >= 9.0) return 'CRITICAL';
        if ($s >= 7.0) return 'HIGH';
        if ($s >= 4.0) return 'MEDIUM';
        if ($s > 0.0)  return 'LOW';
        return 'NONE';
    }

    /** Map NVD CVSS severity onto SecScan's finding severities. */
    private function mapCveSeverity(string $sev): string
    {
        return match (strtoupper($sev)) {
            'CRITICAL', 'HIGH' => 'critical',
            'MEDIUM'           => 'warning',
            default            => 'info',
        };
    }

    private function truncate(string $s, int $len): string
    {
        $s = trim(preg_replace('/\s+/', ' ', $s));
        return strlen($s) > $len ? substr($s, 0, $len - 1) . '…' : $s;
    }

    private function cveCachePath(string $cms, int $windowDays): ?string
    {
        $dataDir = (string)secscan_config('data_dir');
        if ($dataDir === '') {
            return null;
        }

        $cacheDir = rtrim($dataDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'cache';
        if (!is_dir($cacheDir) && !@mkdir($cacheDir, 0750, true) && !is_dir($cacheDir)) {
            return null;
        }

        $slug = strtolower((string)preg_replace('/[^a-z0-9]+/i', '-', $cms));
        $slug = trim($slug, '-') ?: 'cms';

        return $cacheDir . DIRECTORY_SEPARATOR . "nvd-{$slug}-{$windowDays}d-" . gmdate('Ymd') . '.json';
    }

    private function readCveCache(string $path, int $ttl): ?string
    {
        if (!is_readable($path)) {
            return null;
        }

        $mtime = @filemtime($path);
        if ($mtime === false || (time() - $mtime) > $ttl) {
            return null;
        }

        $body = @file_get_contents($path);
        return is_string($body) && $body !== '' ? $body : null;
    }

    private function writeCveCache(string $path, string $body): void
    {
        if ($body === '') {
            return;
        }

        $dir = dirname($path);
        if (!is_dir($dir) || !is_writable($dir)) {
            return;
        }

        $tmp = $path . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (@file_put_contents($tmp, $body, LOCK_EX) === false) {
            return;
        }
        @chmod($tmp, 0640);
        @rename($tmp, $path);
    }

    /** Outbound GET to the NVD API. Returns the raw body, or null on failure. */
    private function fetchCveFeed(string $url, ?string $cachePath = null, int $cacheTtl = 86400): ?string
    {
        if ($cachePath !== null) {
            $cached = $this->readCveCache($cachePath, $cacheTtl);
            if ($cached !== null) {
                return $cached;
            }
        }

        $ch = curl_init();
        $headers = ['Accept: application/json'];
        if ($key = getenv('SECSCAN_NVD_API_KEY')) $headers[] = 'apiKey: ' . $key;

        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_USERAGENT      => 'SecScan/2.1 (+CVE lookup)',
            CURLOPT_HTTPHEADER     => $headers,
            // NVD presents a valid public cert; verification stays on here
            // because — unlike the user-supplied scan target — this host is
            // fixed and trusted.
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $this->closeCurl($ch);

        if ($body === false || $code !== 200) {
            if ($cachePath !== null && is_readable($cachePath)) {
                $stale = @file_get_contents($cachePath);
                if (is_string($stale) && $stale !== '') {
                    return $stale;
                }
            }
            return null;
        }

        $body = (string)$body;
        if ($cachePath !== null) {
            $this->writeCveCache($cachePath, $body);
        }

        return $body;
    }

    // ================================================================
    //  11. EXPOSED SENSITIVE FILES
    // ================================================================

    /**
     * Probe a few random, definitely-nonexistent paths to learn how the server
     * responds to "not found". Many servers (SPAs, WordPress catch-alls, custom
     * error handlers, some CDNs) answer 200 with the homepage for ANY path —
     * a "soft 404". Without this baseline, every file/endpoint probe looks
     * "accessible" and produces false-positive criticals.
     */
    private function getBaseline(): array
    {
        if ($this->baselineProbe['done']) return $this->baselineProbe;

        $base  = $this->originBase();
        $rand  = substr(md5((string)mt_rand() . microtime()), 0, 16);
        $paths = ["/{$rand}", "/{$rand}.php", "/{$rand}-not-here/"];

        $mh = curl_multi_init();
        $handles = [];
        foreach ($paths as $p) {
            $ch = curl_init();
            curl_setopt_array($ch, $this->withAuth([
                CURLOPT_URL => $base . $p, CURLOPT_RESOLVE => $this->pinResolve(), CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 6, CURLOPT_CONNECTTIMEOUT => 4,
                CURLOPT_FOLLOWLOCATION => false, CURLOPT_USERAGENT => self::TARGET_USER_AGENT,
                CURLOPT_SSL_VERIFYPEER => false,
            ]));
            $handles[$p] = $ch;
            curl_multi_add_handle($mh, $ch);
        }
        $running = null;
        do { curl_multi_exec($mh, $running); curl_multi_select($mh, 0.5); } while ($running > 0);

        $catchall = false;
        $samples  = [];
        foreach ($handles as $ch) {
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $body = (string)curl_multi_getcontent($ch);
            if ($code === 200) { $catchall = true; $samples[] = substr($body, 0, 8000); }
            curl_multi_remove_handle($mh, $ch);
            $this->closeCurl($ch);
        }
        curl_multi_close($mh);

        return $this->baselineProbe = ['done' => true, 'catchall' => $catchall, 'samples' => $samples];
    }

    /**
     * True when a probe response looks the same as the server's catch-all
     * "not found" page — i.e. the path almost certainly does NOT exist and the
     * 200 is a soft-404. Uses length proximity + textual similarity.
     */
    private function matchesBaseline(string $body): bool
    {
        $bl = $this->getBaseline();
        if (!$bl['catchall']) return false;

        $b  = substr($body, 0, 8000);
        $lb = strlen($b);
        foreach ($bl['samples'] as $s) {
            $ls = strlen($s);
            if ($ls === 0 && $lb === 0) return true;
            if ($ls === 0 || $lb === 0) continue;
            $ratio = min($lb, $ls) / max($lb, $ls);
            if ($ratio < 0.90) continue;            // very different size → not the catch-all
            $pct = 0.0;
            similar_text(substr($b, 0, 4000), substr($s, 0, 4000), $pct);
            if ($pct >= 88.0) return true;
        }
        return false;
    }

    private function isJsonBody(string $s): bool
    {
        $s = trim($s);
        if ($s === '' || ($s[0] !== '{' && $s[0] !== '[')) return false;
        json_decode($s);
        return json_last_error() === JSON_ERROR_NONE;
    }

    private function isHtmlBody(string $s): bool
    {
        $h = strtolower(substr($s, 0, 600));
        return str_contains($h, '<!doctype html')
            || str_contains($h, '<html')
            || str_contains($h, '<head')
            || str_contains($h, '<body')
            || str_contains($h, '<title');
    }

    private function checkExposedFiles(): void
    {
        $files = [
            '/.env'               => ['.env — env vars (DB creds, API keys)', true],
            '/.git/HEAD'          => ['.git/HEAD — Git repo exposed', true],
            '/wp-config.php'      => ['wp-config.php — WordPress DB creds', true],
            '/phpinfo.php'        => ['phpinfo.php — PHP/server config', true],
            '/composer.json'      => ['composer.json — PHP dependency list', false],
            '/package.json'       => ['package.json — Node.js deps', false],
            '/.htaccess'          => ['.htaccess — Apache config', false],
            '/web.config'         => ['web.config — IIS config', true],
            '/backup.sql'         => ['backup.sql — database backup', true],
            '/dump.sql'           => ['dump.sql — database dump', true],
            '/.DS_Store'          => ['.DS_Store — macOS metadata', false],
            '/Dockerfile'         => ['Dockerfile — container config', false],
            '/docker-compose.yml' => ['docker-compose.yml — Docker config', false],
        ];

        $base    = $this->originBase();
        $mh      = curl_multi_init();
        $handles = [];

        foreach ($files as $path => [$desc, $critical]) {
            $ch = curl_init();
            curl_setopt_array($ch, $this->withAuth([CURLOPT_URL => $base . $path, CURLOPT_RESOLVE => $this->pinResolve(), CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 6, CURLOPT_CONNECTTIMEOUT => 4, CURLOPT_FOLLOWLOCATION => false, CURLOPT_USERAGENT => self::TARGET_USER_AGENT, CURLOPT_SSL_VERIFYPEER => false]));
            $handles[$path] = ['handle' => $ch, 'desc' => $desc, 'critical' => $critical];
            curl_multi_add_handle($mh, $ch);
        }

        $running = null;
        do { curl_multi_exec($mh, $running); curl_multi_select($mh, 0.5); } while ($running > 0);

        $exposed = [];
        foreach ($handles as $path => $info) {
            $ch   = $info['handle'];
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $body = (string)curl_multi_getcontent($ch);

            // Only a real 200 with content matters; a soft-404 catch-all is ignored.
            if ($code === 200 && strlen($body) > 0 && !$this->matchesBaseline($body)) {
                // Every path requires a POSITIVE content signature — never "just not an
                // error page", which a catch-all homepage would satisfy.
                $isReal = match(true) {
                    $path === '/.env'          => (bool)preg_match('/^[A-Z][A-Z0-9_]+=\S/m', $body) && !$this->isHtmlBody($body),
                    $path === '/.git/HEAD'     => (bool)preg_match('/^(ref:\s+refs\/|[0-9a-f]{40}\b)/m', $body) && !$this->isHtmlBody($body),
                    $path === '/wp-config.php' => (bool)preg_match('/DB_(NAME|USER|PASSWORD)|define\s*\(\s*[\'"]DB_/i', $body),
                    $path === '/phpinfo.php'   => str_contains($body, 'PHP Version') && (stripos($body, 'phpinfo()') !== false || stripos($body, '<title>phpinfo') !== false),
                    $path === '/composer.json' => $this->isJsonBody($body) && (str_contains($body, '"require"') || str_contains($body, '"autoload"')),
                    $path === '/package.json'  => $this->isJsonBody($body) && (str_contains($body, '"dependencies"') || str_contains($body, '"devDependencies"') || str_contains($body, '"version"')),
                    $path === '/.htaccess'     => (bool)preg_match('/RewriteEngine|RewriteRule|<Directory|<Files|AuthType|Order\s+(allow|deny)|Require\s+/i', $body) && !$this->isHtmlBody($body),
                    $path === '/web.config'    => stripos($body, '<configuration') !== false && !$this->isHtmlBody($body),
                    $path === '/Dockerfile'    => (bool)preg_match('/^\s*FROM\s+\S+/mi', $body) && !$this->isHtmlBody($body),
                    $path === '/docker-compose.yml' => (bool)preg_match('/^\s*(services|version)\s*:/mi', $body) && !$this->isHtmlBody($body),
                    $path === '/.DS_Store'     => str_contains($body, 'Bud1') || str_starts_with($body, "\x00\x00\x00\x01"),
                    str_contains($path, '.sql') => (bool)preg_match('/(INSERT\s+INTO|CREATE\s+TABLE|DROP\s+TABLE|--\s+MySQL dump|ENGINE=)/i', $body),
                    default                    => false,
                };
                if ($isReal) $exposed[] = ['path' => $path, 'desc' => $info['desc'], 'critical' => $info['critical']];
            }
            curl_multi_remove_handle($mh, $ch);
            $this->closeCurl($ch);
        }
        curl_multi_close($mh);

        if (!empty($exposed)) {
            foreach ($exposed as $f) {
                $this->addFinding('Exposed Files', 'Sensitive File Accessible', $f['critical'] ? 'critical' : 'warning',
                    "Accessible: {$f['path']} — {$f['desc']}",
                    'Restrict via server config or move outside web root.');
            }
        } else {
            $this->addFinding('Exposed Files', 'Sensitive File Check', 'pass', 'No common sensitive files publicly accessible.');
        }

        // Transparency: tell the user when the host returns 200 for missing paths,
        // since that is the usual cause of file-exposure false positives.
        if ($this->getBaseline()['catchall']) {
            $this->addFinding('Exposed Files', 'Soft-404 / Catch-all', 'info',
                'The server returns HTTP 200 for non-existent paths (soft-404 / catch-all). File and endpoint checks were validated by content signature against a baseline to avoid false positives.',
                'Optionally configure the server to return a real 404 status for unknown paths so security tooling and crawlers behave correctly.');
        }
    }

    private function checkAdminEndpoints(): void
    {
        $endpoints = [
            '/wp-admin/'                 => ['WordPress Admin Panel',                  true],
            '/administrator/'            => ['Joomla Admin Panel',                     true],
            '/phpmyadmin/'               => ['phpMyAdmin Database Manager',            true],
            '/adminer.php'               => ['Adminer Database Tool',                  true],
            '/adminer/'                  => ['Adminer Directory',                      true],
            '/xmlrpc.php'                => ['WordPress XML-RPC (common attack vector)', true],
            '/readme.html'               => ['WordPress Readme (version disclosure)',  false],
            '/wp-debug.log'              => ['WordPress Debug Log (credential leakage)', true],
            '/storage/logs/laravel.log'  => ['Laravel Application Log',               true],
            '/.aws/credentials'          => ['AWS Credentials File',                  true],
            '/server-status'             => ['Apache Server Status',                   true],
            '/server-info'               => ['Apache Server Info',                     true],
            '/actuator/health'           => ['Spring Boot Actuator Health Endpoint',   true],
            '/actuator/env'              => ['Spring Boot Actuator Env (config dump)', true],
            '/config.php'                => ['PHP Config File',                        true],
            '/install.php'               => ['Install Script (should be removed)',     true],
            '/setup.php'                 => ['Setup Script (should be removed)',       true],
        ];

        $base    = $this->originBase();
        $mh      = curl_multi_init();
        $handles = [];

        foreach ($endpoints as $path => [$desc, $critical]) {
            $ch = curl_init();
            curl_setopt_array($ch, $this->withAuth([
                CURLOPT_URL            => $base . $path,
                CURLOPT_RESOLVE        => $this->pinResolve(),
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 6,
                CURLOPT_CONNECTTIMEOUT => 4,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_USERAGENT => self::TARGET_USER_AGENT,
                CURLOPT_SSL_VERIFYPEER => false,
            ]));
            $handles[$path] = ['handle' => $ch, 'desc' => $desc, 'critical' => $critical];
            curl_multi_add_handle($mh, $ch);
        }

        $running = null;
        do { curl_multi_exec($mh, $running); curl_multi_select($mh, 0.5); } while ($running > 0);

        $exposed = [];
        foreach ($handles as $path => $info) {
            $ch   = $info['handle'];
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $body = (string)(curl_multi_getcontent($ch) ?? '');

            if ($code !== 200 || strlen($body) === 0 || $this->matchesBaseline($body)) {
                curl_multi_remove_handle($mh, $ch);
                $this->closeCurl($ch);
                continue;
            }

            // Each endpoint needs a positive fingerprint. Severity is chosen by what is
            // actually exposed: a *login page* being reachable is a warning (extremely
            // common, still authenticated), while a config/credential/log dump or an
            // unauthenticated DB tool is critical.
            $hit = null; // [severity, note]
            switch (true) {
                case $path === '/xmlrpc.php':
                    if (str_contains($body, 'XML-RPC') || str_contains($body, 'methodCall') || str_contains($body, 'methodResponse'))
                        $hit = ['warning', 'XML-RPC reachable — common brute-force/DDoS vector'];
                    break;
                case $path === '/readme.html':
                    if (stripos($body, 'WordPress') !== false && stripos($body, 'Version') !== false)
                        $hit = ['warning', 'version disclosure'];
                    break;
                case $path === '/wp-debug.log':
                    if (preg_match('/PHP (Notice|Warning|Error|Fatal)|Stack trace/i', $body))
                        $hit = ['critical', 'debug log with internal errors exposed'];
                    break;
                case str_contains($path, 'laravel.log'):
                    if (preg_match('/\[\d{4}-\d{2}-\d{2}.*\]\s*(production|local|staging)?\.?(ERROR|WARNING|INFO)/i', $body) || preg_match('/\[\d{4}-\d{2}-\d{2}/', $body) && stripos($body, 'stack trace') !== false)
                        $hit = ['critical', 'application log exposed'];
                    break;
                case str_contains($path, 'actuator'):
                    if (preg_match('/"status"\s*:|"UP"|"DOWN"|"propertySources"|"activeProfiles"|"diskSpace"/', $body))
                        $hit = ['critical', 'Spring Boot Actuator data exposed'];
                    break;
                case str_contains($path, 'phpmyadmin'):
                    if (stripos($body, 'phpMyAdmin') !== false) {
                        $isLogin = stripos($body, 'input_username') !== false || stripos($body, 'pma_username') !== false || stripos($body, 'login_form') !== false || stripos($body, 'name="pma_password"') !== false;
                        $hit = $isLogin ? ['warning', 'login page reachable — restrict by IP/VPN'] : ['critical', 'phpMyAdmin reachable without an obvious login gate'];
                    }
                    break;
                case str_contains($path, 'adminer'):
                    if (stripos($body, 'Adminer') !== false || stripos($body, 'adminer.org') !== false) {
                        $isLogin = stripos($body, 'login') !== false || stripos($body, 'name="auth') !== false;
                        $hit = $isLogin ? ['warning', 'login page reachable — restrict by IP/VPN'] : ['critical', 'Adminer reachable without an obvious login gate'];
                    }
                    break;
                case $path === '/wp-admin/':
                    if (stripos($body, 'wp-login') !== false || stripos($body, 'user_login') !== false || stripos($body, 'id="loginform"') !== false)
                        $hit = ['warning', 'login page reachable (normal for WordPress) — add IP allowlist / 2FA / rate-limiting'];
                    break;
                case $path === '/administrator/':
                    if (stripos($body, 'Joomla') !== false || stripos($body, 'com_login') !== false || stripos($body, 'mod-login') !== false || stripos($body, 'form-login') !== false)
                        $hit = ['warning', 'Joomla admin login reachable — restrict access'];
                    break;
                case str_contains($path, 'server-status'):
                    if (preg_match('/Apache Server Status|Server uptime|Total Traffic|requests currently being processed/i', $body))
                        $hit = ['critical', 'Apache server-status exposed (internal traffic/IPs)'];
                    break;
                case str_contains($path, 'server-info'):
                    if (preg_match('/Apache Server Information|Server Settings|Module Name|Configuration Files/i', $body))
                        $hit = ['critical', 'Apache server-info exposed (full config)'];
                    break;
                case str_contains($path, 'credentials'):
                    if (preg_match('/aws_access_key_id|aws_secret_access_key/i', $body))
                        $hit = ['critical', 'AWS credentials file exposed'];
                    break;
                case $path === '/config.php':
                    if (preg_match('/DB_(NAME|USER|PASSWORD)|\$config\b|define\s*\(\s*[\'"]DB_|mysqli?_connect|new\s+PDO/i', $body))
                        $hit = ['critical', 'PHP config source exposed (likely DB credentials)'];
                    break;
                case $path === '/install.php' || $path === '/setup.php':
                    if (preg_match('/install|setup|configuration wizard|step\s*\d/i', $body) && stripos($body, '<form') !== false)
                        $hit = ['warning', 'installer/setup script reachable — remove after installation'];
                    break;
            }

            if ($hit !== null) {
                $exposed[] = ['path' => $path, 'desc' => $info['desc'], 'severity' => $hit[0], 'note' => $hit[1]];
            }

            curl_multi_remove_handle($mh, $ch);
            $this->closeCurl($ch);
        }
        curl_multi_close($mh);

        if (!empty($exposed)) {
            foreach ($exposed as $f) {
                $this->addFinding('Exposed Files', 'Admin/Sensitive Endpoint', $f['severity'],
                    "Accessible: {$f['path']} — {$f['desc']}" . (!empty($f['note']) ? " ({$f['note']})" : ''),
                    'Restrict via server config, IP allowlist, authentication, or remove if not needed.');
            }
        } else {
            $this->addFinding('Exposed Files', 'Admin Endpoint Check', 'pass',
                'No common admin panels or sensitive endpoints publicly accessible.');
        }
    }

    private function looksLikeErrorPage(string $body): bool
    {
        $lower = strtolower(substr($body, 0, 2000));
        return str_contains($lower, '404 not found')
            || str_contains($lower, 'page not found')
            || str_contains($lower, '403 forbidden')
            || str_contains($lower, 'access denied')
            || str_contains($lower, 'access forbidden')
            || str_contains($lower, '500 internal server error')
            || str_contains($lower, 'object not found');
    }

    // ================================================================
    //  12. SECURITY.TXT & ROBOTS.TXT
    // ================================================================

    private function checkSecurityTxt(): void
    {
        $base  = $this->originBase();
        foreach (['/.well-known/security.txt', '/security.txt'] as $path) {
            $ch = curl_init();
            curl_setopt_array($ch, [CURLOPT_URL => $base . $path, CURLOPT_RESOLVE => $this->pinResolve(), CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 8, CURLOPT_USERAGENT => self::TARGET_USER_AGENT, CURLOPT_SSL_VERIFYPEER => false, CURLOPT_FOLLOWLOCATION => false]);
            $body = (string)curl_exec($ch);
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $this->closeCurl($ch);
            // A real security.txt is plain text with a Contact: field — not the
            // site's catch-all HTML shell. Guard against soft-404 false positives.
            if ($code === 200 && $body !== '' && stripos($body, 'Contact:') !== false
                && !$this->isHtmlBody($body) && !$this->matchesBaseline($body)) {
                $missing = [];
                if (stripos($body, 'Expires:') === false)    $missing[] = 'Expires';
                if (stripos($body, 'Encryption:') === false) $missing[] = 'Encryption (recommended)';
                if ($missing) $this->addFinding('Security', 'security.txt', 'info', "security.txt at {$path} missing: " . implode(', ', $missing) . '.', 'See RFC 9116.');
                else $this->addFinding('Security', 'security.txt', 'pass', "security.txt well-formed at {$path}.");
                return;
            }
        }
        $this->addFinding('Security', 'security.txt', 'info', 'No security.txt found.', 'Create /.well-known/security.txt per RFC 9116.');
    }

    private function checkRobotsTxt(): void
    {
        $ch = curl_init();
        curl_setopt_array($ch, [CURLOPT_URL => $this->originBase() . '/robots.txt', CURLOPT_RESOLVE => $this->pinResolve(), CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 8, CURLOPT_USERAGENT => self::TARGET_USER_AGENT, CURLOPT_SSL_VERIFYPEER => false, CURLOPT_FOLLOWLOCATION => false]);
        $body = (string)curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $this->closeCurl($ch);
        // Must look like an actual robots.txt directive file — not the catch-all
        // HTML shell that a soft-404 server returns for every path.
        $looksLikeRobots = (bool)preg_match('/^\s*(User-agent|Disallow|Allow|Sitemap|Crawl-delay)\s*:/im', $body);
        if ($code !== 200 || $body === '' || $this->isHtmlBody($body) || $this->matchesBaseline($body) || !$looksLikeRobots) {
            $this->addFinding('Security', 'robots.txt', 'info', 'No robots.txt found.', 'Add a robots.txt to manage crawler access.');
            return;
        }
        $sensitive = ['/admin', '/backup', '/config', '/private', '/secret', '/staging', '/dev', '/test', '/api/internal', '/.env', '/db'];
        $disclosed = [];
        foreach ($sensitive as $p) { if (stripos($body, "Disallow: {$p}") !== false || stripos($body, "Allow: {$p}") !== false) $disclosed[] = $p; }
        if (!empty($disclosed)) $this->addFinding('Security', 'robots.txt Path Disclosure', 'info', 'robots.txt reveals paths: ' . implode(', ', $disclosed) . '.', 'Ensure these paths are properly access-controlled.');
        else $this->addFinding('Security', 'robots.txt', 'pass', 'robots.txt found with no sensitive path disclosures.');
    }

    // ================================================================
    //  13. OPEN PORT SCAN — PARALLEL NON-BLOCKING
    //  Fix: replaced sequential fsockopen (16 × 1.5s = 24s) with
    //  stream_select-based parallel scan (~1.5s total wall time)
    // ================================================================

    private function checkOpenPorts(): void
    {
        $host = $this->hostname;

        $ports = [
            21    => ['FTP',        'critical', 'FTP transmits credentials in plaintext. Use SFTP or disable.'],
            22    => ['SSH',        'pass',     'SSH open — expected for remote management.'],
            23    => ['Telnet',     'critical', 'Telnet is unencrypted. Disable immediately.'],
            25    => ['SMTP',       'warning',  'SMTP open — ensure it is not an open relay.'],
            53    => ['DNS',        'pass',     'DNS port open — expected for nameservers.'],
            80    => ['HTTP',       'pass',     'HTTP open — should redirect to HTTPS.'],
            110   => ['POP3',       'warning',  'POP3 open. Enforce TLS.'],
            143   => ['IMAP',       'warning',  'IMAP open. Enforce STARTTLS/993.'],
            443   => ['HTTPS',      'pass',     'HTTPS port open — expected.'],
            445   => ['SMB',        'critical', 'SMB exposed — high risk (EternalBlue etc). Block immediately.'],
            3306  => ['MySQL',      'critical', 'MySQL publicly accessible — never expose database ports.'],
            5432  => ['PostgreSQL', 'critical', 'PostgreSQL publicly accessible — restrict via firewall.'],
            6379  => ['Redis',      'critical', 'Redis publicly accessible — unauthenticated access risk.'],
            8080  => ['Alt-HTTP',   'info',     'Alternate HTTP port open.'],
            8443  => ['Alt-HTTPS',  'info',     'Alternate HTTPS port open.'],
            27017 => ['MongoDB',    'critical', 'MongoDB publicly accessible — restrict immediately.'],
        ];

        // Phase 1 — connect all sockets simultaneously (non-blocking async)
        $timeout = 1.5;
        $sockets = [];

        foreach ($ports as $port => $info) {
            $errno = 0; $errstr = '';
            $sock  = @stream_socket_client(
                "tcp://{$this->connectHost()}:{$port}",
                $errno, $errstr,
                $timeout,
                STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT
            );
            if ($sock !== false) {
                stream_set_blocking($sock, false);
                $sockets[$port] = $sock;
            }
        }

        // Phase 2 — poll writable sockets. NOTE: a non-blocking connect() marks
        // the descriptor writable both when it SUCCEEDS and when it fails
        // immediately (e.g. ECONNREFUSED/RST) — see Stevens, "UNIX Network
        // Programming" §16.3. Writability alone cannot tell the two apart, so
        // "writable" only makes a port a *candidate*; verifyConnectedSocket()
        // below confirms it before it is ever reported as open.
        $deadline   = microtime(true) + $timeout;
        $candidates = [];

        while (!empty($sockets) && microtime(true) < $deadline) {
            $read   = null;
            $write  = array_values($sockets);
            $except = null;

            $n = @stream_select($read, $write, $except, 0, 200000); // 200ms polling slice
            if ($n === false || $n === 0) { usleep(10000); continue; }

            foreach ($write as $sock) {
                $port = array_search($sock, $sockets, true);
                if ($port === false) continue;
                $candidates[$port] = $sock;
                unset($sockets[$port]);
            }
        }

        // Close sockets that never became writable within the deadline — no
        // response (silently filtered/dropped) is correctly treated as closed.
        foreach ($sockets as $sock) { @fclose($sock); }

        // Phase 3 — verify each candidate actually connected, then report.
        $openPorts = [];
        foreach ($candidates as $port => $sock) {
            if ($this->verifyConnectedSocket($sock)) {
                $openPorts[$port] = $ports[$port];
            }
            @fclose($sock);
        }

        if (empty($openPorts)) {
            $this->addFinding('Ports', 'Port Scan', 'pass', 'No unexpected open ports detected.');
            return;
        }

        ksort($openPorts);
        foreach ($openPorts as $port => [$service, $sev, $msg]) {
            $this->addFinding('Ports', "Port {$port} ({$service})", $sev,
                "Port {$port} ({$service}) is open. {$msg}");
        }
    }

    /**
     * Disambiguate a "writable" async-connect socket from checkOpenPorts().
     * A non-blocking connect() marks the descriptor writable both on success
     * AND on an immediate refusal (RST), so writability alone is not proof
     * the port is actually open — without this check, an actively-refused
     * (fully closed) port would be misreported as "open", including for the
     * critical-severity ports (MySQL/Redis/MongoDB/SMB) this check exists to
     * flag. Verified empirically: on Linux, connecting to a closed TCP port
     * makes the socket both readable AND writable in select(), with
     * getsockopt(SO_ERROR) reporting ECONNREFUSED.
     *
     * Prefers getsockopt(SO_ERROR) via ext-sockets when available (definitive
     * proof either way). Falls back to a short read probe when ext-sockets is
     * not loaded: a refused/reset connection surfaces as an immediate EOF,
     * while a genuinely open port either sends a banner (SSH, FTP, MySQL, …)
     * or simply has nothing to say yet — in which case the read times out
     * without EOF, which still counts as "open".
     */
    private function verifyConnectedSocket($sock): bool
    {
        if (function_exists('socket_import_stream') && function_exists('socket_get_option')) {
            $s = @socket_import_stream($sock);
            if ($s !== false) {
                $err = @socket_get_option($s, SOL_SOCKET, SO_ERROR);
                if (is_int($err)) {
                    return $err === 0;
                }
            }
        }

        stream_set_blocking($sock, true);
        stream_set_timeout($sock, 0, 250000); // 250ms peek
        $byte = @fread($sock, 1);
        $meta = stream_get_meta_data($sock);

        if ($byte !== '' && $byte !== false) {
            return true; // server sent data unprompted — genuinely connected
        }
        if (!empty($meta['timed_out'])) {
            return true; // no data yet, but the socket did not close — still open
        }
        // Empty read with no timeout means the peer closed/reset the
        // connection immediately — the earlier "writable" signal was a
        // failed connect (refused port), not a successful one.
        return false;
    }

    // ================================================================
    //  DNS LANJUTAN: CAA, MTA-STS, TLS-RPT, BIMI
    // ================================================================

    private function checkCAA(): void
    {
        $baseDomain = preg_replace('/^www\./i', '', $this->hostname);

        $caaFound = false;

        // PHP 7.4+ mendedahkan DNS_CAA constant
        if (defined('DNS_CAA')) {
            $records = @dns_get_record($baseDomain, DNS_CAA) ?: [];
            if (!empty($records)) {
                $caaFound = true;
                $issuers = [];
                foreach ($records as $r) {
                    if (isset($r['tag']) && $r['tag'] === 'issue' && isset($r['value'])) {
                        $issuers[] = $r['value'];
                    }
                }
                $this->addFinding('DNS', 'CAA Record', 'pass',
                    'CAA record found for ' . $baseDomain . ($issuers ? ' — issuers: ' . implode(', ', $issuers) : '') . '.',
                    'Verify the listed CAs match your certificate provider.');
            }
        }

        // Fallback: dig jika PHP tidak dedahkan DNS_CAA
        if (!$caaFound) {
            $digPath = $this->getDigPath();
            if ($digPath !== null) {
                $dig = escapeshellcmd($digPath);
                $arg = escapeshellarg($baseDomain);
                $output = trim((string)@shell_exec("{$dig} +time=3 +tries=1 +short {$arg} CAA 2>/dev/null"));
                if ($output !== '') {
                    $caaFound = true;
                    $this->addFinding('DNS', 'CAA Record', 'pass',
                        'CAA record found via dig for ' . $baseDomain . ': ' . substr($output, 0, 120),
                        'Verify the listed CAs match your certificate provider.');
                }
            }
        }

        if (!$caaFound) {
            $this->addFinding('DNS', 'CAA Record', 'warning',
                'No CAA record found for ' . $baseDomain . '. Any CA can issue certificates for this domain.',
                'Add CAA record to restrict cert issuance. Example: ' . $baseDomain . ' CAA 0 issue "letsencrypt.org"');
        }
    }

    private function checkMTASTS(): void
    {
        $baseDomain = preg_replace('/^www\./i', '', $this->hostname);

        // MTA-STS TXT record
        $hasMtaSts = false;
        $mtaStsTxt = @dns_get_record("_mta-sts.{$baseDomain}", DNS_TXT) ?: [];
        foreach ($mtaStsTxt as $r) {
            $txt = is_array($r['entries'] ?? null) ? implode('', $r['entries']) : ($r['txt'] ?? '');
            if (stripos($txt, 'v=STSv1') === 0) {
                $hasMtaSts = true;
                break;
            }
        }

        if ($hasMtaSts) {
            $this->addFinding('DNS', 'MTA-STS', 'pass',
                "MTA-STS record found for {$baseDomain} — SMTP connections must use TLS.",
                'Ensure mta-sts.' . $baseDomain . '/.well-known/mta-sts.txt is published and up to date.');
        } else {
            $this->addFinding('DNS', 'MTA-STS', 'info',
                "No MTA-STS record found for {$baseDomain}.",
                "MTA-STS enforces TLS for incoming email. Add: _mta-sts.{$baseDomain} TXT \"v=STSv1; id=$(date +%Y%m%d)\" and publish the policy file.");
        }

        // TLS-RPT — SMTP TLS reporting
        $hasTlsRpt = false;
        $tlsRptRecs = @dns_get_record("_smtp._tls.{$baseDomain}", DNS_TXT) ?: [];
        foreach ($tlsRptRecs as $r) {
            $txt = is_array($r['entries'] ?? null) ? implode('', $r['entries']) : ($r['txt'] ?? '');
            if (stripos($txt, 'v=TLSRPTv1') === 0) {
                $hasTlsRpt = true;
                break;
            }
        }

        if ($hasTlsRpt) {
            $this->addFinding('DNS', 'TLS-RPT', 'pass',
                "TLS-RPT record found — SMTP TLS failure reports enabled.");
        } else {
            $this->addFinding('DNS', 'TLS-RPT', 'info',
                "No TLS-RPT record found.",
                "Add: _smtp._tls.{$baseDomain} TXT \"v=TLSRPTv1; rua=mailto:tlsrpt@{$baseDomain}\" to receive SMTP TLS failure reports.");
        }
    }

    private function checkBIMI(): void
    {
        $baseDomain = preg_replace('/^www\./i', '', $this->hostname);

        $bimiRecs = @dns_get_record("default._bimi.{$baseDomain}", DNS_TXT) ?: [];
        foreach ($bimiRecs as $r) {
            $txt = is_array($r['entries'] ?? null) ? implode('', $r['entries']) : ($r['txt'] ?? '');
            if (stripos($txt, 'v=BIMI1') === 0) {
                $hasVmc = stripos($txt, 'a=') !== false && stripos($txt, '.pem') !== false;
                $this->addFinding('DNS', 'BIMI', 'pass',
                    "BIMI record found for {$baseDomain}" . ($hasVmc ? ' with VMC certificate (fully verified)' : ' (no VMC — logo may not show in all clients)') . '.',
                    $hasVmc ? '' : 'Add a Verified Mark Certificate (VMC) for full BIMI support across all email clients.');
                return;
            }
        }

        $this->addFinding('DNS', 'BIMI', 'info',
            "No BIMI record found for {$baseDomain}.",
            "BIMI displays your brand logo in supporting email clients. Requires DMARC p=reject. Add: default._bimi.{$baseDomain} TXT \"v=BIMI1; l=https://{$baseDomain}/logo.svg\"");
    }

    // ================================================================
    //  MODERN SECURITY HEADERS
    // ================================================================

    private function checkModernHeaders(): void
    {
        // Report-To / Reporting-Endpoints
        $reportTo    = $this->getHeader('Report-To');
        $reportingEP = $this->getHeader('Reporting-Endpoints');
        if ($reportingEP) {
            $this->addFinding('Headers', 'Reporting-Endpoints', 'pass',
                'Reporting-Endpoints header present — violation reports will be collected.',
                'Ensure the report endpoint is actively monitored.');
        } elseif ($reportTo) {
            $this->addFinding('Headers', 'Report-To (Legacy)', 'pass',
                'Report-To header present. Consider migrating to the newer Reporting-Endpoints header.');
        } else {
            $this->addFinding('Headers', 'Security Reporting', 'info',
                'No Reporting-Endpoints or Report-To header.',
                'Add Reporting-Endpoints to collect CSP, CORS, and NEL violation reports.');
        }

        // NEL — Network Error Logging
        $nel = $this->getHeader('NEL');
        if ($nel) {
            $this->addFinding('Headers', 'Network Error Logging (NEL)', 'pass',
                'NEL header present — network failures will be reported to the endpoint.');
        } else {
            $this->addFinding('Headers', 'Network Error Logging (NEL)', 'info',
                'NEL header not set.',
                'Add: NEL: {"report_to":"default","max_age":86400,"include_subdomains":true} to log network errors.');
        }

        // Origin-Agent-Cluster
        $oac = $this->getHeader('Origin-Agent-Cluster');
        if ($oac === '?1') {
            $this->addFinding('Headers', 'Origin-Agent-Cluster', 'pass',
                'Origin-Agent-Cluster: ?1 — origin-keyed agent cluster enabled for side-channel isolation.');
        } else {
            $this->addFinding('Headers', 'Origin-Agent-Cluster', 'info',
                'Origin-Agent-Cluster header not set.',
                'Add: Origin-Agent-Cluster: ?1 to enable process isolation per origin (mitigates some side-channel attacks).');
        }

        // Clear-Site-Data — only meaningful on logout/sign-out endpoints, note if present
        $csd = $this->getHeader('Clear-Site-Data');
        if ($csd) {
            $this->addFinding('Headers', 'Clear-Site-Data', 'pass',
                "Clear-Site-Data header present: {$csd}. Appropriate on sign-out pages to wipe cached credentials.");
        }
    }

    // ================================================================
    //  DANGEROUS HTTP METHODS  (TRACE / XST, PUT, DELETE …)
    // ================================================================

    private function checkHTTPMethods(): void
    {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $this->url,
            CURLOPT_RESOLVE        => $this->pinResolve(),
            CURLOPT_CUSTOMREQUEST  => 'OPTIONS',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_NOBODY         => true,
            CURLOPT_TIMEOUT        => 8,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_USERAGENT => self::TARGET_USER_AGENT,
            CURLOPT_SSL_VERIFYPEER => false,
        ]);
        $resp = (string)@curl_exec($ch);
        $this->closeCurl($ch);

        $allow = '';
        if (preg_match('/^Allow:\s*(.+)$/mi', $resp, $m)) {
            $allow = strtoupper(trim($m[1]));
        }

        $risky = [];
        foreach (['TRACE', 'TRACK', 'PUT', 'DELETE', 'CONNECT', 'PATCH'] as $method) {
            if ($allow !== '' && str_contains($allow, $method)) {
                $risky[] = $method;
            }
        }

        // Actively probe TRACE — XST lets script read otherwise-HttpOnly cookies.
        $traceEnabled = false;
        $ch2 = curl_init();
        curl_setopt_array($ch2, [
            CURLOPT_URL            => $this->url,
            CURLOPT_RESOLVE        => $this->pinResolve(),
            CURLOPT_CUSTOMREQUEST  => 'TRACE',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 8,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_USERAGENT => self::TARGET_USER_AGENT,
            CURLOPT_SSL_VERIFYPEER => false,
        ]);
        $traceBody = (string)@curl_exec($ch2);
        $traceCode = (int)curl_getinfo($ch2, CURLINFO_HTTP_CODE);
        $this->closeCurl($ch2);
        if ($traceCode === 200 && stripos($traceBody, 'TRACE') !== false) {
            $traceEnabled = true;
        }

        if ($traceEnabled || in_array('TRACE', $risky, true) || in_array('TRACK', $risky, true)) {
            $this->addFinding('Headers', 'HTTP TRACE Method', 'warning',
                'The HTTP TRACE/TRACK method is enabled — this can enable Cross-Site Tracing (XST) to steal HttpOnly cookies.',
                'Disable TRACE/TRACK at the web server (Apache: "TraceEnable Off"; Nginx: only allow needed methods).');
        }

        $writeMethods = array_values(array_intersect(['PUT', 'DELETE', 'PATCH', 'CONNECT'], $risky));
        if (!empty($writeMethods)) {
            $this->addFinding('Headers', 'Write HTTP Methods', 'warning',
                'Allow header advertises potentially dangerous method(s): ' . implode(', ', $writeMethods) . '.',
                'Restrict to GET/HEAD/POST unless the endpoint is a deliberate REST/WebDAV API with authentication.');
        }

        if (!$traceEnabled && empty($risky)) {
            $this->addFinding('Headers', 'HTTP Methods', 'pass',
                $allow !== '' ? "Only safe methods advertised: {$allow}." : 'No dangerous HTTP methods detected.');
        }
    }

    // ================================================================
    //  WAF / EDGE PROTECTION FINGERPRINTING
    // ================================================================

    private function checkWAF(): void
    {
        $signatures = [
            'Cloudflare'            => ['headers' => ['cf-ray', 'cf-cache-status', 'cf-request-id', 'cf-mitigated'], 'server' => ['cloudflare'], 'cookies' => ['__cfduid', '__cf_bm', 'cf_clearance'], 'body' => ['attention required! | cloudflare', 'cloudflare ray id', 'checking your browser before accessing']],
            'AWS WAF / CloudFront'  => ['headers' => ['x-amz-cf-id', 'x-amzn-requestid', 'x-amz-apigw-id'], 'server' => ['awselb', 'cloudfront'], 'cookies' => ['aws-waf-token'], 'body' => ['request blocked']],
            'Akamai'                => ['headers' => ['x-akamai-transformed', 'akamai-grn'], 'server' => ['akamaighost'], 'cookies' => ['ak_bmsc', 'bm_sz', '_abck'], 'body' => ['access denied', 'reference #']],
            'Imperva / Incapsula'   => ['headers' => ['x-iinfo', 'x-cdn'], 'server' => ['incapsula'], 'cookies' => ['incap_ses', 'visid_incap'], 'body' => ['incapsula incident id', 'powered by incapsula']],
            'Sucuri'                => ['headers' => ['x-sucuri-id', 'x-sucuri-cache'], 'server' => ['sucuri/cloudproxy'], 'cookies' => [], 'body' => ['sucuri website firewall', 'access denied - sucuri']],
            'F5 BIG-IP ASM'         => ['headers' => [], 'server' => ['big-ip', 'bigip'], 'cookies' => ['ts', 'bigipserver', 'bnis_x-bni-jas', 'x-bni-ci', 'f5_cspm'], 'body' => ['the requested url was rejected', 'validation request', 'user validation required', 'captcha_resp', 'web page blocked']],
            'Barracuda'             => ['headers' => [], 'server' => ['barracuda'], 'cookies' => ['barra_counter_session'], 'body' => ['barracuda']],
            'Fastly'                => ['headers' => ['x-fastly-request-id', 'fastly-debug-digest'], 'server' => ['fastly'], 'cookies' => [], 'body' => []],
            'Azure (Front Door/WAF)'=> ['headers' => ['x-azure-ref', 'x-msedge-ref'], 'server' => [], 'cookies' => [], 'body' => []],
            'Wordfence'             => ['headers' => [], 'server' => [], 'cookies' => ['wordfence_verifiedhuman'], 'body' => ['generated by wordfence']],
            'ModSecurity'           => ['headers' => ['x-mod-security'], 'server' => ['mod_security', 'modsecurity'], 'cookies' => [], 'body' => ['mod_security', 'this error was generated by mod_security']],
            'Fortinet FortiWeb'     => ['headers' => ['x-fortiweb'], 'server' => ['fortiweb'], 'cookies' => ['fortiwafsid'], 'body' => ['fortiweb']],
            'Citrix ADC / NetScaler'=> ['headers' => ['ns_af', 'citrix_ns_id', 'x-citrix-application'], 'server' => ['netscaler', 'citrix adc'], 'cookies' => ['nsc_', 'citrix_ns_id', 'ns_af'], 'body' => ['citrix adc', 'netscaler application firewall']],
            'Radware AppWall'       => ['headers' => ['x-sl-compstate', 'x-sl-request-id'], 'server' => ['radware'], 'cookies' => ['rdwr'], 'body' => ['radware appwall', 'appwall']],
            'Wallarm'               => ['headers' => ['x-wallarm-request-id'], 'server' => ['wallarm'], 'cookies' => [], 'body' => ['wallarm']],
            'Reblaze'               => ['headers' => ['x-reblaze-id'], 'server' => ['reblaze'], 'cookies' => ['rbzid', 'rbzsessionid'], 'body' => ['reblaze']],
            'DDoS-Guard'            => ['headers' => ['x-ddos-guard'], 'server' => ['ddos-guard'], 'cookies' => ['__ddg1_', '__ddgid_', '__ddgmark_'], 'body' => ['ddos-guard']],
            'StackPath'             => ['headers' => ['x-sp-cache', 'x-stackpath-cache'], 'server' => ['stackpath'], 'cookies' => ['sp_lit'], 'body' => ['stackpath']],
            'NAXSI'                 => ['headers' => ['x-naxsi'], 'server' => [], 'cookies' => [], 'body' => ['naxsi']],
            'Imunify360'            => ['headers' => [], 'server' => [], 'cookies' => ['imunify360_uuid', 'imunify360_uid'], 'body' => ['imunify360']],
            'CloudWAF / Huawei Cloud WAF' => ['headers' => [], 'server' => ['cloudwaf'], 'cookies' => ['hwwafsesid', 'hwwafsestime'], 'body' => ['cloudwaf']],
        ];

        $headersForWaf = $this->primaryResponseHeaders ?: $this->responseHeaders;
        $bodyForWaf = $this->primaryResponseBody !== '' ? $this->primaryResponseBody : $this->responseBody;
        $cookiesForWaf = $this->primaryCookies ?: $this->cookies;
        $seed = strtolower(json_encode($headersForWaf, JSON_UNESCAPED_SLASHES) . ' ' . implode(' ', $cookiesForWaf) . ' ' . substr($bodyForWaf, 0, 4000));
        if (!preg_match('/cf-ray|cloudflare|bnis_x-bni-jas|x-bni-ci|bigip|incap_ses|visid_incap|hwwaf|x-sucuri|akamai|aws-waf|x-wallarm|x-ddos-guard|x-sl-request-id|fortiwaf|citrix|nsc_|mod_security|validation request|captcha_resp/i', $seed)) {
            $probe = $this->fetchWafFingerprintProbe();
            foreach ($probe['headers'] as $name => $values) {
                $headersForWaf[$name] = array_merge($headersForWaf[$name] ?? [], $values);
            }
            $cookiesForWaf = array_merge($cookiesForWaf, $probe['cookies']);
            if ($bodyForWaf === '' && $probe['body'] !== '') {
                $bodyForWaf = $probe['body'];
            }
        }
        $getWafHeader = static fn(string $name): ?string => $headersForWaf[strtolower($name)][0] ?? null;

        $serverHdr = strtolower($getWafHeader('server') ?? '');
        $bodyLower = strtolower(substr($bodyForWaf, 0, 100000));
        $cookieNames = [];
        foreach ($cookiesForWaf as $cookie) {
            $name = strtolower(trim(explode('=', explode(';', $cookie, 2)[0], 2)[0] ?? ''));
            if ($name !== '') {
                $cookieNames[] = $name;
            }
        }
        $cookieMatches = static function (string $needle) use ($cookieNames): bool {
            $needle = strtolower($needle);
            foreach ($cookieNames as $name) {
                if ($name === $needle || str_starts_with($name, $needle)) {
                    return true;
                }
            }
            return false;
        };

        $detected = [];
        $evidence = [];
        foreach ($signatures as $name => $sig) {
            foreach ($sig['headers'] as $h) {
                if ($getWafHeader($h) !== null) {
                    $detected[$name] = true;
                    $evidence[$name][] = "header {$h}";
                }
            }
            foreach ($sig['server'] as $s) {
                if ($s !== '' && str_contains($serverHdr, $s)) {
                    $detected[$name] = true;
                    $evidence[$name][] = "server {$s}";
                }
            }
            foreach ($sig['cookies'] as $c) {
                if ($c !== '' && $cookieMatches($c)) {
                    $detected[$name] = true;
                    $evidence[$name][] = "cookie {$c}";
                }
            }
            foreach ($sig['body'] as $b) {
                if ($b !== '' && str_contains($bodyLower, $b)) {
                    $detected[$name] = true;
                    $evidence[$name][] = "body marker {$b}";
                }
            }
        }

        if (!empty($detected)) {
            $list = implode(', ', array_keys($detected));
            $this->detectedWafVendors = array_keys($detected);
            $this->detectedWafSignals = array_map(
                static fn(array $signals): array => array_values(array_unique($signals)),
                $evidence
            );
            $signalSummary = [];
            foreach ($this->detectedWafVendors as $vendor) {
                $sigList = $this->detectedWafSignals[$vendor] ?? [];
                if ($sigList !== []) {
                    $signalSummary[] = $vendor . ' (' . implode(', ', array_slice($sigList, 0, 2)) . ')';
                }
            }
            $this->addFinding('Technology', 'WAF / Edge Protection', 'pass',
                "Web Application Firewall / edge protection detected: {$list}. Signals: " . implode('; ', array_slice($signalSummary, 0, 4)) . ".",
                'Confirm the WAF is in blocking (not detection-only) mode and that rule sets are kept current.');
        } else {
            if ($this->applyWafOverride('waf_probe_no_fingerprint')) {
                return;
            }
            $this->detectedWafVendors = [];
            $this->detectedWafSignals = [];
            $this->addFinding('Technology', 'WAF / Edge Protection', 'info',
                'No Web Application Firewall fingerprint detected from headers, cookies, or body.',
                'A WAF (e.g. Cloudflare, AWS WAF, ModSecurity) adds a layer of protection against common web attacks. Absence is not a vulnerability by itself but reduces defence-in-depth.');
        }
    }

    private function applyWafOverride(string $reason = '', string $detail = ''): bool
    {
        if ($this->detectedWafVendors !== []) {
            return false;
        }

        $override = $this->lookupWafOverride($this->hostname);
        if ($override === null) {
            return false;
        }

        $vendors = array_values(array_filter(array_map(
            static fn($v): string => trim((string)$v),
            is_array($override['vendors'] ?? null) ? $override['vendors'] : []
        )));
        if ($vendors === []) {
            return false;
        }

        $signals = array_values(array_filter(array_map(
            static fn($v): string => trim((string)$v),
            is_array($override['signals'] ?? null) ? $override['signals'] : []
        )));
        $source = trim((string)($override['source'] ?? 'Local WAF evidence override'));
        if ($signals === []) {
            $signals = [$source];
        }

        $signalMap = [];
        foreach ($vendors as $vendor) {
            $signalMap[$vendor] = $signals;
        }

        $this->detectedWafVendors = $vendors;
        $this->detectedWafSignals = $signalMap;

        $message = 'WAF / edge protection identified from local evidence override: '
            . implode(', ', $vendors)
            . '. Signals: '
            . implode('; ', array_slice($signals, 0, 4))
            . '.';
        if ($detail !== '') {
            $message .= ' Scanner connection detail: ' . $detail;
        }

        $this->addFinding(
            'Technology',
            'WAF / Edge Protection',
            'info',
            $message,
            'Validate the fingerprint with the target owner and allowlist the SecScan server IP if authorised scanning should complete.',
            [],
            false
        );

        if ($reason === 'reachability_failure' && $this->scanBlocked === []) {
            $this->scanBlocked = [
                'type' => 'network_waf_timeout',
                'title' => 'Scan tidak dapat melengkapkan sambungan; WAF / firewall disyaki',
                'message' => 'Server SecScan tidak menerima respons daripada target, tetapi sistem mempunyai bukti fingerprint WAF untuk hostname ini.',
                'actions' => [
                    'Allowlist IP/server SecScan pada WAF, firewall, atau load balancer target.',
                    'Minta pemilik target sahkan fingerprint WAF dan window scan yang dibenarkan.',
                    'Ulang scan selepas akses dari server SecScan dibenarkan.',
                ],
            ];
        }

        return true;
    }

    private function lookupWafOverride(string $host): ?array
    {
        static $overrides = null;
        if ($overrides === null) {
            $paths = array_filter([
                getenv('SECSCAN_WAF_OVERRIDES_FILE') ?: null,
                __DIR__ . '/src/waf_overrides.json',
                __DIR__ . '/data/waf_overrides.json',
            ]);
            $overrides = [];
            foreach ($paths as $path) {
                if (!is_readable($path)) {
                    continue;
                }
                $raw = file_get_contents($path);
                $decoded = is_string($raw) ? json_decode($raw, true) : null;
                if (is_array($decoded)) {
                    $overrides = $decoded;
                    break;
                }
            }
        }

        $host = strtolower(rtrim(trim($host), '.'));
        if ($host === '' || $overrides === []) {
            return null;
        }

        $candidates = [$host];
        if (str_starts_with($host, 'www.')) {
            $candidates[] = substr($host, 4);
        } else {
            $candidates[] = 'www.' . $host;
        }

        foreach (array_unique($candidates) as $candidate) {
            if (isset($overrides[$candidate]) && is_array($overrides[$candidate])) {
                return $overrides[$candidate];
            }
        }

        return null;
    }

    private function fetchWafFingerprintProbe(): array
    {
        $headers = [];
        $cookies = [];
        $ch = curl_init();
        curl_setopt_array($ch, $this->withAuth([
            CURLOPT_URL            => $this->url,
            CURLOPT_RESOLVE        => $this->pinResolve(),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_NOBODY         => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT        => 8,
            CURLOPT_CONNECTTIMEOUT => 4,
            CURLOPT_USERAGENT => self::TARGET_USER_AGENT,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_1_1,
            CURLOPT_HEADERFUNCTION => static function ($ch, $header) use (&$headers, &$cookies) {
                $len = strlen($header);
                $parts = explode(':', $header, 2);
                if (count($parts) === 2) {
                    $name  = strtolower(trim($parts[0]));
                    $value = trim($parts[1]);
                    $headers[$name][] = $value;
                }
                if (stripos($header, 'Set-Cookie:') === 0) {
                    $cookies[] = trim(substr($header, 11));
                }
                return $len;
            },
        ]));
        $body = curl_exec($ch);
        $this->closeCurl($ch);

        return [
            'headers' => $headers,
            'cookies' => $cookies,
            'body'    => is_string($body) ? $body : '',
        ];
    }

    // ================================================================
    //  OUTDATED / END-OF-LIFE SOFTWARE ADVISORY
    // ================================================================

    private function checkOutdatedSoftware(): void
    {
        $flagged = false;

        // --- Server-side PHP version (X-Powered-By) -------------------
        $powered = $this->getHeader('x-powered-by') ?? '';
        if (preg_match('/PHP\/(\d+)\.(\d+)(?:\.(\d+))?/i', $powered, $m)) {
            $major = (int)$m[1]; $minor = (int)$m[2];
            $ver = "{$major}.{$minor}";
            // PHP branches < 8.2 are end-of-life as of mid-2026 (8.1 reached EOL
            // 2025-12-31; keep this cutoff moving forward as branches age out —
            // see https://www.php.net/supported-versions.php.
            if ($major < 8 || ($major === 8 && $minor < 2)) {
                $flagged = true;
                $this->addFinding('Technology', 'Outdated PHP', 'critical',
                    "PHP {$ver} is end-of-life and no longer receives security patches.",
                    'Upgrade to a supported PHP branch (8.3+). Check the EOL calendar at https://www.php.net/supported-versions.php.',
                    ['https://www.php.net/supported-versions.php', 'https://endoflife.date/php']);
            }
        }

        // --- Web server version vs. known-old majors ------------------
        $server = $this->getHeader('server') ?? '';
        if (preg_match('/Apache\/(\d+)\.(\d+)\.(\d+)/i', $server, $m)) {
            // 2.4.x is current; anything < 2.4 is very old.
            if ((int)$m[1] < 2 || ((int)$m[1] === 2 && (int)$m[2] < 4)) {
                $flagged = true;
                $this->addFinding('Technology', 'Outdated Apache', 'warning',
                    "Apache {$m[1]}.{$m[2]}.{$m[3]} is an outdated major branch.",
                    'Upgrade to the latest Apache 2.4.x and apply security patches.',
                    ['https://httpd.apache.org/security/vulnerabilities_24.html']);
            }
        }
        if (preg_match('/nginx\/(\d+)\.(\d+)\.(\d+)/i', $server, $m)) {
            // Current stable is 1.30.x as of mid-2026 (nginx.org/en/download.html);
            // flag anything more than a couple of minor releases behind. Update
            // this cutoff periodically as new stable branches ship.
            if ((int)$m[1] === 1 && (int)$m[2] < 28) {
                $flagged = true;
                $this->addFinding('Technology', 'Outdated nginx', 'warning',
                    "nginx {$m[1]}.{$m[2]}.{$m[3]} is behind the current stable branch.",
                    'Upgrade to the latest stable nginx and review the security advisories.',
                    ['https://nginx.org/en/security_advisories.html']);
            }
        }

        // --- Client-side JS libraries (version disclosure + known-old) -
        $body = $this->responseBody;
        $jsChecks = [
            'jQuery'    => ['/jquery[.-](\d+)\.(\d+)\.(\d+)(?:\.min)?\.js/i', 3, 0, 'jQuery < 3.x has known XSS issues (CVE-2019-11358, CVE-2020-11022/11023). Upgrade to jQuery 3.5+.'],
            'Bootstrap' => ['/bootstrap[.-](\d+)\.(\d+)\.(\d+)(?:\.min)?\.(?:js|css)/i', 4, 0, 'Bootstrap < 4.x has XSS issues in tooltip/popover data attributes. Upgrade to Bootstrap 5.x.'],
            'AngularJS' => ['/angular[.-](\d+)\.(\d+)\.(\d+)(?:\.min)?\.js/i', 999, 0, 'AngularJS (1.x) reached end-of-life in January 2022 and receives no security fixes. Migrate to a supported framework.'],
        ];
        foreach ($jsChecks as $lib => [$re, $minMajor, $minMinor, $advice]) {
            if (preg_match($re, $body, $m)) {
                $major = (int)$m[1]; $minor = (int)$m[2];
                $ver = "{$m[1]}.{$m[2]}.{$m[3]}";
                $isOld = ($lib === 'AngularJS') ? ($major === 1) : ($major < $minMajor);
                if ($isOld) {
                    $flagged = true;
                    $this->addFinding('Technology', "Outdated {$lib}", 'warning',
                        "{$lib} {$ver} detected on the page — a version with known security issues.",
                        $advice,
                        ['https://owasp.org/www-project-top-ten/', 'https://security.snyk.io/']);
                } else {
                    $this->addFinding('Technology', "{$lib} Version", 'info',
                        "{$lib} {$ver} detected (no known critical issues for this major version).",
                        'Keep front-end libraries patched and pinned to known-good versions.');
                }
            }
        }

        if (!$flagged) {
            $this->addFinding('Technology', 'Software Currency', 'pass',
                'No clearly end-of-life or known-vulnerable software versions were fingerprinted.',
                'Continue monitoring dependencies with a tool like Dependabot, Snyk, or Trivy.');
        }
    }

    // ================================================================
    //  SUBDOMAIN TAKEOVER (dangling CNAME / unclaimed service)
    // ================================================================

    private function checkSubdomainTakeover(): void
    {
        // Dangling-service fingerprints: CNAME target substring => [service, body fingerprint].
        $fingerprints = [
            's3.amazonaws.com'        => ['AWS S3',          'nosuchbucket'],
            'github.io'               => ['GitHub Pages',    "there isn't a github pages site here"],
            'herokudns.com'           => ['Heroku',          'no such app'],
            'herokuapp.com'           => ['Heroku',          'no such app'],
            'azurewebsites.net'       => ['Azure App Svc',   'error 404 - web app not found'],
            'cloudapp.azure.com'      => ['Azure',           'error 404'],
            'trafficmanager.net'      => ['Azure TM',        'error 404'],
            'fastly.net'              => ['Fastly',          'fastly error: unknown domain'],
            'myshopify.com'           => ['Shopify',         'sorry, this shop is currently unavailable'],
            'ghost.io'                => ['Ghost',           'the thing you were looking for is no longer here'],
            'wpengine.com'            => ['WP Engine',       'the site you were looking for couldn\'t be found'],
            'pantheonsite.io'         => ['Pantheon',        'the gods are wise'],
            'zendesk.com'             => ['Zendesk',         'help center closed'],
            'readthedocs.io'          => ['Read the Docs',   'unknown domain'],
            'surge.sh'                => ['Surge',           'project not found'],
            'bitbucket.io'            => ['Bitbucket',       'repository not found'],
        ];

        $host = $this->hostname;

        // Only meaningful when a CNAME chain exists. Apex domains rarely have one.
        $cnames = $this->dnsQuery($host, DNS_CNAME);
        $targets = [];
        foreach ($cnames as $r) {
            if (!empty($r['target'])) $targets[] = strtolower($r['target']);
        }

        if (empty($targets)) {
            $this->addFinding('DNS', 'Subdomain Takeover', 'pass',
                "No dangling CNAME detected for {$host} — not pointed at an external service that could be hijacked.");
            return;
        }

        $matchedService = null;
        $matchedTarget  = null;
        $bodyNeedle     = null;
        foreach ($targets as $t) {
            foreach ($fingerprints as $needle => [$svc, $bodyFp]) {
                if (str_contains($t, $needle)) {
                    $matchedService = $svc;
                    $matchedTarget  = $t;
                    $bodyNeedle     = $bodyFp;
                    break 2;
                }
            }
        }

        if ($matchedService === null) {
            $this->addFinding('DNS', 'Subdomain Takeover', 'info',
                "{$host} is a CNAME to " . implode(', ', $targets) . " (not a known takeover-prone service).",
                'Ensure the target resource stays under your control; remove the CNAME if the service is decommissioned.');
            return;
        }

        if (!UrlGuard::isPublicHost($host)) {
            $this->addFinding('DNS', 'Subdomain Takeover', 'info',
                "{$host} did not pass public target safety checks, so takeover body probing was skipped.",
                'Review the CNAME target manually if this is an internal domain.');
            return;
        }

        // Fetch the page body to look for the "unclaimed resource" fingerprint.
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $this->originBase() . '/',
            CURLOPT_RESOLVE        => $this->pinResolve(),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 8,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_USERAGENT => self::TARGET_USER_AGENT,
            CURLOPT_SSL_VERIFYPEER => false,
        ]);
        $probeBody  = strtolower((string)@curl_exec($ch));
        $hitPrivate = $this->curlHitPrivateIp($ch);
        $this->closeCurl($ch);

        if ($hitPrivate) {
            $this->addFinding('DNS', 'Subdomain Takeover', 'info',
                "Skipped body probe for {$host}: it resolved to a private or reserved IP at connection time.",
                'Review the CNAME target manually if this is an internal domain.');
            return;
        }

        if ($bodyNeedle !== '' && str_contains($probeBody, $bodyNeedle)) {
            $this->addFinding('DNS', 'Subdomain Takeover', 'critical',
                "{$host} points to {$matchedService} ({$matchedTarget}) and the service returns an 'unclaimed resource' page — this subdomain is likely vulnerable to takeover.",
                "Immediately remove the dangling CNAME or re-claim the {$matchedService} resource. An attacker who registers the unclaimed name can serve content on your subdomain.",
                ['https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html', 'https://github.com/EdOverflow/can-i-take-over-xyz']);
        } else {
            $this->addFinding('DNS', 'Subdomain Takeover', 'info',
                "{$host} is a CNAME to {$matchedService} ({$matchedTarget}). The resource currently responds, so it appears claimed — but takeover-prone services warrant monitoring.",
                "Verify the {$matchedService} resource remains owned by you and is removed from DNS if decommissioned.",
                ['https://github.com/EdOverflow/can-i-take-over-xyz']);
        }
    }

    // ================================================================
    //  REFERENCE LINKS  (auto-attached to findings)
    // ================================================================

    /**
     * Map a finding's category/check to authoritative documentation so the
     * report can show "learn more / how to fix" links next to each item.
     */
    // ================================================================
    //  CORS — active reflected-origin probe
    // ================================================================
    //
    // The passive checkCORS() only inspects headers returned for a same-origin
    // request. The most common *serious* CORS bug is an endpoint that blindly
    // reflects whatever Origin it is sent. We test that directly by sending an
    // attacker-style Origin and seeing whether it is echoed back — especially
    // dangerous when combined with Access-Control-Allow-Credentials: true.

    private function checkCORSReflection(): void
    {
        $probeOrigin = 'https://secscan-cors-probe.example'; // reserved TLD (RFC 2606)
        $headers = $this->corsProbe($probeOrigin);
        if ($headers === null) return;
        $acao = $headers['acao'];
        $acac = $headers['acac'];

        if ($acao === '') {
            $this->addFinding('CORS', 'CORS Reflection', 'pass',
                'The server did not reflect an arbitrary Origin in Access-Control-Allow-Origin.');
        } elseif (strcasecmp($acao, $probeOrigin) === 0) {
            if ($acac === 'true') {
                $this->addFinding('CORS', 'CORS Reflection', 'critical',
                    "Server reflects any Origin (tested {$probeOrigin}) and also sends Access-Control-Allow-Credentials: true — any website can read this site's authenticated responses on a victim's behalf.",
                    'Never reflect arbitrary origins together with credentials. Validate the Origin against an explicit allow-list and echo back only known-good origins.');
            } else {
                $this->addFinding('CORS', 'CORS Reflection', 'warning',
                    "Server reflects any Origin (tested {$probeOrigin}) in Access-Control-Allow-Origin. Cross-origin sites can read non-credentialed responses.",
                    'Do not reflect the Origin blindly. Restrict Access-Control-Allow-Origin to an explicit allow-list of trusted origins.');
            }
        } else {
            $this->addFinding('CORS', 'CORS Reflection', 'pass',
                "An arbitrary Origin was not reflected (Access-Control-Allow-Origin: {$acao}).");
        }

        // `null` is a special opaque origin produced by sandboxed iframes and
        // local files. It must be evaluated separately from a normal attacker
        // URL because some origin allow-lists accidentally include it.
        $null = $this->corsProbe('null');
        if ($null !== null && strtolower($null['acao']) === 'null') {
            $severity = $null['acac'] === 'true' ? 'critical' : 'warning';
            $this->addFinding('CORS', 'CORS Null Origin', $severity,
                "Server accepts Origin: null" . ($null['acac'] === 'true' ? ' with credentials.' : '.'),
                'Never allow the null origin. Use an explicit allow-list of HTTPS application origins.');
        }

        // A non-mutating OPTIONS preflight checks whether an arbitrary origin
        // can request a sensitive method. No application state is changed.
        $preflight = $this->corsProbe($probeOrigin, true);
        if ($preflight !== null && strcasecmp($preflight['acao'], $probeOrigin) === 0
            && $preflight['acac'] === 'true'
            && preg_match('/(?:^|,\s*)(?:DELETE|\*)(?:,|$)/i', $preflight['acam'])) {
            $this->addFinding('CORS', 'CORS Credentialed Preflight', 'critical',
                'An arbitrary Origin is approved for credentialed DELETE preflight requests.',
                'Validate Origin against an explicit allow-list and restrict credentialed CORS methods to only the required trusted applications.');
        }
    }

    /** @return array{acao:string,acac:string,acam:string}|null */
    private function corsProbe(string $origin, bool $preflight = false): ?array
    {
        $headers = ['Origin: ' . $origin];
        if ($preflight) {
            $headers[] = 'Access-Control-Request-Method: DELETE';
            $headers[] = 'Access-Control-Request-Headers: X-SecScan-Probe';
        }
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $this->url, CURLOPT_RESOLVE => $this->pinResolve(),
            CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true,
            CURLOPT_NOBODY => !$preflight, CURLOPT_CUSTOMREQUEST => $preflight ? 'OPTIONS' : 'HEAD',
            CURLOPT_TIMEOUT => 8, CURLOPT_CONNECTTIMEOUT => 5, CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_USERAGENT => self::TARGET_USER_AGENT, CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_HTTPHEADER => $headers,
        ]);
        $response = (string)@curl_exec($ch);
        $hitPrivate = $this->curlHitPrivateIp($ch);
        $this->closeCurl($ch);
        if ($hitPrivate) return null;

        $read = static function (string $name) use ($response): string {
            return preg_match('/^' . preg_quote($name, '/') . ':\s*(.+)$/mi', $response, $m) ? trim($m[1]) : '';
        };
        return ['acao' => $read('Access-Control-Allow-Origin'), 'acac' => strtolower($read('Access-Control-Allow-Credentials')), 'acam' => $read('Access-Control-Allow-Methods')];
    }

    // ================================================================
    //  CROSS-DOMAIN POLICY FILES (Flash / Silverlight legacy)
    // ================================================================

    private function checkCrossDomainPolicy(): void
    {
        $base = $this->originBase();
        $targets = [
            '/crossdomain.xml'        => 'Adobe Flash/Acrobat cross-domain policy',
            '/clientaccesspolicy.xml' => 'Silverlight client-access policy',
        ];

        $mh = curl_multi_init();
        $handles = [];
        foreach ($targets as $path => $desc) {
            $ch = curl_init();
            curl_setopt_array($ch, $this->withAuth([
                CURLOPT_URL => $base . $path, CURLOPT_RESOLVE => $this->pinResolve(),
                CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 6, CURLOPT_CONNECTTIMEOUT => 4,
                CURLOPT_FOLLOWLOCATION => false, CURLOPT_USERAGENT => self::TARGET_USER_AGENT, CURLOPT_SSL_VERIFYPEER => false,
            ]));
            $handles[$path] = ['ch' => $ch, 'desc' => $desc];
            curl_multi_add_handle($mh, $ch);
        }
        $running = null;
        do { curl_multi_exec($mh, $running); curl_multi_select($mh, 0.5); } while ($running > 0);

        $found = false;
        foreach ($handles as $path => $info) {
            $ch   = $info['ch'];
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $body = (string)curl_multi_getcontent($ch);
            curl_multi_remove_handle($mh, $ch);
            $this->closeCurl($ch);

            $isPolicy = stripos($body, '<cross-domain-policy') !== false
                     || stripos($body, '<access-policy') !== false;
            if ($code !== 200 || $body === '' || !$isPolicy || $this->matchesBaseline($body)) {
                continue;
            }

            $found = true;
            $wildcard = (bool)preg_match('/<allow-access-from\s+domain\s*=\s*["\']\*["\']/i', $body)
                     || (bool)preg_match('/<domain\s+uri\s*=\s*["\']\*["\']/i', $body);

            if ($wildcard) {
                $this->addFinding('CORS', 'Cross-Domain Policy', 'critical',
                    "{$path} allows access from ANY domain (wildcard '*') — {$info['desc']}. Legacy Flash/Silverlight clients hosted on any website could make cross-domain requests to this host.",
                    "Remove the wildcard: restrict allow-access-from to specific trusted domains, or delete {$path} if Flash/Silverlight is not in use.");
            } else {
                $this->addFinding('CORS', 'Cross-Domain Policy', 'info',
                    "{$path} is present ({$info['desc']}) and scoped to specific domains.",
                    "If Flash/Silverlight is no longer used, delete {$path} to reduce attack surface.");
            }
        }
        curl_multi_close($mh);

        if (!$found) {
            $this->addFinding('CORS', 'Cross-Domain Policy', 'pass',
                'No overly permissive crossdomain.xml / clientaccesspolicy.xml detected.');
        }
    }

    // ================================================================
    //  DIRECTORY LISTING (autoindex) DETECTION
    // ================================================================

    private function checkDirectoryListing(): void
    {
        $base = $this->originBase();
        $dirs = ['/images/', '/img/', '/assets/', '/uploads/', '/files/', '/css/', '/js/', '/backup/', '/old/', '/tmp/', '/static/', '/media/'];

        $mh = curl_multi_init();
        $handles = [];
        foreach ($dirs as $d) {
            $ch = curl_init();
            curl_setopt_array($ch, $this->withAuth([
                CURLOPT_URL => $base . $d, CURLOPT_RESOLVE => $this->pinResolve(),
                CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 6, CURLOPT_CONNECTTIMEOUT => 4,
                CURLOPT_FOLLOWLOCATION => false, CURLOPT_USERAGENT => self::TARGET_USER_AGENT, CURLOPT_SSL_VERIFYPEER => false,
            ]));
            $handles[$d] = $ch;
            curl_multi_add_handle($mh, $ch);
        }
        $running = null;
        do { curl_multi_exec($mh, $running); curl_multi_select($mh, 0.5); } while ($running > 0);

        $listed = [];
        foreach ($handles as $d => $ch) {
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $body = (string)curl_multi_getcontent($ch);
            if ($code === 200 && $this->looksLikeDirectoryListing($body)) {
                $listed[] = $d;
            }
            curl_multi_remove_handle($mh, $ch);
            $this->closeCurl($ch);
        }
        curl_multi_close($mh);

        if (!empty($listed)) {
            $this->addFinding('Exposed Files', 'Directory Listing', 'warning',
                'Automatic directory listing (autoindex) is enabled on: ' . implode(', ', $listed) . '. This reveals the complete file inventory of those paths and can expose forgotten or sensitive files.',
                'Disable directory indexing (Apache: "Options -Indexes"; nginx: "autoindex off;") and ensure each directory has an index file.');
        } else {
            $this->addFinding('Exposed Files', 'Directory Listing', 'pass',
                'No automatic directory listings detected on common paths.');
        }
    }

    /** Positive signatures for Apache/nginx/Python autoindex pages. */
    private function looksLikeDirectoryListing(string $body): bool
    {
        if ($body === '') {
            return false;
        }
        $head = substr($body, 0, 4000);
        return (bool)preg_match('/<title>\s*Index of \//i', $head)
            || stripos($head, '<h1>Index of /') !== false
            || (bool)preg_match('/<a[^>]+href\s*=\s*["\']\.\.\/?["\']>\s*(Parent Directory|\.\.)\s*<\/a>/i', $head)
            || stripos($head, 'Directory listing for /') !== false; // Python http.server
    }

    // ================================================================
    //  DNS ZONE TRANSFER (AXFR)
    // ================================================================
    //
    // A nameserver that permits AXFR to the public hands over the entire DNS
    // zone — every subdomain, mail host, and internal record — to anyone. We
    // enumerate the authoritative nameservers and ask each for a transfer.

    private function checkZoneTransfer(): void
    {
        $domain     = strtolower(rtrim(trim($this->hostname), '.'));
        $baseDomain = preg_replace('/^www\./i', '', $domain);
        $namePattern = '/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i';

        // Only meaningful for real DNS names (skip IP-literal targets, etc.).
        if (!preg_match($namePattern, $baseDomain)) {
            return;
        }

        $digPath = $this->getDigPath();
        if ($digPath === null) {
            $this->addFinding('DNS', 'Zone Transfer (AXFR)', 'info',
                'Zone-transfer test skipped — dig is unavailable or shell_exec is disabled.',
                "Test manually: dig AXFR {$baseDomain} @<nameserver>. Install bind9-dnsutils to enable this check.");
            return;
        }

        $nameservers = [];
        foreach ($this->dnsQuery($baseDomain, DNS_NS) as $r) {
            $ns = strtolower(rtrim((string)($r['target'] ?? ''), '.'));
            if ($ns !== '' && preg_match($namePattern, $ns)) {
                $nameservers[] = $ns;
            }
        }
        $nameservers = array_slice(array_values(array_unique($nameservers)), 0, 3);

        if (empty($nameservers)) {
            $this->addFinding('DNS', 'Zone Transfer (AXFR)', 'info',
                "Could not enumerate authoritative nameservers for {$baseDomain}; AXFR not tested.");
            return;
        }

        $dig     = escapeshellcmd($digPath);
        $zoneArg = escapeshellarg($baseDomain);
        $vulnerable = [];

        foreach ($nameservers as $ns) {
            $nsArg = escapeshellarg('@' . $ns);
            $out   = trim((string)@shell_exec("{$dig} +time=4 +tries=1 AXFR {$zoneArg} {$nsArg} 2>/dev/null"));
            if ($out === '') {
                continue;
            }
            $lower = strtolower($out);
            foreach (['transfer failed', 'communications error', 'connection timed out',
                      'connection refused', 'no servers could be reached', "couldn't get address"] as $failMarker) {
                if (str_contains($lower, $failMarker)) {
                    continue 2;
                }
            }
            // A real transfer returns multiple records and includes the SOA.
            $records = array_filter(
                preg_split('/\R+/', $out) ?: [],
                static fn ($l) => $l !== '' && $l[0] !== ';'
            );
            if (preg_match('/\bSOA\b/i', $out) && count($records) >= 2) {
                $vulnerable[$ns] = count($records);
            }
        }

        if (!empty($vulnerable)) {
            $detail = [];
            foreach ($vulnerable as $ns => $cnt) {
                $detail[] = "{$ns} ({$cnt} records)";
            }
            $this->addFinding('DNS', 'Zone Transfer (AXFR)', 'critical',
                'DNS zone transfer (AXFR) is permitted to the public by: ' . implode(', ', $detail) . '. This leaks the entire DNS zone — every subdomain, mail/host record, and internal name.',
                'Restrict AXFR to authorized secondary nameservers only (BIND: allow-transfer { <secondaries>; }; ). Public AXFR must be disabled.');
        } else {
            $this->addFinding('DNS', 'Zone Transfer (AXFR)', 'pass',
                "Authoritative nameservers refused AXFR zone transfers for {$baseDomain}.");
        }
    }

    // ================================================================
    //  API / GRAPHQL INTROSPECTION
    // ================================================================
    //
    // A GraphQL endpoint with introspection left enabled hands attackers the
    // full schema — every type, field, mutation and argument — which massively
    // accelerates API abuse. We POST a minimal introspection query to common
    // paths and report when the schema is returned.

    private function checkApiGraphQL(): void
    {
        $base    = $this->originBase();
        $paths   = ['/graphql', '/api/graphql', '/v1/graphql', '/graphql/v1', '/query'];
        $payload = '{"query":"query{__schema{queryType{name}}}"}';

        $introspectableAt = null;
        $presentAt        = null;

        foreach ($paths as $path) {
            $ch = curl_init();
            curl_setopt_array($ch, $this->withAuth([
                CURLOPT_URL            => $base . $path,
                CURLOPT_RESOLVE        => $this->pinResolve(),
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 8,
                CURLOPT_CONNECTTIMEOUT => 5,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_USERAGENT => self::TARGET_USER_AGENT,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => $payload,
                CURLOPT_HTTPHEADER     => ['Content-Type: application/json', 'Accept: application/json'],
            ]));
            $body       = (string)@curl_exec($ch);
            $hitPrivate = $this->curlHitPrivateIp($ch);
            $this->closeCurl($ch);
            if ($hitPrivate) return; // SSRF guard — abort the whole check
            if ($body === '' || $this->matchesBaseline($body)) continue;

            $class = $this->classifyGraphqlResponse($body);
            if ($class === 'enabled') { $introspectableAt = $path; break; }
            if ($class === 'present' && $presentAt === null) { $presentAt = $path; }
        }

        if ($introspectableAt !== null) {
            $this->addFinding('API', 'GraphQL Introspection', 'warning',
                "GraphQL introspection is enabled at {$introspectableAt} — the full API schema is publicly queryable.",
                'Disable introspection in production (e.g. Apollo introspection:false, or a validation rule blocking __schema/__type), and require authentication on the GraphQL endpoint.',
                ['https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html']);
        } elseif ($presentAt !== null) {
            $this->addFinding('API', 'GraphQL Introspection', 'pass',
                "A GraphQL endpoint was found at {$presentAt} but introspection appears disabled.",
                '', ['https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html']);
        } else {
            $this->addFinding('API', 'GraphQL Introspection', 'info',
                'No public GraphQL endpoint was found at common paths.',
                '', [], false);
        }
    }

    /**
     * Classify a GraphQL HTTP response body. Pure/offline for unit testing.
     *   'enabled' — introspection returned a schema
     *   'present' — endpoint is GraphQL but introspection is off / errored
     *   'none'    — not a GraphQL endpoint
     */
    public function classifyGraphqlResponse(string $body): string
    {
        if ($body === '') return 'none';
        $sample = substr($body, 0, 200000);

        if (strpos($sample, '"__schema"') !== false || strpos($sample, '"queryType"') !== false) {
            return 'enabled';
        }
        // GraphQL servers answer non-query requests with recognisable errors.
        $graphqlSignals = [
            'Must provide query string',
            'GraphQLError',
            'Cannot query field',
            'introspection is disabled',
            'introspection has been disabled',
            'must provide an operation',
            'Syntax Error: Unexpected',
            'PersistedQueryNotFound',
        ];
        foreach ($graphqlSignals as $sig) {
            if (stripos($sample, $sig) !== false) return 'present';
        }
        // An "errors" array that also mentions graphql is a decent tell.
        if (stripos($sample, '"errors"') !== false && stripos($sample, 'graphql') !== false) {
            return 'present';
        }
        return 'none';
    }

    // ================================================================
    //  EMAIL AUTH HARDENING DEPTH (SPF / DMARC / TLS-RPT)
    // ================================================================
    //
    // checkDNSSecurity() reports presence/absence of SPF, DMARC and DKIM.
    // This adds the deeper, spoofing-relevant analysis: SPF DNS-lookup limits,
    // deprecated/dangerous mechanisms, duplicate SPF records (which cause a
    // permerror), DMARC enforcement coverage (pct/sp/rua), and SMTP TLS
    // reporting. Only runs for domains that actually handle mail.

    private function checkEmailAuthHardening(): void
    {
        $base = preg_replace('/^www\./i', '', $this->hostname);

        $txt = @dns_get_record($base, DNS_TXT) ?: [];
        $spfRecords = [];
        foreach ($txt as $r) {
            $s = is_array($r['entries'] ?? null) ? implode('', $r['entries']) : ($r['txt'] ?? '');
            if (stripos($s, 'v=spf1') === 0) $spfRecords[] = $s;
        }
        $mx = @dns_get_record($base, DNS_MX) ?: [];

        // Skip non-mail domains to avoid advisory noise.
        if (empty($mx) && empty($spfRecords)) return;

        // --- SPF depth ---
        if (count($spfRecords) > 1) {
            $this->addFinding('DNS', 'SPF Multiple Records', 'critical',
                'More than one v=spf1 TXT record is published — this is a permanent error (permerror) and receivers may ignore SPF entirely.',
                'Publish exactly one SPF record; merge all mechanisms into a single v=spf1 line.');
        } elseif (count($spfRecords) === 1) {
            $a = $this->analyzeSpfRecord($spfRecords[0]);
            if ($a['lookups'] > 10) {
                $this->addFinding('DNS', 'SPF Lookup Limit', 'warning',
                    "SPF references ~{$a['lookups']} DNS-lookup mechanisms directly (RFC 7208 hard limit is 10; nested includes add more). Exceeding it causes a permerror.",
                    'Reduce include:/a/mx/exists mechanisms, flatten SPF, or use a hosted SPF-flattening service.');
            } elseif ($a['lookups'] >= 8) {
                $this->addFinding('DNS', 'SPF Lookup Limit', 'info',
                    "SPF uses ~{$a['lookups']} DNS-lookup mechanisms directly — approaching the RFC 7208 limit of 10 once nested includes are counted.",
                    'Keep the total (including nested includes) at or under 10.');
            }
            foreach ($a['issues'] as $issue) {
                $this->addFinding('DNS', 'SPF Mechanisms', 'warning',
                    "SPF record {$issue}.",
                    'Tighten the SPF record; remove deprecated/permissive mechanisms.');
            }
        }

        // --- DMARC depth ---
        $dmarcRecs = @dns_get_record("_dmarc.{$base}", DNS_TXT) ?: [];
        foreach ($dmarcRecs as $r) {
            $s = is_array($r['entries'] ?? null) ? implode('', $r['entries']) : ($r['txt'] ?? '');
            if (stripos($s, 'v=DMARC1') !== 0) continue;
            $d = $this->analyzeDmarcRecord($s);
            foreach ($d['issues'] as $issue) {
                $this->addFinding('DNS', 'DMARC Coverage', 'warning',
                    "DMARC {$issue}.",
                    'Enforce on all mail: p=reject (or quarantine), sp matching p, pct=100, and a rua= address for aggregate reports.');
            }
            foreach ($d['notes'] as $note) {
                $this->addFinding('DNS', 'DMARC Coverage', 'info', "DMARC {$note}.");
            }
            break;
        }

        // --- SMTP TLS reporting (TLS-RPT) ---
        if (!empty($mx)) {
            $tlsrpt = @dns_get_record("_smtp._tls.{$base}", DNS_TXT) ?: [];
            $hasTlsRpt = false;
            foreach ($tlsrpt as $r) {
                $s = is_array($r['entries'] ?? null) ? implode('', $r['entries']) : ($r['txt'] ?? '');
                if (stripos($s, 'v=TLSRPTv1') === 0) { $hasTlsRpt = true; break; }
            }
            if ($hasTlsRpt) {
                $this->addFinding('DNS', 'TLS-RPT', 'pass', 'SMTP TLS reporting (TLS-RPT) is published.');
            } else {
                $this->addFinding('DNS', 'TLS-RPT', 'info',
                    'No SMTP TLS reporting (TLS-RPT) record found.',
                    'Publish _smtp._tls TXT (v=TLSRPTv1; rua=mailto:tlsrpt@...) to receive delivery/TLS failure reports.');
            }
        }
    }

    /**
     * Analyse an SPF record. Pure/offline for unit testing.
     * Returns ['lookups' => int, 'issues' => string[]]. `lookups` counts the
     * DNS-lookup mechanisms present in *this* record only (nested includes not
     * expanded), so it is a lower bound on the RFC 7208 count.
     *
     * @return array{lookups:int, issues:string[]}
     */
    public function analyzeSpfRecord(string $spf): array
    {
        $tokens  = preg_split('/\s+/', trim($spf)) ?: [];
        $lookups = 0;
        $issues  = [];
        $hasAll  = false;

        foreach ($tokens as $tok) {
            if ($tok === '') continue;
            $bare = ltrim($tok, '+-~?');
            $low  = strtolower($bare);

            if (str_starts_with($low, 'include:') || str_starts_with($low, 'exists:') || str_starts_with($low, 'redirect=')) {
                $lookups++;
            } elseif ($low === 'a' || str_starts_with($low, 'a:') || str_starts_with($low, 'a/')) {
                $lookups++;
            } elseif ($low === 'mx' || str_starts_with($low, 'mx:') || str_starts_with($low, 'mx/')) {
                $lookups++;
            } elseif ($low === 'ptr' || str_starts_with($low, 'ptr:')) {
                $lookups++;
                $issues[] = 'uses the deprecated and unreliable ptr mechanism';
            }

            if ($low === 'all') {
                $hasAll = true;
                $qual = $tok[0] ?? '+';
                if ($qual === '?') $issues[] = "uses neutral '?all' which provides no protection";
            }
        }

        if (!$hasAll) $issues[] = "has no 'all' mechanism, leaving the default policy undefined";

        return ['lookups' => $lookups, 'issues' => $issues];
    }

    /**
     * Analyse a DMARC record. Pure/offline for unit testing.
     * Returns ['issues' => string[], 'notes' => string[]].
     *
     * @return array{issues:string[], notes:string[]}
     */
    public function analyzeDmarcRecord(string $dmarc): array
    {
        $tags = [];
        foreach (explode(';', $dmarc) as $part) {
            $part = trim($part);
            if ($part === '' || strpos($part, '=') === false) continue;
            [$k, $v] = explode('=', $part, 2);
            $tags[strtolower(trim($k))] = trim($v);
        }

        $issues = [];
        $notes  = [];
        $p = strtolower($tags['p'] ?? '');

        if (isset($tags['pct']) && (int)$tags['pct'] < 100) {
            $issues[] = "applies to only {$tags['pct']}% of mail (pct=" . (int)$tags['pct'] . ') — the rest is unenforced';
        }
        if (empty($tags['rua'])) {
            $issues[] = 'has no rua= aggregate-report address, so you get no visibility into spoofing attempts';
        }
        if (isset($tags['sp'])) {
            $sp = strtolower($tags['sp']);
            if ($sp === 'none' && in_array($p, ['quarantine', 'reject'], true)) {
                $issues[] = "sets a weaker subdomain policy (sp=none) than the domain policy (p={$p}), leaving subdomains spoofable";
            }
        }
        if (($tags['adkim'] ?? 'r') === 'r' || ($tags['aspf'] ?? 'r') === 'r') {
            $notes[] = 'uses relaxed alignment (adkim/aspf=r); strict alignment (s) is tighter if your mail flow supports it';
        }

        return ['issues' => $issues, 'notes' => $notes];
    }

    private function referencesFor(string $category, string $check): array
    {
        $c = strtolower($check);
        $map = [
            'content-security-policy'  => ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy', 'https://content-security-policy.com/'],
            'strict-transport-security'=> ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security', 'https://hstspreload.org/'],
            'x-content-type'           => ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'],
            'x-frame-options'          => ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'],
            'referrer-policy'          => ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'],
            'permissions-policy'       => ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy'],
            'cookie'                   => ['https://owasp.org/www-community/controls/SecureCookieAttribute', 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie'],
            'cors'                     => ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS', 'https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny'],
            'cross-domain policy'      => ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/'],
            'directory listing'        => ['https://owasp.org/www-community/attacks/Forced_browsing', 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'],
            'zone transfer'            => ['https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/'],
            'spf'                      => ['https://datatracker.ietf.org/doc/html/rfc7208', 'https://dmarcian.com/spf-syntax-table/'],
            'dmarc'                    => ['https://datatracker.ietf.org/doc/html/rfc7489', 'https://dmarc.org/overview/'],
            'dkim'                     => ['https://datatracker.ietf.org/doc/html/rfc6376'],
            'tls-rpt'                  => ['https://datatracker.ietf.org/doc/html/rfc8460'],
            'graphql'                  => ['https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html'],
            'dnssec'                   => ['https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en'],
            'caa'                      => ['https://datatracker.ietf.org/doc/html/rfc8659'],
            'mta-sts'                  => ['https://datatracker.ietf.org/doc/html/rfc8461'],
            'tls'                      => ['https://wiki.mozilla.org/Security/Server_Side_TLS', 'https://www.ssllabs.com/ssltest/'],
            'cipher'                   => ['https://wiki.mozilla.org/Security/Server_Side_TLS'],
            'certificate'              => ['https://letsencrypt.org/docs/'],
            'trace'                    => ['https://owasp.org/www-community/attacks/Cross_Site_Tracing'],
            'http methods'             => ['https://owasp.org/www-project-web-security-testing-guide/'],
            'write http methods'       => ['https://owasp.org/www-project-web-security-testing-guide/'],
            'subdomain takeover'       => ['https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html', 'https://github.com/EdOverflow/can-i-take-over-xyz'],
            'waf'                      => ['https://owasp.org/www-community/Web_Application_Firewall'],
            'sensitive file'           => ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/', 'https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information.html'],
            'admin'                    => ['https://owasp.org/www-project-web-security-testing-guide/'],
            'sri'                      => ['https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity'],
            'csrf'                     => ['https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html', 'https://owasp.org/www-community/attacks/csrf'],
            'secret'                   => ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html', 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'],
            'mixed content'            => ['https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content'],
            'port'                     => ['https://owasp.org/www-project-web-security-testing-guide/'],
        ];

        foreach ($map as $needle => $links) {
            if (str_contains($c, $needle)) return $links;
        }
        return [];
    }

    // ================================================================
    //  SCORING
    // ================================================================

    /** @return SecurityFinding[] */
    private function scoreableFindings(): array
    {
        return array_values(array_filter($this->findings, fn($f) => $f->scoreable));
    }

    private function gradeForScore(int $score): string
    {
        if ($score >= 90) return 'A+';
        if ($score >= 80) return 'A';
        if ($score >= 70) return 'B';
        if ($score >= 60) return 'C';
        if ($score >= 45) return 'D';
        return 'F';
    }

    private function calculateScore(): array
    {
        $findings = $this->scoreableFindings();
        if (empty($findings)) return ['score' => 0, 'grade' => 'F'];

        // 'info' findings are advisory (e.g. "no IPv6", "DNSSEC not detected"),
        // not security failures, so they are weighted close to a pass and don't
        // unfairly cap the grade of an otherwise well-configured site.
        $weights = ['pass' => 100, 'info' => 85, 'warning' => 35, 'critical' => 0];
        $total   = 0;
        foreach ($findings as $f) $total += $weights[$f->severity] ?? 0;
        $score = (int)round($total / count($findings));
        $grade = $this->gradeForScore($score);

        $crits = count(array_filter($findings, fn($f) => $f->severity === 'critical'));
        if ($crits >= 5 && in_array($grade, ['A+', 'A', 'B', 'C'])) $grade = 'D';
        elseif ($crits >= 3 && in_array($grade, ['A+', 'A', 'B']))   $grade = 'C';
        elseif ($crits >= 1 && $grade === 'A+')                       $grade = 'A';

        return ['score' => $score, 'grade' => $grade];
    }

    // ================================================================
    //  BUILD RESULT
    // ================================================================

    private function buildResult(): array
    {
        $scoring = $this->calculateScore();
        $elapsed = round(microtime(true) - $this->scanStart, 2);
        $categories = [];
        $scoreableCount = count($this->scoreableFindings());
        foreach ($this->findings as $f) {
            $categories[$f->category][] = [
                'check'          => $f->check,
                'severity'       => $f->severity,
                'message'        => $f->message,
                'recommendation' => $f->recommendation,
                'references'     => $f->references,
                'scoreable'      => $f->scoreable,
            ];
        }
        $counts = ['pass' => 0, 'info' => 0, 'warning' => 0, 'critical' => 0];
        foreach ($this->findings as $f) $counts[$f->severity]++;

        return [
            'url'             => $this->url,
            'hostname'        => $this->hostname,
            'authenticated'   => $this->authEnabled,
            'score'           => $scoring['score'],
            'grade'           => $scoring['grade'],
            'total_checks'    => count($this->findings),
            'scoreable_checks' => $scoreableCount,
            'passed'          => $counts['pass'],
            'info'            => $counts['info'],
            'warnings'        => $counts['warning'],
            'critical'        => $counts['critical'],
            'server_ip'       => ['ipv4' => array_values(array_unique($this->resolvedIpv4)), 'ipv6' => array_values(array_unique($this->resolvedIpv6))],
            'detected_cms'    => $this->detectedCms,
            'detected_cms_version' => $this->detectedCmsVersion,
            'detected_cms_signals' => $this->detectedCmsSignals,
            'scan_blocked'    => $this->scanBlocked !== [],
            'scan_blocked_type' => (string)($this->scanBlocked['type'] ?? ''),
            'scan_blocked_detail' => $this->scanBlocked,
            'waf'             => [
                'detected' => $this->detectedWafVendors !== [],
                'vendors'  => $this->detectedWafVendors,
                'signals'  => $this->detectedWafSignals,
            ],
            'edge'            => ['cloudflare' => $this->isCloudflareEdge()],
            'tls'             => [
                'protocol'       => $this->negotiatedTlsProtocol,
                'cipher_name'    => $this->negotiatedCipherName,
                'cipher_bits'    => $this->negotiatedCipherBits,
                'cipher_version' => $this->negotiatedCipherVersion,
            ],
            'category_scores' => $this->categoryScores(),
            'recommendations' => $this->prioritizedRecommendations(),
            'categories'      => $categories,
            'scan_time'       => date('Y-m-d H:i:s T'),
            'duration'        => "{$elapsed}s",
        ];
    }

    /**
     * Per-category score + grade so the UI can show where a site is weakest
     * (e.g. "Headers: 45/F" vs "TLS/SSL: 95/A+").
     */
    private function categoryScores(): array
    {
        $weights = ['pass' => 100, 'info' => 85, 'warning' => 35, 'critical' => 0];
        $buckets = [];
        foreach ($this->scoreableFindings() as $f) {
            $buckets[$f->category][] = $weights[$f->severity] ?? 0;
        }
        $out = [];
        foreach ($buckets as $cat => $scores) {
            $avg = (int) round(array_sum($scores) / count($scores));
            $grade = $this->gradeForScore($avg);
            $out[$cat] = ['score' => $avg, 'grade' => $grade, 'checks' => count($scores)];
        }
        // Weakest categories first — most useful ordering for a reader.
        uasort($out, fn($a, $b) => $a['score'] <=> $b['score']);
        return $out;
    }

    /**
     * A flat, severity-ranked "fix this first" list. Critical items come first,
     * then warnings; passes/info are excluded. Each item carries the concrete
     * action and reference links, plus a quick-win flag for cheap config fixes.
     */
    private function prioritizedRecommendations(): array
    {
        $rank = ['critical' => 0, 'warning' => 1];
        // Categories where the fix is typically a one-line server/DNS config change.
        $quickWinCats = ['Headers', 'DNS', 'Information Leakage'];

        $items = [];
        foreach ($this->findings as $f) {
            if (!$f->scoreable) continue;
            if (!isset($rank[$f->severity])) continue; // skip pass/info
            $items[] = $f;
        }

        // Stable sort by severity rank.
        usort($items, fn($a, $b) => $rank[$a->severity] <=> $rank[$b->severity]);

        $out = [];
        $priority = 1;
        foreach ($items as $f) {
            $out[] = [
                'priority'   => $priority++,
                'severity'   => $f->severity,
                'category'   => $f->category,
                'check'      => $f->check,
                'issue'      => $f->message,
                'action'     => $f->recommendation !== '' ? $f->recommendation : 'Review and remediate this finding.',
                'quick_win'  => in_array($f->category, $quickWinCats, true) && $f->severity === 'warning',
                'references' => $f->references,
            ];
        }
        return $out;
    }
}
