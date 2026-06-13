<?php

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/src/UrlGuard.php';

class SecurityFinding
{
    public string $category;
    public string $check;
    public string $severity;
    public string $message;
    public string $recommendation;
    /** @var string[] Documentation/standard references (OWASP, MDN, RFC, …). */
    public array $references;

    public function __construct(string $category, string $check, string $severity, string $message, string $recommendation = '', array $references = [])
    {
        $this->category = $category;
        $this->check = $check;
        $this->severity = $severity;
        $this->message = $message;
        $this->recommendation = $recommendation;
        $this->references = $references;
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
    private int $httpCode = 0;
    private float $scanStart;
    private array $resolvedIpv4 = [];
    private array $resolvedIpv6 = [];

    // Memoised DNS results, keyed by "name|type" — see dnsQuery().
    private array $dnsCache = [];

    // Negotiated TLS metadata captured once in checkTLS() and reused by
    // later checks to avoid TLS 1.3 / CDN false positives.
    private string $negotiatedTlsProtocol = '';
    private string $negotiatedCipherName = '';
    private int $negotiatedCipherBits = 0;
    private string $negotiatedCipherVersion = '';

    private const WEAK_CIPHERS = [
        'RC4', 'DES-CBC', '3DES', 'DES-CBC3', 'NULL',
        'EXPORT', 'anon', 'ADH', 'AECDH', 'MD5',
        'SEED', 'IDEA', 'CAMELLIA'
    ];

    private const STRONG_KEY_EXCHANGES = ['ECDHE', 'DHE', 'X25519', 'X448', 'CECPQ'];
    private const STRONG_AEAD_CIPHERS  = ['GCM', 'CHACHA20', 'POLY1305', 'CCM'];
    private const PFS_CIPHERS          = ['ECDHE', 'DHE', 'ECDH'];

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

    private function addFinding(string $category, string $check, string $severity, string $message, string $recommendation = '', array $references = []): void
    {
        // Auto-attach standard references when the caller didn't supply any.
        if (empty($references)) {
            $references = $this->referencesFor($category, $check);
        }
        $this->findings[] = new SecurityFinding($category, $check, $severity, $message, $recommendation, $references);
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
            'checkCORS',
            'checkMixedContent', 'checkSRI', 'checkInsecureForms', 'checkMetaCSP',
            'checkHTTPVersions',
            'checkDNSSecurity',
            'checkCMSDetection',
            'checkWAF',
            'checkOutdatedSoftware',
            'checkSubdomainTakeover',
            'checkExposedFiles',
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
            if (!UrlGuard::isPublicUrl($currentUrl)) {
                $this->addFinding(
                    'Connection',
                    'Redirect Safety',
                    'critical',
                    'Refused to follow a redirect to a private, reserved, or local network target.',
                    'Ensure redirects only point to public http/https URLs.'
                );
                return false;
            }

            $ch = curl_init();
            $headers = [];

            curl_setopt_array($ch, [
                CURLOPT_URL            => $currentUrl,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_TIMEOUT        => 20,
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_USERAGENT      => 'SecScan/2.0 Security Scanner',
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
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
            ]);

            $body           = curl_exec($ch);
            $this->httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $error          = curl_error($ch);
            $errno          = curl_errno($ch);
            $this->closeCurl($ch);

            if ($body === false || $this->httpCode === 0) {
                $msg = $error ?: "cURL error #{$errno}";
                $this->addFinding('Connection', 'Reachability', 'critical',
                    "Could not connect to {$currentUrl}: {$msg}",
                    'Verify the URL is correct and the server is running.');
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

            $this->url = $currentUrl;
            $this->responseHeaders = $headers;
            $this->responseBody    = (string)$body;
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
        if (strpos($csp, "'unsafe-inline'") !== false) $issues[] = "allows 'unsafe-inline' (XSS risk)";
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
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT        => 8,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_USERAGENT      => 'SecScan/2.0',
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
        $client = @stream_socket_client("ssl://{$this->hostname}:{$this->port}", $errno, $errstr, 15, STREAM_CLIENT_CONNECT, $ctx);
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
        $client = @stream_socket_client("tcp://{$this->hostname}:{$this->port}", $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $ctx);
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
        $client = @stream_socket_client("ssl://{$this->hostname}:{$this->port}", $errno, $errstr, 8, STREAM_CLIENT_CONNECT, $ctx);
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
        $client = @stream_socket_client("ssl://{$this->hostname}:{$this->port}", $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $ctx);
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
        $client = @stream_socket_client("ssl://{$this->hostname}:{$this->port}", $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $ctx);
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
    //  8. HTTP/2 & HTTP/3
    // ================================================================

    private function checkHTTPVersions(): void
    {
        $ch = curl_init();
        curl_setopt_array($ch, [CURLOPT_URL => $this->url, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10, CURLOPT_CONNECTTIMEOUT => 8, CURLOPT_USERAGENT => 'SecScan/2.0', CURLOPT_SSL_VERIFYPEER => false, CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_2_0]);
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
        $body  = $this->responseBody;
        $lower = strtolower(substr($body, 0, 200000));
        $cms   = null;

        if (strpos($lower, '/wp-content/') !== false || strpos($lower, '/wp-includes/') !== false) {
            $cms = 'WordPress';
            if (preg_match('/<meta[^>]+generator[^>]+WordPress\s*([\d.]+)/i', $body, $m)) $cms .= ' ' . $m[1];
        } elseif (strpos($lower, '/components/com_') !== false || strpos($lower, 'joomla') !== false) {
            $cms = 'Joomla';
        } elseif (strpos($lower, 'drupal') !== false || stripos($this->getHeader('x-generator') ?? '', 'Drupal') !== false) {
            $cms = 'Drupal';
        } elseif (strpos($lower, 'cdn.shopify.com') !== false) { $cms = 'Shopify'; }
        elseif (strpos($lower, 'wix.com') !== false)           { $cms = 'Wix'; }
        elseif (strpos($lower, 'squarespace') !== false)       { $cms = 'Squarespace'; }
        elseif (strpos($lower, 'ghost-') !== false)            { $cms = 'Ghost'; }

        if ($cms) $this->addFinding('Technology', 'CMS Detected', 'info', "CMS: {$cms}.", 'Keep CMS, themes, and plugins updated.');
        else $this->addFinding('Technology', 'CMS Detection', 'pass', 'No common CMS fingerprint detected.');

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
        if (preg_match('/ng-version=["\'][\d.]+/i', $body)) $frameworks[] = 'Angular';
        if (strpos($lower, 'django') !== false || $this->cookieNameExists('csrftoken')) $frameworks[] = 'Django';
        if ($frameworks) $this->addFinding('Technology', 'Framework', 'info', 'Detected: ' . implode(', ', $frameworks) . '.', 'Keep frameworks and dependencies updated.');

        $cdns = [];
        if ($this->getHeader('cf-ray'))              $cdns[] = 'Cloudflare';
        if ($this->getHeader('x-amz-cf-id'))         $cdns[] = 'AWS CloudFront';
        if ($this->getHeader('x-fastly-request-id')) $cdns[] = 'Fastly';
        if ($this->getHeader('x-azure-ref'))         $cdns[] = 'Azure CDN';
        if ($cdns) $this->addFinding('Technology', 'CDN/WAF', 'pass', 'Detected: ' . implode(', ', $cdns) . '.');
    }

    private function cookieNameExists(string $name): bool
    {
        foreach ($this->cookies as $c) { if (stripos(explode(';', $c)[0], $name . '=') !== false) return true; }
        return false;
    }

    // ================================================================
    //  11. EXPOSED SENSITIVE FILES
    // ================================================================

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

        $base    = $this->scheme . '://' . $this->hostname;
        $mh      = curl_multi_init();
        $handles = [];

        foreach ($files as $path => [$desc, $critical]) {
            $ch = curl_init();
            curl_setopt_array($ch, [CURLOPT_URL => $base . $path, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 6, CURLOPT_CONNECTTIMEOUT => 4, CURLOPT_FOLLOWLOCATION => false, CURLOPT_USERAGENT => 'SecScan/2.0', CURLOPT_SSL_VERIFYPEER => false]);
            $handles[$path] = ['handle' => $ch, 'desc' => $desc, 'critical' => $critical];
            curl_multi_add_handle($mh, $ch);
        }

        $running = null;
        do { curl_multi_exec($mh, $running); curl_multi_select($mh, 0.5); } while ($running > 0);

        $exposed = [];
        foreach ($handles as $path => $info) {
            $ch   = $info['handle'];
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $body = curl_multi_getcontent($ch);
            if ($code === 200 && strlen((string)$body) > 10) {
                $isReal = match(true) {
                    $path === '/.env'          => (bool)preg_match('/[A-Z_]+=.+/', (string)$body),
                    $path === '/.git/HEAD'     => (bool)preg_match('/^(ref:|[0-9a-f]{40})/m', (string)$body),
                    $path === '/phpinfo.php'   => str_contains((string)$body, 'PHP Version'),
                    $path === '/composer.json' => str_contains((string)$body, '"require"'),
                    $path === '/package.json'  => str_contains((string)$body, '"dependencies"') || str_contains((string)$body, '"name"'),
                    $path === '/Dockerfile'    => str_contains((string)$body, 'FROM '),
                    str_contains($path, '.sql') => strlen((string)$body) > 500,
                    default                    => strlen((string)$body) > 50 && !$this->looksLikeErrorPage((string)$body),
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

        $base    = $this->scheme . '://' . $this->hostname;
        $mh      = curl_multi_init();
        $handles = [];

        foreach ($endpoints as $path => [$desc, $critical]) {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $base . $path,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 6,
                CURLOPT_CONNECTTIMEOUT => 4,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_USERAGENT      => 'SecScan/2.0',
                CURLOPT_SSL_VERIFYPEER => false,
            ]);
            $handles[$path] = ['handle' => $ch, 'desc' => $desc, 'critical' => $critical];
            curl_multi_add_handle($mh, $ch);
        }

        $running = null;
        do { curl_multi_exec($mh, $running); curl_multi_select($mh, 0.5); } while ($running > 0);

        $exposed = [];
        foreach ($handles as $path => $info) {
            $ch   = $info['handle'];
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $body = (string)(curl_multi_getcontent($ch) ?? '');

            if ($code === 200 && strlen($body) > 20) {
                $isReal = match(true) {
                    $path === '/xmlrpc.php'                => str_contains($body, 'XML-RPC') || str_contains($body, 'xmlrpc') || str_contains($body, 'methodCall'),
                    $path === '/readme.html'               => stripos($body, 'WordPress') !== false,
                    $path === '/wp-debug.log'              => str_contains($body, 'PHP') && (str_contains($body, 'Error') || str_contains($body, 'Notice') || str_contains($body, 'Warning')),
                    str_contains($path, 'laravel.log')     => preg_match('/\[\d{4}-\d{2}-\d{2}/', $body) === 1,
                    str_contains($path, 'actuator')        => str_contains($body, '"status"') || str_contains($body, '"UP"') || str_contains($body, '"DOWN"'),
                    str_contains($path, 'phpmyadmin') || str_contains($path, 'adminer') => !$this->looksLikeErrorPage($body),
                    str_contains($path, 'server-status')   => str_contains($body, 'Apache') || str_contains($body, 'Server Version'),
                    str_contains($path, 'credentials')     => preg_match('/aws_access_key_id|aws_secret/i', $body) === 1,
                    $path === '/install.php' || $path === '/setup.php' => !$this->looksLikeErrorPage($body),
                    default                                => strlen($body) > 50 && !$this->looksLikeErrorPage($body),
                };
                if ($isReal) $exposed[] = ['path' => $path, 'desc' => $info['desc'], 'critical' => $info['critical']];
            }

            curl_multi_remove_handle($mh, $ch);
            $this->closeCurl($ch);
        }
        curl_multi_close($mh);

        if (!empty($exposed)) {
            foreach ($exposed as $f) {
                $this->addFinding('Exposed Files', 'Admin/Sensitive Endpoint', $f['critical'] ? 'critical' : 'warning',
                    "Accessible: {$f['path']} — {$f['desc']}",
                    'Restrict via server config, IP whitelist, or remove if not needed.');
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
        $base  = $this->scheme . '://' . $this->hostname;
        foreach (['/.well-known/security.txt', '/security.txt'] as $path) {
            $ch = curl_init();
            curl_setopt_array($ch, [CURLOPT_URL => $base . $path, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 8, CURLOPT_USERAGENT => 'SecScan/2.0', CURLOPT_SSL_VERIFYPEER => false, CURLOPT_FOLLOWLOCATION => false]);
            $body = curl_exec($ch);
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $this->closeCurl($ch);
            if ($code === 200 && $body && stripos($body, 'Contact:') !== false) {
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
        curl_setopt_array($ch, [CURLOPT_URL => $this->scheme . '://' . $this->hostname . '/robots.txt', CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 8, CURLOPT_USERAGENT => 'SecScan/2.0', CURLOPT_SSL_VERIFYPEER => false]);
        $body = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $this->closeCurl($ch);
        if ($code !== 200 || !$body) { $this->addFinding('Security', 'robots.txt', 'info', 'No robots.txt found.', 'Add a robots.txt to manage crawler access.'); return; }
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
                "tcp://{$host}:{$port}",
                $errno, $errstr,
                $timeout,
                STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT
            );
            if ($sock !== false) {
                stream_set_blocking($sock, false);
                $sockets[$port] = $sock;
            }
        }

        // Phase 2 — poll writable sockets (connection success = writable)
        $deadline  = microtime(true) + $timeout;
        $openPorts = [];

        while (!empty($sockets) && microtime(true) < $deadline) {
            $read   = null;
            $write  = array_values($sockets);
            $except = null;

            $n = @stream_select($read, $write, $except, 0, 200000); // 200ms polling slice
            if ($n === false || $n === 0) { usleep(10000); continue; }

            foreach ($write as $sock) {
                $port = array_search($sock, $sockets, true);
                if ($port === false) continue;
                $openPorts[$port] = $ports[$port];
                fclose($sock);
                unset($sockets[$port]);
            }
        }

        // Close timed-out sockets
        foreach ($sockets as $sock) { @fclose($sock); }

        // Phase 3 — report
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
            CURLOPT_CUSTOMREQUEST  => 'OPTIONS',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_NOBODY         => true,
            CURLOPT_TIMEOUT        => 8,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_USERAGENT      => 'SecScan/2.1',
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
            CURLOPT_CUSTOMREQUEST  => 'TRACE',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 8,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_USERAGENT      => 'SecScan/2.1',
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
            'Cloudflare'            => ['headers' => ['cf-ray', 'cf-cache-status', 'cf-request-id'], 'server' => ['cloudflare'], 'cookies' => ['__cfduid', '__cf_bm'], 'body' => ['attention required! | cloudflare']],
            'AWS WAF / CloudFront'  => ['headers' => ['x-amz-cf-id', 'x-amzn-requestid', 'x-amz-apigw-id'], 'server' => ['awselb', 'cloudfront'], 'cookies' => ['aws-waf-token'], 'body' => []],
            'Akamai'                => ['headers' => ['x-akamai-transformed', 'akamai-grn'], 'server' => ['akamaighost'], 'cookies' => ['ak_bmsc', 'bm_sz'], 'body' => ['access denied', 'reference #']],
            'Imperva / Incapsula'   => ['headers' => ['x-iinfo', 'x-cdn'], 'server' => ['incapsula'], 'cookies' => ['incap_ses', 'visid_incap'], 'body' => ['incapsula incident id', 'powered by incapsula']],
            'Sucuri'                => ['headers' => ['x-sucuri-id', 'x-sucuri-cache'], 'server' => ['sucuri/cloudproxy'], 'cookies' => [], 'body' => ['sucuri website firewall', 'access denied - sucuri']],
            'F5 BIG-IP ASM'         => ['headers' => [], 'server' => ['big-ip', 'bigip'], 'cookies' => ['ts', 'bigipserver'], 'body' => ['the requested url was rejected']],
            'Barracuda'             => ['headers' => [], 'server' => ['barracuda'], 'cookies' => ['barra_counter_session'], 'body' => ['barracuda']],
            'Fastly'                => ['headers' => ['x-fastly-request-id', 'fastly-debug-digest'], 'server' => ['fastly'], 'cookies' => [], 'body' => []],
            'Azure (Front Door/WAF)'=> ['headers' => ['x-azure-ref', 'x-msedge-ref'], 'server' => [], 'cookies' => [], 'body' => []],
            'Wordfence'             => ['headers' => [], 'server' => [], 'cookies' => ['wordfence_verifiedhuman'], 'body' => ['generated by wordfence']],
            'ModSecurity'           => ['headers' => ['x-mod-security'], 'server' => ['mod_security', 'modsecurity'], 'cookies' => [], 'body' => ['mod_security', 'this error was generated by mod_security']],
        ];

        $serverHdr = strtolower($this->getHeader('server') ?? '');
        $bodyLower = strtolower(substr($this->responseBody, 0, 100000));
        $cookieStr = strtolower(implode(' | ', $this->cookies));

        $detected = [];
        foreach ($signatures as $name => $sig) {
            foreach ($sig['headers'] as $h) {
                if ($this->getHeader($h) !== null) { $detected[$name] = true; }
            }
            foreach ($sig['server'] as $s) {
                if ($s !== '' && str_contains($serverHdr, $s)) { $detected[$name] = true; }
            }
            foreach ($sig['cookies'] as $c) {
                if ($c !== '' && str_contains($cookieStr, $c)) { $detected[$name] = true; }
            }
            foreach ($sig['body'] as $b) {
                if ($b !== '' && str_contains($bodyLower, $b)) { $detected[$name] = true; }
            }
        }

        if (!empty($detected)) {
            $list = implode(', ', array_keys($detected));
            $this->addFinding('Technology', 'WAF / Edge Protection', 'pass',
                "Web Application Firewall / edge protection detected: {$list}.",
                'Confirm the WAF is in blocking (not detection-only) mode and that rule sets are kept current.');
        } else {
            $this->addFinding('Technology', 'WAF / Edge Protection', 'info',
                'No Web Application Firewall fingerprint detected from headers, cookies, or body.',
                'A WAF (e.g. Cloudflare, AWS WAF, ModSecurity) adds a layer of protection against common web attacks. Absence is not a vulnerability by itself but reduces defence-in-depth.');
        }
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
            // PHP branches < 8.1 are end-of-life as of June 2026 (no security fixes).
            if ($major < 8 || ($major === 8 && $minor < 1)) {
                $flagged = true;
                $this->addFinding('Technology', 'Outdated PHP', 'critical',
                    "PHP {$ver} is end-of-life and no longer receives security patches.",
                    'Upgrade to a supported PHP branch (8.2+). Check the EOL calendar at https://www.php.net/supported-versions.php.',
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
            if ((int)$m[1] === 1 && (int)$m[2] < 24) {
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
            CURLOPT_URL            => $this->scheme . '://' . $host . '/',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 8,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_USERAGENT      => 'SecScan/2.1',
            CURLOPT_SSL_VERIFYPEER => false,
        ]);
        $probeBody = strtolower((string)@curl_exec($ch));
        $this->closeCurl($ch);

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
            'spf'                      => ['https://datatracker.ietf.org/doc/html/rfc7208', 'https://dmarcian.com/spf-syntax-table/'],
            'dmarc'                    => ['https://datatracker.ietf.org/doc/html/rfc7489', 'https://dmarc.org/overview/'],
            'dkim'                     => ['https://datatracker.ietf.org/doc/html/rfc6376'],
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

    private function calculateScore(): array
    {
        if (empty($this->findings)) return ['score' => 0, 'grade' => 'F'];
        $weights = ['pass' => 100, 'info' => 70, 'warning' => 35, 'critical' => 0];
        $total   = 0;
        foreach ($this->findings as $f) $total += $weights[$f->severity] ?? 0;
        $score = (int)round($total / count($this->findings));
        if ($score >= 90) $grade = 'A+';
        elseif ($score >= 80) $grade = 'A';
        elseif ($score >= 70) $grade = 'B';
        elseif ($score >= 60) $grade = 'C';
        elseif ($score >= 45) $grade = 'D';
        else $grade = 'F';

        $crits = count(array_filter($this->findings, fn($f) => $f->severity === 'critical'));
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
        foreach ($this->findings as $f) {
            $categories[$f->category][] = [
                'check'          => $f->check,
                'severity'       => $f->severity,
                'message'        => $f->message,
                'recommendation' => $f->recommendation,
                'references'     => $f->references,
            ];
        }
        $counts = ['pass' => 0, 'info' => 0, 'warning' => 0, 'critical' => 0];
        foreach ($this->findings as $f) $counts[$f->severity]++;

        return [
            'url'             => $this->url,
            'hostname'        => $this->hostname,
            'score'           => $scoring['score'],
            'grade'           => $scoring['grade'],
            'total_checks'    => count($this->findings),
            'passed'          => $counts['pass'],
            'info'            => $counts['info'],
            'warnings'        => $counts['warning'],
            'critical'        => $counts['critical'],
            'server_ip'       => ['ipv4' => array_values(array_unique($this->resolvedIpv4)), 'ipv6' => array_values(array_unique($this->resolvedIpv6))],
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
        $weights = ['pass' => 100, 'info' => 70, 'warning' => 35, 'critical' => 0];
        $buckets = [];
        foreach ($this->findings as $f) {
            $buckets[$f->category][] = $weights[$f->severity] ?? 0;
        }
        $out = [];
        foreach ($buckets as $cat => $scores) {
            $avg = (int) round(array_sum($scores) / count($scores));
            $grade = $avg >= 90 ? 'A+' : ($avg >= 80 ? 'A' : ($avg >= 70 ? 'B' : ($avg >= 60 ? 'C' : ($avg >= 45 ? 'D' : 'F'))));
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
