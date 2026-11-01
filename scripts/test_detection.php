<?php
/**
 * scripts/test_detection.php — Offline unit tests for the new detection logic.
 *
 * Runs fully offline (no network) by exercising the pure helper methods:
 *   - scanBodyForSecrets()   — leaked credential/key detection
 *   - analyzeFormsForCsrf()  — anti-CSRF token coverage on POST forms
 *
 * Run from the project root:
 *     php scripts/test_detection.php
 * or via Composer:
 *     composer test:detection
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('This script is CLI-only.');
}

require_once dirname(__DIR__) . '/scanner.php';

$pass = 0;
$fail = 0;
function check(string $label, bool $cond): void
{
    global $pass, $fail;
    if ($cond) { $pass++; echo "  \033[32m[PASS]\033[0m {$label}\n"; }
    else       { $fail++; echo "  \033[31m[FAIL]\033[0m {$label}\n"; }
}

// Build an instance without the (network-touching) constructor.
$scanner = (new ReflectionClass('SecurityScanner'))->newInstanceWithoutConstructor();

echo "============================================================\n";
echo "  Detection unit tests (offline)\n";
echo "============================================================\n\n";

// ------------------------------------------------------------------
// 1. Exposed-secret detection
// ------------------------------------------------------------------
echo "Part 1 — scanBodyForSecrets()\n";

$secretBody = <<<'HTML'
<script>
  const awsKey = "AKIAIOSFODNN7EXAMPLE";
  const gmaps  = "AIzaSyA1234567890abcdefghijklmnopqrstuv";
  const stripe = "sk_live_1234567890abcdefABCDEF";
  const gh     = "ghp_ABCDEFabcdef0123456789ABCDEFabcdef01";
</script>
-----BEGIN RSA PRIVATE KEY-----
MIIEfake...
-----END RSA PRIVATE KEY-----
HTML;

$hits = $scanner->scanBodyForSecrets($secretBody);
$types = array_column($hits, 'type');

check('detects AWS Access Key ID',  in_array('AWS Access Key ID', $types, true));
check('detects Google API Key',     in_array('Google API Key', $types, true));
check('detects Stripe Secret Key',  in_array('Stripe Secret Key', $types, true));
check('detects GitHub Token',       in_array('GitHub Token', $types, true));
check('detects Private Key Block',  in_array('Private Key Block', $types, true));

$critical = array_filter($hits, fn($h) => $h['severity'] === 'critical');
check('secret hits are flagged critical', count($critical) >= 4);

// Samples must be redacted (never echo the full secret).
$leaks = array_filter($hits, fn($h) => str_contains($h['sample'], 'AKIAIOSFODNN7EXAMPLE'));
check('secret samples are masked (no full secret leaked)', count($leaks) === 0);

// Clean page must produce nothing.
$clean = '<html><body><h1>Hello</h1><p>No secrets here.</p></body></html>';
check('clean body yields no secret findings', count($scanner->scanBodyForSecrets($clean)) === 0);

// A random 40-char base64 string that is NOT a known format should not match.
$noise = '<div data-hash="abc123DEF456ghi789JKL012mno345PQR678stu"></div>';
check('random hash does not false-positive', count($scanner->scanBodyForSecrets($noise)) === 0);

echo "\n";

// ------------------------------------------------------------------
// 1a. Cookie attribute parsing
// ------------------------------------------------------------------
echo "Part 1a — analyzeSetCookie()\n";

$cookie = $scanner->analyzeSetCookie('PHPSESSID=abc; Secure; HttpOnly; SameSite=Lax; Path=/');
check('secure session cookie has no issues', $cookie['sensitive'] === true && $cookie['issues'] === []);

$cookie = $scanner->analyzeSetCookie('theme=dark; Secure; SameSite=Lax');
check('non-sensitive client-readable cookie does not require HttpOnly', $cookie['sensitive'] === false && $cookie['issues'] === []);

$cookie = $scanner->analyzeSetCookie('secure_token=abc; HttpOnly; SameSite=Lax');
check('word "secure" in cookie name does not fake the Secure flag', in_array('missing Secure flag', $cookie['issues'], true));

$cookie = $scanner->analyzeSetCookie('__Host-session=abc; Secure; HttpOnly; SameSite=Strict; Path=/; Domain=example.test');
check('__Host- cookie rejects a Domain attribute', in_array('__Host- prefix forbids Domain', $cookie['issues'], true));

$cookie = $scanner->analyzeSetCookie('__Secure-id=abc; SameSite=None');
check('__Secure- and SameSite=None both require Secure',
    in_array('__Secure- prefix requires Secure', $cookie['issues'], true)
    && in_array('SameSite=None requires Secure', $cookie['issues'], true));

$cookie = $scanner->analyzeSetCookie('prefs=1; Secure; SameSite=Maybe');
check('invalid SameSite value is reported', in_array('invalid SameSite value', $cookie['issues'], true));

echo "\n";

// ------------------------------------------------------------------
// 1b. Detailed error disclosure
// ------------------------------------------------------------------
echo "Part 1b — analyzeErrorDisclosure()\n";

$errors = $scanner->analyzeErrorDisclosure('Fatal error: Uncaught RuntimeException in /var/www/app.php on line 42');
check('detects PHP runtime path disclosure', in_array('PHP runtime error with server path', array_column($errors, 'type'), true));

$errors = $scanner->analyzeErrorDisclosure('SQLSTATE[HY000]: General error PDOException Stack trace: #0');
check('detects database error disclosure', in_array('Database error details', array_column($errors, 'type'), true));

$errors = $scanner->analyzeErrorDisclosure("Traceback (most recent call last):\n  File \"/srv/app.py\", line 12, in index\nValueError");
check('detects Python traceback disclosure', in_array('Python traceback', array_column($errors, 'type'), true));

check('ordinary page text has no error disclosure finding',
    $scanner->analyzeErrorDisclosure('<h1>Support</h1><p>Contact us if an error occurs.</p>') === []);

echo "\n";

// ------------------------------------------------------------------
// 1c. Cross-origin isolation header validation
// ------------------------------------------------------------------
echo "Part 1c — analyzeCrossOriginIsolationHeaders()\n";

$isolation = $scanner->analyzeCrossOriginIsolationHeaders('require-corp', 'same-origin', 'same-site');
check('protective COEP/COOP/CORP values pass', count(array_filter($isolation, fn($f) => $f['severity'] === 'pass')) === 3);

$isolation = $scanner->analyzeCrossOriginIsolationHeaders('invalid', 'unsafe-none', null);
check('invalid COEP value is a warning', $isolation[0]['severity'] === 'warning');
check('permissive or missing optional isolation headers are non-scoreable info',
    $isolation[1]['severity'] === 'info' && $isolation[1]['scoreable'] === false
    && $isolation[2]['severity'] === 'info' && $isolation[2]['scoreable'] === false);

echo "\n";

// ------------------------------------------------------------------
// 1d. Client-side dependency fingerprints
// ------------------------------------------------------------------
echo "Part 1d — analyzeClientSideDependencies()\n";
$deps = $scanner->analyzeClientSideDependencies(
    '<script src="/assets/jquery-3.4.1.min.js"></script>'
    . '<script src="/js/lodash-4.17.20.min.js"></script>'
    . '<script src="/js/angular-1.8.2.min.js"></script>'
);
$depKeys = array_map(static fn(array $d): string => $d['name'] . ' ' . $d['version'], $deps);
check('detects vulnerable jQuery version', in_array('jQuery 3.4.1', $depKeys, true));
check('detects vulnerable Lodash version', in_array('Lodash 4.17.20', $depKeys, true));
check('detects AngularJS end-of-life', in_array('AngularJS 1.8.2', $depKeys, true));
check('does not flag patched jQuery', $scanner->analyzeClientSideDependencies('<script src="/jquery-3.7.1.min.js"></script>') === []);

echo "\n";

// ------------------------------------------------------------------
// 1e. SEO poisoning indicator analysis
// ------------------------------------------------------------------
echo "Part 1e — SEO poisoning helpers\n";

$seoRef = new ReflectionClass('SecurityScanner');
$seoTerms = $seoRef->getMethod('seoSpamTermsIn');
$seoHidden = $seoRef->getMethod('seoHiddenText');
$seoCount = $seoRef->getMethod('seoSpamOccurrenceCount');
$seoStrong = $seoRef->getMethod('seoHasStrongSpamTerm');
$challengeBody = $seoRef->getMethod('bodyLooksLikeValidationChallenge');
$seoRefresh = $seoRef->getMethod('seoMetaRefreshTarget');
$httpFallback = $seoRef->getMethod('shouldTryHttpFallback');

$hiddenSpam = '<main>Portal rasmi organisasi.</main><div style="display:none">Buy Viagra dan slot-gacor murah</div>';
$hiddenText = $seoHidden->invoke($scanner, $hiddenSpam);
$hiddenTerms = $seoTerms->invoke($scanner, $hiddenText);
check('detects spam term in hidden HTML content', in_array('buy viagra', $hiddenTerms, true) && in_array('slot gacor', $hiddenTerms, true));

$plainTerms = $seoTerms->invoke($scanner, 'Portal rasmi maklumat keselamatan siber.');
check('clean page text has no SEO-spam terms', $plainTerms === []);

$keywordHackTerms = $seoTerms->invoke($scanner, 'SLOT-GACOR hari ini dan スーパーコピー');
check('detects Malay/Indonesian and Japanese keyword-hack phrases',
    in_array('slot gacor', $keywordHackTerms, true) && in_array('スーパーコピー', $keywordHackTerms, true));
check('recognises a single strong SEO-spam phrase', $seoStrong->invoke($scanner, ['slot gacor']) === true);
check('counts repeated spam phrases for keyword-stuffing detection',
    $seoCount->invoke($scanner, 'slot gacor slot-gacor slot/gacor') === 3);
check('detects a generic browser-verification challenge page',
    $challengeBody->invoke($scanner, '<title>Just a moment</title><p>Checking your browser before accessing the site.</p>') === true);

$refresh = $seoRefresh->invoke($scanner, '<meta http-equiv="refresh" content="0; url=https://spam.example/landing">');
check('extracts external meta-refresh target', $refresh === 'https://spam.example/landing');
check('HTTPS timeout permits HTTP-only fallback', $httpFallback->invoke($scanner, 'https', 28, 'Timeout was reached') === true);
check('certificate failure does not downgrade to HTTP', $httpFallback->invoke($scanner, 'https', 60, 'SSL certificate problem') === false);

echo "\n";

// ------------------------------------------------------------------
// 2. CSRF form analysis
// ------------------------------------------------------------------
echo "Part 2 — analyzeFormsForCsrf()\n";

$unprotected = '<form method="post" action="/pay"><input name="amount"></form>';
$r1 = $scanner->analyzeFormsForCsrf($unprotected);
check('POST form without token -> unprotected', $r1['post_forms'] === 1 && $r1['unprotected'] === 1);

$hidden = '<form method="POST" action="/pay"><input type="hidden" name="_token" value="x"><input name="amount"></form>';
$r2 = $scanner->analyzeFormsForCsrf($hidden);
check('POST form with _token field -> protected', $r2['post_forms'] === 1 && $r2['unprotected'] === 0);

$meta = '<head><meta name="csrf-token" content="abc"></head><form method="post"><input name="q"></form>';
$r3 = $scanner->analyzeFormsForCsrf($meta);
check('page CSRF meta tag -> form protected', $r3['unprotected'] === 0);

$getForm = '<form method="get" action="/search"><input name="q"></form>';
$r4 = $scanner->analyzeFormsForCsrf($getForm);
check('GET form is ignored (not state-changing)', $r4['post_forms'] === 0 && $r4['unprotected'] === 0);

$mixed = $unprotected . $hidden . $getForm;
$r5 = $scanner->analyzeFormsForCsrf($mixed);
check('mixed page counts only unprotected POST forms', $r5['post_forms'] === 2 && $r5['unprotected'] === 1);

echo "\n";

// ------------------------------------------------------------------
// 3. GraphQL introspection classification
// ------------------------------------------------------------------
echo "Part 3 — classifyGraphqlResponse()\n";

$schema = '{"data":{"__schema":{"queryType":{"name":"Query"}}}}';
check('schema response -> enabled', $scanner->classifyGraphqlResponse($schema) === 'enabled');

$disabled = '{"errors":[{"message":"GraphQL introspection is disabled"}]}';
check('introspection-disabled error -> present', $scanner->classifyGraphqlResponse($disabled) === 'present');

$syntaxErr = '{"errors":[{"message":"Syntax Error: Unexpected Name"}]}';
check('graphql syntax error -> present', $scanner->classifyGraphqlResponse($syntaxErr) === 'present');

$notGraphql = '<html><body>404 Not Found</body></html>';
check('plain HTML 404 -> none', $scanner->classifyGraphqlResponse($notGraphql) === 'none');

echo "\n";

// ------------------------------------------------------------------
// 4. SPF / DMARC hardening analysis
// ------------------------------------------------------------------
echo "Part 4 — analyzeSpfRecord() / analyzeDmarcRecord()\n";

$spfClean = 'v=spf1 include:_spf.google.com -all';
$a1 = $scanner->analyzeSpfRecord($spfClean);
check('clean SPF -> 1 lookup, no issues', $a1['lookups'] === 1 && $a1['issues'] === []);

$spfMany = 'v=spf1 include:a.com include:b.com include:c.com a mx exists:%{i}.d.com redirect=e.com -all';
$a2 = $scanner->analyzeSpfRecord($spfMany);
check('counts multiple lookup mechanisms', $a2['lookups'] >= 7);

$spfPtr = 'v=spf1 ptr ?all';
$a3 = $scanner->analyzeSpfRecord($spfPtr);
check('flags ptr + neutral ?all', count($a3['issues']) >= 2);

$spfNoAll = 'v=spf1 include:x.com';
$a4 = $scanner->analyzeSpfRecord($spfNoAll);
check('flags missing all mechanism', in_array("has no 'all' mechanism, leaving the default policy undefined", $a4['issues'], true));

$dmarcWeak = 'v=DMARC1; p=reject; sp=none; pct=50';
$d1 = $scanner->analyzeDmarcRecord($dmarcWeak);
check('DMARC pct<100 + sp weaker + no rua -> 3 issues', count($d1['issues']) === 3);

$dmarcStrong = 'v=DMARC1; p=reject; rua=mailto:d@x.com; pct=100';
$d2 = $scanner->analyzeDmarcRecord($dmarcStrong);
check('strong DMARC -> no enforcement issues', $d2['issues'] === []);

echo "\n";

// ------------------------------------------------------------------
// 5. Authenticated-scan credential handling
// ------------------------------------------------------------------
echo "Part 5 — setAuth() / withAuth()\n";

$ref        = new ReflectionClass('SecurityScanner');
$pAuthHead  = $ref->getProperty('authHeaders');
$pAuthCook  = $ref->getProperty('authCookie');
$pAuthOn    = $ref->getProperty('authEnabled');
$pHost      = $ref->getProperty('hostname');
$mWithAuth  = $ref->getMethod('withAuth');

// (a) Allow-list: Authorization + X-* kept; disallowed header dropped.
$s = $ref->newInstanceWithoutConstructor();
$s->setAuth(['Authorization: Bearer abc', 'X-Api-Key: k1', 'User-Agent: evil'], '');
$hdrs = $pAuthHead->getValue($s);
check('keeps Authorization header', in_array('Authorization: Bearer abc', $hdrs, true));
check('keeps X-* header', in_array('X-Api-Key: k1', $hdrs, true));
check('drops non-allow-listed header (User-Agent)', !in_array('User-Agent: evil', $hdrs, true));

// (b) Map form + Cookie header merged into cookie jar.
$s2 = $ref->newInstanceWithoutConstructor();
$s2->setAuth(['Cookie' => 'sid=1'], 'csrf=2');
$cook = $pAuthCook->getValue($s2);
check('cookie param + Cookie header merged', str_contains($cook, 'sid=1') && str_contains($cook, 'csrf=2'));
check('Cookie header not left in header list', $pAuthHead->getValue($s2) === []);

// (c) CRLF header-injection attempt is stripped.
$s3 = $ref->newInstanceWithoutConstructor();
$s3->setAuth(["X-Evil: a\r\nX-Injected: b"], '');
$joined = implode('|', $pAuthHead->getValue($s3));
check('strips CR/LF from header values', strpos($joined, "\r") === false && strpos($joined, "\n") === false);

// (d) withAuth() merges into cURL opts and preserves existing headers.
$s4 = $ref->newInstanceWithoutConstructor();
$pHost->setValue($s4, 'secure.example.test');
$s4->setAuth(['Authorization: Bearer t'], 'sid=9');
$opts = $mWithAuth->invoke($s4, [
    CURLOPT_URL => 'https://secure.example.test/api',
    CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
]);
check('withAuth sets CURLOPT_COOKIE', ($opts[CURLOPT_COOKIE] ?? '') === 'sid=9');
check('withAuth preserves caller headers + adds auth',
    in_array('Content-Type: application/json', $opts[CURLOPT_HTTPHEADER], true)
    && in_array('Authorization: Bearer t', $opts[CURLOPT_HTTPHEADER], true));
$crossHost = $mWithAuth->invoke($s4, [CURLOPT_URL => 'https://redirected.example.test/api']);
check('withAuth skips credentials for redirected host',
    !isset($crossHost[CURLOPT_COOKIE]) && !isset($crossHost[CURLOPT_HTTPHEADER]));
$crossPort = $mWithAuth->invoke($s4, [CURLOPT_URL => 'https://secure.example.test:8443/api']);
check('withAuth skips credentials for a different port',
    !isset($crossPort[CURLOPT_COOKIE]) && !isset($crossPort[CURLOPT_HTTPHEADER]));
$plainHttp = $mWithAuth->invoke($s4, [CURLOPT_URL => 'http://secure.example.test/api']);
check('withAuth skips credentials over plaintext HTTP',
    !isset($plainHttp[CURLOPT_COOKIE]) && !isset($plainHttp[CURLOPT_HTTPHEADER]));
check('withAuth forces TLS certificate verification when credentials are attached',
    ($opts[CURLOPT_SSL_VERIFYPEER] ?? false) === true && ($opts[CURLOPT_SSL_VERIFYHOST] ?? 0) === 2);

// (e) No auth configured -> withAuth is a no-op.
$s5 = $ref->newInstanceWithoutConstructor();
$s5->setAuth([], '');
check('empty auth -> authEnabled false', $pAuthOn->getValue($s5) === false);
$noop = $mWithAuth->invoke($s5, [CURLOPT_URL => 'x']);
check('empty auth -> withAuth unchanged', $noop === [CURLOPT_URL => 'x']);

// ------------------------------------------------------------------
// 6. Active-probe helpers (offline)
// ------------------------------------------------------------------
echo "Part 6 — active-probe analysis helpers\n";

// 6a. SQL error signatures
check('detects MySQL syntax error', $scanner->analyzeSqlError("You have an error in your SQL syntax near '1''") === 'MySQL/MariaDB');
check('detects PDO/SQLSTATE error', $scanner->analyzeSqlError('SQLSTATE[42000]: Syntax error or access violation') === 'PDO');
check('detects PostgreSQL error', $scanner->analyzeSqlError('PostgreSQL ERROR: unterminated quoted string at or near') === 'PostgreSQL');
check('clean page yields no SQL error', $scanner->analyzeSqlError('<h1>Products</h1><p>Nothing here.</p>') === '');

// 6b. JWT structural analysis
$noneJwt = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.';
$noneIssues = $scanner->analyzeJwt($noneJwt);
check('flags alg=none JWT', in_array('uses alg=none (unsigned token)', $noneIssues, true));
check('flags JWT without exp claim', in_array('no exp (expiry) claim', $noneIssues, true));

$header = rtrim(strtr(base64_encode('{"alg":"HS256","typ":"JWT"}'), '+/', '-_'), '=');
$payload = rtrim(strtr(base64_encode('{"sub":"1","exp":' . (time() + 3600) . '}'), '+/', '-_'), '=');
check('well-formed JWT yields no issues', $scanner->analyzeJwt($header . '.' . $payload . '.sig') === []);

// 6c. OpenAPI / Swagger document detection
check('detects OpenAPI JSON', $scanner->analyzeOpenApiDocument('{"openapi":"3.0.0","paths":{"/users":{}}}') === 'OpenAPI/Swagger (JSON)');
check('detects Swagger YAML', $scanner->analyzeOpenApiDocument("swagger: '2.0'\npaths:\n  /users:") === 'OpenAPI/Swagger (YAML)');
check('plain JSON is not OpenAPI', $scanner->analyzeOpenApiDocument('{"hello":"world"}') === '');

// 6d. MTA-STS policy validation
$goodPolicy = "version: STSv1\nmode: enforce\nmx: mail.example.test\nmax_age: 604800\n";
$good = $scanner->analyzeMtaStsPolicy($goodPolicy, 'example.test');
check('valid MTA-STS policy passes', $good['mode'] === 'enforce' && $good['issues'] === []);
$badPolicy = "version: STSv1\nmode: testing\nmx: mail.example.test\nmax_age: 3600\n";
$bad = $scanner->analyzeMtaStsPolicy($badPolicy, 'example.test');
check('weak MTA-STS policy is flagged', in_array('mode: testing does not enforce TLS', $bad['issues'], true) && in_array('max_age below 604800 seconds', $bad['issues'], true));

// MTA-STS TXT record validation
check('valid MTA-STS record passes', $scanner->analyzeMtaStsRecords(['v=STSv1; id=20261101']) === []);
check('MTA-STS record with trailing delimiter passes', $scanner->analyzeMtaStsRecords(['v=STSv1; id=20261101;']) === []);
check('MTA-STS record without spaces passes', $scanner->analyzeMtaStsRecords(['v=STSv1;id=abc123']) === []);
check('MTA-STS extension field is allowed', $scanner->analyzeMtaStsRecords(['v=STSv1; ext=1; id=abc123']) === []);
check('no MTA-STS records is not an issue here', $scanner->analyzeMtaStsRecords([]) === []);
$shellIssue = $scanner->analyzeMtaStsRecords(['v=STSv1; id=$(date +%Y%m%d)']);
check('unexpanded shell id is flagged', count($shellIssue) === 1 && str_contains($shellIssue[0], 'unexpanded shell command'));
check('backtick shell id is flagged', str_contains($scanner->analyzeMtaStsRecords(['v=STSv1; id=`date`'])[0] ?? '', 'unexpanded shell command'));
check('missing MTA-STS id is flagged', str_contains($scanner->analyzeMtaStsRecords(['v=STSv1'])[0] ?? '', 'id field is missing'));
check('empty MTA-STS id is flagged', str_contains($scanner->analyzeMtaStsRecords(['v=STSv1; id='])[0] ?? '', '1-32 letters'));
check('33-character MTA-STS id is flagged', str_contains($scanner->analyzeMtaStsRecords(['v=STSv1; id=' . str_repeat('a', 33)])[0] ?? '', '1-32 letters'));
check('32-character MTA-STS id passes', $scanner->analyzeMtaStsRecords(['v=STSv1; id=' . str_repeat('a', 32)]) === []);
check('punctuation in MTA-STS id is flagged', str_contains($scanner->analyzeMtaStsRecords(['v=STSv1; id=2026-11-01'])[0] ?? '', '1-32 letters'));
check('wrong version case is flagged', str_contains($scanner->analyzeMtaStsRecords(['V=STSV1; id=abc'])[0] ?? '', 'v=STSv1'));
check('duplicate MTA-STS records are flagged', str_contains($scanner->analyzeMtaStsRecords(['v=STSv1; id=a', 'v=STSv1; id=b'])[0] ?? '', 'exactly one'));

// 6e. Redirect target classification (open-redirect helper)
$ref = new ReflectionClass('SecurityScanner');
$locMethod = $ref->getMethod('locationPointsTo');
$locScanner = $ref->newInstanceWithoutConstructor();
$ref->getProperty('url')->setValue($locScanner, 'https://example.test/path?q=1');
check('absolute external redirect is flagged', $locMethod->invoke($locScanner, 'https://secscan7f3a9c.example/login', 'secscan7f3a9c.example') === true);
check('relative redirect is not flagged', $locMethod->invoke($locScanner, '/dashboard', 'secscan7f3a9c.example') === false);
check('same-host absolute redirect is not flagged', $locMethod->invoke($locScanner, 'https://example.test/dashboard', 'secscan7f3a9c.example') === false);

// 6f. Expanded secret formats
$moreSecrets = 'key=' . 'sk-' . str_repeat('a', 40) . ' hook=https://discord.com/api/webhooks/123456789012345678/AbCdEfGh';
$moreTypes = array_column($scanner->scanBodyForSecrets($moreSecrets), 'type');
check('detects OpenAI-style key', in_array('OpenAI API Key', $moreTypes, true));
check('detects Discord webhook', in_array('Discord Webhook', $moreTypes, true));

$newFormats = [
    'OpenAI Project/Service Key' => 'sk-proj-' . str_repeat('aB3_-', 8),
    'OpenRouter API Key'         => 'sk-or-v1-' . str_repeat('a1', 32),
    'Groq API Key'               => 'gsk_' . str_repeat('aB3', 18),
    'xAI API Key'                => 'xai-' . str_repeat('aB3', 20),
    'Hugging Face Token'         => 'hf_' . str_repeat('aB3', 12),
    'Replicate API Token'        => 'r8_' . str_repeat('a', 37),
    'GitHub Fine-grained Token'  => 'github_pat_' . str_repeat('a1B', 10) . '_' . str_repeat('c2D', 20),
    'GitLab Access Token'        => 'glpat-' . str_repeat('aB3', 8),
    'PyPI API Token'             => 'pypi-AgE' . str_repeat('aB3', 20),
    'Stripe Webhook Secret'      => 'whsec_' . str_repeat('aB3', 10),
    'Google OAuth Client Secret' => 'GOCSPX-' . str_repeat('aB3-', 7),
    'Supabase Secret Key'        => 'sb_secret_' . str_repeat('aB3', 8),
];
foreach ($newFormats as $type => $token) {
    check("detects {$type}", in_array($type, array_column($scanner->scanBodyForSecrets("x = \"{$token}\";"), 'type'), true));
}
$anthropicOnly = array_column($scanner->scanBodyForSecrets('sk-ant-' . str_repeat('aB3', 12)), 'type');
check('Anthropic key is not also labelled as OpenAI', $anthropicOnly === ['Anthropic API Key']);
$pgpTypes = array_column($scanner->scanBodyForSecrets("-----BEGIN PGP PRIVATE KEY BLOCK-----\n"), 'type');
check('detects PGP private key block', in_array('Private Key Block', $pgpTypes, true));
$encryptedTypes = array_column($scanner->scanBodyForSecrets("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"), 'type');
check('detects encrypted private key block', in_array('Private Key Block', $encryptedTypes, true));
check('public key block is not a secret', $scanner->scanBodyForSecrets("-----BEGIN PUBLIC KEY-----\n") === []);

// ------------------------------------------------------------------
// 7. Version-matched core advisories
// ------------------------------------------------------------------
echo "\nPart 7 — CMS core advisories\n";

$advisoryIds = fn(string $cms, string $version): array => array_column($scanner->cmsCoreAdvisoriesFor($cms, $version)['matches'], 'id');

check('WP 7.1.1 is affected by CVE-2026-87902', in_array('CVE-2026-87902', $advisoryIds('WordPress', '7.1.1'), true));
check('WP 7.1.2 is fixed for CVE-2026-87902', !in_array('CVE-2026-87902', $advisoryIds('WordPress', '7.1.2'), true));
check('WP 7.1.2 still misses 7.1.4 fixes', in_array('WordPress 7.1.4 security release', $advisoryIds('WordPress', '7.1.2'), true));
check('WP 7.1.4 is clear', $scanner->cmsCoreAdvisoriesFor('WordPress', '7.1.4')['status'] === 'clear');
check('WP 7.1 is read as 7.1.0', in_array('CVE-2026-87902', $advisoryIds('WordPress', '7.1'), true));
check('WP 6.2.12 is affected', in_array('CVE-2026-87902', $advisoryIds('WordPress', '6.2.12'), true));
check('WP 6.2.13 backport is fixed', $advisoryIds('WordPress', '6.2.13') === []);
check('WP 6.2.14 stays fixed', $advisoryIds('WordPress', '6.2.14') === []);
check('WP 4.7.37 backport is fixed', $advisoryIds('WordPress', '4.7.37') === []);
check('WP 4.6.1 predates the affected range', $advisoryIds('WordPress', '4.6.1') === []);
check('WP 7.2 beta is outside tracked ranges', $advisoryIds('WordPress', '7.2-beta3') === []);
check('every match recommends a newer version', (function () use ($scanner): bool {
    foreach (['WordPress' => '7.1.1', 'Joomla' => '6.1.3', 'Drupal' => '11.3.9'] as $cms => $version) {
        foreach ($scanner->cmsCoreAdvisoriesFor($cms, $version)['matches'] as $match) {
            if (version_compare($version, $match['fixed'], '>=')) return false;
        }
    }
    return true;
})());

check('Joomla 5.4.8 is affected', $scanner->cmsCoreAdvisoriesFor('Joomla', '5.4.8')['status'] === 'affected');
check('Joomla 5.4.9 is clear', $scanner->cmsCoreAdvisoriesFor('Joomla', '5.4.9')['status'] === 'clear');
check('Joomla 6.1.3 is affected', $scanner->cmsCoreAdvisoriesFor('Joomla', '6.1.3')['status'] === 'affected');
check('Joomla 6.1.4 is clear', $scanner->cmsCoreAdvisoriesFor('Joomla', '6.1.4')['status'] === 'clear');
check('Joomla 6.0.9 is affected, not skipped by the 5.x range', $scanner->cmsCoreAdvisoriesFor('Joomla', '6.0.9')['status'] === 'affected');
check('short Joomla version is imprecise', $scanner->cmsCoreAdvisoriesFor('Joomla', '6.1')['status'] === 'imprecise');

check('Drupal major-only generator is imprecise', $scanner->cmsCoreAdvisoriesFor('Drupal', '11')['status'] === 'imprecise');
check('Drupal 11.3.9 hits all three advisories', count($advisoryIds('Drupal', '11.3.9')) === 3);
check('Drupal 11.3.18 only hits Field UI RCE', $advisoryIds('Drupal', '11.3.18') === ['CVE-2026-108097']);
check('Drupal 11.3.19 is clear', $scanner->cmsCoreAdvisoriesFor('Drupal', '11.3.19')['status'] === 'clear');
check('Drupal 11.4.9 is affected', $advisoryIds('Drupal', '11.4.9') === ['CVE-2026-108097']);
check('Drupal 11.4.10 is clear', $scanner->cmsCoreAdvisoriesFor('Drupal', '11.4.10')['status'] === 'clear');
check('Drupal 10.6.19 is clear', $scanner->cmsCoreAdvisoriesFor('Drupal', '10.6.19')['status'] === 'clear');
check('Drupal 12 beta1 is affected', in_array('CVE-2026-108097', $advisoryIds('Drupal', '12.0.0-beta1'), true));
check('Drupal 12 beta2 is clear', $scanner->cmsCoreAdvisoriesFor('Drupal', '12.0.0-beta2')['status'] === 'clear');
check('Drupal 7 is outside the tracked ranges', $advisoryIds('Drupal', '7.103.0') === []);
check('unknown version is reported as unknown', $scanner->cmsCoreAdvisoriesFor('WordPress', '')['status'] === 'unknown');
check('CMS without a table is reported as unknown', $scanner->cmsCoreAdvisoriesFor('Ghost', '5.0.0')['status'] === 'unknown');

// ------------------------------------------------------------------
// 8. Server banners
// ------------------------------------------------------------------
echo "\nPart 8 — PHP2Shell and web server banners\n";

check('PHP 8.5.11 is critical', ($scanner->php2shellAdvisoryForBanner('PHP/8.5.11')['severity'] ?? '') === 'critical');
check('PHP 8.5.12 is fixed', $scanner->php2shellAdvisoryForBanner('PHP/8.5.12') === null);
check('PHP 8.4.26 is critical', ($scanner->php2shellAdvisoryForBanner('PHP/8.4.26')['severity'] ?? '') === 'critical');
check('PHP 8.4.27 is fixed', $scanner->php2shellAdvisoryForBanner('PHP/8.4.27') === null);
check('PHP 8.3.35 is critical', ($scanner->php2shellAdvisoryForBanner('PHP/8.3.35')['severity'] ?? '') === 'critical');
check('PHP 8.3.36 is fixed', $scanner->php2shellAdvisoryForBanner('PHP/8.3.36') === null);
check('PHP 8.2.34 is critical', ($scanner->php2shellAdvisoryForBanner('PHP/8.2.34')['severity'] ?? '') === 'critical');
check('PHP 8.2.35 is fixed', $scanner->php2shellAdvisoryForBanner('PHP/8.2.35') === null);
check('PHP 7.4.33 is critical', ($scanner->php2shellAdvisoryForBanner('PHP/7.4.33')['severity'] ?? '') === 'critical');
check('distro-tagged PHP is a warning', ($scanner->php2shellAdvisoryForBanner('PHP/8.1.2-1ubuntu2.22')['severity'] ?? '') === 'warning');
check('mod_php in a Server banner is read', ($scanner->php2shellAdvisoryForBanner('Apache/2.4.69 (Unix) PHP/8.3.1')['severity'] ?? '') === 'critical');
check('future PHP branch is not flagged', $scanner->php2shellAdvisoryForBanner('PHP/8.6.0') === null);
check('no version means no PHP2Shell claim', $scanner->php2shellAdvisoryForBanner('PHP') === null);

$serverHit = fn(string $banner): array => $scanner->analyzeWebServerBanner($banner)[0] ?? [];
check('nginx 1.30.3 cites CVE-2026-42533', str_contains($serverHit('nginx/1.30.3')['message'] ?? '', 'CVE-2026-42533'));
check('nginx 1.30.4 only misses medium fixes', !str_contains($serverHit('nginx/1.30.4')['message'] ?? 'CVE-2026-42533', 'CVE-2026-42533'));
check('nginx 1.30.6 is clean', $scanner->analyzeWebServerBanner('nginx/1.30.6') === []);
check('nginx 1.31.2 cites CVE-2026-42533', str_contains($serverHit('nginx/1.31.2')['message'] ?? '', 'CVE-2026-42533'));
check('nginx 1.31.6 is a warning', ($serverHit('nginx/1.31.6')['severity'] ?? '') === 'warning');
check('nginx 1.31.7 is clean', $scanner->analyzeWebServerBanner('nginx/1.31.7') === []);
check('nginx 1.28.0 cites CVE-2026-42533', str_contains($serverHit('nginx/1.28.0')['message'] ?? '', 'CVE-2026-42533'));
check('distro nginx keeps the major flaw as a warning', ($serverHit('nginx/1.24.0 (Ubuntu)')['severity'] ?? '') === 'warning');
check('distro nginx medium gap is info', ($serverHit('nginx/1.30.5 (Ubuntu)')['severity'] ?? '') === 'info');
check('unversioned nginx is ignored', $scanner->analyzeWebServerBanner('nginx') === []);
check('Apache 2.4.66 is critical', ($serverHit('Apache/2.4.66')['severity'] ?? '') === 'critical');
check('Apache (Unix) is not treated as distro', ($serverHit('Apache/2.4.66 (Unix)')['severity'] ?? '') === 'critical');
check('distro Apache 2.4.66 is a warning', ($serverHit('Apache/2.4.66 (Debian)')['severity'] ?? '') === 'warning');
check('Apache 2.4.68 is a warning', ($serverHit('Apache/2.4.68')['severity'] ?? '') === 'warning');
check('distro Apache 2.4.58 is info', ($serverHit('Apache/2.4.58 (Ubuntu)')['severity'] ?? '') === 'info');
check('Apache 2.4.69 is clean', $scanner->analyzeWebServerBanner('Apache/2.4.69') === []);
check('Apache 2.2.34 is outdated', str_contains($serverHit('Apache/2.2.34')['message'] ?? '', 'outdated major branch'));

// ------------------------------------------------------------------
// 9. Known-exploited product fingerprints
// ------------------------------------------------------------------
echo "\nPart 9 — analyzeKevProducts()\n";

$kevProducts = fn(string $body, array $headers = [], array $cookies = []): array => array_keys($scanner->analyzeKevProducts($body, $headers, $cookies));
check('Ivanti from dana-na path', $kevProducts('<a href="/dana-na/auth/url_default/welcome.cgi">') === ['Ivanti Connect Secure']);
check('NetScaler from NSC_ cookie', $kevProducts('', [], ['NSC_vsrv_web=ffff; path=/']) === ['Citrix NetScaler']);
check('Cisco ASA from CSCOE path', $kevProducts('<script src="/+CSCOE+/logon.js">') === ['Cisco Secure Firewall ASA/FTD']);
check('GlobalProtect from portal path', $kevProducts('<form action="/global-protect/login.esp">') === ['Palo Alto PAN-OS GlobalProtect']);
check('GitLab from og:site_name', $kevProducts('<meta property="og:site_name" content="GitLab">') === ['GitLab']);
check('GitLab from session cookie', $kevProducts('', [], ['_gitlab_session=abc; path=/']) === ['GitLab']);
check('Confluence from header', $kevProducts('', ['x-confluence-request-time' => ['1']]) === ['Atlassian Data Center']);
check('ScreenConnect from Server header', $kevProducts('', ['server' => ['ScreenConnect/25.1']]) === ['ConnectWise ScreenConnect']);
check('Magento from init script', $kevProducts('<script type="text/x-magento-init">') === ['Magento / Adobe Commerce']);
check('Magento from cookie', $kevProducts('', [], ['mage-cache-sessid=true; path=/']) === ['Magento / Adobe Commerce']);
check('plain page matches nothing', $kevProducts('<html><body>Welcome</body></html>', ['server' => ['nginx']], ['session=1']) === []);
check('prose mentioning a product does not match', $kevProducts('<p>We migrated from GitLab and Citrix NetScaler to Ivanti.</p>') === []);

echo "\n============================================================\n";
echo "  Result: {$pass} PASS, {$fail} FAIL\n";
echo "============================================================\n";

exit($fail === 0 ? 0 : 1);
