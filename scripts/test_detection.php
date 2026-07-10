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
// 1b. Client-side dependency fingerprints
// ------------------------------------------------------------------
echo "Part 1b — analyzeClientSideDependencies()\n";
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

echo "\n============================================================\n";
echo "  Result: {$pass} PASS, {$fail} FAIL\n";
echo "============================================================\n";

exit($fail === 0 ? 0 : 1);
