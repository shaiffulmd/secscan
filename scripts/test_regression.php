<?php

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('This script is CLI-only.');
}

require_once dirname(__DIR__) . '/scanner.php';
require_once dirname(__DIR__) . '/src/GeoIp.php';

$failures = [];

$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

$assertSame = static function ($expected, $actual, string $message) use (&$failures): void {
    if ($expected !== $actual) {
        $failures[] = $message . ' Expected ' . var_export($expected, true) . ', got ' . var_export($actual, true) . '.';
    }
};

$publicTarget = UrlGuard::normalizeAndValidate('8.8.8.8');
$assert(($publicTarget['ok'] ?? false) === true, 'Public literal IP should be accepted.');
$assertSame('https://8.8.8.8', $publicTarget['url'] ?? null, 'Bare host should normalize to https URL.');

foreach (['127.0.0.1', '10.0.0.1', '100.64.0.1', '203.0.113.1', 'localhost'] as $target) {
    $result = UrlGuard::normalizeAndValidate($target);
    $assert(($result['ok'] ?? false) === false, "Unsafe target {$target} should be blocked.");
}

$credentialTarget = UrlGuard::normalizeAndValidate('https://user:secret@8.8.8.8/');
$assert(($credentialTarget['ok'] ?? true) === false, 'URLs containing credentials must be rejected.');

$geoPdo = new PDO('sqlite::memory:');
$geoPdo->exec('CREATE TABLE geoip_country (family INTEGER NOT NULL, ip_start BLOB NOT NULL, ip_end BLOB NOT NULL, country TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY (family, ip_start))');
$geoPdo->prepare('INSERT INTO geoip_country VALUES (?, ?, ?, ?, ?)')->execute([4, inet_pton('8.8.8.0'), inet_pton('8.8.8.255'), 'US', '2026-07-10T00:00:00Z']);
$assertSame('US', GeoIp::lookup($geoPdo, '8.8.8.8'), 'GeoIP should resolve a matching local IPv4 range.');
$assertSame('', GeoIp::lookup($geoPdo, '8.8.9.1'), 'GeoIP should not resolve an IP outside the local range.');

$scanner = new SecurityScanner('https://8.8.8.8');
$ref = new ReflectionClass(SecurityScanner::class);

$cmsFindingFor = static function (string $body, array $headers = []) use ($ref): ?SecurityFinding {
    $scanner = new SecurityScanner('https://8.8.8.8');
    $responseBody = $ref->getProperty('responseBody');
    $responseBody->setValue($scanner, $body);
    if ($headers) {
        $responseHeaders = $ref->getProperty('responseHeaders');
        $responseHeaders->setValue($scanner, $headers);
    }
    $checkCms = $ref->getMethod('checkCMSDetection');
    $checkCms->invoke($scanner);
    $findings = $ref->getProperty('findings')->getValue($scanner);
    foreach ($findings as $finding) {
        if ($finding->category === 'Technology' && $finding->check === 'CMS Detected') {
            return $finding;
        }
    }
    return null;
};

$cms = $cmsFindingFor('<html><meta name="generator" content="WordPress 6.5.4"></html>');
$assert($cms !== null && str_contains($cms->message, 'WordPress 6.5.4'), 'WordPress should be detected from generator meta alone.');

$cmsScanner = new SecurityScanner('https://8.8.8.8');
$ref->getProperty('responseBody')->setValue($cmsScanner, '<html><meta name="generator" content="WordPress 6.5.4"></html>');
$ref->getMethod('checkCMSDetection')->invoke($cmsScanner);
$cmsResult = $ref->getMethod('buildResult')->invoke($cmsScanner);
$assertSame('WordPress', $cmsResult['detected_cms'] ?? null, 'Detected CMS should be exposed in the result payload.');
$assertSame('6.5.4', $cmsResult['detected_cms_version'] ?? null, 'Detected CMS version should be exposed in the result payload.');

$cms = $cmsFindingFor('{"asset":"https:\/\/example.com\/wp-content\/themes\/main\/style.css"}');
$assert($cms !== null && str_contains($cms->message, 'WordPress'), 'WordPress should be detected from escaped wp-content asset paths.');

$kedaLikeWordPress = <<<'HTML'
<!doctype html>
<html lang="ms-MY">
<head>
  <link rel="alternate" title="oEmbed (JSON)" type="application/json+oembed" href="https://www.example.gov.my/index.php/wp-json/oembed/1.0/embed?url=https%3A%2F%2Fwww.example.gov.my%2F">
  <link rel="stylesheet" href="https://www.example.gov.my/wp-content/themes/keda_web/style.css?ver=20260128-v10">
  <link rel="stylesheet" href="https://www.example.gov.my/wp-includes/css/dashicons.min.css?ver=6.9">
  <script src="https://www.example.gov.my/wp-includes/js/wp-emoji-release.min.js?ver=6.9"></script>
</head>
</html>
HTML;
$kedaWpScanner = new SecurityScanner('https://8.8.8.8');
$ref->getProperty('responseBody')->setValue($kedaWpScanner, $kedaLikeWordPress);
$ref->getMethod('checkCMSDetection')->invoke($kedaWpScanner);
$kedaWpResult = $ref->getMethod('buildResult')->invoke($kedaWpScanner);
$assertSame('WordPress', $kedaWpResult['detected_cms'] ?? null, 'KEDA-like WordPress source should expose detected_cms.');
$assertSame('6.9', $kedaWpResult['detected_cms_version'] ?? null, 'WordPress core asset version should be exposed when generator meta is hidden.');

$snapshot = $ref->getMethod('passiveCmsSnapshot')->invoke($scanner, $kedaLikeWordPress, [
    'link' => ['<https://www.example.gov.my/index.php/wp-json/oembed/1.0/embed>; rel="alternate"'],
], ['pll_language=ms; path=/; secure; SameSite=Lax']);
$assertSame('WordPress', $snapshot['cms'] ?? null, 'Passive fallback snapshot should detect KEDA-like WordPress.');
$assertSame('6.9', $snapshot['version'] ?? null, 'Passive fallback snapshot should keep the WordPress core version.');

$cms = $cmsFindingFor('<img src="https://www.moe.gov.my/wp-content/uploads/peta.svg"><img src="/wp-content/uploads/faq.svg">');
$assert($cms === null, 'WordPress should not be detected from wp-content/uploads media assets alone.');

$cms = $cmsFindingFor('', ['link' => ['<https://example.com/wp-json/>; rel="https://api.w.org/"']]);
$assert($cms !== null && str_contains($cms->message, 'WordPress'), 'WordPress should be detected from api.w.org Link header.');

$cms = $cmsFindingFor('<a href="/index.php?option=com_content&view=article">Article</a>');
$assert($cms !== null && str_contains($cms->message, 'Joomla'), 'Joomla should be detected from option=com_ routes.');

$joomlaHead = <<<'HTML'
<head>
  <meta name="description" content="My Joomla CMS">
  <meta name="generator" content="Joomla! - Open Source Content Management">
  <link href="/media/vendor/awesomplete/css/awesomplete.css?1.1.5" rel="stylesheet">
  <link href="/components/com_sppagebuilder/assets/css/sppagebuilder.css?143fb2b8" rel="stylesheet">
  <link href="/cache/com_templates/templates/shaper_educon/c437a894.css" rel="stylesheet">
  <link href="https://example.edu.my/index.php/component/search/?id=30&amp;Itemid=101&amp;format=opensearch" rel="search" title="Search My Joomla">
</head>
HTML;
$cms = $cmsFindingFor($joomlaHead);
$assert($cms !== null && str_contains($cms->message, 'Joomla'), 'Joomla should be detected from the supplied Joomla head source.');

$cms = $cmsFindingFor('<html><meta content="Joomla! - Open Source Content Management" name="generator"></html>');
$assert($cms !== null && str_contains($cms->message, 'Joomla'), 'Joomla generator meta should be detected regardless of attribute order.');

$lateJoomlaScanner = new SecurityScanner('https://8.8.8.8');
$lateJoomlaBody = str_repeat('<div class="noise">x</div>', 18000)
    . '<body class="site com-content view-article itemid-101">'
    . '<link href="/media/templates/site/cassiopeia/css/template.min.css" rel="stylesheet">'
    . '<script type="application/json" class="joomla-script-options new">{}</script>';
$ref->getProperty('responseBody')->setValue($lateJoomlaScanner, $lateJoomlaBody);
$ref->getMethod('checkCMSDetection')->invoke($lateJoomlaScanner);
$lateJoomlaResult = $ref->getMethod('buildResult')->invoke($lateJoomlaScanner);
$assertSame('Joomla', $lateJoomlaResult['detected_cms'] ?? null, 'Joomla should be exposed even when source markers appear after the old 300KB sample window.');

$challengeScanner = new SecurityScanner('https://8.8.8.8');
$challengeBody = '<html><title>Validation request</title><h3>User validation required to continue..</h3>'
    . '<img src="/captcha.gif"><form action="/captcha_resp"><input name="captcha_resp_txt"></form></html>';
$ref->getProperty('responseBody')->setValue($challengeScanner, $challengeBody);
$ref->getMethod('checkCMSDetection')->invoke($challengeScanner);
$challengeResult = $ref->getMethod('buildResult')->invoke($challengeScanner);
$challengeTech = $challengeResult['categories']['Technology'] ?? [];
$assertSame(true, $challengeResult['scan_blocked'] ?? null, 'Captcha/validation pages should set scan_blocked=true.');
$assertSame('captcha_validation', $challengeResult['scan_blocked_type'] ?? null, 'Captcha/validation pages should expose the blocked type.');
$assert(
    (bool)array_filter($challengeTech, fn($f) => ($f['check'] ?? '') === 'CMS Detection Blocked'),
    'Captcha/validation pages should be reported as blocked CMS detection.'
);
$assert(
    !(bool)array_filter($challengeTech, fn($f) => ($f['check'] ?? '') === 'CMS Detection' && ($f['severity'] ?? '') === 'pass'),
    'Captcha/validation pages should not produce a false "No common CMS" pass.'
);

$wafScanner = new SecurityScanner('https://8.8.8.8');
$ref->getProperty('responseHeaders')->setValue($wafScanner, [
    'cf-ray' => ['abc-KUL'],
]);
$ref->getProperty('cookies')->setValue($wafScanner, [
    'BNIS_x-bni-jas=test; Path=/',
]);
$ref->getProperty('responseBody')->setValue($wafScanner, '<html><title>Validation request</title><form action="/captcha_resp"></form></html>');
$ref->getMethod('checkWAF')->invoke($wafScanner);
$wafResult = $ref->getMethod('buildResult')->invoke($wafScanner);
$assertSame(true, $wafResult['waf']['detected'] ?? null, 'WAF result should expose detected=true.');
$assert(in_array('Cloudflare', $wafResult['waf']['vendors'] ?? [], true), 'WAF result should include Cloudflare from cf-ray.');
$assert(in_array('F5 BIG-IP ASM', $wafResult['waf']['vendors'] ?? [], true), 'WAF result should include F5 BIG-IP ASM from BNIS/captcha markers.');
$assert(isset($wafResult['waf']['signals']['Cloudflare']), 'WAF result should include Cloudflare evidence signals.');
$assert(isset($wafResult['waf']['signals']['F5 BIG-IP ASM']), 'WAF result should include F5 evidence signals.');

$extraWafScanner = new SecurityScanner('https://8.8.8.8');
$ref->getProperty('responseHeaders')->setValue($extraWafScanner, [
    'x-wallarm-request-id' => ['req-1'],
    'x-ddos-guard' => ['active'],
    'x-sl-request-id' => ['radware-1'],
    'server' => ['CloudWAF'],
]);
$ref->getProperty('cookies')->setValue($extraWafScanner, [
    'NSC_example=1; Path=/',
    'rbzid=abc; Path=/',
    'imunify360_uuid=abc; Path=/',
    'HWWAFSESID=abc; Path=/',
]);
$ref->getMethod('checkWAF')->invoke($extraWafScanner);
$extraWafResult = $ref->getMethod('buildResult')->invoke($extraWafScanner);
$extraVendors = $extraWafResult['waf']['vendors'] ?? [];
$assert(in_array('Citrix ADC / NetScaler', $extraVendors, true), 'WAF result should include Citrix ADC / NetScaler from NSC_ cookie.');
$assert(in_array('Radware AppWall', $extraVendors, true), 'WAF result should include Radware AppWall from x-sl-request-id.');
$assert(in_array('Wallarm', $extraVendors, true), 'WAF result should include Wallarm from x-wallarm-request-id.');
$assert(in_array('Reblaze', $extraVendors, true), 'WAF result should include Reblaze from rbzid cookie.');
$assert(in_array('DDoS-Guard', $extraVendors, true), 'WAF result should include DDoS-Guard from x-ddos-guard.');
$assert(in_array('Imunify360', $extraVendors, true), 'WAF result should include Imunify360 from imunify360_uuid cookie.');
$assert(in_array('CloudWAF / Huawei Cloud WAF', $extraVendors, true), 'WAF result should include CloudWAF / Huawei Cloud WAF from server/cookie markers.');

$cms = $cmsFindingFor('<script type="application/json" data-drupal-selector="drupal-settings-json">{}</script>');
$assert($cms !== null && str_contains($cms->message, 'Drupal'), 'Drupal should be detected from drupal-settings-json.');

$pinResolve = $ref->getMethod('pinResolveForHost');
$pins = $pinResolve->invoke($scanner, 'www.example.com', 443, ['93.184.216.34'], [], [80]);
$assertSame(
    ['www.example.com:443:93.184.216.34', 'www.example.com:80:93.184.216.34'],
    $pins,
    'Redirect target pinning should emit CURLOPT_RESOLVE entries for target ports.'
);

$pins = $pinResolve->invoke($scanner, 'www.example.com', 443, ['10.0.0.1', '93.184.216.34'], [], []);
$assertSame(
    ['www.example.com:443:93.184.216.34'],
    $pins,
    'Redirect target pinning should ignore private resolved IPs.'
);

$findingsProp = $ref->getProperty('findings');
$findingsProp->setValue($scanner, [
    new SecurityFinding('Connection', 'Reachability', 'pass', 'ok'),
    new SecurityFinding('Technology', 'CVE-TEST-1', 'info', 'intelligence only', '', [], false),
    new SecurityFinding('Technology', 'CVE-TEST-2', 'info', 'intelligence only', '', [], false),
]);

$calculateScore = $ref->getMethod('calculateScore');
$score = $calculateScore->invoke($scanner);
$assertSame(100, $score['score'] ?? null, 'Non-scoreable CVE intelligence should not reduce the score.');
$assertSame('A+', $score['grade'] ?? null, 'Non-scoreable CVE intelligence should not reduce the grade.');

$categoryScores = $ref->getMethod('categoryScores');
$categories = $categoryScores->invoke($scanner);
$assert(isset($categories['Connection']), 'Scoreable category should be present.');
$assert(!isset($categories['Technology']), 'Category with only non-scoreable findings should not appear in category scores.');

$findingsProp->setValue($scanner, [
    new SecurityFinding('Connection', 'Reachability', 'pass', 'ok'),
    new SecurityFinding('Headers', 'Header Missing', 'warning', 'missing header'),
]);
$score = $calculateScore->invoke($scanner);
$assert(($score['score'] ?? 100) < 100, 'Scoreable warnings should still reduce the score.');

$mapSeverity = $ref->getMethod('mapCveSeverity');
$assertSame('critical', $mapSeverity->invoke($scanner, 'HIGH'), 'High CVEs should map to critical findings.');
$assertSame('warning', $mapSeverity->invoke($scanner, 'MEDIUM'), 'Medium CVEs should map to warning findings.');

$cachePath = sys_get_temp_dir() . '/secscan-cve-cache-test-' . bin2hex(random_bytes(4)) . '.json';
file_put_contents($cachePath, '{"cached":true}');
$fetchCveFeed = $ref->getMethod('fetchCveFeed');
$cachedBody = $fetchCveFeed->invoke($scanner, 'https://127.0.0.1:9/not-used', $cachePath, 86400);
@unlink($cachePath);
$assertSame('{"cached":true}', $cachedBody, 'Fresh CVE cache should be returned without a network request.');

if ($failures) {
    foreach ($failures as $failure) {
        fwrite(STDERR, "FAIL: {$failure}" . PHP_EOL);
    }
    exit(1);
}

echo 'Regression tests passed.' . PHP_EOL;
