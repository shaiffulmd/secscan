<?php

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('This script is CLI-only.');
}

require_once dirname(__DIR__) . '/scanner.php';

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

$cms = $cmsFindingFor('', ['link' => ['<https://example.com/wp-json/>; rel="https://api.w.org/"']]);
$assert($cms !== null && str_contains($cms->message, 'WordPress'), 'WordPress should be detected from api.w.org Link header.');

$cms = $cmsFindingFor('<a href="/index.php?option=com_content&view=article">Article</a>');
$assert($cms !== null && str_contains($cms->message, 'Joomla'), 'Joomla should be detected from option=com_ routes.');

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
