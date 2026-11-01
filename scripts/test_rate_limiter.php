<?php

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('This script is CLI-only.');
}

$tempDir = sys_get_temp_dir() . '/secscan-rate-limit-' . bin2hex(random_bytes(8));
if (!mkdir($tempDir, 0700, true) && !is_dir($tempDir)) {
    fwrite(STDERR, "Unable to create the test directory.\n");
    exit(1);
}

putenv('SECSCAN_DATA_DIR=' . $tempDir);
$_ENV['SECSCAN_DATA_DIR'] = $tempDir;
$_SERVER['SECSCAN_DATA_DIR'] = $tempDir;

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/src/RateLimiter.php';

$pass = 0;
$fail = 0;
$check = static function (string $label, bool $condition) use (&$pass, &$fail): void {
    if ($condition) {
        $pass++;
        echo "  [PASS] {$label}\n";
        return;
    }
    $fail++;
    echo "  [FAIL] {$label}\n";
};

$cleanup = static function (string $dir): void {
    if (!is_dir($dir)) return;
    $items = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($items as $item) {
        if ($item->isDir()) {
            @rmdir($item->getPathname());
        } else {
            @unlink($item->getPathname());
        }
    }
    @rmdir($dir);
};

echo "Rate limiter and owner-bypass storage tests\n\n";

try {
    $first = RateLimiter::consume('fixture', '198.51.100.8', 2, 60);
    $second = RateLimiter::consume('fixture', '198.51.100.8', 2, 60);
    $third = RateLimiter::consume('fixture', '198.51.100.8', 2, 60);
    $rateFile = $tempDir . '/ratelimit/secscan_ratelimit_fixture.json';

    $check('first hit is allowed', $first['allowed'] === true && $first['storage_failed'] === false);
    $check('second hit is allowed', $second['allowed'] === true && $second['remaining'] === 0);
    $check('third hit is denied', $third['allowed'] === false && $third['storage_failed'] === false);
    $check('rate-limit file is private', is_file($rateFile) && (fileperms($rateFile) & 0777) === 0600);

    file_put_contents($rateFile, '{invalid json');
    $corrupt = RateLimiter::consume('fixture', '198.51.100.9', 2, 60);
    $check('corrupt rate-limit JSON self-heals instead of bricking scanning', $corrupt['allowed'] === true && $corrupt['storage_failed'] === false);
    $check('corrupt rate-limit file is rewritten as valid JSON', is_file($rateFile) && is_array(json_decode((string)file_get_contents($rateFile), true)));
    $check('corrupt rate-limit content is quarantined for forensics', is_file($rateFile . '.corrupt') && file_get_contents($rateFile . '.corrupt') === '{invalid json');
    $check('genuine storage failure still fails closed', RateLimiter::consume('fixture', '198.51.100.9', 0, 60)['storage_failed'] === true);

    $ownerIp = '203.0.113.9';
    $check('owner bypass can be stored', secscan_remember_owner_bypass_ip($ownerIp, 300));
    $ownerFile = $tempDir . '/owner_bypass_ips.json';
    $check('owner-bypass file is private', is_file($ownerFile) && (fileperms($ownerFile) & 0777) === 0600);
    $check('stored owner bypass is returned', isset(secscan_auto_owner_bypass_entries()[$ownerIp]));
    secscan_forget_owner_bypass_ip($ownerIp);
    $check('owner bypass can be removed', !isset(secscan_auto_owner_bypass_entries()[$ownerIp]));

    file_put_contents($ownerFile, '{invalid json');
    $check('corrupt owner-bypass JSON grants no bypass', secscan_auto_owner_bypass_entries() === []);
    $check('corrupt owner-bypass JSON is not overwritten silently', !secscan_remember_owner_bypass_ip($ownerIp, 300));
} finally {
    $cleanup($tempDir);
}

echo "\nResult: {$pass} PASS, {$fail} FAIL\n";
exit($fail === 0 ? 0 : 1);
