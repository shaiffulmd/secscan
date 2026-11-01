<?php

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('This script is CLI-only.');
}

$tempDir = sys_get_temp_dir() . '/secscan-storage-' . bin2hex(random_bytes(8));
if (!mkdir($tempDir, 0700, true) && !is_dir($tempDir)) {
    fwrite(STDERR, "Unable to create the test directory.\n");
    exit(1);
}
$dbPath = $tempDir . '/secscan.db';
foreach (['SECSCAN_DATA_DIR' => $tempDir, 'SECSCAN_DB_PATH' => $dbPath, 'SECSCAN_IP_HASH_SALT' => 'storage-test-salt'] as $key => $value) {
    putenv($key . '=' . $value);
    $_ENV[$key] = $value;
    $_SERVER[$key] = $value;
}

require_once dirname(__DIR__) . '/logger.php';

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
    foreach (glob($dir . '/*') ?: [] as $path) {
        if (is_file($path)) @unlink($path);
    }
    @rmdir($dir);
};

echo "SQLite and encrypted contact storage tests\n\n";

$logger = new ScanLogger();
$logger->log([
    'hostname' => 'example.com',
    'url' => 'https://example.com',
    'score' => 100,
    'grade' => 'A+',
    'passed' => 1,
    'warnings' => 0,
    'critical' => 0,
    'info' => 0,
    'total_checks' => 1,
    'duration' => '0.01s',
    'categories' => [],
], '198.51.100.20');

$reflection = new ReflectionClass($logger);
$pdoProperty = $reflection->getProperty('pdo');
$pdo = $pdoProperty->getValue($logger);

$check('SQLite database is created', is_file($dbPath));
$check('SQLite database is private', is_file($dbPath) && (fileperms($dbPath) & 0777) === 0600);
$check('SQLite busy timeout is configured', $pdo instanceof PDO && (int)$pdo->query('PRAGMA busy_timeout')->fetchColumn() === 5000);
$check('scan record is persisted', $pdo instanceof PDO && (int)$pdo->query('SELECT COUNT(*) FROM scans')->fetchColumn() === 1);

foreach ([$dbPath . '-wal', $dbPath . '-shm'] as $runtimePath) {
    if (is_file($runtimePath)) {
        $check(basename($runtimePath) . ' is private', (fileperms($runtimePath) & 0777) === 0600);
    }
}

$contactKey = random_bytes(32);
$contactId = $logger->storeContactMessage([
    'name' => 'Storage Test',
    'email' => 'storage@example.com',
    'subject' => 'Encrypted fixture',
    'message' => 'This plaintext must not be stored directly.',
], $contactKey);
$check('encrypted contact can be stored', is_int($contactId) && $contactId > 0);

$ciphertext = $pdo instanceof PDO ? (string)$pdo->query('SELECT payload_enc FROM contact_messages LIMIT 1')->fetchColumn() : '';
$check('contact plaintext is absent from ciphertext', $ciphertext !== '' && !str_contains($ciphertext, 'Storage Test'));
$messages = $logger->getContactMessages($contactKey, 5);
$check('contact decrypts with the configured key', ($messages[0]['message'] ?? '') === 'This plaintext must not be stored directly.');

if (is_int($contactId)) {
    $logger->markContactMailSent($contactId);
    $messages = $logger->getContactMessages($contactKey, 5);
    $check('mail status update is persisted', (int)($messages[0]['mail_sent'] ?? 0) === 1);
    $check('contact can be deleted', $logger->deleteContactMessages([$contactId]) === 1);
}

unset($pdo, $logger);
gc_collect_cycles();
$cleanup($tempDir);

echo "\nResult: {$pass} PASS, {$fail} FAIL\n";
exit($fail === 0 ? 0 : 1);
