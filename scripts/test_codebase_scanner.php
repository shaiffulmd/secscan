<?php

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    exit("CLI only\n");
}

require_once dirname(__DIR__) . '/src/CodebaseScanner.php';

$failures = [];
$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

$dynamic = CodebaseScanner::analyzeSource('fixture.php', '<?php eval($_GET["x"]);');
$assert(count(array_filter($dynamic, static fn(array $f): bool => $f['id'] === 'dynamic-code' && $f['severity'] === 'critical')) === 1, 'dynamic code must be critical');

$tls = CodebaseScanner::analyzeSource('fixture.php', 'curl_setopt($ch, CURLOPT_SSL_VERIFYPEER => false);');
$assert(count(array_filter($tls, static fn(array $f): bool => $f['id'] === 'tls-verification-bypass')) === 1, 'TLS verification bypass must be detected');

$include = CodebaseScanner::analyzeSource('fixture.php', '<?php require $_GET["page"];');
$assert(count(array_filter($include, static fn(array $f): bool => $f['id'] === 'request-driven-include' && $f['severity'] === 'critical')) === 1, 'request-driven include must be critical');

$sql = CodebaseScanner::analyzeSource('fixture.php', '<?php $pdo->query("SELECT * FROM users WHERE id=" . $_GET["id"]);');
$assert(count(array_filter($sql, static fn(array $f): bool => $f['id'] === 'request-driven-sql' && $f['severity'] === 'critical')) === 1, 'request-driven SQL must be critical');

$lock = CodebaseScanner::analyzeSource('fixture.php', "<?php\nflock(\$fp, LOCK_EX);\nfwrite(\$fp, 'x');");
$assert(count(array_filter($lock, static fn(array $f): bool => $f['id'] === 'unchecked-file-lock')) === 1, 'unchecked exclusive lock must be detected');

$weakRandom = CodebaseScanner::analyzeSource('fixture.php', '<?php $nonce = md5((string)mt_rand());');
$assert(count(array_filter($weakRandom, static fn(array $f): bool => $f['id'] === 'weak-randomness')) === 1, 'weak randomness must be detected');
$assert(count(array_filter($weakRandom, static fn(array $f): bool => $f['id'] === 'weak-hash')) === 1, 'legacy hash must be detected');

$perms = CodebaseScanner::analyzeSource('fixture.php', '<?php chmod($path, 0777);');
$assert(count(array_filter($perms, static fn(array $f): bool => $f['id'] === 'world-writable-mode')) === 1, 'world-writable mode must be detected');

$secret = CodebaseScanner::analyzeSource('fixture.txt', '-----BEGIN RSA PRIVATE KEY-----');
$assert(count(array_filter($secret, static fn(array $f): bool => $f['id'] === 'private-key' && $f['severity'] === 'critical')) === 1, 'private key material must be critical');

$clean = CodebaseScanner::analyzeSource('clean.php', '<?php echo htmlspecialchars($value, ENT_QUOTES, "UTF-8");');
$assert($clean === [], 'clean source must not produce findings');

if ($failures !== []) {
    foreach ($failures as $failure) {
        fwrite(STDERR, "[FAIL] {$failure}\n");
    }
    exit(1);
}

echo "Codebase scanner tests passed.\n";
