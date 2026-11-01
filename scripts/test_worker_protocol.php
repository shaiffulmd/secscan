<?php

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('This script is CLI-only.');
}

require_once dirname(__DIR__) . '/src/WorkerProtocol.php';

$pass = 0;
$fail = 0;
$check = static function (string $label, bool $condition) use (&$pass, &$fail): void {
    if ($condition) {
        $pass++;
        echo "  [PASS] {$label}\n";
    } else {
        $fail++;
        echo "  [FAIL] {$label}\n";
    }
};

$secret = 'a-worker-secret-with-more-than-thirty-two-characters';
$timestamp = (string)time();
$nonce = bin2hex(random_bytes(24));
$body = '{"url":"https://example.com"}';

echo "Worker protocol tests\n\n";

$signature = WorkerProtocol::requestSignature($secret, $timestamp, $nonce, $body);
$check('request signature has expected length', preg_match('/^[a-f0-9]{64}$/', $signature) === 1);
$check('request signature changes when body changes',
    !hash_equals($signature, WorkerProtocol::requestSignature($secret, $timestamp, $nonce, '{"url":"https://example.org"}')));
$check('response signature binds job nonce',
    !hash_equals(
        WorkerProtocol::responseSignature($secret, $nonce, '{"ok":true}'),
        WorkerProtocol::responseSignature($secret, bin2hex(random_bytes(24)), '{"ok":true}')
    ));
$check('current timestamp is accepted', WorkerProtocol::isFreshTimestamp($timestamp));
$check('stale timestamp is rejected', !WorkerProtocol::isFreshTimestamp((string)(time() - 301)));
$check('valid nonce is accepted', WorkerProtocol::isValidNonce($nonce));
$check('short nonce is rejected', !WorkerProtocol::isValidNonce('abcdef'));

echo "\nResult: {$pass} PASS, {$fail} FAIL\n";
exit($fail === 0 ? 0 : 1);
