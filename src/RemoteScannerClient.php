<?php

require_once __DIR__ . '/WorkerProtocol.php';

final class RemoteScannerClient
{
    public function __construct(
        private readonly string $workerUrl,
        private readonly string $sharedSecret,
        private readonly int $timeoutSeconds,
        private readonly int $maxResponseBytes
    ) {
    }

    /**
     * @param array<int|string,string> $authHeaders
     * @return array<string,mixed>
     */
    public function scan(string $url, array $authHeaders = [], string $authCookie = ''): array
    {
        if (!filter_var($this->workerUrl, FILTER_VALIDATE_URL)
            || strtolower((string)parse_url($this->workerUrl, PHP_URL_SCHEME)) !== 'https') {
            throw new RuntimeException('Worker scanner URL mesti menggunakan HTTPS.');
        }
        if (strlen($this->sharedSecret) < 32) {
            throw new RuntimeException('Worker scanner shared secret belum dikonfigurasi.');
        }

        $payload = ['url' => $url];
        if ($authHeaders !== [] || $authCookie !== '') {
            $payload['auth_headers'] = $authHeaders;
            $payload['auth_cookie'] = $authCookie;
        }
        $body = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        $timestamp = (string)time();
        $nonce = bin2hex(random_bytes(24));
        $signature = WorkerProtocol::requestSignature($this->sharedSecret, $timestamp, $nonce, $body);
        $responseHeaders = [];
        $response = '';
        $responseTooLarge = false;

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $this->workerUrl,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => min(15, $this->timeoutSeconds),
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Accept: application/json',
                'X-SecScan-Timestamp: ' . $timestamp,
                'X-SecScan-Nonce: ' . $nonce,
                'X-SecScan-Signature: ' . $signature,
            ],
            CURLOPT_HEADERFUNCTION => static function ($ch, string $header) use (&$responseHeaders): int {
                $parts = explode(':', $header, 2);
                if (count($parts) === 2) {
                    $responseHeaders[strtolower(trim($parts[0]))] = trim($parts[1]);
                }
                return strlen($header);
            },
            CURLOPT_WRITEFUNCTION => function ($ch, string $chunk) use (&$response, &$responseTooLarge): int {
                $remaining = $this->maxResponseBytes - strlen($response);
                if ($remaining <= 0 || strlen($chunk) > $remaining) {
                    if ($remaining > 0) $response .= substr($chunk, 0, $remaining);
                    $responseTooLarge = true;
                    return 0;
                }
                $response .= $chunk;
                return strlen($chunk);
            },
        ]);
        $ok = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        if (PHP_VERSION_ID < 80000 && is_resource($ch)) curl_close($ch);

        if ($responseTooLarge) {
            throw new RuntimeException('Respons worker scanner melebihi had yang dibenarkan.');
        }
        if ($ok !== true) {
            throw new RuntimeException('Worker scanner tidak dapat dicapai: ' . ($error ?: 'cURL request failed.'));
        }
        $responseNonce = (string)($responseHeaders['x-secscan-job-nonce'] ?? '');
        $responseSignature = (string)($responseHeaders['x-secscan-response-signature'] ?? '');
        $expectedSignature = WorkerProtocol::responseSignature($this->sharedSecret, $nonce, $response);
        if (!hash_equals($nonce, $responseNonce) || !hash_equals($expectedSignature, $responseSignature)) {
            throw new RuntimeException('Respons worker scanner gagal pengesahan tandatangan.');
        }

        $decoded = json_decode($response, true);
        if (!is_array($decoded)) {
            throw new RuntimeException('Worker scanner memulangkan respons tidak sah.');
        }
        if ($status < 200 || $status >= 300) {
            $message = trim((string)($decoded['error'] ?? 'Worker scanner gagal menjalankan scan.'));
            throw new RuntimeException($message);
        }
        return $decoded;
    }
}
