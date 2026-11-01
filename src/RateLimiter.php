<?php

class RateLimiter
{
    /**
     * Where rate-limit state lives. Prefer the app's private data dir (denied by
     * data/.htaccess and ideally outside the web root) over the world-shared
     * system temp dir, where on shared hosting another tenant could read or
     * poison predictably-named state files. If durable private storage is not
     * available, callers fail closed rather than disable limiting.
     */
    private static function storageDir(): ?string
    {
        if (function_exists('secscan_config')) {
            $dataDir = (string)secscan_config('data_dir');
            if ($dataDir !== '') {
                $rlDir = $dataDir . '/ratelimit';
                if (is_dir($rlDir) || @mkdir($rlDir, 0750, true) || is_dir($rlDir)) {
                    if (is_writable($rlDir)) {
                        return $rlDir;
                    }
                }
            }
        }
        return null;
    }

    public static function consume(string $bucket, string $key, int $limit, int $window): array
    {
        $now = time();
        if ($limit < 1 || $window < 1) {
            error_log('[SecScan] Invalid rate-limit configuration.');
            return self::failure($limit, $window, $now);
        }

        $safeBucket = preg_replace('/[^a-z0-9_.-]/i', '_', $bucket);
        $dir = self::storageDir();
        if ($dir === null) {
            error_log('[SecScan] Rate-limit storage directory is unavailable.');
            return self::failure($limit, $window, $now);
        }
        $file = $dir . "/secscan_ratelimit_{$safeBucket}.json";

        $fp = @fopen($file, 'c+');
        if (!$fp) {
            error_log('[SecScan] Rate limit file could not be opened: ' . $file);
            return self::failure($limit, $window, $now);
        }
        @chmod($file, 0600);

        if (!flock($fp, LOCK_EX)) {
            fclose($fp);
            error_log('[SecScan] Rate limit file could not be locked: ' . $file);
            return self::failure($limit, $window, $now);
        }

        if (!rewind($fp)) {
            self::closeLockedFile($fp);
            error_log('[SecScan] Rate limit file could not be read: ' . $file);
            return self::failure($limit, $window, $now);
        }
        $content = stream_get_contents($fp);
        if ($content === false) {
            self::closeLockedFile($fp);
            error_log('[SecScan] Rate limit file could not be read: ' . $file);
            return self::failure($limit, $window, $now);
        }

        $rates = [];
        if ($content !== '') {
            $decoded = json_decode($content, true);
            if (!is_array($decoded) || json_last_error() !== JSON_ERROR_NONE) {
                // A corrupt state file must not permanently brick rate limiting:
                // previously this failed closed on every request until an
                // operator deleted the file. Preserve the bad content for
                // forensics, then reset the bucket in place and continue.
                // Deleting the file already resets it (fopen 'c+' recreates),
                // so self-healing grants no capability an attacker with write
                // access to the private data dir did not already have.
                @file_put_contents($file . '.corrupt', $content, LOCK_EX);
                error_log('[SecScan] Rate limit file contained invalid JSON; resetting bucket: ' . $file);
                $rates = [];
            } else {
                $rates = $decoded;
            }
        }

        foreach ($rates as $rateKey => $timestamps) {
            if (!is_array($timestamps)) {
                unset($rates[$rateKey]);
                continue;
            }

            $rates[$rateKey] = array_values(array_filter(
                $timestamps,
                static fn ($t): bool => ($now - (int)$t) < $window
            ));

            if (!$rates[$rateKey]) {
                unset($rates[$rateKey]);
            }
        }

        $maxKeys = function_exists('secscan_config') ? (int)secscan_config('rate_limit_max_keys') : 10000;
        if (!isset($rates[$key]) && count($rates) >= max(100, $maxKeys)) {
            // Persist expired-key cleanup before failing. Otherwise a full file
            // could remain permanently full after its entries have expired.
            if (!self::persist($fp, $rates)) {
                error_log('[SecScan] Rate-limit cleanup could not be persisted: ' . $file);
            }
            self::closeLockedFile($fp);
            error_log('[SecScan] Rate-limit key capacity reached.');
            return self::failure($limit, $window, $now);
        }

        $currentHits = isset($rates[$key]) && is_array($rates[$key]) ? count($rates[$key]) : 0;
        $allowed = $currentHits < $limit;
        $oldestHit = $rates[$key][0] ?? $now;
        $retryAfter = max(1, ((int)$oldestHit + $window) - $now);

        if ($allowed) {
            $rates[$key][] = $now;
            if (!self::persist($fp, $rates)) {
                self::closeLockedFile($fp);
                error_log('[SecScan] Rate-limit state could not be persisted: ' . $file);
                return self::failure($limit, $window, $now);
            }
            $currentHits++;
        }

        self::closeLockedFile($fp);

        return [
            'allowed' => $allowed,
            'limit' => $limit,
            'remaining' => max(0, $limit - $currentHits),
            'retry_after' => $retryAfter,
            'reset' => $now + $retryAfter,
            'storage_failed' => false,
        ];
    }

    private static function failure(int $limit, int $window, int $now): array
    {
        return [
            'allowed' => false,
            'limit' => max(0, $limit),
            'remaining' => 0,
            'retry_after' => max(1, $window),
            'reset' => $now + max(1, $window),
            'storage_failed' => true,
        ];
    }

    /** @param resource $fp */
    private static function persist($fp, array $rates): bool
    {
        $payload = json_encode($rates, JSON_UNESCAPED_SLASHES);
        if (!is_string($payload) || !ftruncate($fp, 0) || !rewind($fp)) {
            return false;
        }

        $written = fwrite($fp, $payload);
        return $written === strlen($payload) && fflush($fp);
    }

    /** @param resource $fp */
    private static function closeLockedFile($fp): void
    {
        flock($fp, LOCK_UN);
        fclose($fp);
    }
}
