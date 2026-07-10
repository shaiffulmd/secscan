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

        flock($fp, LOCK_EX);
        rewind($fp);
        $content = stream_get_contents($fp);
        $rates = $content ? (json_decode($content, true) ?: []) : [];

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
            ftruncate($fp, 0);
            rewind($fp);
            fwrite($fp, json_encode($rates, JSON_UNESCAPED_SLASHES));
            flock($fp, LOCK_UN);
            fclose($fp);
            error_log('[SecScan] Rate-limit key capacity reached.');
            return self::failure($limit, $window, $now);
        }

        $currentHits = isset($rates[$key]) && is_array($rates[$key]) ? count($rates[$key]) : 0;
        $allowed = $currentHits < $limit;
        $oldestHit = $rates[$key][0] ?? $now;
        $retryAfter = max(1, ((int)$oldestHit + $window) - $now);

        if ($allowed) {
            $rates[$key][] = $now;
            ftruncate($fp, 0);
            rewind($fp);
            fwrite($fp, json_encode($rates, JSON_UNESCAPED_SLASHES));
            $currentHits++;
        }

        flock($fp, LOCK_UN);
        fclose($fp);

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
}
