<?php

class RateLimiter
{
    public static function consume(string $bucket, string $key, int $limit, int $window): array
    {
        $safeBucket = preg_replace('/[^a-z0-9_.-]/i', '_', $bucket);
        $file = sys_get_temp_dir() . "/secscan_ratelimit_{$safeBucket}.json";
        $now = time();

        $fp = @fopen($file, 'c+');
        if (!$fp) {
            error_log('[SecScan] Rate limit file could not be opened: ' . $file);
            return [
                'allowed' => true,
                'limit' => $limit,
                'remaining' => $limit,
                'retry_after' => 0,
                'reset' => $now + $window,
            ];
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
        ];
    }
}
