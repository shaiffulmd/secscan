<?php

/**
 * Local country-level GeoIP lookup and DB-IP Lite updater.
 *
 * DB-IP Lite is used locally so scanner IPs are never sent to an external
 * lookup API. The provider requires visible attribution in the UI.
 */
final class GeoIp
{
    private const DBIP_DOWNLOAD_HOST = 'download.db-ip.com';
    private const MAX_IMPORT_RECORDS = 5000000;
    private const MAX_CSV_LINE_BYTES = 4096;

    public static function lookup(PDO $pdo, string $ip): string
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return '';
        }
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return '';
        }

        $family = strlen($packed) === 4 ? 4 : 6;
        try {
            $stmt = $pdo->prepare(
                'SELECT ip_end, country FROM geoip_country '
                . 'WHERE family = :family AND ip_start <= :ip '
                . 'ORDER BY ip_start DESC LIMIT 1'
            );
            $stmt->bindValue(':family', $family, PDO::PARAM_INT);
            $stmt->bindValue(':ip', $packed, PDO::PARAM_LOB);
            $stmt->execute();
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!is_array($row) || !isset($row['ip_end'], $row['country'])) {
                return '';
            }
            return strcmp((string)$row['ip_end'], $packed) >= 0
                ? strtoupper((string)$row['country'])
                : '';
        } catch (Throwable) {
            return '';
        }
    }

    /** @return array{available:bool,records:int,updated_at:string} */
    public static function status(PDO $pdo): array
    {
        try {
            $row = $pdo->query('SELECT COUNT(*) AS records, MAX(updated_at) AS updated_at FROM geoip_country')->fetch(PDO::FETCH_ASSOC);
            return [
                'available' => true,
                'records' => (int)($row['records'] ?? 0),
                'updated_at' => (string)($row['updated_at'] ?? ''),
            ];
        } catch (Throwable) {
            return ['available' => false, 'records' => 0, 'updated_at' => ''];
        }
    }

    /** @return array{ok:bool,message:string,records:int,backfilled:int} */
    public static function update(PDO $pdo): array
    {
        if (!function_exists('gzopen')) {
            return ['ok' => false, 'message' => 'Sambungan zlib/gzip PHP diperlukan untuk mengemas kini GeoIP.', 'records' => 0, 'backfilled' => 0];
        }

        $dataDir = (string)secscan_config('data_dir');
        if ($dataDir === '' || (!is_dir($dataDir) && !@mkdir($dataDir, 0750, true)) || !is_writable($dataDir)) {
            return ['ok' => false, 'message' => 'Folder data GeoIP tidak boleh ditulis.', 'records' => 0, 'backfilled' => 0];
        }

        $url = self::downloadUrl();
        if ($url === '') {
            return ['ok' => false, 'message' => 'URL muat turun GeoIP tidak sah.', 'records' => 0, 'backfilled' => 0];
        }
        $tmp = tempnam($dataDir, 'secscan-geoip-');
        if ($tmp === false) {
            return ['ok' => false, 'message' => 'Tidak dapat menyediakan fail sementara GeoIP.', 'records' => 0, 'backfilled' => 0];
        }
        @chmod($tmp, 0600);

        try {
            $out = fopen($tmp, 'wb');
            if ($out === false) {
                throw new RuntimeException('Tidak dapat menulis fail GeoIP sementara.');
            }
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => $url, CURLOPT_FILE => $out, CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_TIMEOUT => 180, CURLOPT_CONNECTTIMEOUT => 15,
                CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_USERAGENT => 'SecScan-GeoIP-Updater/1.0',
            ]);
            $ok = curl_exec($ch);
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $error = curl_error($ch);
            if (PHP_VERSION_ID < 80000 && is_resource($ch)) curl_close($ch);
            fclose($out);
            $size = (int)@filesize($tmp);
            if ($ok !== true || $code !== 200 || $size < 1024 * 1024 || $size > 100 * 1024 * 1024) {
                throw new RuntimeException('Muat turun DB-IP gagal' . ($error !== '' ? ": {$error}" : " (HTTP {$code})") . '.');
            }

            $records = self::importCsv($pdo, $tmp);
            $backfilled = self::backfillScanCountries($pdo);
            return ['ok' => true, 'message' => 'Pangkalan GeoIP berjaya dikemas kini daripada DB-IP Lite.', 'records' => $records, 'backfilled' => $backfilled];
        } catch (Throwable $e) {
            error_log('[SecScan GeoIP] Update failed: ' . $e->getMessage());
            $detail = preg_replace('/[\r\n]+/', ' ', $e->getMessage()) ?: 'ralat tidak diketahui';
            return ['ok' => false, 'message' => 'Kemaskini GeoIP gagal: ' . substr($detail, 0, 180), 'records' => 0, 'backfilled' => 0];
        } finally {
            @unlink($tmp);
        }
    }

    private static function downloadUrl(): string
    {
        $configured = trim((string)secscan_env('SECSCAN_GEOIP_UPDATE_URL', ''));
        if ($configured !== '') {
            $parts = parse_url($configured);
            return is_array($parts) && ($parts['scheme'] ?? '') === 'https' ? $configured : '';
        }
        return 'https://' . self::DBIP_DOWNLOAD_HOST . '/free/dbip-country-lite-' . gmdate('Y-m') . '.csv.gz';
    }

    private static function importCsv(PDO $pdo, string $path): int
    {
        $gz = gzopen($path, 'rb');
        if ($gz === false) {
            throw new RuntimeException('Fail GeoIP bukan arkib gzip yang sah.');
        }
        $pdo->beginTransaction();
        try {
            $pdo->exec('DROP TABLE IF EXISTS geoip_country_next');
            $pdo->exec('CREATE TABLE geoip_country_next (family INTEGER NOT NULL, ip_start BLOB NOT NULL, ip_end BLOB NOT NULL, country TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY (family, ip_start))');
            $insert = $pdo->prepare('INSERT INTO geoip_country_next (family, ip_start, ip_end, country, updated_at) VALUES (?, ?, ?, ?, ?)');
            $updatedAt = gmdate('Y-m-d\\TH:i:s\\Z');
            $records = 0;
            while (($line = gzgets($gz, self::MAX_CSV_LINE_BYTES)) !== false) {
                if (!str_ends_with($line, "\n") && !gzeof($gz)) {
                    throw new RuntimeException('Baris CSV GeoIP melebihi had yang dibenarkan.');
                }
                $row = str_getcsv(trim($line));
                if (count($row) < 3) continue;
                $start = @inet_pton(trim((string)$row[0], '"'));
                $end = @inet_pton(trim((string)$row[1], '"'));
                $country = strtoupper(trim((string)$row[2], '"'));
                if ($start === false || $end === false || strlen($start) !== strlen($end) || !preg_match('/^[A-Z]{2}$/', $country)) continue;
                if ($records >= self::MAX_IMPORT_RECORDS) {
                    throw new RuntimeException('Import GeoIP melebihi had rekod yang dibenarkan.');
                }
                $insert->bindValue(1, strlen($start) === 4 ? 4 : 6, PDO::PARAM_INT);
                $insert->bindValue(2, $start, PDO::PARAM_LOB);
                $insert->bindValue(3, $end, PDO::PARAM_LOB);
                $insert->bindValue(4, $country, PDO::PARAM_STR);
                $insert->bindValue(5, $updatedAt, PDO::PARAM_STR);
                $insert->execute();
                $records++;
            }
            gzclose($gz);
            $gz = null;
            if ($records < 100000) {
                throw new RuntimeException('Import GeoIP tidak lengkap.');
            }
            $pdo->exec('DROP TABLE IF EXISTS geoip_country_previous');
            $exists = $pdo->query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'geoip_country'")->fetchColumn();
            if ($exists) $pdo->exec('ALTER TABLE geoip_country RENAME TO geoip_country_previous');
            $pdo->exec('ALTER TABLE geoip_country_next RENAME TO geoip_country');
            $pdo->exec('CREATE INDEX IF NOT EXISTS idx_geoip_country_lookup ON geoip_country (family, ip_start)');
            $pdo->exec('DROP TABLE IF EXISTS geoip_country_previous');
            $pdo->commit();
            return $records;
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) $pdo->rollBack();
            if (is_resource($gz)) gzclose($gz);
            throw $e;
        }
    }

    private static function backfillScanCountries(PDO $pdo): int
    {
        $rows = $pdo->query("SELECT DISTINCT client_ip FROM scans WHERE client_ip IS NOT NULL AND client_ip <> ''")->fetchAll(PDO::FETCH_COLUMN);
        $update = $pdo->prepare('UPDATE scans SET client_country = ? WHERE client_ip = ?');
        $updated = 0;
        foreach ($rows as $ip) {
            $country = self::lookup($pdo, (string)$ip);
            if ($country === '') continue;
            $update->execute([$country, $ip]);
            $updated += $update->rowCount();
        }
        return $updated;
    }
}
