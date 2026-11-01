<?php

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/src/GeoIp.php';

/**
 * ScanLogger — simpan setiap scan ke SQLite dan sediakan data untuk dashboard.
 *
 * Database disimpan di data/secscan.db (dilindungi oleh data/.htaccess).
 * IP pengguna disimpan untuk audit dashboard dan turut di-hash (SHA-256 + salt)
 * untuk statistik unique-IP tanpa bergantung pada plaintext.
 */
class ScanLogger
{
    private ?PDO $pdo    = null;
    private string $dbPath;

    public function __construct()
    {
        $this->dbPath = (string)secscan_config('database_path');
    }

    // ----------------------------------------------------------------
    //  SETUP
    // ----------------------------------------------------------------

    private function connect(): bool
    {
        if ($this->pdo !== null) return true;

        try {
            $dir = dirname($this->dbPath);
            if (!is_dir($dir)) {
                mkdir($dir, 0750, true);
            }

            $this->pdo = new PDO('sqlite:' . $this->dbPath, null, null, [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ]);

            $this->pdo->exec('PRAGMA journal_mode=WAL');
            $this->pdo->exec('PRAGMA synchronous=NORMAL');
            $this->pdo->exec('PRAGMA foreign_keys=ON');
            $this->pdo->exec('PRAGMA busy_timeout=5000');
            $this->migrate();

            // WAL/SHM files are normally created by the PRAGMAs or migration,
            // so apply private modes after those operations as well as to DB.
            $this->hardenRuntimeFiles();
            return true;
        } catch (Throwable $e) {
            error_log('[SecScan Logger] DB connect failed: ' . $e->getMessage());
            return false;
        }
    }

    private function hardenRuntimeFiles(): void
    {
        foreach ([$this->dbPath, $this->dbPath . '-wal', $this->dbPath . '-shm'] as $runtimeFile) {
            if (is_file($runtimeFile)) {
                @chmod($runtimeFile, 0600);
            }
        }
    }

    private function migrate(): void
    {
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS scans (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                hostname      TEXT    NOT NULL,
                url           TEXT    NOT NULL,
                score         INTEGER NOT NULL DEFAULT 0,
                grade         TEXT    NOT NULL DEFAULT 'F',
                passed        INTEGER NOT NULL DEFAULT 0,
                warnings      INTEGER NOT NULL DEFAULT 0,
                critical      INTEGER NOT NULL DEFAULT 0,
                info          INTEGER NOT NULL DEFAULT 0,
                total_checks  INTEGER NOT NULL DEFAULT 0,
                duration_ms   INTEGER NOT NULL DEFAULT 0,
                client_ip     TEXT,
                client_ip_hash TEXT,
                tls_protocol  TEXT,
                detected_cms  TEXT,
                detected_cms_version TEXT,
                scan_blocked  INTEGER NOT NULL DEFAULT 0,
                scan_blocked_type TEXT,
                assessment_status TEXT NOT NULL DEFAULT 'complete',
                assessment_reason TEXT,
                waf_vendors   TEXT,
                waf_signals   TEXT,
                is_cloudflare INTEGER NOT NULL DEFAULT 0,
                top_issues    TEXT
            )
        ");

        $this->ensureColumn('scans', 'client_ip', 'TEXT');
        $this->ensureColumn('scans', 'client_ip_hash', 'TEXT');
        $this->ensureColumn('scans', 'client_country', 'TEXT');
        $this->ensureColumn('scans', 'tls_protocol', 'TEXT');
        $this->ensureColumn('scans', 'detected_cms', 'TEXT');
        $this->ensureColumn('scans', 'detected_cms_version', 'TEXT');
        $this->ensureColumn('scans', 'scan_blocked', 'INTEGER NOT NULL DEFAULT 0');
        $this->ensureColumn('scans', 'scan_blocked_type', 'TEXT');
        $this->ensureColumn('scans', 'assessment_status', "TEXT NOT NULL DEFAULT 'complete'");
        $this->ensureColumn('scans', 'assessment_reason', 'TEXT');
        $this->ensureColumn('scans', 'waf_vendors', 'TEXT');
        $this->ensureColumn('scans', 'waf_signals', 'TEXT');
        $this->ensureColumn('scans', 'is_cloudflare', 'INTEGER NOT NULL DEFAULT 0');
        $this->ensureColumn('scans', 'top_issues', 'TEXT');

        $this->pdo->exec("UPDATE scans SET assessment_status = 'unavailable' WHERE grade = 'N/A' AND assessment_status = 'complete'");
        $this->pdo->exec("
            UPDATE scans
            SET grade = 'N/A',
                assessment_status = 'unavailable',
                assessment_reason = COALESCE(NULLIF(assessment_reason, ''),
                    CASE WHEN scan_blocked = 1
                        THEN 'Historical scan was blocked by a WAF, captcha, or validation page.'
                        ELSE 'Historical scan did not complete target reachability checks.'
                    END)
            WHERE grade = 'F'
              AND (
                  scan_blocked = 1
                  OR (total_checks <= 3 AND top_issues LIKE '%Reachability%')
              )
        ");

        $this->pdo->exec("CREATE INDEX IF NOT EXISTS idx_scanned_at ON scans(scanned_at)");
        $this->pdo->exec("CREATE INDEX IF NOT EXISTS idx_hostname   ON scans(hostname)");
        $this->pdo->exec("CREATE INDEX IF NOT EXISTS idx_grade      ON scans(grade)");
        $this->pdo->exec("CREATE INDEX IF NOT EXISTS idx_client_ip  ON scans(client_ip)");
        $this->pdo->exec("CREATE INDEX IF NOT EXISTS idx_ip_hash    ON scans(client_ip_hash)");
        $this->pdo->exec("CREATE INDEX IF NOT EXISTS idx_country    ON scans(client_country)");

        $this->pdo->exec("CREATE TABLE IF NOT EXISTS contact_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
            payload_enc TEXT NOT NULL,
            iv TEXT NOT NULL,
            tag TEXT NOT NULL,
            mail_sent INTEGER NOT NULL DEFAULT 0
        )");
        $this->pdo->exec("CREATE INDEX IF NOT EXISTS idx_contact_received ON contact_messages(received_at)");
    }

    /** Store a Contact Us submission as AES-256-GCM encrypted JSON. */
    public function storeContactMessage(array $message, string $key): ?int
    {
        if (!$this->connect() || strlen($key) !== 32) return null;
        try {
            $iv = random_bytes(12);
            $tag = '';
            $json = json_encode($message, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            $cipher = openssl_encrypt($json, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
            if ($cipher === false || $tag === '') return null;
            $stmt = $this->pdo->prepare('INSERT INTO contact_messages (payload_enc, iv, tag) VALUES (?, ?, ?)');
            $stmt->execute([base64_encode($cipher), base64_encode($iv), base64_encode($tag)]);
            $this->hardenRuntimeFiles();
            return (int)$this->pdo->lastInsertId();
        } catch (Throwable) {
            return null;
        }
    }

    public function markContactMailSent(int $id): void
    {
        if (!$this->connect() || $id < 1) return;
        try {
            $stmt = $this->pdo->prepare('UPDATE contact_messages SET mail_sent = 1 WHERE id = ?');
            $stmt->execute([$id]);
            $this->hardenRuntimeFiles();
        } catch (Throwable $e) {
            error_log('[SecScan Logger] Contact mail status update failed: ' . $e->getMessage());
        }
    }

    /** @return array<int, array<string, mixed>> */
    public function getContactMessages(string $key, int $limit = 30): array
    {
        if (!$this->connect() || strlen($key) !== 32) return [];
        try {
            $stmt = $this->pdo->prepare('SELECT id, received_at, payload_enc, iv, tag, mail_sent FROM contact_messages ORDER BY id DESC LIMIT ?');
            $stmt->bindValue(1, max(1, min(100, $limit)), PDO::PARAM_INT);
            $stmt->execute();
            $items = [];
            foreach ($stmt->fetchAll() as $row) {
                $plain = openssl_decrypt((string)base64_decode((string)$row['payload_enc'], true), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, (string)base64_decode((string)$row['iv'], true), (string)base64_decode((string)$row['tag'], true));
                $payload = is_string($plain) ? json_decode($plain, true) : null;
                if (!is_array($payload)) continue;
                $items[] = ['id' => (int)$row['id'], 'received_at' => (string)$row['received_at'], 'mail_sent' => (int)$row['mail_sent']] + $payload;
            }
            return $items;
        } catch (Throwable) {
            return [];
        }
    }

    /** Delete selected encrypted contact records; dashboard authentication is enforced by the caller. */
    public function deleteContactMessages(array $ids): int
    {
        if (!$this->connect()) return 0;
        $ids = array_values(array_unique(array_filter(array_map('intval', $ids), static fn(int $id): bool => $id > 0)));
        if ($ids === []) return 0;
        try {
            $placeholders = implode(',', array_fill(0, count($ids), '?'));
            $stmt = $this->pdo->prepare("DELETE FROM contact_messages WHERE id IN ({$placeholders})");
            $stmt->execute($ids);
            $this->hardenRuntimeFiles();
            return $stmt->rowCount();
        } catch (Throwable) {
            return 0;
        }
    }

    private function ensureColumn(string $table, string $column, string $definition): void
    {
        $cols = $this->pdo->query('PRAGMA table_info(' . $table . ')')->fetchAll();
        foreach ($cols as $col) {
            if (($col['name'] ?? '') === $column) {
                return;
            }
        }
        $this->pdo->exec('ALTER TABLE ' . $table . ' ADD COLUMN ' . $column . ' ' . $definition);
    }

    // ----------------------------------------------------------------
    //  LOG SCAN
    // ----------------------------------------------------------------

    public function log(array $result, string $clientIp = ''): void
    {
        if (!$this->connect()) return;

        try {
            // Kumpul nama checks yang critical/warning
            $topIssues = [];
            foreach ($result['categories'] ?? [] as $findings) {
                foreach ($findings as $f) {
                    if (in_array($f['severity'] ?? '', ['critical', 'warning'], true)) {
                        $topIssues[] = $f['check'] ?? '';
                    }
                }
            }
            $topIssues = array_values(array_filter(array_unique($topIssues)));

            // Hash IP untuk statistik unique-IP, simpan plaintext untuk audit dashboard.
            $ipHash = $clientIp !== ''
                ? hash('sha256', $clientIp . (string)secscan_config('ip_hash_salt'))
                : null;
            $clientCountry = $clientIp !== '' ? GeoIp::lookup($this->pdo, $clientIp) : null;

            // Parse duration "1.23s" → ms
            $durationMs = (int)(((float)rtrim($result['duration'] ?? '0s', 's')) * 1000);
            $waf = is_array($result['waf'] ?? null) ? $result['waf'] : [];
            $wafVendors = array_values(array_filter(array_map('strval', $waf['vendors'] ?? [])));
            $wafSignals = is_array($waf['signals'] ?? null) ? $waf['signals'] : [];
            $isCloudflare = ($result['edge']['cloudflare'] ?? false) || in_array('Cloudflare', $wafVendors, true);

            $stmt = $this->pdo->prepare("
                INSERT INTO scans
                    (hostname, url, score, grade, passed, warnings, critical, info,
                     total_checks, duration_ms, client_ip, client_ip_hash, client_country, tls_protocol,
                     detected_cms, detected_cms_version, scan_blocked, scan_blocked_type,
                     assessment_status, assessment_reason,
                     waf_vendors, waf_signals, is_cloudflare, top_issues)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");

            $stmt->execute([
                $result['hostname']            ?? '',
                $result['url']                 ?? '',
                (int)($result['score']         ?? 0),
                $result['grade']               ?? 'F',
                (int)($result['passed']        ?? 0),
                (int)($result['warnings']      ?? 0),
                (int)($result['critical']      ?? 0),
                (int)($result['info']          ?? 0),
                (int)($result['total_checks']  ?? 0),
                $durationMs,
                $clientIp !== '' ? $clientIp : null,
                $ipHash,
                $clientCountry,
                $result['tls']['protocol']     ?? null,
                $result['detected_cms']         ?? null,
                $result['detected_cms_version'] ?? null,
                !empty($result['scan_blocked']) ? 1 : 0,
                $result['scan_blocked_type']    ?? null,
                $result['assessment_status']    ?? 'complete',
                $result['assessment_reason']    ?? null,
                json_encode($wafVendors, JSON_UNESCAPED_UNICODE),
                json_encode($wafSignals, JSON_UNESCAPED_UNICODE),
                $isCloudflare ? 1 : 0,
                json_encode(array_slice($topIssues, 0, 15), JSON_UNESCAPED_UNICODE),
            ]);
            $this->hardenRuntimeFiles();
        } catch (Throwable $e) {
            error_log('[SecScan Logger] Log failed: ' . $e->getMessage());
        }
    }

    // ----------------------------------------------------------------
    //  DASHBOARD QUERIES
    // ----------------------------------------------------------------

    public function getSummary(): array
    {
        if (!$this->connect()) return [];
        try {
            $row = $this->pdo->query("
                SELECT
                    COUNT(*)                                      AS total_scans,
                    ROUND(AVG(CASE WHEN grade IN ('A+','A','B','C','D','F') THEN score END), 1) AS avg_score,
                    COUNT(DISTINCT client_ip_hash)                AS unique_ips,
                    SUM(CASE WHEN date(scanned_at) = date('now') THEN 1 ELSE 0 END) AS scans_today,
                    ROUND(AVG(duration_ms) / 1000.0, 1)           AS avg_duration_s,
                    SUM(CASE WHEN grade IN ('A+','A') THEN 1 ELSE 0 END) AS grade_a_count,
                    SUM(CASE WHEN grade IN ('A+','A','B','C','D','F') THEN critical ELSE 0 END) AS total_critical,
                    SUM(CASE WHEN grade IN ('A+','A','B','C','D','F') AND critical > 0 THEN 1 ELSE 0 END) AS scans_with_criticals,
                    SUM(CASE WHEN grade NOT IN ('A+','A','B','C','D','F') THEN 1 ELSE 0 END) AS unassessed_total,
                    SUM(CASE WHEN scan_blocked = 1 THEN 1 ELSE 0 END) AS scan_blocked_total,
                    SUM(CASE WHEN waf_vendors IS NOT NULL AND waf_vendors <> '' AND waf_vendors <> '[]' THEN 1 ELSE 0 END) AS waf_detected_total
                FROM scans
            ")->fetch();
            return $row ?: [];
        } catch (Throwable) { return []; }
    }

    public function getGradeDistribution(): array
    {
        if (!$this->connect()) return [];
        try {
            $rows = $this->pdo->query("
                SELECT grade, COUNT(*) AS cnt
                FROM scans
                GROUP BY grade
                ORDER BY CASE grade
                    WHEN 'A+' THEN 1 WHEN 'A' THEN 2 WHEN 'B' THEN 3
                    WHEN 'C'  THEN 4 WHEN 'D' THEN 5 WHEN 'F' THEN 6
                    ELSE 7 END
            ")->fetchAll();
            $result = [];
            foreach ($rows as $r) $result[$r['grade']] = (int)$r['cnt'];
            return $result;
        } catch (Throwable) { return []; }
    }

    public function getDailyScans(int $days = 30): array
    {
        if (!$this->connect()) return [];
        try {
            $days = max(1, min(365, $days));
            $rows = $this->pdo->query("
                SELECT date(scanned_at) AS day, COUNT(*) AS cnt
                FROM scans
                WHERE scanned_at >= datetime('now', '-{$days} days')
                GROUP BY day
                ORDER BY day ASC
            ")->fetchAll();
            $map = [];
            foreach ($rows as $r) $map[$r['day']] = (int)$r['cnt'];
            // Fill in zeros for missing days
            $result = [];
            for ($i = $days - 1; $i >= 0; $i--) {
                $d = date('Y-m-d', strtotime("-{$i} days"));
                $result[$d] = $map[$d] ?? 0;
            }
            return $result;
        } catch (Throwable) { return []; }
    }

    /** @return array<int,array{country:string,cnt:int,avg_score:float|int|null,last_scan:string}> */
    public function getCountryStats(int $limit = 20): array
    {
        if (!$this->connect()) return [];
        try {
            $limit = max(1, min(100, $limit));
            return $this->pdo->query(
                "SELECT s.client_country AS country, COUNT(*) AS cnt,
                        ROUND(AVG(CASE WHEN s.grade IN ('A+','A','B','C','D','F') THEN s.score END), 1) AS avg_score,
                        MAX(s.scanned_at) AS last_scan
                 FROM scans s
                 LEFT JOIN scans newer ON newer.hostname = s.hostname
                    AND (newer.scanned_at > s.scanned_at OR (newer.scanned_at = s.scanned_at AND newer.id > s.id))
                 WHERE newer.id IS NULL AND s.client_country IS NOT NULL AND s.client_country <> ''
                 GROUP BY s.client_country
                 ORDER BY cnt DESC, country ASC
                 LIMIT {$limit}"
            )->fetchAll();
        } catch (Throwable) {
            return [];
        }
    }

    /** Country totals split by grade for interactive dashboard filtering. */
    public function getCountryGradeStats(): array
    {
        if (!$this->connect()) return [];
        try {
            return $this->pdo->query(
                "SELECT s.client_country AS country, s.grade, COUNT(*) AS cnt,
                        ROUND(AVG(CASE WHEN s.grade IN ('A+','A','B','C','D','F') THEN s.score END), 1) AS avg_score
                 FROM scans s
                 LEFT JOIN scans newer ON newer.hostname = s.hostname
                    AND (newer.scanned_at > s.scanned_at OR (newer.scanned_at = s.scanned_at AND newer.id > s.id))
                 WHERE newer.id IS NULL AND s.client_country IS NOT NULL AND s.client_country <> ''
                 GROUP BY s.client_country, s.grade
                 ORDER BY s.client_country ASC, s.grade ASC"
            )->fetchAll();
        } catch (Throwable) {
            return [];
        }
    }

    /** Latest result for each domain, optionally narrowed to one grade. */
    public function getLatestDomainScans(string $grade = 'all', string $sort = 'recent', int $limit = 25, int $offset = 0): array
    {
        if (!$this->connect()) return [];
        try {
            $limit = max(1, min(100, $limit));
            $offset = max(0, $offset);
            $allowedGrades = ['A+', 'A', 'B', 'C', 'D', 'F', 'N/A'];
            $filterGrade = in_array($grade, $allowedGrades, true) ? $grade : null;
            $sql = "SELECT s.hostname, s.url, s.score, s.grade, s.client_country, s.scanned_at,
                           s.critical, s.warnings, s.assessment_status, s.assessment_reason
                    FROM scans s
                    LEFT JOIN scans newer ON newer.hostname = s.hostname
                       AND (newer.scanned_at > s.scanned_at OR (newer.scanned_at = s.scanned_at AND newer.id > s.id))
                    WHERE newer.id IS NULL AND s.hostname IS NOT NULL AND s.hostname <> ''";
            if ($filterGrade !== null) $sql .= ' AND s.grade = :grade';
            $orderBy = match ($sort) {
                'highest' => "CASE WHEN s.grade = 'N/A' THEN 1 ELSE 0 END ASC, s.score DESC, s.scanned_at DESC, s.id DESC",
                'lowest' => "CASE WHEN s.grade = 'N/A' THEN 1 ELSE 0 END ASC, s.score ASC, s.scanned_at DESC, s.id DESC",
                default => 's.scanned_at DESC, s.id DESC',
            };
            $sql .= " ORDER BY {$orderBy} LIMIT :limit OFFSET :offset";
            $stmt = $this->pdo->prepare($sql);
            if ($filterGrade !== null) $stmt->bindValue(':grade', $filterGrade, PDO::PARAM_STR);
            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
            $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetchAll();
        } catch (Throwable) {
            return [];
        }
    }

    /** Number of unique domains represented by their latest scan result. */
    public function getLatestDomainScanCount(string $grade = 'all'): int
    {
        if (!$this->connect()) return 0;
        try {
            $allowedGrades = ['A+', 'A', 'B', 'C', 'D', 'F', 'N/A'];
            $filterGrade = in_array($grade, $allowedGrades, true) ? $grade : null;
            $sql = "SELECT COUNT(*)
                    FROM scans s
                    LEFT JOIN scans newer ON newer.hostname = s.hostname
                       AND (newer.scanned_at > s.scanned_at OR (newer.scanned_at = s.scanned_at AND newer.id > s.id))
                    WHERE newer.id IS NULL AND s.hostname IS NOT NULL AND s.hostname <> ''";
            if ($filterGrade !== null) $sql .= ' AND s.grade = :grade';
            $stmt = $this->pdo->prepare($sql);
            if ($filterGrade !== null) $stmt->bindValue(':grade', $filterGrade, PDO::PARAM_STR);
            $stmt->execute();
            return (int)$stmt->fetchColumn();
        } catch (Throwable) {
            return 0;
        }
    }

    /** Domain unik mengikut suffix, dengan www. dianggap domain yang sama. */
    public function getDomainSuffixStats(): array
    {
        if (!$this->connect()) return [];
        try {
            return $this->pdo->query(
                "WITH unique_domains AS (
                    SELECT DISTINCT CASE
                        WHEN lower(hostname) LIKE 'www.%' THEN substr(lower(hostname), 5)
                        ELSE lower(hostname)
                    END AS domain
                    FROM scans
                    WHERE hostname IS NOT NULL AND hostname <> ''
                )
                SELECT CASE
                    WHEN domain LIKE '%.edu.my' THEN 'edu_my'
                    WHEN domain LIKE '%.gov.my' THEN 'gov_my'
                    WHEN domain LIKE '%.com.my' THEN 'com_my'
                    WHEN domain LIKE '%.my' THEN 'my_other'
                    WHEN domain LIKE '%.com' THEN 'com'
                    WHEN domain LIKE '%.org' THEN 'org'
                    WHEN domain LIKE '%.net' THEN 'net'
                    ELSE 'other'
                END AS category,
                COUNT(*) AS cnt
                FROM unique_domains
                GROUP BY category"
            )->fetchAll();
        } catch (Throwable) {
            return [];
        }
    }

    /** @return array{available:bool,records:int,updated_at:string} */
    public function getGeoIpStatus(): array
    {
        return $this->connect() ? GeoIp::status($this->pdo) : ['available' => false, 'records' => 0, 'updated_at' => ''];
    }

    /** @return array{ok:bool,message:string,records:int,backfilled:int} */
    public function updateGeoIp(): array
    {
        if (!$this->connect()) {
            return ['ok' => false, 'message' => 'Pangkalan data dashboard tidak dapat dibuka.', 'records' => 0, 'backfilled' => 0];
        }
        $result = GeoIp::update($this->pdo);
        $this->hardenRuntimeFiles();
        return $result;
    }

    public function getTopDomains(int $limit = 10): array
    {
        if (!$this->connect()) return [];
        try {
            $limit = max(1, min(100, $limit));
            return $this->pdo->query("
                SELECT hostname, COUNT(*) AS cnt,
                       ROUND(AVG(CASE WHEN grade IN ('A+','A','B','C','D','F') THEN score END),1) AS avg_score,
                       MAX(scanned_at) AS last_scan
                FROM scans
                GROUP BY hostname
                ORDER BY cnt DESC
                LIMIT {$limit}
            ")->fetchAll();
        } catch (Throwable) { return []; }
    }

    public function getCdnDomains(int $limit = 10): array
    {
        if (!$this->connect()) return [];
        try {
            $limit = max(1, min(100, $limit));
            return $this->pdo->query("
                SELECT hostname,
                       COUNT(*) AS scan_count,
                       MAX(scanned_at) AS last_scan,
                       ROUND(AVG(CASE WHEN grade IN ('A+','A','B','C','D','F') THEN score END), 1) AS avg_score,
                       (
                           SELECT waf_vendors
                           FROM scans AS latest
                           WHERE latest.hostname = scans.hostname
                             AND latest.waf_vendors IS NOT NULL
                             AND latest.waf_vendors <> ''
                             AND latest.waf_vendors <> '[]'
                           ORDER BY latest.scanned_at DESC
                           LIMIT 1
                       ) AS waf_vendors
                FROM scans
                WHERE is_cloudflare = 1
                   OR scan_blocked = 1
                   OR (waf_vendors IS NOT NULL AND waf_vendors <> '' AND waf_vendors <> '[]')
                GROUP BY hostname
                ORDER BY last_scan DESC
                LIMIT {$limit}
            ")->fetchAll();
        } catch (Throwable) { return []; }
    }

    public function getTopIssues(int $limit = 12): array
    {
        if (!$this->connect()) return [];
        try {
            $limit = max(1, min(100, $limit));
            // Parse JSON arrays in top_issues column
            $rows = $this->pdo->query("SELECT top_issues FROM scans WHERE top_issues IS NOT NULL AND grade IN ('A+','A','B','C','D','F')")->fetchAll();
            $counts = [];
            foreach ($rows as $r) {
                $issues = json_decode($r['top_issues'], true) ?: [];
                foreach ($issues as $issue) {
                    if ($issue !== '') $counts[$issue] = ($counts[$issue] ?? 0) + 1;
                }
            }
            arsort($counts);
            $result = [];
            foreach (array_slice($counts, 0, $limit, true) as $check => $cnt) {
                $result[] = ['check' => $check, 'cnt' => $cnt];
            }
            return $result;
        } catch (Throwable) { return []; }
    }

    public function getPeakHours(): array
    {
        if (!$this->connect()) return [];
        try {
            $rows = $this->pdo->query("
                SELECT CAST(strftime('%H', scanned_at) AS INTEGER) AS hour,
                       COUNT(*) AS cnt
                FROM scans
                GROUP BY hour
                ORDER BY hour ASC
            ")->fetchAll();
            $map = [];
            foreach ($rows as $r) $map[(int)$r['hour']] = (int)$r['cnt'];
            $result = [];
            for ($h = 0; $h < 24; $h++) $result[$h] = $map[$h] ?? 0;
            return $result;
        } catch (Throwable) { return []; }
    }

    public function getRecentScans(int $limit = 50, int $offset = 0): array
    {
        if (!$this->connect()) return [];
        try {
            $limit = max(1, min(250, $limit));
            $offset = max(0, $offset);
            return $this->pdo->query("
                SELECT id, scanned_at, hostname, score, grade, passed, warnings,
                       critical, total_checks, duration_ms, client_ip, client_country, tls_protocol,
                       detected_cms, detected_cms_version, scan_blocked, scan_blocked_type,
                       assessment_status, assessment_reason,
                       waf_vendors, waf_signals, is_cloudflare
                FROM scans
                ORDER BY scanned_at DESC
                LIMIT {$limit} OFFSET {$offset}
            ")->fetchAll();
        } catch (Throwable) { return []; }
    }

    public function getTotalCount(): int
    {
        if (!$this->connect()) return 0;
        try {
            return (int)$this->pdo->query("SELECT COUNT(*) FROM scans")->fetchColumn();
        } catch (Throwable) { return 0; }
    }

    public function getScoreDistribution(): array
    {
        if (!$this->connect()) return [];
        try {
            $rows = $this->pdo->query("
                SELECT
                    SUM(CASE WHEN grade IN ('A+','A','B','C','D','F') AND score >= 90 THEN 1 ELSE 0 END) AS s90,
                    SUM(CASE WHEN grade IN ('A+','A','B','C','D','F') AND score >= 70 AND score < 90 THEN 1 ELSE 0 END) AS s70,
                    SUM(CASE WHEN grade IN ('A+','A','B','C','D','F') AND score >= 50 AND score < 70 THEN 1 ELSE 0 END) AS s50,
                    SUM(CASE WHEN grade IN ('A+','A','B','C','D','F') AND score < 50 THEN 1 ELSE 0 END) AS s0
                FROM scans
            ")->fetch();
            return $rows ?: [];
        } catch (Throwable) { return []; }
    }
}
