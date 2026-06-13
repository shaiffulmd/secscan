<?php

require_once __DIR__ . '/config.php';

/**
 * ScanLogger — simpan setiap scan ke SQLite dan sediakan data untuk dashboard.
 *
 * Database disimpan di data/secscan.db (dilindungi oleh data/.htaccess).
 * IP pengguna di-hash (SHA-256 + salt) untuk privasi — tidak disimpan dalam plaintext.
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
            $this->migrate();
            return true;
        } catch (Throwable $e) {
            error_log('[SecScan Logger] DB connect failed: ' . $e->getMessage());
            return false;
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
                client_ip_hash TEXT,
                tls_protocol  TEXT,
                is_cloudflare INTEGER NOT NULL DEFAULT 0,
                top_issues    TEXT
            )
        ");

        $this->pdo->exec("CREATE INDEX IF NOT EXISTS idx_scanned_at ON scans(scanned_at)");
        $this->pdo->exec("CREATE INDEX IF NOT EXISTS idx_hostname   ON scans(hostname)");
        $this->pdo->exec("CREATE INDEX IF NOT EXISTS idx_grade      ON scans(grade)");
        $this->pdo->exec("CREATE INDEX IF NOT EXISTS idx_ip_hash    ON scans(client_ip_hash)");
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

            // Hash IP — tidak simpan dalam plaintext
            $ipHash = $clientIp !== ''
                ? hash('sha256', $clientIp . (string)secscan_config('ip_hash_salt'))
                : null;

            // Parse duration "1.23s" → ms
            $durationMs = (int)(((float)rtrim($result['duration'] ?? '0s', 's')) * 1000);

            $stmt = $this->pdo->prepare("
                INSERT INTO scans
                    (hostname, url, score, grade, passed, warnings, critical, info,
                     total_checks, duration_ms, client_ip_hash, tls_protocol,
                     is_cloudflare, top_issues)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                $ipHash,
                $result['tls']['protocol']     ?? null,
                ($result['edge']['cloudflare'] ?? false) ? 1 : 0,
                json_encode(array_slice($topIssues, 0, 15), JSON_UNESCAPED_UNICODE),
            ]);
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
                    ROUND(AVG(score), 1)                          AS avg_score,
                    COUNT(DISTINCT client_ip_hash)                AS unique_ips,
                    SUM(CASE WHEN date(scanned_at) = date('now') THEN 1 ELSE 0 END) AS scans_today,
                    ROUND(AVG(duration_ms) / 1000.0, 1)           AS avg_duration_s,
                    SUM(CASE WHEN grade IN ('A+','A') THEN 1 ELSE 0 END) AS grade_a_count,
                    SUM(critical)                                 AS total_critical,
                    SUM(CASE WHEN critical > 0 THEN 1 ELSE 0 END) AS scans_with_criticals
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

    public function getTopDomains(int $limit = 10): array
    {
        if (!$this->connect()) return [];
        try {
            $limit = max(1, min(100, $limit));
            return $this->pdo->query("
                SELECT hostname, COUNT(*) AS cnt, ROUND(AVG(score),1) AS avg_score,
                       MAX(scanned_at) AS last_scan
                FROM scans
                GROUP BY hostname
                ORDER BY cnt DESC
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
            $rows = $this->pdo->query("SELECT top_issues FROM scans WHERE top_issues IS NOT NULL")->fetchAll();
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
                       critical, total_checks, duration_ms, tls_protocol, is_cloudflare
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
                    SUM(CASE WHEN score >= 90 THEN 1 ELSE 0 END) AS s90,
                    SUM(CASE WHEN score >= 70 AND score < 90 THEN 1 ELSE 0 END) AS s70,
                    SUM(CASE WHEN score >= 50 AND score < 70 THEN 1 ELSE 0 END) AS s50,
                    SUM(CASE WHEN score < 50 THEN 1 ELSE 0 END) AS s0
                FROM scans
            ")->fetch();
            return $rows ?: [];
        } catch (Throwable) { return []; }
    }
}
