<?php

/**
 * Read-only audit of a SecScan checkout and its deployment configuration.
 *
 * This deliberately reports review items instead of attempting to rewrite or
 * delete files. It is useful in CI, before deployment, and during a server
 * handover where the runtime scanner cannot inspect its own source safely.
 */
final class CodebaseScanner
{
    private const IGNORED_DIRECTORIES = ['.git', 'vendor', 'node_modules'];
    private const TEXT_EXTENSIONS = [
        'php', 'inc', 'phtml', 'js', 'css', 'json', 'md', 'sh', 'sql',
        'yml', 'yaml', 'ini', 'conf', 'txt', 'htaccess', 'env',
    ];

    /** @return array<string,mixed> */
    public function scan(string $root): array
    {
        $root = realpath($root) ?: $root;
        $findings = [];
        $files = $this->collectFiles($root);
        $phpFiles = array_values(array_filter($files, static fn(string $path): bool => strtolower(pathinfo($path, PATHINFO_EXTENSION)) === 'php'));

        $this->scanPhpSyntax($root, $phpFiles, $findings);
        $this->scanConfiguration($root, $findings);
        $this->scanArtifactsAndPermissions($root, $files, $findings);
        $this->scanSourcePatterns($root, $files, $findings);
        $this->scanWebServerRules($root, $findings);
        $this->scanTestCoverage($root, $findings);

        return [
            'root' => $root,
            'scanned_at' => gmdate('c'),
            'stats' => [
                'files' => count($files),
                'php_files' => count($phpFiles),
                'findings' => count($findings),
            ],
            'findings' => $findings,
        ];
    }

    /**
     * Analyze a source buffer without reading the filesystem.
     * This is also used by the offline unit test for the scanner rules.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function analyzeSource(string $relativePath, string $contents): array
    {
        $findings = [];
        $patterns = [
            [
                'id' => 'dynamic-code',
                'regex' => '/\b(?:eval|assert)\s*\(/i',
                'severity' => 'critical',
                'title' => 'Dynamic code execution pattern',
                'detail' => 'eval() atau assert() ditemui dalam source code.',
                'recommendation' => 'Buang dynamic execution; gunakan parser atau fungsi khusus dengan input yang divalidasi.',
            ],
            [
                'id' => 'unsafe-process',
                'regex' => '/\b(?:shell_exec|system|passthru|popen|proc_open)\s*\(/i',
                'severity' => 'warning',
                'title' => 'Process execution requires review',
                'detail' => 'Kod memanggil proses OS dari aplikasi.',
                'recommendation' => 'Pastikan executable dan argumen allowlist, guna escapeshellarg(), dan elak input pengguna terus ke shell.',
            ],
            [
                'id' => 'request-driven-include',
                'regex' => '/\b(?:include|include_once|require|require_once)\s*(?:\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE)\b/i',
                'severity' => 'critical',
                'title' => 'Request data used in a file include',
                'detail' => 'Input request digunakan terus pada include/require dan boleh membuka local/remote file inclusion.',
                'recommendation' => 'Petakan pilihan kepada allowlist path tetap; jangan gabungkan input pengguna dengan nama fail.',
            ],
            [
                'id' => 'request-driven-sql',
                'regex' => '/->(?:query|exec)\s*\([^;\n]*\$_(?:GET|POST|REQUEST|COOKIE)\b/i',
                'severity' => 'critical',
                'title' => 'Request data used directly in SQL',
                'detail' => 'Input request dihantar terus kepada query/exec database.',
                'recommendation' => 'Gunakan prepared statement dan bind parameter dengan jenis yang sesuai.',
            ],
            [
                'id' => 'unsafe-unserialize',
                'regex' => '/\bunserialize\s*\(/i',
                'severity' => 'warning',
                'title' => 'Untrusted unserialize() requires review',
                'detail' => 'unserialize() boleh menyebabkan object injection jika menerima data tidak dipercayai.',
                'recommendation' => 'Guna JSON atau allowlist kelas melalui pilihan kedua unserialize() selepas mengesahkan sumber data.',
            ],
            [
                'id' => 'unchecked-file-lock',
                'regex' => '/^[ \t]*flock\s*\([^;\n]*LOCK_EX[^;\n]*\)\s*;/mi',
                'severity' => 'warning',
                'title' => 'Exclusive file lock result is ignored',
                'detail' => 'Kod meneruskan operasi walaupun flock(LOCK_EX) mungkin gagal.',
                'recommendation' => 'Periksa nilai pulangan flock() dan gagal tertutup sebelum membaca atau menulis state keselamatan.',
            ],
            [
                'id' => 'weak-randomness',
                'regex' => '/\b(?:mt_rand|rand)\s*\(/i',
                'severity' => 'warning',
                'title' => 'Non-cryptographic randomness requires review',
                'detail' => 'rand()/mt_rand() tidak sesuai untuk token, nonce atau nama keselamatan yang sukar dijangka.',
                'recommendation' => 'Gunakan random_bytes() untuk token atau random_int() untuk nombor rawak.',
            ],
            [
                'id' => 'weak-hash',
                'regex' => '/\b(?:md5|sha1)\s*\(/i',
                'severity' => 'warning',
                'title' => 'Legacy hash function requires review',
                'detail' => 'MD5/SHA-1 tidak sesuai untuk password, tandatangan atau semakan integriti bermusuhan.',
                'recommendation' => 'Gunakan password_hash(), hash_hmac() atau SHA-256/lebih kuat mengikut tujuan.',
            ],
            [
                'id' => 'world-writable-mode',
                'regex' => '/\bchmod\s*\([^,]+,\s*0?777\s*\)/i',
                'severity' => 'warning',
                'title' => 'World-writable file mode detected',
                'detail' => 'Kod menetapkan permission 0777 yang membenarkan semua pengguna menulis.',
                'recommendation' => 'Gunakan 0700/0750 untuk direktori dan 0600/0640 untuk fail mengikut keperluan proses web.',
            ],
            [
                'id' => 'tls-verification-bypass',
                'regex' => '/CURLOPT_SSL_VERIFYPEER\s*=>\s*false|CURLOPT_SSL_VERIFYHOST\s*=>\s*0/i',
                'severity' => 'warning',
                'title' => 'TLS certificate verification disabled',
                'detail' => 'Probe cURL mematikan pengesahan sijil TLS; ini perlu kekal terhad kepada probe yang memang menguji sijil rosak.',
                'recommendation' => 'Gunakan true/2 untuk request biasa. Tandakan probe diagnostik dengan jelas dan jangan hantar credentials apabila verification dimatikan.',
            ],
            [
                'id' => 'private-key',
                'regex' => '/-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----/i',
                'severity' => 'critical',
                'title' => 'Private key material detected',
                'detail' => 'Blok private key dikesan dalam fail codebase.',
                'recommendation' => 'Rotate key, keluarkan daripada repository/deploy bundle, dan simpan melalui secret manager.',
            ],
            [
                'id' => 'aws-key',
                'regex' => '/\bAKIA[0-9A-Z]{16}\b/',
                'severity' => 'critical',
                'title' => 'AWS access key pattern detected',
                'detail' => 'Corak access key AWS dikesan; kandungan sebenar tidak dicetak.',
                'recommendation' => 'Revoke/rotate credential dan semak history repository serta log deployment.',
            ],
            [
                'id' => 'display-errors',
                'regex' => '/display_errors\s*[=,]\s*[\'\"]?(?:1|on|true)/i',
                'severity' => 'warning',
                'title' => 'Detailed PHP errors may be exposed',
                'detail' => 'display_errors aktif dalam source/config.',
                'recommendation' => 'Matikan display_errors di production dan hantar detail ke error log dalaman sahaja.',
            ],
        ];

        foreach ($patterns as $pattern) {
            if (!preg_match($pattern['regex'], $contents, $match, PREG_OFFSET_CAPTURE)) {
                continue;
            }
            $offset = (int)($match[0][1] ?? 0);
            $line = substr_count(substr($contents, 0, $offset), "\n") + 1;
            $findings[] = [
                'id' => $pattern['id'],
                'severity' => $pattern['severity'],
                'category' => 'Source',
                'title' => $pattern['title'],
                'detail' => $pattern['detail'],
                'recommendation' => $pattern['recommendation'],
                'file' => $relativePath,
                'line' => $line,
            ];
        }

        return $findings;
    }

    /** @return array<int,string> */
    private function collectFiles(string $root): array
    {
        if (!is_dir($root)) {
            return [];
        }

        $files = [];
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );
        foreach ($iterator as $file) {
            if (!$file->isFile() || $this->isIgnoredPath($root, $file->getPathname())) {
                continue;
            }
            $files[] = $file->getPathname();
        }
        sort($files);
        return $files;
    }

    private function isIgnoredPath(string $root, string $path): bool
    {
        $relative = $this->relativePath($root, $path);
        foreach (explode('/', $relative) as $part) {
            if (in_array($part, self::IGNORED_DIRECTORIES, true)) {
                return true;
            }
        }
        return false;
    }

    private function relativePath(string $root, string $path): string
    {
        $root = rtrim(str_replace('\\', '/', $root), '/');
        $path = str_replace('\\', '/', $path);
        return ltrim(str_starts_with($path, $root) ? substr($path, strlen($root)) : $path, '/');
    }

    /** @param array<int,string> $phpFiles @param array<int,array<string,mixed>> $findings */
    private function scanPhpSyntax(string $root, array $phpFiles, array &$findings): void
    {
        if (!function_exists('exec')) {
            $this->add($findings, 'warning', 'Syntax', 'PHP lint command is unavailable', 'exec() is disabled, so the audit cannot run php -l for each file.', 'Run the audit in CLI PHP with exec enabled, or run scripts/check.php in a separate build step.');
            return;
        }

        $failed = [];
        foreach ($phpFiles as $file) {
            $output = [];
            $code = 0;
            exec(escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($file) . ' 2>&1', $output, $code);
            if ($code !== 0) {
                $failed[] = $this->relativePath($root, $file) . (isset($output[0]) ? ': ' . trim($output[0]) : '');
            }
        }

        if ($failed !== []) {
            foreach ($failed as $item) {
                $this->add($findings, 'critical', 'Syntax', 'PHP syntax error', $item, 'Betulkan syntax sebelum deploy atau release.');
            }
            return;
        }

        $this->add($findings, 'pass', 'Syntax', 'All PHP files passed syntax check', count($phpFiles) . ' fail PHP disemak.', '');
    }

    /** @param array<int,array<string,mixed>> $findings */
    private function scanConfiguration(string $root, array &$findings): void
    {
        $envPath = $root . '/.env';
        if (is_file($envPath)) {
            $this->add($findings, 'warning', 'Configuration', 'Local .env file is present', 'Fail .env mengandungi konfigurasi deployment dan mungkin rahsia.', 'Pastikan ia tidak di-commit, tidak berada dalam public web root, dan akses web disekat di web server.');
        } else {
            $this->add($findings, 'pass', 'Configuration', 'No local .env file in checkout', 'Nilai deployment akan datang daripada environment server.', '');
        }

        $configPath = $root . '/config.php';
        if (!is_file($configPath)) {
            $this->add($findings, 'critical', 'Configuration', 'config.php is missing', 'Fail konfigurasi teras tidak ditemui.', 'Pulihkan config.php sebelum menjalankan aplikasi.');
            return;
        }

        try {
            require_once $configPath;
        } catch (Throwable $e) {
            $this->add($findings, 'critical', 'Configuration', 'config.php could not be loaded', 'Konfigurasi gagal dimuatkan tanpa memaparkan detail rahsia.', 'Semak PHP error log dan konfigurasi environment.');
            return;
        }

        if (!function_exists('secscan_config')) {
            $this->add($findings, 'critical', 'Configuration', 'secscan_config() is unavailable', 'Fungsi konfigurasi tidak didefinisikan selepas config.php dimuatkan.', 'Semak config.php.');
            return;
        }

        $salt = (string)secscan_config('ip_hash_salt');
        if ($salt === '' || $salt === 'change-this-salt-before-production') {
            $this->add($findings, 'critical', 'Configuration', 'IP hash salt is missing or default', 'Statistik IP menggunakan salt yang kosong atau default.', 'Set SECSCAN_IP_HASH_SALT kepada nilai rawak panjang dan rahsiakan daripada repository.');
        } else {
            $this->add($findings, 'pass', 'Configuration', 'IP hash salt is configured', 'Nilai bukan default digunakan; nilainya tidak dicetak.', '');
        }

        $passwordHash = (string)secscan_config('dashboard_password_hash');
        if ($passwordHash === '') {
            $this->add($findings, 'warning', 'Configuration', 'Dashboard password hash is not configured', 'Dashboard password login akan dilumpuhkan.', 'Set SECSCAN_DASHBOARD_PASSWORD_HASH menggunakan password_hash().');
        } elseif ((password_get_info($passwordHash)['algo'] ?? 0) === 0) {
            $this->add($findings, 'critical', 'Configuration', 'Dashboard password hash format is invalid', 'Nilai password hash tidak dikenali oleh PHP.', 'Jana hash bcrypt/Argon2 baharu dan set environment variable.');
        } else {
            $this->add($findings, 'pass', 'Configuration', 'Dashboard password hash is valid', 'Format hash dikenali oleh PHP.', '');
        }

        $dataDir = (string)secscan_config('data_dir');
        $databasePath = (string)secscan_config('database_path');
        if ($dataDir === '' || !is_dir($dataDir)) {
            $this->add($findings, 'warning', 'Configuration', 'Configured data directory is missing', 'Folder data untuk SQLite, rate-limit dan cache belum wujud.', 'Cipta folder data dan beri owner web process akses tulis yang minimum.');
        } elseif (!is_writable($dataDir)) {
            $this->add($findings, 'critical', 'Configuration', 'Configured data directory is not writable', 'Aplikasi tidak dapat menulis database/rate-limit/cache.', 'Baiki owner dan permission folder data tanpa memberi world-write.');
        } else {
            $this->add($findings, 'pass', 'Configuration', 'Configured data directory is writable', 'Folder storage boleh ditulis oleh proses semasa.', '');
        }

        if (is_dir($dataDir)) {
            $dataMode = @fileperms($dataDir);
            if ($dataMode !== false && ($dataMode & 0x0007) !== 0) {
                $this->add($findings, 'warning', 'Permissions', 'Data directory is accessible to other users', 'Folder data menggunakan mode ' . substr(sprintf('%o', $dataMode), -4) . '.', 'Gunakan mode 0750 atau 0700 dan owner/group khusus untuk proses aplikasi.');
            }
        }

        if ($databasePath !== '') {
            $dbParent = dirname($databasePath);
            if (!is_dir($dbParent)) {
                $this->add($findings, 'warning', 'Configuration', 'Database parent directory is missing', 'Direktori untuk database belum wujud.', 'Cipta direktori database dengan permission minimum.');
            }
            $rootReal = realpath($root);
            $dbParentReal = realpath($dbParent);
            if ($rootReal !== false && $dbParentReal !== false && ($dbParentReal === $rootReal || str_starts_with($dbParentReal, $rootReal . DIRECTORY_SEPARATOR))) {
                $this->add($findings, 'warning', 'Configuration', 'SQLite database is inside the web root', 'Database path berada dalam checkout aplikasi.', 'Pindahkan SECSCAN_DB_PATH dan SECSCAN_DATA_DIR ke luar public web root; gunakan .htaccess hanya sebagai defense in depth.');
            }
        }

        $mode = (string)secscan_config('scanner_mode');
        if ($mode === 'remote') {
            $workerUrl = (string)secscan_config('worker_url');
            $secret = (string)secscan_config('worker_shared_secret');
            if (strtolower((string)parse_url($workerUrl, PHP_URL_SCHEME)) !== 'https') {
                $this->add($findings, 'critical', 'Configuration', 'Remote worker URL is not HTTPS', 'Remote scan jobs boleh dihantar tanpa TLS.', 'Set SECSCAN_WORKER_URL kepada endpoint https:// yang sah.');
            }
            if (strlen($secret) < 32) {
                $this->add($findings, 'critical', 'Configuration', 'Remote worker shared secret is too short', 'Worker HMAC secret mesti sekurang-kurangnya 32 aksara.', 'Jana secret rawak sekurang-kurangnya 32 aksara dan set pada kedua-dua server.');
            }
        } else {
            $this->add($findings, 'pass', 'Configuration', 'Scanner mode is local', 'Tiada worker remote diaktifkan.', '');
        }

        if ((bool)secscan_config('allow_auth_scan')) {
            $this->add($findings, 'warning', 'Configuration', 'Authenticated scanning is enabled', 'Endpoint scan boleh menerima credential untuk dihantar ke target HTTPS.', 'Pastikan deployment berakses terhad, audit log dilindungi, dan matikan SECSCAN_ALLOW_AUTH_SCAN pada scanner awam.');
        }
    }

    /** @param array<int,string> $files @param array<int,array<string,mixed>> $findings */
    private function scanArtifactsAndPermissions(string $root, array $files, array &$findings): void
    {
        $sensitive = [];
        $publicDocs = [];
        foreach ($files as $file) {
            $relative = $this->relativePath($root, $file);
            $lower = strtolower($relative);
            $basename = strtolower(basename($file));
            $isExampleEnv = $basename === '.env.example';
            if (!$isExampleEnv && preg_match('/(?:^|\/)(?:\.env(?:\..*)?|.*\.(?:bak|backup|old|orig|swp|tmp|sql|db|sqlite|sqlite3|zip|tar|gz|log))(?:\.|$)/i', $lower)) {
                $sensitive[] = $relative;
            } elseif (preg_match('/\.(?:pdf|docx)$/i', $lower)) {
                $publicDocs[] = $relative;
            }

            if (!$isExampleEnv && preg_match('/(?:^|\/)(?:\.env(?:\..*)?|.*\.(?:db|sqlite|sqlite3|sql|zip|bak|backup|old|orig))$/i', $lower)) {
                $mode = @fileperms($file);
                if ($mode !== false && (($mode & 0x0004) !== 0 || ($mode & 0x0002) !== 0)) {
                    $this->add($findings, 'warning', 'Permissions', 'Sensitive artifact is broadly readable/writable', $relative . ' mode ' . substr(sprintf('%o', $mode), -4) . '.', 'Hadkan permission fail kepada owner/group yang diperlukan sahaja dan keluarkan daripada public web root.');
                }
            }
        }

        if ($sensitive !== []) {
            $shown = array_slice($sensitive, 0, 8);
            $extra = count($sensitive) > count($shown) ? ' +' . (count($sensitive) - count($shown)) . ' lagi' : '';
            $this->add($findings, 'warning', 'Artifacts', 'Sensitive deployment artifacts are present', implode(', ', $shown) . $extra, 'Jangan deploy artefak ini ke public web root; simpan archive/DB/backup di storage persendirian.');
        } else {
            $this->add($findings, 'pass', 'Artifacts', 'No obvious sensitive artifacts found', 'Tiada .env/DB/backup/archive matching rule ditemui.', '');
        }
        if ($publicDocs !== []) {
            $this->add($findings, 'info', 'Artifacts', 'Documentation files are present in the checkout', count($publicDocs) . ' PDF/DOCX file(s) ditemui.', 'Pastikan dokumen yang tidak dimaksudkan untuk umum disimpan di luar public web root.');
        }

        $dataDir = $root . '/data';
        if (is_dir($dataDir)) {
            $this->add(
                $findings,
                is_file($dataDir . '/.htaccess') ? 'pass' : 'warning',
                'Permissions',
                is_file($dataDir . '/.htaccess') ? 'data/ has an Apache deny rule' : 'data/ has no local Apache deny rule',
                is_file($dataDir . '/.htaccess') ? 'Defense in depth tersedia untuk Apache.' : 'Database dan cache mungkin boleh diminta terus oleh web server Apache.',
                is_file($dataDir . '/.htaccess') ? '' : 'Tambah rule deny dan, lebih penting, pindahkan SECSCAN_DATA_DIR ke luar public web root.'
            );
        }
    }

    /** @param array<int,string> $files @param array<int,array<string,mixed>> $findings */
    private function scanSourcePatterns(string $root, array $files, array &$findings): void
    {
        $reported = [];
        foreach ($files as $file) {
            $relative = $this->relativePath($root, $file);
            if ($this->isTestPath($relative) || $relative === 'src/CodebaseScanner.php') {
                // Unit-test fixtures and this scanner's own detection rules
                // intentionally contain security signatures.
                continue;
            }
            $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
            $basename = strtolower(basename($file));
            $executableExtensions = ['php', 'inc', 'phtml', 'js', 'sh'];
            if (!in_array($extension, $executableExtensions, true) && $basename !== '.htaccess') {
                continue;
            }
            $size = @filesize($file);
            if ($size === false || $size > 4194304) {
                continue;
            }
            $contents = @file_get_contents($file);
            if (!is_string($contents)) {
                continue;
            }
            foreach (self::analyzeSource($relative, $contents) as $finding) {
                $key = $finding['id'] . '|' . $relative;
                if (isset($reported[$key])) {
                    continue;
                }
                $reported[$key] = true;
                $findings[] = $finding;
            }
        }
    }

    private function isTestPath(string $relativePath): bool
    {
        $relativePath = strtolower(str_replace('\\', '/', $relativePath));
        return str_starts_with($relativePath, 'scripts/test_') || str_contains($relativePath, '/tests/');
    }

    /** @param array<int,array<string,mixed>> $findings */
    private function scanWebServerRules(string $root, array &$findings): void
    {
        $htaccess = $root . '/.htaccess';
        if (!is_file($htaccess)) {
            $this->add($findings, 'warning', 'Web server', 'Root .htaccess is missing', 'Apache deployments may lack the project defense-in-depth rules.', 'Use an equivalent Apache/Nginx server policy and keep runtime headers enabled.');
            return;
        }
        $contents = (string)@file_get_contents($htaccess);
        $checks = [
            ['pattern' => '/FilesMatch[^\n]*\.env|RewriteRule[^\n]*\.git/i', 'title' => 'Sensitive path blocking rules present', 'detail' => 'Rule untuk dotfiles atau VCS metadata dikesan.'],
            ['pattern' => '/X-Content-Type-Options/i', 'title' => 'Baseline security headers present', 'detail' => 'nosniff header dikesan pada web-server layer.'],
            ['pattern' => '/REQUEST_METHOD[^\n]*TRACE/i', 'title' => 'TRACE blocking rule present', 'detail' => 'HTTP TRACE disekat pada web-server layer.'],
        ];
        foreach ($checks as $check) {
            $this->add(
                $findings,
                preg_match($check['pattern'], $contents) ? 'pass' : 'warning',
                'Web server',
                preg_match($check['pattern'], $contents) ? $check['title'] : 'Expected web-server rule is missing',
                preg_match($check['pattern'], $contents) ? $check['detail'] : 'Rule yang disyorkan tidak dikesan dalam .htaccess.',
                preg_match($check['pattern'], $contents) ? '' : 'Tambah polisi setara untuk Apache atau Nginx deployment sebenar.'
            );
        }
    }

    /** @param array<int,array<string,mixed>> $findings */
    private function scanTestCoverage(string $root, array &$findings): void
    {
        $required = [
            'scripts/check.php',
            'scripts/preflight.php',
            'scripts/security_scan.php',
            'scripts/test_codebase_scanner.php',
            'scripts/test_detection.php',
            'scripts/test_rate_limiter.php',
            'scripts/test_regression.php',
            'scripts/test_storage.php',
        ];
        $missing = array_values(array_filter($required, static fn(string $file): bool => !is_file($root . '/' . $file)));
        if ($missing !== []) {
            $this->add($findings, 'warning', 'Tests', 'Core verification scripts are missing', implode(', ', $missing), 'Pulihkan lint, preflight dan regression checks sebelum release.');
        } else {
            $this->add($findings, 'pass', 'Tests', 'Core verification scripts are present', 'Lint, preflight, detection dan regression checks tersedia.', '');
        }

        if (is_file($root . '/composer.json') && !is_file($root . '/composer.lock')) {
            $this->add($findings, 'info', 'Dependencies', 'composer.lock is not present', 'Manifest wujud tetapi dependency lockfile tiada.', 'Jika dependency production digunakan, commit composer.lock untuk build yang repeatable.');
        }
    }

    /** @param array<int,array<string,mixed>> $findings */
    private function add(array &$findings, string $severity, string $category, string $title, string $detail, string $recommendation): void
    {
        $findings[] = [
            'severity' => $severity,
            'category' => $category,
            'title' => $title,
            'detail' => $detail,
            'recommendation' => $recommendation,
        ];
    }
}
