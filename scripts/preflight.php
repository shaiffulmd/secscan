<?php
/**
 * scripts/preflight.php — Semak kesediaan deployment SEBELUM scan.
 *
 * Tujuan: elak "ralat dalaman 500" yang berlaku bila fail wajib (config.php,
 * src/UrlGuard.php, src/RateLimiter.php) atau sambungan PHP tiada di server.
 *
 * Jalankan di server (dari root projek):
 *     php scripts/preflight.php
 * atau melalui Composer:
 *     composer preflight
 */

declare(strict_types=1);

$root = dirname(__DIR__);
$cli  = (PHP_SAPI === 'cli');

// Preflight reveals deployment internals (paths, extensions, whether the
// dashboard password / IP salt are configured). Never expose that over the web
// unless an operator explicitly opts in via SECSCAN_ALLOW_WEB_PREFLIGHT=1.
if (!$cli && getenv('SECSCAN_ALLOW_WEB_PREFLIGHT') !== '1') {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Forbidden. Run preflight from the command line:\n  php scripts/preflight.php\n";
    exit;
}

$nl   = $cli ? "\n" : "<br>\n";
if (!$cli) { header('Content-Type: text/plain; charset=utf-8'); }

$pass = 0; $fail = 0; $warn = 0;
function res(string $status, string $label, string $detail = ''): void
{
    global $pass, $fail, $warn, $nl;
    $tag = match ($status) { 'PASS' => '[PASS]', 'FAIL' => '[FAIL]', default => '[WARN]' };
    if ($status === 'PASS') $GLOBALS['pass']++;
    elseif ($status === 'FAIL') $GLOBALS['fail']++;
    else $GLOBALS['warn']++;
    echo "  {$tag} {$label}" . ($detail !== '' ? "  —  {$detail}" : '') . $nl;
}

echo "============================================================" . $nl;
echo "  SecScan Preflight Check" . $nl;
echo "  Root : " . $root . $nl;
echo "  PHP  : " . PHP_VERSION . $nl;
echo "============================================================" . $nl;

// ---- 1. Versi PHP -------------------------------------------------
echo $nl . "1. Versi PHP" . $nl;
res(PHP_VERSION_ID >= 80100 ? 'PASS' : 'WARN', 'PHP 8.1+', PHP_VERSION);
// PHP2Shell (CVE-2026-109618, CVE-2026-109619): this host also runs PHP.
$php2shellFixed = ['8.2' => '8.2.35', '8.3' => '8.3.36', '8.4' => '8.4.27', '8.5' => '8.5.12'][PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION] ?? null;
if (PHP_VERSION_ID < 80200) {
    res('WARN', 'PHP2Shell', 'cawangan ini tiada keluaran rasmi yang dibaiki; naik taraf ke PHP 8.3+');
} elseif ($php2shellFixed !== null && version_compare(PHP_VERSION, $php2shellFixed, '<')) {
    res('WARN', 'PHP2Shell', "naik taraf ke {$php2shellFixed}, atau sahkan backport distro dalam changelog pakej");
} else {
    res('PASS', 'PHP2Shell', 'versi ini tidak berada dalam julat terjejas');
}

// ---- 2. Sambungan PHP wajib --------------------------------------
echo $nl . "2. Sambungan PHP" . $nl;
$required = ['curl', 'openssl', 'json', 'mbstring', 'pdo', 'pdo_sqlite'];
$optional = ['sockets'];
foreach ($required as $ext) {
    res(extension_loaded($ext) ? 'PASS' : 'FAIL', "ext-{$ext}", extension_loaded($ext) ? '' : 'WAJIB — pasang sambungan ini');
}
foreach ($optional as $ext) {
    res(extension_loaded($ext) ? 'PASS' : 'WARN', "ext-{$ext} (pilihan)", extension_loaded($ext) ? '' : 'disyorkan');
}
res(function_exists('gzopen') ? 'PASS' : 'WARN', 'zlib/gzip (GeoIP update)', function_exists('gzopen') ? '' : 'diperlukan untuk butang kemas kini GeoIP');

// ---- 3. Fail wajib ------------------------------------------------
echo $nl . "3. Fail & folder wajib" . $nl;
$files = [
    'config.php'            => true,
    'scanner.php'           => true,
    'src/UrlGuard.php'      => true,
    'src/RateLimiter.php'   => true,
    'api.php'               => true,
    'index.php'             => true,
    'logger.php'            => false,
];
foreach ($files as $rel => $must) {
    $ok = is_file($root . '/' . $rel);
    res($ok ? 'PASS' : ($must ? 'FAIL' : 'WARN'), $rel, $ok ? '' : 'TIADA di server — upload fail ini');
}

// ---- 4. Folder data/ boleh ditulis -------------------------------
echo $nl . "4. Folder data (untuk DB / rate-limit)" . $nl;
$dataDir = $root . '/data';
if (!is_dir($dataDir)) {
    res('WARN', 'data/', 'tiada — akan dicipta automatik jika induk boleh ditulis');
} else {
    res(is_writable($dataDir) ? 'PASS' : 'FAIL', 'data/ boleh ditulis', is_writable($dataDir) ? '' : 'chmod 775 data/');
}

// ---- 5. Muatkan config & kelas teras -----------------------------
echo $nl . "5. Muatkan dependency teras" . $nl;
$configPath = $root . '/config.php';
if (is_file($configPath)) {
    require_once $configPath;
    res(function_exists('secscan_config') ? 'PASS' : 'FAIL', 'config.php → secscan_config()',
        function_exists('secscan_config') ? '' : 'fungsi tidak ditemui');
    if (function_exists('secscan_config')) {
        $salt = secscan_config('ip_hash_salt');
        res($salt && $salt !== 'change-this-salt-before-production' ? 'PASS' : 'WARN',
            'SECSCAN_IP_HASH_SALT ditetapkan',
            ($salt === 'change-this-salt-before-production') ? 'masih guna default — set env untuk produksi' : '');
        $pwd = secscan_config('dashboard_password_hash');
        res($pwd !== '' ? 'PASS' : 'WARN', 'SECSCAN_DASHBOARD_PASSWORD_HASH ditetapkan',
            $pwd === '' ? 'kosong — login dashboard dilumpuhkan sehingga hash ditetapkan' : '');
    }
} else {
    res('FAIL', 'config.php', 'TIADA — punca utama ralat 500');
}

$guardPath = $root . '/src/UrlGuard.php';
if (is_file($guardPath)) {
    require_once $guardPath;
    res(class_exists('UrlGuard') ? 'PASS' : 'FAIL', 'src/UrlGuard.php → class UrlGuard',
        class_exists('UrlGuard') ? '' : 'kelas tidak ditemui');
} else {
    res('FAIL', 'src/UrlGuard.php', 'TIADA — scanner.php akan fatal di require');
}

// ---- 6. Muatkan scanner.php (ujian require sebenar) --------------
echo $nl . "6. Muat scanner.php (ujian require sebenar)" . $nl;
if ($fail === 0) {
    try {
        require_once $root . '/scanner.php';
        res(class_exists('SecurityScanner') ? 'PASS' : 'FAIL', 'scanner.php → class SecurityScanner',
            class_exists('SecurityScanner') ? '' : 'kelas tidak ditemui');
    } catch (Throwable $e) {
        res('FAIL', 'scanner.php dimuatkan', $e->getMessage());
    }
} else {
    res('WARN', 'scanner.php', 'dilangkau — betulkan FAIL di atas dahulu');
}

// ---- Ringkasan ----------------------------------------------------
echo $nl . "============================================================" . $nl;
echo "  Keputusan: {$pass} PASS, {$warn} WARN, {$fail} FAIL" . $nl;
echo ($fail === 0
    ? "  Sedia untuk scan."
    : "  Betulkan item FAIL dahulu — itu punca ralat dalaman.") . $nl;
echo "============================================================" . $nl;

if ($cli) { exit($fail === 0 ? 0 : 1); }
