<?php
/**
 * scripts/test_baseline.php — Sahkan soft-404 / catch-all false-positive suppression.
 *
 * Jalankan pada server yang ada PHP + ext-curl (dari root projek):
 *     php scripts/test_baseline.php
 *     php scripts/test_baseline.php https://laman-lain.com/
 * atau melalui Composer:
 *     composer test:baseline
 *
 * Skrip ni uji logik baru dalam scanner.php (getBaseline / matchesBaseline)
 * dan jalankan satu scan penuh untuk pastikan tiada CRITICAL palsu pada
 * laman yang pulangkan HTTP 200 untuk semua path.
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('This script is CLI-only.');
}

$root = dirname(__DIR__);
require_once $root . '/scanner.php';

$target = $argv[1] ?? 'https://eossad.saufiwahab.com/';

$pass = 0;
$fail = 0;
function check(string $label, bool $cond): bool
{
    global $pass, $fail;
    if ($cond) { $pass++; echo "  \033[32m[PASS]\033[0m {$label}\n"; }
    else       { $fail++; echo "  \033[31m[FAIL]\033[0m {$label}\n"; }
    return $cond;
}
function line(string $s = ''): void { echo $s . "\n"; }

if (!function_exists('curl_init')) {
    line("RALAT: sambungan PHP cURL tidak dipasang. Pasang php-curl dahulu.");
    exit(1);
}

line("============================================================");
line("  Ujian Baseline / Soft-404 Suppression");
line("  Target : {$target}");
line("  Masa   : " . date('Y-m-d H:i:s'));
line("============================================================");
line();

// ------------------------------------------------------------------
// Bahagian 1 — uji helper peribadi melalui Reflection
// ------------------------------------------------------------------
$scanner = new SecurityScanner($target);
$ref     = new ReflectionClass($scanner);

$mGetBaseline = $ref->getMethod('getBaseline');
$mMatches     = $ref->getMethod('matchesBaseline');

$baseline = $mGetBaseline->invoke($scanner);

line("Bahagian 1 — Pengesanan catch-all (probe path rawak)");
line("  Catch-all dikesan : " . ($baseline['catchall'] ? 'YA' : 'tidak'));
line("  Sampel ditangkap  : " . count($baseline['samples']));
line();

if (!$baseline['catchall']) {
    line("  Nota: laman ni pulangkan 404 sebenar untuk path tak wujud — bagus,");
    line("  tiada risiko false positive jenis soft-404. Ujian B dilangkau.");
    line();
} else {
    line("Bahagian 2 — matchesBaseline() bezakan catch-all vs kebocoran sebenar");

    // (a) Body catch-all sebenar MESTI ditindas (suppress).
    $catchAllBody = $baseline['samples'][0] ?? '';
    check("Body shell catch-all dikenali sebagai soft-404 (ditindas)",
          $mMatches->invoke($scanner, $catchAllBody) === true);

    // (b) Kebocoran sebenar yang berbeza TAK boleh ditindas (kekal dilapor).
    $fakeLeak = "<?php\ndefine('DB_NAME','prod_db');\ndefine('DB_USER','root');\n"
              . "define('DB_PASSWORD','S3cr3t!Passw0rd');\ndefine('DB_HOST','localhost');\n";
    check("Kebocoran wp-config.php tulen TIDAK ditindas (masih akan dilapor)",
          $mMatches->invoke($scanner, $fakeLeak) === false);
    line();
}

// ------------------------------------------------------------------
// Bahagian 3 — scan penuh: pastikan tiada CRITICAL palsu Exposed Files
// ------------------------------------------------------------------
line("Bahagian 3 — Scan penuh (mungkin ambil 30–60 saat)...");
$scanner2 = new SecurityScanner($target);
$result   = $scanner2->scan();

$exposed = $result['categories']['Exposed Files'] ?? [];
$bogus   = ['wp-config.php', 'web.config', 'wp-admin', 'administrator',
            'phpmyadmin', 'adminer', 'server-info', 'config.php',
            'install.php', 'setup.php'];

$falsePositives = [];
foreach ($exposed as $f) {
    if (($f['severity'] ?? '') !== 'critical') continue;
    foreach ($bogus as $b) {
        if (stripos($f['message'] ?? '', $b) !== false) {
            $falsePositives[] = $f['message'];
            break;
        }
    }
}

line();
line("  Jumlah finding Exposed Files : " . count($exposed));
line("  CRITICAL palsu (path catch-all) : " . count($falsePositives));
foreach ($falsePositives as $m) line("    - {$m}");
line();

check("Tiada CRITICAL palsu untuk path catch-all biasa", count($falsePositives) === 0);

if ($baseline['catchall']) {
    $hasSoftNote = false;
    foreach ($exposed as $f) {
        if (stripos($f['check'] ?? '', 'Soft-404') !== false
            || stripos($f['message'] ?? '', 'soft-404') !== false) { $hasSoftNote = true; break; }
    }
    check("Finding maklumat 'Soft-404 / Catch-all' hadir", $hasSoftNote);
}

// Papar semua finding Exposed Files untuk semakan mata.
line();
line("  --- Senarai penuh finding Exposed Files ---");
foreach ($exposed as $f) {
    $sev = strtoupper($f['severity'] ?? '?');
    line("    [{$sev}] " . ($f['message'] ?? ''));
}

// ------------------------------------------------------------------
line();
line("============================================================");
line("  Keputusan: {$pass} PASS, {$fail} FAIL");
line("  Skor scan : " . ($result['score'] ?? '?') . "/100  Gred: " . ($result['grade'] ?? '?'));
line("============================================================");

exit($fail === 0 ? 0 : 1);
