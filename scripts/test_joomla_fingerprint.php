<?php
/**
 * scripts/test_joomla_fingerprint.php — Ujian offline untuk pengesanan Joomla berlapis.
 *
 * Menguji JoomlaFingerprint (src/JoomlaFingerprint.php) tanpa rangkaian:
 *   - passiveSignals()  — isyarat HTML/header + skor keyakinan
 *   - validateProbe()   — pengesahan respons endpoint aktif + kebocoran versi
 *
 * Jalankan:  php scripts/test_joomla_fingerprint.php
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') { http_response_code(403); exit('CLI-only.'); }

require_once dirname(__DIR__) . '/src/JoomlaFingerprint.php';

$pass = 0; $fail = 0;
function check(string $label, bool $cond): void {
    global $pass, $fail;
    if ($cond) { $pass++; echo "  \033[32m[PASS]\033[0m {$label}\n"; }
    else       { $fail++; echo "  \033[31m[FAIL]\033[0m {$label}\n"; }
}

echo "============================================================\n";
echo "  Joomla fingerprint tests (offline)\n";
echo "============================================================\n\n";

// ------------------------------------------------------------------
// 1. HTML dunia sebenar (pusatsukan.uitm.edu.my) — patut skor tinggi.
// ------------------------------------------------------------------
$realHtml = <<<'HTML'
<link href="/images/RecognitionLogo2021.png" rel="icon" type="image/vnd.microsoft.icon">
<link href="https://pusatsukan.uitm.edu.my/index.php/component/search/?id=30&Itemid=101&format=opensearch" rel="search" title="Search My Joomla" type="application/opensearchdescription+xml">
<link href="/media/vendor/awesomplete/css/awesomplete.css?1.1.5" rel="stylesheet" />
<link href="/components/com_sppagebuilder/assets/css/sppagebuilder.css?143fb2b8" rel="stylesheet" />
<link href="/media/com_sppagebuilder/assets/iconfont/icofont/icofont.min.css" rel="stylesheet" />
<link href="/cache/com_templates/templates/shaper_educon/c437a894eb8c92f0.css" rel="stylesheet" />
HTML;

echo "1) Real hardened-ish Joomla homepage (pusatsukan.uitm.edu.my):\n";
$r = JoomlaFingerprint::passiveSignals($realHtml, '', '');
echo "   score={$r['score']} confidence=" . JoomlaFingerprint::confidence($r['score'])
    . " signals=" . count($r['signals']) . "\n";
check('detected (score >= THRESHOLD_DETECTED)', $r['score'] >= JoomlaFingerprint::THRESHOLD_DETECTED);
check('high confidence', JoomlaFingerprint::confidence($r['score']) === 'high');
check('picked up SEF component route', in_array('Joomla SEF component route', array_column($r['signals'], 'label'), true));
check('picked up template cache path', in_array('Joomla template cache path', array_column($r['signals'], 'label'), true));

// ------------------------------------------------------------------
// 2. Separa hardening — generator DAN /components/com_ dibuang, tinggal 1-2 aset.
//    Masih patut dikesan (survivability).
// ------------------------------------------------------------------
echo "\n2) Partially hardened (generator + com_ paths stripped):\n";
$hardened = '<link href="/media/system/js/core.js" rel="stylesheet"><div class="moduletable">x</div>';
$r2 = JoomlaFingerprint::passiveSignals($hardened, '', '');
echo "   score={$r2['score']} confidence=" . JoomlaFingerprint::confidence($r2['score']) . "\n";
check('still detected after partial hardening', $r2['score'] >= JoomlaFingerprint::THRESHOLD_DETECTED);

// ------------------------------------------------------------------
// 2b. Joomla 4/5 moden — banyak site tidak guna /components/com_ di head,
//     tetapi body class dan /media/templates/site/ masih jelas.
// ------------------------------------------------------------------
echo "\n2b) Modern Joomla 4/5 source markers:\n";
$modern = <<<'HTML'
<body class="site com-content view-article no-layout no-task itemid-101">
<link href="/media/templates/site/cassiopeia/css/template.min.css?b7f1a2" rel="stylesheet">
<script type="application/json" class="joomla-script-options new">{"system.paths":{"root":""}}</script>
<joomla-alert type="warning"></joomla-alert>
</body>
HTML;
$r2b = JoomlaFingerprint::passiveSignals($modern, '', '');
echo "   score={$r2b['score']} confidence=" . JoomlaFingerprint::confidence($r2b['score']) . "\n";
check('modern Joomla source detected', $r2b['score'] >= JoomlaFingerprint::THRESHOLD_DETECTED);
check('picked up com-content body class', in_array('Joomla body component class', array_column($r2b['signals'], 'label'), true));

// ------------------------------------------------------------------
// 3. Generator tag membekalkan versi tepat.
// ------------------------------------------------------------------
echo "\n3) Generator tag with version:\n";
$r3 = JoomlaFingerprint::passiveSignals('<html><body>clean</body></html>', '', 'Joomla! - Open Source Content Management');
check('generator tag alone reaches detection threshold', $r3['score'] >= JoomlaFingerprint::THRESHOLD_DETECTED);
$r3b = JoomlaFingerprint::passiveSignals('x', '', 'Joomla! 4.4.5');
check('version 4.4.5 extracted from generator', $r3b['version'] === '4.4.5');

// ------------------------------------------------------------------
// 4. Negatif — WordPress/laman bersih tidak patut dikesan sebagai Joomla.
// ------------------------------------------------------------------
echo "\n4) Negative: WordPress page must NOT score as Joomla:\n";
$wp = '<link href="/wp-content/themes/x/style.css"><script src="/wp-includes/js/jquery.js"></script>';
$r4 = JoomlaFingerprint::passiveSignals($wp, 'api.w.org', '');
echo "   score={$r4['score']}\n";
check('WordPress page below Joomla threshold', $r4['score'] < JoomlaFingerprint::THRESHOLD_DETECTED);

echo "\n4b) Negative: SecScan page mentioning Joomla must NOT reach Joomla threshold:\n";
$secscanHtml = <<<'HTML'
<!doctype html><html><body>
<h1>Imbasan keselamatan web organisasi</h1>
<p>Kenal pasti Joomla, WordPress, penanda sumber, aset, tag penjana, dan pilihan semakan.</p>
<form id="scanForm"><input name="url"><button>Mula Scan Sah</button></form>
</body></html>
HTML;
$r4b = JoomlaFingerprint::passiveSignals($secscanHtml, '', '');
echo "   score={$r4b['score']}\n";
check('generic Joomla text stays below threshold', $r4b['score'] < JoomlaFingerprint::THRESHOLD_DETECTED);

// ------------------------------------------------------------------
// 5. validateProbe — endpoint aktif.
// ------------------------------------------------------------------
echo "\n5) Active probe validation:\n";
$manifest = '<?xml version="1.0"?><extension type="file" method="upgrade"><name>files_joomla</name><version>5.1.2</version></extension>';
$p1 = JoomlaFingerprint::validateProbe('/administrator/manifests/files/joomla.xml', 200, $manifest);
check('joomla.xml matched', $p1['matched']);
check('joomla.xml exact version 5.1.2', $p1['version'] === '5.1.2');

$readme = "Joomla! is free software released under the GNU General Public License.\n1- What is this?";
$p2 = JoomlaFingerprint::validateProbe('/README.txt', 200, $readme);
check('README.txt matched', $p2['matched']);

$api = '{"links":{"self":"https://example.test/api/index.php/v1/"},"errors":[{"title":"Login required","code":401}],"jsonapi":{"version":"1.0"}}';
$p3 = JoomlaFingerprint::validateProbe('/api/index.php/v1/', 200, $api);
check('Web Services API matched', $p3['matched']);

// Negatif: soft-404 mengembalikan halaman HTML biasa untuk endpoint XML.
$soft404 = '<!doctype html><html><head><title>Home</title></head><body>Welcome</body></html>';
$p4 = JoomlaFingerprint::validateProbe('/administrator/manifests/files/joomla.xml', 200, $soft404);
check('HTML soft-404 for joomla.xml NOT matched', !$p4['matched']);

$p5 = JoomlaFingerprint::validateProbe('/README.txt', 404, 'Not Found');
check('404 README NOT matched', !$p5['matched']);

$adminFallback = '<!doctype html><html><body><h1>SecScan</h1><p>Kenal pasti Joomla, WordPress dan CMS lain.</p><form id="scanForm"></form></body></html>';
$p6 = JoomlaFingerprint::validateProbe('/administrator/', 200, $adminFallback);
check('/administrator/ fallback HTML mentioning Joomla NOT matched', !$p6['matched']);

$langFallback = '<!doctype html><html><body>Joomla guide page, not XML.</body></html>';
$p7 = JoomlaFingerprint::validateProbe('/language/en-GB/en-GB.xml', 200, $langFallback);
check('HTML fallback for language XML NOT matched', !$p7['matched']);

// ------------------------------------------------------------------
echo "\n============================================================\n";
echo "  Result: {$pass} passed, {$fail} failed\n";
echo "============================================================\n";
exit($fail === 0 ? 0 : 1);
