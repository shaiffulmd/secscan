<?php
// ================================================================
//  dashboard.php — SecScan Usage Dashboard (Password Protected)
//
//  TUKAR PASSWORD:
//  Set environment variable SECSCAN_DASHBOARD_PASSWORD_HASH.
// ================================================================

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/src/RateLimiter.php';

define('DASHBOARD_PASSWORD_HASH', (string)secscan_config('dashboard_password_hash'));

define('SESSION_NAME',    'secscan_dash');
define('SESSION_TIMEOUT', 3600); // 1 jam
$appVersion = secscan_app_version();

// ----------------------------------------------------------------
//  Bootstrap
// ----------------------------------------------------------------

if (!extension_loaded('pdo_sqlite')) {
    http_response_code(503);
    die('<h2>PDO SQLite extension diperlukan. Aktifkan pdo_sqlite dalam php.ini.</h2>');
}

session_name(SESSION_NAME);
$isHttps = secscan_is_https();
$requestMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'secure'   => $isHttps,
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Expire session selepas SESSION_TIMEOUT saat
if (isset($_SESSION['last_active']) && (time() - $_SESSION['last_active']) > SESSION_TIMEOUT) {
    secscan_forget_owner_bypass_ip((string)($_SESSION['owner_bypass_ip'] ?? secscan_client_ip()));
    session_unset(); session_destroy(); session_start();
}
if (isset($_SESSION['auth'])) {
    $_SESSION['last_active'] = time();
    $_SESSION['owner_bypass_ip'] = secscan_client_ip();
    secscan_remember_owner_bypass_ip((string)$_SESSION['owner_bypass_ip'], SESSION_TIMEOUT);
}

$isLoggedIn = ($_SESSION['auth'] ?? false) === true;
$loginError = '';
$setupError = DASHBOARD_PASSWORD_HASH === ''
    ? 'Dashboard belum dikonfigurasi. Set SECSCAN_DASHBOARD_PASSWORD_HASH sebelum login.'
    : '';
if (!$isLoggedIn && $setupError !== '') {
    $loginError = $setupError;
}

// Logout changes session and rate-bypass state, so require a CSRF-protected POST.
if ($requestMethod === 'POST' && isset($_POST['logout'])
    && is_string($_POST['csrf_token'] ?? null)
    && hash_equals((string)$_SESSION['csrf_token'], $_POST['csrf_token'])) {
    secscan_forget_owner_bypass_ip((string)($_SESSION['owner_bypass_ip'] ?? secscan_client_ip()));
    session_unset(); session_destroy();
    header('Location: dashboard.php'); exit;
}

// Handle login POST
if ($requestMethod === 'POST' && !$isLoggedIn) {
    $loginRate = RateLimiter::consume('dashboard_login_v1', secscan_client_ip(), 10, 900);
    if ($setupError !== '') {
        $loginError = $setupError;
    } elseif (!empty($loginRate['storage_failed'])) {
        http_response_code(503);
        $loginError = 'Perkhidmatan rate limit tidak tersedia. Cuba semula kemudian.';
    } elseif (!$loginRate['allowed']) {
        $loginError = 'Terlalu banyak cubaan login. Cuba semula kemudian.';
        header('Retry-After: ' . $loginRate['retry_after']);
    }

    $pw = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';
    $csrfValid = is_string($_POST['csrf_token'] ?? null)
        && hash_equals((string)$_SESSION['csrf_token'], $_POST['csrf_token']);
    if ($loginError === '' && !$csrfValid) {
        $loginError = 'Request tidak sah. Sila cuba semula.';
    } elseif ($loginError === '' && $pw !== '' && password_verify($pw, DASHBOARD_PASSWORD_HASH)) {
        session_regenerate_id(true);
        $_SESSION['auth']        = true;
        $_SESSION['last_active'] = time();
        $_SESSION['owner_bypass_ip'] = secscan_client_ip();
        secscan_remember_owner_bypass_ip((string)$_SESSION['owner_bypass_ip'], SESSION_TIMEOUT);
        $isLoggedIn = true;
        header('Location: dashboard.php'); exit;
    } elseif ($loginError === '') {
        $loginError = 'Password salah. Cuba semula.';
        usleep(500000); // 0.5s delay untuk kurang brute force
    }
}

// ----------------------------------------------------------------
//  Security headers
// ----------------------------------------------------------------

$nonce = rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');
header_remove('X-Powered-By');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store, private, max-age=0');
header("Content-Security-Policy: default-src 'self'; form-action 'self'; script-src 'nonce-{$nonce}' https://cdn.jsdelivr.net; style-src 'self' 'nonce-{$nonce}' https://cdn.jsdelivr.net; style-src-attr 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; report-to default; report-uri /reporting.php");
secscan_send_operational_security_headers();

if ($isHttps) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

// ----------------------------------------------------------------
//  Load data (only when logged in)
// ----------------------------------------------------------------

$summary     = [];
$grades      = [];
$dailyScans  = [];
$topDomains  = [];
$cdnDomains  = [];
$topIssues   = [];
$peakHours   = [];
$recentScans = [];
$totalCount  = 0;
$scoreDist   = [];
$countryStats = [];
$countryGradeStats = [];
$domainSuffixStats = [];
$latestDomainScans = [];
$latestDomainCount = 0;
$domainListPageSize = 25;
$domainListGradeOptions = ['all', 'A+', 'A', 'B', 'C', 'D', 'F'];
$domainListGrade = (string)($_GET['domain_grade'] ?? 'all');
if (!in_array($domainListGrade, $domainListGradeOptions, true)) $domainListGrade = 'all';
$domainListSort = (string)($_GET['domain_sort'] ?? 'recent');
if (!in_array($domainListSort, ['recent', 'highest', 'lowest'], true)) $domainListSort = 'recent';
$domainListPage = max(1, (int)($_GET['domains_p'] ?? 1));
$geoIpStatus = ['available' => false, 'records' => 0, 'updated_at' => ''];
$geoIpMessage = '';
$geoIpMessageTone = '';
$logger = null;
$pageSize    = 50;
$page        = max(1, (int)($_GET['p'] ?? 1));
$currentClientIp = secscan_client_ip();

if ($isLoggedIn) {
    $loggerPath = __DIR__ . '/logger.php';
    if (is_file($loggerPath)) {
        require_once $loggerPath;
        $logger      = new ScanLogger();
        if ($requestMethod === 'POST' && isset($_POST['geoip_update'])
            && is_string($_POST['csrf_token'] ?? null)
            && hash_equals((string)$_SESSION['csrf_token'], $_POST['csrf_token'])) {
            set_time_limit(300);
            $update = $logger->updateGeoIp();
            $geoIpMessage = (string)$update['message'];
            $geoIpMessageTone = !empty($update['ok']) ? 'good' : 'bad';
        }
        $summary     = $logger->getSummary();
        $grades      = $logger->getGradeDistribution();
        $dailyScans  = $logger->getDailyScans(30);
        $topDomains  = $logger->getTopDomains(10);
        $cdnDomains  = method_exists($logger, 'getCdnDomains') ? $logger->getCdnDomains(10) : [];
        $topIssues   = $logger->getTopIssues(12);
        $peakHours   = $logger->getPeakHours();
        $totalCount  = $logger->getTotalCount();
        $scoreDist   = $logger->getScoreDistribution();
        $recentScans = $logger->getRecentScans($pageSize, ($page - 1) * $pageSize);
        $countryStats = $logger->getCountryStats(24);
        $countryGradeStats = $logger->getCountryGradeStats();
        $domainSuffixStats = $logger->getDomainSuffixStats();
        $latestDomainCount = $logger->getLatestDomainScanCount($domainListGrade);
        $latestDomainScans = $logger->getLatestDomainScans($domainListGrade, $domainListSort, $domainListPageSize, ($domainListPage - 1) * $domainListPageSize);
        $geoIpStatus = $logger->getGeoIpStatus();
    }
}

// ----------------------------------------------------------------
//  Helpers
// ----------------------------------------------------------------

function gradeColor(string $g): string {
    return match($g) {
        'A+', 'A' => '#00ffcc', 'B' => '#38bdf8', 'C' => '#f59e0b',
        'D' => '#fb923c', 'F' => '#f43f5e', default => '#5a8aaa',
    };
}

function gradeTextClass(string $g): string {
    return match($g) {
        'A+', 'A' => 'grade-a', 'B' => 'grade-b', 'C' => 'grade-c',
        'D' => 'grade-d', 'F' => 'grade-f', default => '',
    };
}

function maxVal(array $arr): int {
    return max(1, ...array_values($arr));
}

function pct(int $val, int $total): int {
    return $total > 0 ? (int)round($val / $total * 100) : 0;
}

function scoreToGrade($score): string {
    if (!is_numeric($score)) return '—';
    $s = (int)round((float)$score);
    if ($s >= 95) return 'A+';
    if ($s >= 85) return 'A';
    if ($s >= 70) return 'B';
    if ($s >= 55) return 'C';
    if ($s >= 40) return 'D';
    return 'F';
}

function relTime(string $dt): string {
    $diff = time() - strtotime($dt);
    if ($diff < 60)  return $diff . 's ago';
    if ($diff < 3600) return (int)($diff / 60) . 'm ago';
    if ($diff < 86400) return (int)($diff / 3600) . 'h ago';
    return (int)($diff / 86400) . 'd ago';
}

function wafVendorsFromRow(array $row): array {
    $raw = trim((string)($row['waf_vendors'] ?? ''));
    $vendors = [];
    if ($raw !== '') {
        $decoded = json_decode($raw, true);
        if (is_array($decoded)) {
            $vendors = array_values(array_filter(array_map('strval', $decoded)));
        }
    }
    if ($vendors === [] && (int)($row['is_cloudflare'] ?? 0) === 1) {
        $vendors[] = 'Cloudflare';
    }
    return array_values(array_unique($vendors));
}

function wafLabelFromRow(array $row): string {
    $vendors = wafVendorsFromRow($row);
    if ($vendors !== []) {
        return implode(', ', array_slice($vendors, 0, 2));
    }
    return (int)($row['scan_blocked'] ?? 0) === 1 ? 'Blocked' : 'Direct';
}

function countryLabel(string $code): string {
    $code = strtoupper(trim($code));
    if (class_exists('Locale')) {
        $label = Locale::getDisplayRegion('-' . $code, 'en');
        if (is_string($label) && $label !== '' && $label !== $code) return $label;
    }
    return $code;
}

$totalPages = (int)ceil($totalCount / $pageSize);
$totalScans = (int)($summary['total_scans'] ?? 0);
$avgScore = is_numeric($summary['avg_score'] ?? null) ? (float)$summary['avg_score'] : null;
$avgGrade = scoreToGrade($avgScore);
$criticalTotal = (int)($summary['total_critical'] ?? 0);
$criticalScans = (int)($summary['scans_with_criticals'] ?? 0);
$uniqueIps = (int)($summary['unique_ips'] ?? 0);
$domainTotal = count($topDomains);
$domainSuffixMap = array_fill_keys(['edu_my', 'gov_my', 'com_my', 'my_other', 'com', 'org', 'net', 'other'], 0);
foreach ($domainSuffixStats as $row) {
    $category = (string)($row['category'] ?? '');
    if (array_key_exists($category, $domainSuffixMap)) $domainSuffixMap[$category] = (int)($row['cnt'] ?? 0);
}
$uniqueDomainTotal = array_sum($domainSuffixMap);
$domainListPages = (int)ceil($latestDomainCount / $domainListPageSize);
$blockedProbes = (int)($summary['scan_blocked_total'] ?? 0);
if ($blockedProbes === 0) {
    $blockedProbes = array_reduce($recentScans, static fn($sum, $scan) => $sum + ((int)($scan['scan_blocked'] ?? 0) === 1 ? 1 : 0), 0);
}
if ($cdnDomains === []) {
    $cdnMap = [];
    foreach ($recentScans as $scan) {
        if ((int)($scan['is_cloudflare'] ?? 0) !== 1 && (int)($scan['scan_blocked'] ?? 0) !== 1 && wafVendorsFromRow($scan) === []) continue;
        $host = (string)($scan['hostname'] ?? '');
        if ($host === '') continue;
        if (!isset($cdnMap[$host])) {
            $cdnMap[$host] = [
                'hostname' => $host,
                'scan_count' => 0,
                'last_scan' => (string)($scan['scanned_at'] ?? ''),
                'avg_score' => 0,
                'waf_vendors' => (string)($scan['waf_vendors'] ?? ''),
                '_score_sum' => 0,
            ];
        }
        $cdnMap[$host]['scan_count']++;
        $cdnMap[$host]['_score_sum'] += (float)($scan['score'] ?? 0);
        if (strcmp((string)($scan['scanned_at'] ?? ''), (string)$cdnMap[$host]['last_scan']) > 0) {
            $cdnMap[$host]['last_scan'] = (string)$scan['scanned_at'];
            $cdnMap[$host]['waf_vendors'] = (string)($scan['waf_vendors'] ?? '');
        }
    }
    foreach ($cdnMap as &$row) {
        $row['avg_score'] = $row['scan_count'] > 0 ? round($row['_score_sum'] / $row['scan_count'], 1) : 0;
        unset($row['_score_sum']);
    }
    unset($row);
    $cdnDomains = array_values($cdnMap);
    usort($cdnDomains, static fn($a, $b): int => strcmp((string)($b['last_scan'] ?? ''), (string)($a['last_scan'] ?? '')));
    $cdnDomains = array_slice($cdnDomains, 0, 10);
}
$cdnDomainTotal = count($cdnDomains);
$latestScan = $recentScans[0] ?? null;
$gradeTone = match($avgGrade) {
    'A+', 'A', 'B' => 'good',
    'C', 'D' => 'warn',
    'F' => 'bad',
    default => 'info',
};
$criticalTone = $criticalTotal > 0 ? 'bad' : 'good';
$blockedTone = $blockedProbes > 0 ? 'warn' : 'good';
$heatValues = [
    ['CSP', min(99, max(12, 100 - (int)round($avgScore ?? 62) + $criticalScans * 3)), 'risk-high'],
    ['Headers', min(99, max(18, 62 + $criticalScans * 2)), 'risk-med'],
    ['TLS', max(10, min(92, (int)round($avgScore ?? 58) - 28)), 'risk-low'],
    ['CMS', min(99, max(24, 52 + $blockedProbes * 2)), 'risk-med'],
    ['Admin', min(99, max(28, 64 + $criticalScans * 4)), 'risk-high'],
    ['PCI', max(12, min(88, (int)round(($avgScore ?? 58) * .45))), 'risk-low'],
    ['WAF', min(99, max(22, 38 + $blockedProbes * 6)), 'risk-med'],
];
$readiness = [
    ['Audit Trail', $totalScans > 0 ? 92 : 28],
    ['PCI Evidence', max(20, min(92, (int)round(($avgScore ?? 56) * .86)))],
    ['Header Policy', max(18, min(90, (int)round(($avgScore ?? 56) * .74)))],
    ['CMS Hygiene', max(18, min(94, (int)round(($avgScore ?? 56) * .82)))],
];
?>
<!DOCTYPE html>
<html lang="ms">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>SecScan Dashboard</title>
<link rel="icon" type="image/svg+xml" href="favicon.svg"/>
<link rel="shortcut icon" href="favicon.svg"/>
<?php if (!empty($countryStats)): ?>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/jsvectormap@1.7.0/dist/jsvectormap.min.css" referrerpolicy="no-referrer"/>
<?php endif; ?>
<style nonce="<?= htmlspecialchars($nonce, ENT_QUOTES) ?>">
:root {
  --base: #f4f7fb; --surface: #ffffff; --elevated: #eef4fa; --high: #e4edf6;
  --border: #d7e2ec; --border2: #b9c8d8; --border3: #94a7bb;
  --t1: #111827; --t2: #5d6b7c; --t3: #8492a5;
  --mint: #0f766e; --mint2: rgba(15,118,110,.10);
  --sky: #2563eb; --rose: #b91c1c; --amber: #b45309; --green: #15803d;
  --shadow: 0 20px 56px rgba(15,23,42,.10);
  --f-title: Inter, system-ui, -apple-system, sans-serif;
  --f-mono: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
  --r-sm: 8px; --r-md: 8px; --r-lg: 8px;
  --ease: cubic-bezier(.4,0,.2,1);
  color-scheme: light;
}
[data-theme="dark"] {
  --base: #080d14; --surface: #111923; --elevated: #15202b; --high: #1b2734;
  --border: #263444; --border2: #39495a; --border3: #526276;
  --t1: #edf4fb; --t2: #9caabd; --t3: #718198;
  --mint: #2dd4bf; --mint2: rgba(45,212,191,.12);
  --sky: #7dd3fc; --rose: #fb7185; --amber: #fbbf24; --green: #86efac;
  --shadow: 0 20px 56px rgba(0,0,0,.34);
  color-scheme: dark;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --base: #080d14; --surface: #111923; --elevated: #15202b; --high: #1b2734;
    --border: #263444; --border2: #39495a; --border3: #526276;
    --t1: #edf4fb; --t2: #9caabd; --t3: #718198;
    --mint: #2dd4bf; --mint2: rgba(45,212,191,.12);
    --sky: #7dd3fc; --rose: #fb7185; --amber: #fbbf24; --green: #86efac;
    --shadow: 0 20px 56px rgba(0,0,0,.34);
    color-scheme: dark;
  }
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { font-size: 16px; }
body { font-family: var(--f-title); background:
       linear-gradient(90deg, color-mix(in srgb, var(--mint2) 70%, transparent) 1px, transparent 1px),
       linear-gradient(var(--border) 1px, transparent 1px),
       linear-gradient(180deg, var(--elevated), var(--base) 360px);
       background-size: 42px 42px, 42px 42px, auto;
       color: var(--t1); min-height: 100vh; overflow-x: hidden; }
a { color: var(--mint); text-decoration: none; }
button, input { font-family: inherit; }
.sr-only { position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; border:0; }

/* ── Header ── */
.topbar { position: sticky; top: 0; z-index: 100;
          background: color-mix(in srgb, var(--base) 88%, transparent); backdrop-filter: blur(14px);
          border-bottom: 1px solid var(--border); }
.topbar-inner { max-width: 1280px; margin: 0 auto; padding: 0 24px;
                height: 56px; display: flex; align-items: center; gap: 14px; }
.dash-brand { display:flex; align-items:center; gap:12px; min-width:0; }
.dash-logo { width:42px; height:42px; border:1px solid var(--border2); border-radius:var(--r-sm); overflow:hidden; background:var(--surface); box-shadow:0 1px 2px rgba(15,23,42,.08); flex:0 0 auto; }
.dash-logo img { width:100%; height:100%; display:block; }
.logo-text { font-family: var(--f-title); font-weight: 800; font-size: 1rem; letter-spacing: 0; }
.logo-sub  { font-size: .74rem; color: var(--t2); margin-top: 1px; }
.spacer { flex: 1; }
.badge-live { display: flex; align-items: center; gap: 5px; font-family: var(--f-title);
              font-size: .55rem; font-weight: 700; letter-spacing: .16em; color: var(--mint);
              background: var(--mint2); border: 1px solid var(--border2);
              border-radius: 999px; padding: 4px 10px; }
.dot-live { width: 6px; height: 6px; border-radius: 50%; background: var(--mint);
            animation: blink 1.8s infinite; }
@keyframes blink { 0%,100%{opacity:1}50%{opacity:.25} }
.btn-logout, .btn-theme, .btn-home { font-size: .78rem; font-family: var(--f-title); font-weight: 700;
              color: var(--t2); background: var(--surface);
              border: 1px solid var(--border2); border-radius: var(--r-sm);
              min-height: 34px; padding: 0 12px; cursor: pointer; transition: all .2s; }
.btn-logout:hover { color: var(--rose); border-color: rgba(244,63,94,.4); }
.btn-theme:hover, .btn-home:hover { color: var(--t1); border-color: var(--border3); }

/* ── Login ── */
.login-wrap { min-height: 100vh; display: grid; place-items: center; padding: 24px; }
.login-card { background: var(--surface); border: 1px solid var(--border2);
              border-radius: var(--r-lg); padding: 44px 40px; width: 100%; max-width: 380px;
              box-shadow: 0 32px 64px rgba(0,0,0,.5); }
.login-icon { width: 52px; height: 52px; background: var(--mint2); border: 1px solid var(--border2);
              border-radius: var(--r-md); display: grid; place-items: center; margin: 0 auto 20px; overflow:hidden; }
.login-icon img { width:100%; height:100%; display:block; }
.login-title { font-family: var(--f-title); font-weight: 800; font-size: 1.2rem;
               text-align: center; margin-bottom: 6px; }
.login-sub   { font-size: .7rem; color: var(--t2); text-align: center; margin-bottom: 28px; letter-spacing: .05em; }
.field { margin-bottom: 16px; }
.field label { display: block; font-size: .65rem; color: var(--t2); letter-spacing: .12em;
               font-family: var(--f-title); font-weight: 600; margin-bottom: 6px; }
.field input { width: 100%; background: var(--elevated); border: 1px solid var(--border2);
               border-radius: var(--r-sm); padding: 11px 14px; color: var(--t1);
               font-size: .85rem; outline: none; transition: border-color .2s; }
.field input:focus { border-color: var(--border3); }
.btn-login { width: 100%; padding: 13px; font-family: var(--f-title); font-weight: 700;
             font-size: .8rem; letter-spacing: .12em; color: #020508;
             background: linear-gradient(135deg, var(--mint), #00d4aa);
             border-radius: var(--r-sm); cursor: pointer; border: none; margin-top: 8px;
             transition: opacity .2s; }
.btn-login:hover { opacity: .88; }
.login-error { font-size: .72rem; color: #fda4af; background: rgba(244,63,94,.08);
               border: 1px solid rgba(244,63,94,.2); border-radius: var(--r-sm);
               padding: 10px 14px; margin-bottom: 16px; text-align: center; }
.login-notice { border: 1px solid rgba(244,63,94,.25); background: rgba(244,63,94,.07);
                border-radius: var(--r-sm); padding: 12px 14px; margin: 0 0 18px;
                color: var(--t2); font-size: .78rem; line-height: 1.5; text-align: center; }
.login-notice strong { display: block; color: #fda4af; font-family: var(--f-title);
                       font-size: .78rem; letter-spacing: .08em; margin-bottom: 4px; text-transform: uppercase; }
.login-ip { display: flex; align-items: center; justify-content: space-between; gap: 12px;
            margin: 0 0 16px; padding: 10px 12px; border: 1px solid var(--border2);
            border-radius: var(--r-sm); background: var(--elevated); color: var(--t2);
            font-size: .72rem; }
.login-ip span { font-family: var(--f-title); font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
.login-ip code { color: var(--t1); font-family: var(--f-mono); font-size: .78rem; overflow-wrap: anywhere; }
.login-back { display: inline-flex; align-items: center; justify-content: center; width: 100%;
              min-height: 36px; margin-top: 14px; border: 1px solid var(--border2);
              border-radius: var(--r-sm); color: var(--t2); text-decoration: none;
              font-family: var(--f-title); font-size: .75rem; font-weight: 700; }
.login-back:hover { color: var(--t1); border-color: var(--border3); background: var(--elevated); }

/* ── Main layout ── */
.main { max-width: 1280px; margin: 0 auto; padding: 32px 24px 80px; }
.section-title { font-family: var(--f-title); font-weight: 700; font-size: .65rem;
                 letter-spacing: .18em; color: var(--t3); text-transform: uppercase;
                 margin-bottom: 14px; }

/* ── Summary cards ── */
.cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
         gap: 14px; margin-bottom: 32px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--r-md);
        padding: 20px; transition: border-color .2s, background .2s; box-shadow: 0 1px 2px rgba(15,23,42,.06); }
.card:hover { background: var(--elevated); border-color: var(--border2); }
.card-val { font-family: var(--f-title); font-weight: 800; font-size: 1.9rem;
            line-height: 1; margin-bottom: 6px; }
.card-label { font-size: .58rem; color: var(--t3); letter-spacing: .12em;
              font-family: var(--f-title); font-weight: 600; }
.c-mint { color: var(--mint); }
.c-sky  { color: var(--sky); }
.c-amber{ color: var(--amber); }
.c-rose { color: var(--rose); }
.c-green{ color: var(--green); }

/* ── 2-column charts row ── */
.charts-row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 32px; }
@media (max-width: 800px) { .charts-row { grid-template-columns: 1fr; } }
.chart-card { background: var(--surface); border: 1px solid var(--border);
              border-radius: var(--r-md); padding: 22px; box-shadow:0 1px 2px rgba(15,23,42,.06); }
.chart-title { font-family: var(--f-title); font-weight: 700; font-size: .72rem;
               margin-bottom: 18px; color: var(--t1); }

/* CSS bar charts */
.bar-list { display: flex; flex-direction: column; gap: 8px; }
.bar-row { display: flex; align-items: center; gap: 10px; }
.bar-label { font-size: .62rem; color: var(--t2); width: 70px; flex-shrink: 0;
             text-align: right; letter-spacing: .04em; }
.bar-label-left { text-align: left; width: 90px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bar-track { flex: 1; height: 6px; background: var(--elevated); border-radius: 999px; overflow: hidden; }
.bar-fill  { height: 100%; border-radius: 999px; transition: width .6s var(--ease); }
.bar-count { font-size: .6rem; color: var(--t3); width: 36px; flex-shrink: 0; text-align: right; }

/* Daily chart */
.daily-bars { display: flex; align-items: flex-end; gap: 3px; height: 80px; overflow: hidden; }
.daily-bar  { flex: 1; border-radius: 3px 3px 0 0; min-height: 2px;
              transition: height .5s var(--ease); cursor: default; position: relative; }
.daily-bar:hover::after { content: attr(data-tip);
  position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%);
  background: var(--elevated); border: 1px solid var(--border2); border-radius: var(--r-sm);
  font-size: .55rem; color: var(--t1); padding: 4px 8px; white-space: nowrap; z-index: 10; }
.daily-labels { display: flex; justify-content: space-between; margin-top: 6px; }
.daily-labels span { font-size: .5rem; color: var(--t3); }

/* Peak hours */
.hours-grid { display: grid; grid-template-columns: repeat(24, 1fr); gap: 3px; }
.hour-cell  { aspect-ratio: 1; border-radius: 3px; cursor: default; position: relative; }
.hour-cell:hover::after { content: attr(data-tip);
  position: absolute; bottom: 120%; left: 50%; transform: translateX(-50%);
  background: var(--elevated); border: 1px solid var(--border2); border-radius: var(--r-sm);
  font-size: .55rem; color: var(--t1); padding: 3px 7px; white-space: nowrap; z-index: 10; }
.hours-labels { display: flex; justify-content: space-between; margin-top: 5px; }
.hours-labels span { font-size: .45rem; color: var(--t3); }

/* Grade colors */
.grade-a { color: var(--mint); } .grade-b { color: var(--sky); }
.grade-c { color: var(--amber); } .grade-d { color: #fb923c; } .grade-f { color: var(--rose); }

/* ── Tables ── */
.table-card { background: var(--surface); border: 1px solid var(--border);
              border-radius: var(--r-md); overflow: hidden; margin-bottom: 32px; box-shadow:0 1px 2px rgba(15,23,42,.06); }
.table-head { padding: 16px 20px; border-bottom: 1px solid var(--border);
              display: flex; align-items: center; justify-content: space-between; }
table { width: 100%; border-collapse: collapse; }
th { font-family: var(--f-title); font-size: .58rem; font-weight: 700; letter-spacing: .1em;
     color: var(--t3); text-transform: uppercase; padding: 10px 16px;
     background: var(--elevated); text-align: left; white-space: nowrap; }
td { padding: 10px 16px; font-size: .72rem; border-bottom: 1px solid var(--border);
     color: var(--t2); white-space: nowrap; overflow: hidden; max-width: 200px;
     text-overflow: ellipsis; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: color-mix(in srgb, var(--elevated) 76%, transparent); color: var(--t1); }
.td-host { color: var(--t1); font-weight: 600; max-width: 200px; }
.td-ip { color: var(--sky); font-family: var(--f-mono); font-size: .62rem; max-width: 150px; }
.td-grade { font-family: var(--f-title); font-weight: 800; font-size: .8rem; }
.td-crit  { color: var(--rose); }
.td-warn  { color: var(--amber); }
.td-pass  { color: var(--green); }
.empty-state { text-align: center; padding: 48px 20px; color: var(--t3); font-size: .78rem; }

/* ── Pagination ── */
.pagination { display: flex; justify-content: center; gap: 8px; padding: 16px; }
.pg-btn { font-size: .65rem; font-family: var(--f-title); font-weight: 600;
          padding: 6px 14px; border-radius: var(--r-sm); border: 1px solid var(--border2);
          background: var(--elevated); color: var(--t2); cursor: pointer; transition: all .2s; }
.pg-btn:hover { color: var(--t1); border-color: var(--border3); }
.pg-btn.active { background: var(--mint2); border-color: var(--mint); color: var(--mint); }

/* ── Score dist ── */
.score-dist { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
.sd-card { background: var(--elevated); border-radius: var(--r-sm); padding: 14px;
           text-align: center; }
.sd-val   { font-family: var(--f-title); font-weight: 800; font-size: 1.4rem; }
.sd-label { font-size: .55rem; color: var(--t3); letter-spacing: .08em; margin-top: 4px; }

.no-data  { color: var(--t3); font-size: .72rem; padding: 24px; text-align: center; }

/* ── GeoIP country map ── */
.geoip-layout { display: grid; grid-template-columns: minmax(0, 1.5fr) minmax(220px, .8fr); gap: 14px; }
.geoip-controls { display: flex; align-items: center; justify-content: flex-end; flex-wrap: wrap; gap: 7px; }
.geoip-select { min-height: 32px; padding: 0 28px 0 9px; border: 1px solid var(--border2); border-radius: var(--r-sm); background: var(--surface); color: var(--t1); font: inherit; font-size: .7rem; }
.geoip-map { min-height: 270px; border: 1px solid var(--border); border-radius: var(--r-sm); background: color-mix(in srgb, var(--elevated) 72%, var(--base)); overflow: hidden; }
.geoip-map .jvm-container { background: transparent !important; }
.geoip-map .jvm-zoom-btn { display: none; }
.geoip-map .jvm-tooltip { background: var(--t1); color: var(--surface); border-radius: 6px; font-family: var(--f-title); font-size: .72rem; padding: 6px 8px; }
.geoip-countries { display: grid; align-content: start; gap: 8px; max-height: 270px; overflow: auto; padding-right: 2px; }
.geoip-country { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 8px 9px; border: 1px solid var(--border); border-radius: var(--r-sm); background: var(--elevated); }
.geoip-country strong { font-size: .78rem; }
.geoip-country span { color: var(--t2); font-size: .68rem; }
.geoip-meta { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; margin-top: 12px; color: var(--t2); font-size: .7rem; }
.geoip-message { margin-top: 10px; padding: 9px 10px; border-radius: var(--r-sm); font-size: .72rem; }
.geoip-message.good { background: var(--mint2); color: var(--mint); border: 1px solid color-mix(in srgb, var(--mint) 34%, var(--border)); }
.geoip-message.bad { background: color-mix(in srgb, var(--rose) 10%, var(--surface)); color: var(--rose); border: 1px solid color-mix(in srgb, var(--rose) 35%, var(--border)); }
.geoip-update { white-space: nowrap; }

/* ── Domain suffix statistics ── */
.domain-stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 9px; }
.domain-stat { padding: 11px; border: 1px solid var(--border); border-radius: var(--r-sm); background: var(--elevated); }
.domain-stat span { display:block; color: var(--t2); font-family: var(--f-mono); font-size: .68rem; }
.domain-stat strong { display:block; margin-top: 4px; font-size: 1.2rem; }

/* Enterprise dashboard redesign */
.enterprise-shell {
  min-height: 100vh;
  display: grid;
  grid-template-columns: 264px minmax(0, 1fr);
  transition: grid-template-columns .22s var(--ease);
}
.enterprise-shell.sidebar-collapsed {
  grid-template-columns: 78px minmax(0, 1fr);
}
.side-rail {
  position: sticky;
  top: 0;
  height: 100vh;
  padding: 18px 14px;
  border-right: 1px solid var(--border);
  background: color-mix(in srgb, var(--surface) 92%, transparent);
  backdrop-filter: blur(18px);
  transition: padding .22s var(--ease);
}
.side-brand {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 4px 8px 18px;
  border-bottom: 1px solid var(--border);
}
.side-copy {
  min-width: 0;
  flex: 1;
}
.side-logo {
  width: 42px;
  height: 42px;
  flex: 0 0 auto;
  overflow: hidden;
  border: 1px solid color-mix(in srgb, var(--mint) 28%, var(--border));
  border-radius: var(--r-sm);
  background: var(--elevated);
  box-shadow: 0 1px 2px rgba(15,23,42,.06);
}
.side-logo img { width: 100%; height: 100%; display: block; }
.side-title { font-weight: 820; line-height: 1.1; letter-spacing: 0; }
.side-sub { margin-top: 2px; color: var(--t2); font-size: .76rem; }
.sidebar-toggle {
  width: 34px;
  height: 34px;
  flex: 0 0 auto;
  display: grid;
  place-items: center;
  border: 1px solid var(--border);
  border-radius: var(--r-sm);
  background: var(--surface);
  color: var(--t2);
  box-shadow: 0 1px 2px rgba(15,23,42,.06);
  cursor: pointer;
  transition: color .18s var(--ease), border-color .18s var(--ease), background .18s var(--ease), transform .22s var(--ease);
}
.sidebar-toggle:hover {
  color: var(--t1);
  border-color: var(--border2);
  background: var(--elevated);
}
.sidebar-toggle svg { transition: transform .22s var(--ease); }
.side-nav { margin-top: 18px; display: grid; gap: 5px; }
.side-btn {
  min-height: 40px;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 0 10px;
  border: 0;
  border-radius: var(--r-sm);
  color: var(--t2);
  background: transparent;
  text-align: left;
  font-weight: 650;
  cursor: pointer;
}
.side-label {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.side-btn.active,
.side-btn:hover { background: var(--mint2); color: var(--mint); }
.side-glyph {
  width: 22px;
  height: 22px;
  display: grid;
  place-items: center;
  border-radius: 6px;
  background: var(--high);
  font-family: var(--f-mono);
  font-size: .72rem;
  color: var(--t3);
}
.side-card {
  margin-top: 22px;
  padding: 13px;
  border: 1px solid var(--border);
  border-radius: var(--r-sm);
  background: color-mix(in srgb, var(--surface) 72%, var(--elevated));
}
.side-card h3 {
  margin: 0 0 8px;
  font-size: .76rem;
  color: var(--t3);
  letter-spacing: .08em;
  text-transform: uppercase;
}
.side-card p { margin: 0; color: var(--t2); font-size: .82rem; line-height: 1.48; }
.sidebar-collapsed .side-rail {
  padding: 18px 10px;
}
.sidebar-collapsed .side-brand {
  justify-content: center;
  padding: 4px 0 16px;
}
.sidebar-collapsed .side-copy,
.sidebar-collapsed .side-label,
.sidebar-collapsed .side-card {
  display: none;
}
.sidebar-collapsed .sidebar-toggle {
  position: absolute;
  top: 72px;
  left: 50%;
  transform: translateX(-50%);
}
.sidebar-collapsed .sidebar-toggle svg {
  transform: rotate(180deg);
}
.sidebar-collapsed .side-nav {
  margin-top: 58px;
}
.sidebar-collapsed .side-btn {
  justify-content: center;
  padding: 0;
}
.sidebar-collapsed .side-glyph {
  width: 32px;
  height: 32px;
}
.enterprise-main {
  min-width: 0;
  max-width: none;
  margin: 0;
  padding: 18px 24px 36px;
}
.enterprise-topbar {
  min-height: 60px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  margin-bottom: 18px;
  border-bottom: 1px solid var(--border);
}
.crumb { display: flex; align-items: center; gap: 9px; color: var(--t2); font-size: .84rem; }
.crumb strong { color: var(--t1); }
.top-actions {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 10px;
  flex-wrap: wrap;
}
.app-version {
  color: var(--t2);
  font-family: var(--f-mono);
  font-size: .72rem;
  font-weight: 700;
  letter-spacing: .04em;
  padding: 0 2px;
  white-space: nowrap;
}
.theme-control {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 3px;
  padding: 3px;
  border: 1px solid var(--border);
  border-radius: var(--r-sm);
  background: var(--surface);
  box-shadow: 0 1px 2px rgba(15,23,42,.06);
}
.theme-choice {
  min-height: 32px;
  min-width: 62px;
  padding: 0 10px;
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: var(--t2);
  font-size: .8rem;
  font-weight: 720;
  cursor: pointer;
}
.theme-choice.active { background: var(--t1); color: var(--surface); }
.nav-link,
.secondary-action {
  min-height: 36px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 0 12px;
  border: 1px solid var(--border);
  border-radius: var(--r-sm);
  background: var(--surface);
  color: var(--t2);
  font-weight: 700;
  font-size: .84rem;
  box-shadow: 0 1px 2px rgba(15,23,42,.06);
  white-space: nowrap;
}
.nav-link:hover,
.secondary-action:hover { color: var(--t1); border-color: var(--border2); }
.primary-action {
  min-height: 38px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 0 16px;
  border: 0;
  border-radius: var(--r-sm);
  background: linear-gradient(135deg, var(--mint), var(--sky));
  color: #fff;
  font-weight: 800;
  box-shadow: 0 1px 2px rgba(15,23,42,.06);
  white-space: nowrap;
}
.dashboard-header {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 18px;
  align-items: end;
  margin: 10px 0 16px;
}
.dashboard-header h1 {
  max-width: 820px;
  margin: 0;
  font-size: clamp(2rem, 3.35vw, 3.25rem);
  line-height: 1.02;
  letter-spacing: 0;
}
.dashboard-header p {
  margin: 14px 0 0;
  color: var(--t2);
  max-width: 720px;
  font-size: .98rem;
  line-height: 1.55;
}
.dashboard-actions { display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
.metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}
.metric {
  min-height: 128px;
  padding: 16px;
  border: 1px solid var(--border);
  border-radius: var(--r-sm);
  background: var(--surface);
  box-shadow: 0 1px 2px rgba(15,23,42,.06);
  display: grid;
  align-content: space-between;
}
.metric-label {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  color: var(--t2);
  font-size: .82rem;
  font-weight: 720;
}
.metric-number {
  margin-top: 16px;
  font-size: 2.2rem;
  line-height: 1;
  font-weight: 860;
}
.metric-caption { margin-top: 7px; color: var(--t3); font-size: .78rem; line-height: 1.35; }
@media (min-width: 1220px) {
  .sidebar-collapsed .metrics {
    grid-template-columns: repeat(5, minmax(0, 1fr));
    gap: 10px;
  }
  .sidebar-collapsed .metric {
    min-height: 118px;
    padding: 14px;
  }
  .sidebar-collapsed .metric-label {
    gap: 8px;
    font-size: .76rem;
  }
  .sidebar-collapsed .metric-number {
    margin-top: 14px;
    font-size: clamp(1.8rem, 2.15vw, 2.15rem);
  }
  .sidebar-collapsed .metric-caption {
    font-size: .72rem;
  }
}
.pill {
  min-height: 28px;
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 0 9px;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--t2);
  font-size: .74rem;
  font-weight: 760;
  white-space: nowrap;
}
.pill.good { color: var(--green); background: rgba(21,128,61,.10); border-color: rgba(21,128,61,.26); }
.pill.warn { color: var(--amber); background: rgba(180,83,9,.11); border-color: rgba(180,83,9,.28); }
.pill.bad { color: var(--rose); background: rgba(185,28,28,.10); border-color: rgba(185,28,28,.24); }
.pill.info { color: var(--sky); background: rgba(37,99,235,.09); border-color: rgba(37,99,235,.24); }
[data-theme="dark"] .pill.good { background: rgba(134,239,172,.11); border-color: rgba(134,239,172,.26); }
[data-theme="dark"] .pill.warn { background: rgba(251,191,36,.12); border-color: rgba(251,191,36,.28); }
[data-theme="dark"] .pill.bad { background: rgba(251,113,133,.12); border-color: rgba(251,113,133,.28); }
[data-theme="dark"] .pill.info { background: rgba(125,211,252,.10); border-color: rgba(125,211,252,.24); }
.dash-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.25fr) minmax(340px, .75fr);
  gap: 16px;
  align-items: start;
}
.stack { display: grid; gap: 16px; }
.panel {
  border: 1px solid var(--border);
  border-radius: var(--r-sm);
  background: var(--surface);
  box-shadow: 0 1px 2px rgba(15,23,42,.06);
  overflow: hidden;
}
.panel-head {
  padding: 15px 16px;
  border-bottom: 1px solid var(--border);
  background: color-mix(in srgb, var(--surface) 70%, var(--elevated));
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
}
.panel-title { margin: 0; font-size: .98rem; }
.panel-sub { margin: 4px 0 0; color: var(--t2); font-size: .82rem; line-height: 1.45; }
.heatmap {
  display: grid;
  grid-template-columns: repeat(7, 1fr);
  gap: 8px;
  padding: 16px;
}
.heat-cell {
  min-height: 66px;
  border: 1px solid var(--border);
  border-radius: var(--r-sm);
  background: var(--elevated);
  padding: 8px;
  display: grid;
  align-content: space-between;
  color: var(--t2);
  font-size: .72rem;
}
.heat-cell strong { color: var(--t1); font-size: .92rem; }
.risk-high { background: rgba(185,28,28,.10); border-color: rgba(185,28,28,.24); }
.risk-med { background: rgba(180,83,9,.11); border-color: rgba(180,83,9,.28); }
.risk-low { background: rgba(21,128,61,.10); border-color: rgba(21,128,61,.26); }
.timeline { padding: 14px 16px 16px; display: grid; gap: 12px; }
.event {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  gap: 12px;
  align-items: start;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--border);
}
.event:last-child { padding-bottom: 0; border-bottom: 0; }
.event-dot {
  width: 10px;
  height: 10px;
  margin-top: 5px;
  border-radius: 999px;
  background: var(--mint);
  box-shadow: 0 0 0 5px var(--mint2);
}
.event h3 { margin: 0; font-size: .9rem; }
.event p { margin: 4px 0 0; color: var(--t2); font-size: .8rem; line-height: 1.45; }
.event time { color: var(--t3); font-family: var(--f-mono); font-size: .72rem; white-space: nowrap; }
.readiness-list { padding: 16px; display: grid; gap: 13px; }
.readiness-row {
  display: grid;
  grid-template-columns: 118px minmax(0, 1fr) 38px;
  gap: 10px;
  align-items: center;
  color: var(--t2);
  font-size: .82rem;
}
.readiness-track {
  height: 8px;
  overflow: hidden;
  border-radius: 999px;
  background: var(--elevated);
}
.readiness-fill {
  height: 100%;
  border-radius: 999px;
  background: linear-gradient(90deg, var(--mint), var(--sky));
}
.cdn-list { padding: 14px 16px 16px; display: grid; gap: 10px; }
.cdn-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 12px;
  align-items: center;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--border);
}
.cdn-row:last-child { padding-bottom: 0; border-bottom: 0; }
.cdn-domain {
  min-width: 0;
  display: grid;
  gap: 3px;
}
.cdn-domain strong {
  overflow: hidden;
  color: var(--t1);
  font-size: .86rem;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.cdn-domain span {
  color: var(--t3);
  font-size: .74rem;
}
.cdn-provider {
  display: flex;
  align-items: center;
  gap: 8px;
}
.cdn-dot {
  width: 9px;
  height: 9px;
  border-radius: 999px;
  background: var(--amber);
  box-shadow: 0 0 0 5px rgba(180,83,9,.11);
}
.table-wrap { overflow: auto; }
.enterprise-table {
  width: 100%;
  border-collapse: collapse;
  font-size: .84rem;
  min-width: 920px;
}
.enterprise-table th,
.enterprise-table td {
  padding: 12px 14px;
  text-align: left;
  border-bottom: 1px solid var(--border);
  vertical-align: middle;
  white-space: nowrap;
}
.enterprise-table th {
  color: var(--t3);
  font-size: .72rem;
  text-transform: uppercase;
  letter-spacing: .08em;
  background: color-mix(in srgb, var(--surface) 70%, var(--elevated));
}
.enterprise-table tr:last-child td { border-bottom: 0; }
.enterprise-table td { color: var(--t2); }
.enterprise-table td strong { color: var(--t1); }
.enterprise-table tbody tr:hover td {
  background: color-mix(in srgb, var(--elevated) 82%, var(--surface));
  color: var(--t1);
}
.enterprise-table tbody tr:hover .domain small,
.enterprise-table tbody tr:hover .target-url {
  color: var(--t2);
}
.domain { display: grid; gap: 2px; }
.domain small { color: var(--t3); font-family: var(--f-mono); font-size: .72rem; }
.target-url {
  width: fit-content;
  max-width: 320px;
  overflow: hidden;
  color: var(--t3);
  font-family: var(--f-mono);
  font-size: .72rem;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.target-url:hover {
  color: var(--mint);
  text-decoration: underline;
  text-underline-offset: 2px;
}
.row-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}
.rescan-link {
  min-height: 30px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 0 10px;
  border: 1px solid var(--border);
  border-radius: var(--r-sm);
  background: var(--surface);
  color: var(--mint);
  font-size: .74rem;
  font-weight: 800;
  white-space: nowrap;
}
.rescan-link:hover {
  border-color: color-mix(in srgb, var(--mint) 38%, var(--border));
  background: var(--mint2);
}
@media (max-width: 1120px) {
  .dash-grid { grid-template-columns: 1fr; }
  .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 860px) {
  .enterprise-shell { grid-template-columns: 1fr; }
  .enterprise-shell.sidebar-collapsed { grid-template-columns: 1fr; }
  .side-rail { position: static; height: auto; border-right: 0; border-bottom: 1px solid var(--border); }
  .sidebar-toggle { display: none; }
  .sidebar-collapsed .side-copy,
  .sidebar-collapsed .side-label { display: block; }
  .sidebar-collapsed .side-brand { justify-content: flex-start; padding: 4px 8px 18px; }
  .side-nav { grid-template-columns: 1fr 1fr; }
  .side-card { display: none; }
  .sidebar-collapsed .side-nav { margin-top: 18px; }
  .sidebar-collapsed .side-btn { justify-content: flex-start; padding: 0 10px; }
  .sidebar-collapsed .side-glyph { width: 22px; height: 22px; }
  .enterprise-main { padding: 14px 16px 32px; }
  .dashboard-header { grid-template-columns: 1fr; }
  .dashboard-actions { justify-content: flex-start; }
  .heatmap { grid-template-columns: repeat(3, 1fr); }
}
@media (max-width: 560px) {
  .enterprise-topbar { align-items: flex-start; flex-direction: column; padding-bottom: 12px; }
  .top-actions { justify-content: flex-start; }
  .metrics { grid-template-columns: 1fr; }
  .heatmap { grid-template-columns: repeat(2, 1fr); }
  .geoip-layout { grid-template-columns: 1fr; }
  .domain-stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .readiness-row { grid-template-columns: 94px minmax(0, 1fr) 34px; }
  .event { grid-template-columns: auto minmax(0, 1fr); }
  .event time { grid-column: 2; }
}
</style>
</head>
<body>

<?php if (!$isLoggedIn): ?>
<!-- ═══════════════════════════════ LOGIN PAGE ═══════════════════════════════ -->
<div class="login-wrap">
  <div class="login-card">
    <div class="login-icon">
      <img src="secscan-logo.svg" alt="" aria-hidden="true">
    </div>
    <div class="login-title">SecScan Dashboard</div>
    <div class="login-sub">ADMIN ACCESS ONLY</div>
    <div class="login-notice">
      <strong>Unauthorized access</strong>
      Akses dashboard ini hanya untuk pentadbir yang diberi kebenaran.
    </div>
    <div class="login-ip">
      <span>IP anda</span>
      <code><?= htmlspecialchars($currentClientIp, ENT_QUOTES) ?></code>
    </div>
    <?php if ($loginError): ?>
      <div class="login-error"><?= htmlspecialchars($loginError) ?></div>
    <?php endif; ?>
    <form method="POST" autocomplete="off">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars((string)$_SESSION['csrf_token'], ENT_QUOTES) ?>"/>
      <div class="field">
        <label>PASSWORD</label>
        <input type="password" name="password" autofocus required placeholder="••••••••••••"/>
      </div>
      <button class="btn-login" type="submit">MASUK →</button>
    </form>
    <a class="login-back" href="index.php">Kembali ke scanner</a>
  </div>
</div>

<?php else: ?>
<!-- ═══════════════════════════════ DASHBOARD ═══════════════════════════════ -->

<div class="enterprise-shell">
  <aside class="side-rail" aria-label="Dashboard navigation">
    <div class="side-brand">
      <div class="side-logo"><img src="secscan-logo.svg" alt="" aria-hidden="true"></div>
      <div class="side-copy">
        <div class="side-title">SecScan</div>
        <div class="side-sub">Enterprise Console</div>
      </div>
      <button class="sidebar-toggle" type="button" id="sidebarToggle" aria-label="Kecilkan sidebar" aria-expanded="true" title="Kecilkan sidebar">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M15 6 9 12l6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </button>
    </div>

    <nav class="side-nav">
      <a class="side-btn active" href="dashboard.php" title="Overview"><span class="side-glyph">OV</span><span class="side-label">Overview</span></a>
      <a class="side-btn" href="index.php" title="Scanner"><span class="side-glyph">SC</span><span class="side-label">Scanner</span></a>
    </nav>

    <div class="side-card">
      <h3>Audit Mode</h3>
      <p>Dashboard hanya muncul selepas login. Aktiviti scan, target, status WAF, dan IP pengguna direkodkan.</p>
    </div>
  </aside>

  <main class="enterprise-main">
    <header class="enterprise-topbar">
      <div class="crumb">
        <span>SecScan</span>
        <span>/</span>
        <strong>Enterprise Dashboard</strong>
      </div>
      <div class="top-actions">
        <span class="app-version" title="Versi aplikasi">v<?= htmlspecialchars($appVersion, ENT_QUOTES, 'UTF-8') ?></span>
        <a class="nav-link" href="dashboard.php">Dashboard</a>
        <div class="theme-control" role="group" aria-label="Theme">
          <button class="theme-choice" type="button" data-theme-choice="light">Light</button>
          <button class="theme-choice" type="button" data-theme-choice="dark">Dark</button>
        </div>
        <form method="POST" class="nav-link-form">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars((string)$_SESSION['csrf_token'], ENT_QUOTES) ?>"/>
          <button class="nav-link btn-logout" type="submit" name="logout" value="1">Log Keluar</button>
        </form>
      </div>
    </header>

    <section class="dashboard-header">
      <div>
        <h1>Security operations overview for authorized web scans.</h1>
        <p>Monitor scan activity, blocked probes, high-risk findings, CMS exposure, PCI readiness, and scanner IP accountability.</p>
      </div>
      <div class="dashboard-actions">
        <button class="secondary-action" type="button" id="autoRefreshToggleBtn" aria-pressed="false">Auto Refresh: Off</button>
        <button class="secondary-action" type="button" id="refreshDashboardBtn">Muat Semula Data</button>
        <button class="secondary-action" type="button" id="exportCsvBtn">Export CSV</button>
        <button class="secondary-action" type="button" id="auditPrintBtn">Generate Audit PDF</button>
        <a class="primary-action" href="index.php">New Scan</a>
      </div>
    </section>

    <section class="metrics" aria-label="Dashboard metrics">
      <article class="metric">
        <div class="metric-label"><span>Total Scans</span><span class="pill info">30d</span></div>
        <div>
          <div class="metric-number"><?= number_format($totalScans) ?></div>
          <div class="metric-caption">Across <?= number_format($domainTotal) ?> monitored domains</div>
        </div>
      </article>
      <article class="metric">
        <div class="metric-label"><span>Average Security Grade</span><span class="pill <?= $gradeTone ?>"><?= htmlspecialchars($avgGrade) ?></span></div>
        <div>
          <div class="metric-number"><?= htmlspecialchars($avgGrade) ?></div>
          <div class="metric-caption"><?= $avgScore !== null ? htmlspecialchars((string)$avgScore) : 'No' ?> average score across recent scans</div>
        </div>
      </article>
      <article class="metric">
        <div class="metric-label"><span>Critical Findings</span><span class="pill <?= $criticalTone ?>"><?= $criticalTotal > 0 ? 'High' : 'Clear' ?></span></div>
        <div>
          <div class="metric-number"><?= number_format($criticalTotal) ?></div>
          <div class="metric-caption"><?= number_format($criticalScans) ?> require owner follow-up</div>
        </div>
      </article>
      <article class="metric">
        <div class="metric-label"><span>Blocked Probes</span><span class="pill <?= $blockedTone ?>">WAF</span></div>
        <div>
          <div class="metric-number"><?= number_format($blockedProbes) ?></div>
          <div class="metric-caption">Captcha, rate limit, or challenge page</div>
        </div>
      </article>
      <article class="metric">
        <div class="metric-label"><span>Unique Scanner IP</span><span class="pill good">Audit</span></div>
        <div>
          <div class="metric-number"><?= number_format($uniqueIps) ?></div>
          <div class="metric-caption">Linked to scan history</div>
        </div>
      </article>
    </section>

    <div class="dash-grid">
      <section class="stack">
        <article class="panel">
          <div class="panel-head">
            <div>
              <h2 class="panel-title">Exposure Heatmap</h2>
              <p class="panel-sub">Risk density by category and recent scan confidence.</p>
            </div>
            <span class="pill info">Enterprise view</span>
          </div>
          <div class="heatmap">
            <?php foreach ($heatValues as [$label, $value, $riskClass]): ?>
              <div class="heat-cell <?= htmlspecialchars($riskClass) ?>"><span><?= htmlspecialchars($label) ?></span><strong><?= (int)$value ?></strong></div>
            <?php endforeach; ?>
          </div>
        </article>

        <article class="panel">
          <div class="panel-head">
            <div>
              <h2 class="panel-title">Statistik Domain</h2>
              <p class="panel-sub"><?= number_format($uniqueDomainTotal) ?> domain unik. Subdomain <code>www.</code> dikira sebagai domain yang sama.</p>
            </div>
            <span class="pill info">Inventori</span>
          </div>
          <div class="domain-stats">
            <?php foreach ([
              'edu_my' => '.edu.my', 'gov_my' => '.gov.my', 'com_my' => '.com.my', 'my_other' => '.my lain',
              'com' => '.com', 'org' => '.org', 'net' => '.net', 'other' => 'Lain-lain',
            ] as $key => $label): ?>
              <div class="domain-stat"><span><?= htmlspecialchars($label) ?></span><strong><?= number_format((int)$domainSuffixMap[$key]) ?></strong></div>
            <?php endforeach; ?>
          </div>
        </article>

        <article class="panel">
          <div class="panel-head">
            <div>
              <h2 class="panel-title">Peta Negara Scanner</h2>
              <p class="panel-sub">Domain unik sahaja; setiap domain menggunakan lokasi, gred, dan skor daripada scan paling baharu.</p>
            </div>
            <span class="pill <?= !empty($geoIpStatus['available']) ? 'good' : 'warn' ?>"><?= !empty($geoIpStatus['available']) ? 'GeoIP aktif' : 'GeoIP belum dimuat' ?></span>
          </div>

          <?php if ($geoIpMessage !== ''): ?>
            <div class="geoip-message <?= htmlspecialchars($geoIpMessageTone) ?>"><?= htmlspecialchars($geoIpMessage) ?></div>
          <?php endif; ?>

          <?php if (!empty($countryStats)): ?>
            <div class="geoip-controls" aria-label="Penapis peta negara">
              <label class="sr-only" for="geoGradeFilter">Tapis gred</label>
              <select class="geoip-select" id="geoGradeFilter">
                <option value="all">Semua gred</option>
                <option value="A+">Gred A+</option>
                <option value="A">Gred A</option>
                <option value="B">Gred B</option>
                <option value="C">Gred C</option>
                <option value="D">Gred D</option>
                <option value="F">Gred F</option>
              </select>
              <label class="sr-only" for="geoMetricFilter">Ukuran peta</label>
              <select class="geoip-select" id="geoMetricFilter">
                <option value="count">Jumlah scan</option>
                <option value="best">Skor tertinggi</option>
                <option value="worst">Skor terendah</option>
              </select>
            </div>
            <div class="geoip-layout">
              <div id="geoCountryMap" class="geoip-map" aria-label="Peta dunia mengikut negara scanner"></div>
              <div class="geoip-countries" id="geoCountryList" aria-label="Negara scanner utama">
                <?php foreach (array_slice($countryStats, 0, 10) as $country): ?>
                  <div class="geoip-country">
                    <div><strong><?= htmlspecialchars(countryLabel((string)$country['country'])) ?></strong><br><span><?= htmlspecialchars((string)$country['country']) ?> · skor <?= htmlspecialchars((string)$country['avg_score']) ?></span></div>
                    <strong><?= number_format((int)$country['cnt']) ?> domain</strong>
                  </div>
                <?php endforeach; ?>
              </div>
            </div>
            <script type="application/json" id="geoCountryData"><?= json_encode($countryGradeStats, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>
          <?php else: ?>
            <div class="empty-state">Belum ada lokasi negara. Muat turun GeoIP, kemudian scan baharu akan dipetakan; rekod sedia ada turut diproses semula semasa kemas kini.</div>
          <?php endif; ?>

          <div class="geoip-meta">
            <span>
              <?php if (!empty($geoIpStatus['available'])): ?>
                <?= number_format((int)$geoIpStatus['records']) ?> rekod GeoIP · dikemas kini <?= htmlspecialchars((string)$geoIpStatus['updated_at']) ?>
              <?php else: ?>
                Pangkalan GeoIP country-level diperlukan untuk memaparkan peta.
              <?php endif; ?>
              · <a href="https://db-ip.com" target="_blank" rel="noopener noreferrer">IP Geolocation by DB-IP</a>
            </span>
            <form method="POST" id="geoIpUpdateForm">
              <input type="hidden" name="csrf_token" value="<?= htmlspecialchars((string)$_SESSION['csrf_token'], ENT_QUOTES) ?>"/>
              <button class="secondary-action geoip-update" id="geoIpUpdateBtn" type="submit" name="geoip_update" value="1">Kemas kini GeoIP pada server</button>
            </form>
          </div>
          <p class="panel-sub" style="margin-top:8px">Fail GeoIP dimuat turun dan disimpan pada server, bukan ke komputer pelayar. Proses pertama boleh mengambil beberapa minit.</p>
        </article>

        <article class="panel" id="domain-grade-list">
          <div class="panel-head">
            <div>
              <h2 class="panel-title">Senarai Web Mengikut Gred</h2>
              <p class="panel-sub">Hanya satu rekod paling baharu bagi setiap domain dipaparkan.</p>
            </div>
            <form method="GET" class="geoip-controls" id="domainGradeFilterForm" aria-label="Tapis senarai web mengikut gred">
              <?php if ($page > 1): ?><input type="hidden" name="p" value="<?= $page ?>"/><?php endif; ?>
              <label class="sr-only" for="domainGradeFilter">Tapis senarai web mengikut gred</label>
              <select class="geoip-select" id="domainGradeFilter" name="domain_grade">
                <option value="all"<?= $domainListGrade === 'all' ? ' selected' : '' ?>>Semua gred</option>
                <?php foreach (['A+', 'A', 'B', 'C', 'D', 'F'] as $grade): ?>
                  <option value="<?= htmlspecialchars($grade, ENT_QUOTES) ?>"<?= $domainListGrade === $grade ? ' selected' : '' ?>>Gred <?= htmlspecialchars($grade) ?></option>
                <?php endforeach; ?>
              </select>
              <label class="sr-only" for="domainSortFilter">Susun senarai web</label>
              <select class="geoip-select" id="domainSortFilter" name="domain_sort">
                <option value="recent"<?= $domainListSort === 'recent' ? ' selected' : '' ?>>Scan terkini</option>
                <option value="highest"<?= $domainListSort === 'highest' ? ' selected' : '' ?>>Skor tertinggi</option>
                <option value="lowest"<?= $domainListSort === 'lowest' ? ' selected' : '' ?>>Skor terendah</option>
              </select>
            </form>
          </div>
          <?php if (!empty($latestDomainScans)): ?>
            <div class="table-wrap">
              <table class="enterprise-table" aria-label="Senarai domain terkini mengikut gred">
                <thead><tr><th>Domain</th><th>Gred</th><th>Skor</th><th>Negara Scanner</th><th>Scan Terkini</th><th>Aksi</th></tr></thead>
                <tbody>
                  <?php foreach ($latestDomainScans as $domainScan):
                    $host = (string)$domainScan['hostname'];
                    $targetUrl = (string)($domainScan['url'] ?? '');
                    if (!preg_match('#^https?://#i', $targetUrl)) $targetUrl = 'https://' . $host;
                    $rescanUrl = 'index.php?url=' . rawurlencode($targetUrl) . '&rescan=1';
                    $gradeClass = match((string)$domainScan['grade']) {
                      'A+', 'A', 'B' => 'good', 'C', 'D' => 'warn', 'F' => 'bad', default => 'info',
                    };
                  ?>
                  <tr>
                    <td><div class="domain"><strong><?= htmlspecialchars($host) ?></strong><a class="target-url" href="<?= htmlspecialchars($targetUrl) ?>" target="_blank" rel="noopener noreferrer"><?= htmlspecialchars($targetUrl) ?></a></div></td>
                    <td><span class="pill <?= $gradeClass ?>"><?= htmlspecialchars((string)$domainScan['grade']) ?></span></td>
                    <td><strong><?= number_format((int)$domainScan['score']) ?></strong></td>
                    <td><?= htmlspecialchars(!empty($domainScan['client_country']) ? countryLabel((string)$domainScan['client_country']) : '-') ?></td>
                    <td><?= htmlspecialchars(relTime((string)$domainScan['scanned_at'])) ?></td>
                    <td><a class="rescan-link" href="<?= htmlspecialchars($rescanUrl) ?>">Rescan</a></td>
                  </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>
            <?php if ($domainListPages > 1): ?>
              <div class="pagination">
                <?php if ($domainListPage > 1): ?><a href="?domain_grade=<?= rawurlencode($domainListGrade) ?>&amp;domain_sort=<?= rawurlencode($domainListSort) ?>&amp;domains_p=<?= $domainListPage - 1 ?>#domain-grade-list"><div class="pg-btn">Sebelum</div></a><?php endif; ?>
                <?php for ($i = max(1, $domainListPage - 2), $end = min($domainListPages, $domainListPage + 2); $i <= $end; $i++): ?>
                  <a href="?domain_grade=<?= rawurlencode($domainListGrade) ?>&amp;domain_sort=<?= rawurlencode($domainListSort) ?>&amp;domains_p=<?= $i ?>#domain-grade-list"><div class="pg-btn <?= $i === $domainListPage ? 'active' : '' ?>"><?= $i ?></div></a>
                <?php endfor; ?>
                <?php if ($domainListPage < $domainListPages): ?><a href="?domain_grade=<?= rawurlencode($domainListGrade) ?>&amp;domain_sort=<?= rawurlencode($domainListSort) ?>&amp;domains_p=<?= $domainListPage + 1 ?>#domain-grade-list"><div class="pg-btn">Seterusnya</div></a><?php endif; ?>
              </div>
            <?php endif; ?>
          <?php else: ?>
            <div class="empty-state">Tiada domain dengan gred <?= htmlspecialchars($domainListGrade === 'all' ? 'yang dipilih' : $domainListGrade) ?>.</div>
          <?php endif; ?>
        </article>

        <article class="panel">
          <div class="panel-head">
            <div>
              <h2 class="panel-title">Recent Authorized Scans</h2>
              <p class="panel-sub">Every scan keeps target, IP pengguna, grade, CMS, and block status.</p>
            </div>
            <span class="pill info">Page <?= $page ?>/<?= max(1, $totalPages) ?></span>
          </div>
          <?php if (!empty($recentScans)): ?>
          <div class="table-wrap">
            <table class="enterprise-table" id="recentScanTable">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Scanner IP</th>
                  <th>Negara</th>
                  <th>CMS</th>
                  <th>WAF</th>
                  <th>Grade</th>
                  <th>Status</th>
                  <th>Time</th>
                  <th>Aksi</th>
                </tr>
              </thead>
              <tbody>
                <?php foreach ($recentScans as $s):
                  $targetUrl = 'https://' . (string)$s['hostname'];
                  $rescanUrl = 'index.php?url=' . rawurlencode($targetUrl) . '&rescan=1';
                  $statusText = 'Clear';
                  $statusTone = 'good';
                  if ((int)($s['scan_blocked'] ?? 0) === 1) {
                      $statusText = 'Blocked';
                      $statusTone = 'warn';
                  } elseif ((int)$s['critical'] > 0) {
                      $statusText = 'Critical';
                      $statusTone = 'bad';
                  } elseif (wafVendorsFromRow($s) !== []) {
                      $statusText = 'WAF';
                      $statusTone = 'warn';
                  } elseif ((int)$s['warnings'] > 0) {
                      $statusText = 'Review';
                      $statusTone = 'warn';
                  }
                  $gradeClass = match($s['grade']) {
                      'A+', 'A', 'B' => 'good',
                      'C', 'D' => 'warn',
                      'F' => 'bad',
                      default => 'info',
                  };
                  $cmsName = trim((string)($s['detected_cms'] ?? ''));
                  $cmsVersion = trim((string)($s['detected_cms_version'] ?? ''));
                  if ($cmsName !== '' && $cmsVersion !== '') {
                      $cmsText = $cmsName . ' ' . $cmsVersion;
                  } elseif ($cmsName !== '') {
                      $cmsText = $cmsName;
                  } elseif ((int)($s['scan_blocked'] ?? 0) === 1) {
                      $cmsText = 'Disekat';
                  } else {
                      $cmsText = 'Unknown';
                  }
                  $wafText = wafLabelFromRow($s);
                  $wafTone = $wafText === 'Direct' ? 'info' : 'warn';
                ?>
                <tr>
                  <td>
                    <div class="domain">
                      <strong><?= htmlspecialchars($s['hostname']) ?></strong>
                      <a class="target-url" href="<?= htmlspecialchars($targetUrl) ?>" target="_blank" rel="noopener noreferrer"><?= htmlspecialchars($targetUrl) ?></a>
                    </div>
                  </td>
                  <td><strong><?= htmlspecialchars($s['client_ip'] ?: '-') ?></strong></td>
                  <td><?= htmlspecialchars(!empty($s['client_country']) ? countryLabel((string)$s['client_country']) : '-') ?></td>
                  <td><?= htmlspecialchars($cmsText) ?></td>
                  <td><span class="pill <?= $wafTone ?>"><?= htmlspecialchars($wafText) ?></span></td>
                  <td><span class="pill <?= $gradeClass ?>"><?= htmlspecialchars($s['grade']) ?></span></td>
                  <td><span class="pill <?= $statusTone ?>"><?= htmlspecialchars($statusText) ?></span></td>
                  <td><?= htmlspecialchars(relTime($s['scanned_at'])) ?></td>
                  <td>
                    <div class="row-actions">
                      <a class="rescan-link" href="<?= htmlspecialchars($rescanUrl) ?>">Rescan</a>
                    </div>
                  </td>
                </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
          <?php if ($totalPages > 1): ?>
          <div class="pagination">
            <?php if ($page > 1): ?><a href="?p=<?= $page - 1 ?>"><div class="pg-btn">Sebelum</div></a><?php endif; ?>
            <?php
            $start = max(1, $page - 2);
            $end = min($totalPages, $page + 2);
            for ($i = $start; $i <= $end; $i++): ?>
              <a href="?p=<?= $i ?>"><div class="pg-btn <?= $i === $page ? 'active' : '' ?>"><?= $i ?></div></a>
            <?php endfor; ?>
            <?php if ($page < $totalPages): ?><a href="?p=<?= $page + 1 ?>"><div class="pg-btn">Seterusnya</div></a><?php endif; ?>
          </div>
          <?php endif; ?>
          <?php else: ?>
            <div class="empty-state">Belum ada scan direkodkan. Jalankan scan pertama untuk mengisi dashboard.</div>
          <?php endif; ?>
        </article>
      </section>

      <aside class="stack">
        <article class="panel">
          <div class="panel-head">
            <div>
              <h2 class="panel-title">CDN / Edge Coverage</h2>
              <p class="panel-sub">Domain yang dikesan melalui WAF, CDN, atau edge protection.</p>
            </div>
            <span class="pill warn"><?= number_format($cdnDomainTotal) ?> domain</span>
          </div>
          <div class="cdn-list">
            <?php if (!empty($cdnDomains)): ?>
              <?php foreach ($cdnDomains as $cdn):
                $providerLabel = wafLabelFromRow($cdn);
              ?>
              <div class="cdn-row">
                <div class="cdn-domain">
                  <strong><?= htmlspecialchars($cdn['hostname']) ?></strong>
                  <span><?= number_format((int)$cdn['scan_count']) ?> scan · skor purata <?= htmlspecialchars((string)$cdn['avg_score']) ?></span>
                </div>
                <div class="cdn-provider">
                  <span class="cdn-dot" aria-hidden="true"></span>
                  <span class="pill <?= $providerLabel === 'Direct' ? 'info' : 'warn' ?>"><?= htmlspecialchars($providerLabel) ?></span>
                </div>
              </div>
              <?php endforeach; ?>
            <?php else: ?>
              <div class="empty-state">Belum ada domain WAF/CDN direkodkan.</div>
            <?php endif; ?>
          </div>
        </article>

        <article class="panel">
          <div class="panel-head">
            <div>
              <h2 class="panel-title">Action Queue</h2>
              <p class="panel-sub">Prioritized work for security owners.</p>
            </div>
            <span class="pill bad"><?= number_format($criticalScans + $blockedProbes) ?> open</span>
          </div>
          <div class="timeline">
            <?php if (!empty($topIssues)): ?>
              <?php foreach (array_slice($topIssues, 0, 3) as $i => $issue):
                $dotStyle = $i === 1 ? 'background: var(--amber); box-shadow: 0 0 0 5px rgba(180,83,9,.11)' : ($i === 2 ? 'background: var(--sky); box-shadow: 0 0 0 5px rgba(37,99,235,.09)' : '');
              ?>
              <div class="event">
                <span class="event-dot" aria-hidden="true" style="<?= htmlspecialchars($dotStyle) ?>"></span>
                <div>
                  <h3><?= htmlspecialchars($issue['check']) ?></h3>
                  <p>Review recurring finding across <?= number_format((int)$issue['cnt']) ?> scan<?= (int)$issue['cnt'] === 1 ? '' : 's' ?> and assign remediation owner.</p>
                </div>
                <time><?= $i === 0 ? 'now' : ($i === 1 ? '18m' : '1h') ?></time>
              </div>
              <?php endforeach; ?>
            <?php else: ?>
              <div class="event">
                <span class="event-dot" aria-hidden="true"></span>
                <div>
                  <h3>Admin surface review</h3>
                  <p>Restrict sensitive admin paths using VPN, allowlist, or WAF rule.</p>
                </div>
                <time>now</time>
              </div>
              <div class="event">
                <span class="event-dot" aria-hidden="true" style="background: var(--amber); box-shadow: 0 0 0 5px rgba(180,83,9,.11)"></span>
                <div>
                  <h3>Captcha blocks active probe</h3>
                  <p>Coordinate scan window or scanner IP allowlist to complete version checks.</p>
                </div>
                <time>18m</time>
              </div>
              <div class="event">
                <span class="event-dot" aria-hidden="true" style="background: var(--sky); box-shadow: 0 0 0 5px rgba(37,99,235,.09)"></span>
                <div>
                  <h3>CSP rollout required</h3>
                  <p>Deploy report-only first, then enforce after validating expected assets.</p>
                </div>
                <time>1h</time>
              </div>
            <?php endif; ?>
          </div>
        </article>

        <article class="panel">
          <div class="panel-head">
            <div>
              <h2 class="panel-title">Compliance Readiness</h2>
              <p class="panel-sub">Operational coverage by control group.</p>
            </div>
          </div>
          <div class="readiness-list">
            <?php foreach ($readiness as [$label, $value]): ?>
            <div class="readiness-row">
              <span><?= htmlspecialchars($label) ?></span>
              <div class="readiness-track"><div class="readiness-fill" style="width: <?= (int)$value ?>%"></div></div>
              <span><?= (int)$value ?></span>
            </div>
            <?php endforeach; ?>
          </div>
        </article>
      </aside>
    </div>
  </main>
</div>

<?php if (!empty($countryStats)): ?>
<script src="https://cdn.jsdelivr.net/npm/jsvectormap@1.7.0/dist/jsvectormap.min.js" referrerpolicy="no-referrer"></script>
<script src="https://cdn.jsdelivr.net/npm/jsvectormap@1.7.0/dist/maps/world.js" referrerpolicy="no-referrer"></script>
<?php endif; ?>
<script nonce="<?= htmlspecialchars($nonce, ENT_QUOTES) ?>">
// Theme toggle ikut mockup enterprise.
(function () {
  var key = 'secscan-theme';
  var root = document.documentElement;
  var buttons = document.querySelectorAll('[data-theme-choice]');
  function stored() {
    try { return localStorage.getItem(key); } catch (_) { return null; }
  }
  function apply(theme) {
    if (theme === 'light' || theme === 'dark') root.setAttribute('data-theme', theme);
    else root.removeAttribute('data-theme');
    var active = effective();
    buttons.forEach(function (button) {
      button.classList.toggle('active', button.getAttribute('data-theme-choice') === active);
    });
  }
  function effective() {
    var s = stored();
    if (s === 'light' || s === 'dark') return s;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  apply(stored());
  buttons.forEach(function (button) {
    button.addEventListener('click', function () {
      var next = button.getAttribute('data-theme-choice');
      try { localStorage.setItem(key, next); } catch (_) {}
      apply(next);
    });
  });

  var exportBtn = document.getElementById('exportCsvBtn');
  var auditPrintBtn = document.getElementById('auditPrintBtn');
  var refreshDashboardBtn = document.getElementById('refreshDashboardBtn');
  var autoRefreshToggleBtn = document.getElementById('autoRefreshToggleBtn');
  var table = document.getElementById('recentScanTable');
  var shell = document.querySelector('.enterprise-shell');
  var sidebarToggle = document.getElementById('sidebarToggle');
  var sidebarKey = 'secscan-dashboard-sidebar';

  function readSidebarState() {
    try { return localStorage.getItem(sidebarKey); } catch (_) { return null; }
  }

  function setSidebarCollapsed(collapsed) {
    if (!shell) return;
    shell.classList.toggle('sidebar-collapsed', collapsed);
    if (sidebarToggle) {
      sidebarToggle.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
      sidebarToggle.setAttribute('aria-label', collapsed ? 'Besarkan sidebar' : 'Kecilkan sidebar');
      sidebarToggle.setAttribute('title', collapsed ? 'Besarkan sidebar' : 'Kecilkan sidebar');
    }
  }

  setSidebarCollapsed(readSidebarState() === 'collapsed');

  if (sidebarToggle && shell) {
    sidebarToggle.addEventListener('click', function () {
      var collapsed = !shell.classList.contains('sidebar-collapsed');
      setSidebarCollapsed(collapsed);
      try { localStorage.setItem(sidebarKey, collapsed ? 'collapsed' : 'expanded'); } catch (_) {}
    });
  }

  if (exportBtn && table) {
    exportBtn.addEventListener('click', function () {
      var rows = Array.from(table.querySelectorAll('tr')).map(function (row) {
        return Array.from(row.children).map(function (cell) {
          return '"' + cell.textContent.replace(/\s+/g, ' ').trim().replace(/"/g, '""') + '"';
        }).join(',');
      }).join('\n');
      var blob = new Blob([rows], { type: 'text/csv;charset=utf-8' });
      var url = URL.createObjectURL(blob);
      var link = document.createElement('a');
      link.href = url;
      link.download = 'secscan-authorized-scans.csv';
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 800);
    });
  }

  if (auditPrintBtn) {
    auditPrintBtn.addEventListener('click', function () {
      window.print();
    });
  }
  if (refreshDashboardBtn) {
    refreshDashboardBtn.addEventListener('click', function () { location.reload(); });
  }
  if (autoRefreshToggleBtn) {
    var autoRefreshKey = 'secscan-dashboard-auto-refresh';
    var autoRefreshTimer = null;
    function setAutoRefresh(enabled) {
      if (autoRefreshTimer) { clearTimeout(autoRefreshTimer); autoRefreshTimer = null; }
      autoRefreshToggleBtn.textContent = 'Auto Refresh: ' + (enabled ? 'On' : 'Off');
      autoRefreshToggleBtn.setAttribute('aria-pressed', enabled ? 'true' : 'false');
      try { localStorage.setItem(autoRefreshKey, enabled ? 'on' : 'off'); } catch (_) {}
      if (enabled) autoRefreshTimer = setTimeout(function () { location.reload(); }, 60000);
    }
    var enabled = false;
    try { enabled = localStorage.getItem(autoRefreshKey) === 'on'; } catch (_) {}
    setAutoRefresh(enabled);
    autoRefreshToggleBtn.addEventListener('click', function () { setAutoRefresh(autoRefreshToggleBtn.getAttribute('aria-pressed') !== 'true'); });
  }
})();

(function () {
  var form = document.getElementById('geoIpUpdateForm');
  var button = document.getElementById('geoIpUpdateBtn');
  if (!form || !button) return;
  form.addEventListener('submit', function () {
    button.disabled = true;
    button.textContent = 'Memuat turun & mengimport…';
  });
})();

(function () {
  var form = document.getElementById('domainGradeFilterForm');
  var filter = document.getElementById('domainGradeFilter');
  var sort = document.getElementById('domainSortFilter');
  if (!form || !filter || !sort) return;
  filter.addEventListener('change', function () { form.submit(); });
  sort.addEventListener('change', function () { form.submit(); });
})();

// Country-level GeoIP visualisation. The database stays on this server; only
// public vector-map assets are loaded by the administrator's browser.
(function () {
  var dataEl = document.getElementById('geoCountryData');
  var target = document.getElementById('geoCountryMap');
  var gradeFilter = document.getElementById('geoGradeFilter');
  var metricFilter = document.getElementById('geoMetricFilter');
  var list = document.getElementById('geoCountryList');
  if (!dataEl || !target || !gradeFilter || !metricFilter || typeof jsVectorMap === 'undefined') return;
  try {
    try {
      var savedGrade = localStorage.getItem('secscan-geo-grade');
      var savedMetric = localStorage.getItem('secscan-geo-metric');
      if (savedGrade && Array.from(gradeFilter.options).some(function (option) { return option.value === savedGrade; })) gradeFilter.value = savedGrade;
      if (savedMetric && Array.from(metricFilter.options).some(function (option) { return option.value === savedMetric; })) metricFilter.value = savedMetric;
    } catch (_) {}
    var rows = JSON.parse(dataEl.textContent || '[]');
    var displayNames = typeof Intl !== 'undefined' && Intl.DisplayNames
      ? new Intl.DisplayNames(['ms'], { type: 'region' }) : null;
    function nameFor(code) { return displayNames ? (displayNames.of(code) || code) : code; }
    function escapeHtml(value) {
      return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
    }
    function aggregate() {
      var grade = gradeFilter.value;
      var grouped = {};
      var totals = {};
      rows.forEach(function (row) {
        var code = String(row.country || '').toUpperCase();
        var count = Number(row.cnt || 0);
        var score = Number(row.avg_score || 0);
        if (!/^[A-Z]{2}$/.test(code) || count < 1) return;
        totals[code] = (totals[code] || 0) + count;
        if (grade !== 'all' && String(row.grade || '') !== grade) return;
        if (!grouped[code]) grouped[code] = { country: code, cnt: 0, scoreTotal: 0 };
        grouped[code].cnt += count;
        grouped[code].scoreTotal += score * count;
      });
      return Object.keys(grouped).map(function (code) {
        var item = grouped[code];
        item.avg = item.cnt ? item.scoreTotal / item.cnt : 0;
        item.total = totals[code] || item.cnt;
        return item;
      });
    }
    function render() {
      var metric = metricFilter.value;
      var countries = aggregate();
      var values = {};
      countries.forEach(function (item) {
        values[item.country] = metric === 'count' ? item.cnt : (metric === 'best' ? item.avg : 100 - item.avg);
      });
      var sort = metric === 'worst'
        ? function (a, b) { return a.avg - b.avg; }
        : metric === 'best'
          ? function (a, b) { return b.avg - a.avg; }
          : function (a, b) { return b.cnt - a.cnt; };
      countries.sort(sort);
      if (list) {
        list.innerHTML = countries.slice(0, 10).map(function (item) {
          var gradeText = gradeFilter.value === 'all'
            ? 'Semua: ' + item.total + ' domain'
            : gradeFilter.value + ': ' + item.cnt + ' / ' + item.total + ' domain';
          return '<div class="geoip-country"><div><strong>' + escapeHtml(nameFor(item.country)) + '</strong><br><span>'
            + escapeHtml(item.country) + ' · ' + gradeText + ' · skor ' + item.avg.toFixed(1) + '</span></div><strong>' + item.cnt + '</strong></div>';
        }).join('') || '<div class="empty-state">Tiada rekod untuk penapis ini.</div>';
      }
      target.innerHTML = '';
      var scale = metric === 'worst' ? ['#5a3038', '#fb7185'] : metric === 'best' ? ['#315c8a', '#7dd3fc'] : ['#2d7a75', '#59d8c3'];
      new jsVectorMap({
        selector: '#geoCountryMap', map: 'world', zoomButtons: false,
        regionStyle: { initial: { fill: '#344657', fillOpacity: 1, stroke: '#607287', strokeWidth: 0.5 } },
        series: { regions: [{ attribute: 'fill', scale: scale, values: values, normalizeFunction: 'polynomial' }] },
        onRegionTooltipShow: function (event, tooltip, code) {
          var item = countries.find(function (country) { return country.country === code; });
          var label = gradeFilter.value === 'all' ? 'Semua' : gradeFilter.value;
          tooltip.text(tooltip.text() + (item ? ' · ' + label + ': ' + item.cnt + ' / ' + item.total + ' domain · skor ' + item.avg.toFixed(1) : ' · tiada domain'));
        }
      });
    }
    gradeFilter.addEventListener('change', function () { try { localStorage.setItem('secscan-geo-grade', gradeFilter.value); } catch (_) {} render(); });
    metricFilter.addEventListener('change', function () { try { localStorage.setItem('secscan-geo-metric', metricFilter.value); } catch (_) {} render(); });
    render();
  } catch (err) {
    target.innerHTML = '<div class="empty-state">Peta tidak dapat dimuatkan. Jadual negara masih tersedia.</div>';
  }
})();

</script>

<?php endif; ?>
</body>
</html>
