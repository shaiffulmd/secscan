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

// Expire session selepas SESSION_TIMEOUT saat
if (isset($_SESSION['last_active']) && (time() - $_SESSION['last_active']) > SESSION_TIMEOUT) {
    session_unset(); session_destroy(); session_start();
}
if (isset($_SESSION['auth'])) $_SESSION['last_active'] = time();

$isLoggedIn = ($_SESSION['auth'] ?? false) === true;
$loginError = '';
$setupError = DASHBOARD_PASSWORD_HASH === ''
    ? 'Dashboard belum dikonfigurasi. Set SECSCAN_DASHBOARD_PASSWORD_HASH sebelum login.'
    : '';
if (!$isLoggedIn && $setupError !== '') {
    $loginError = $setupError;
}

// Handle logout
if (isset($_GET['logout'])) {
    session_unset(); session_destroy();
    header('Location: dashboard.php'); exit;
}

// Handle login POST
if ($requestMethod === 'POST' && !$isLoggedIn) {
    $loginRate = RateLimiter::consume('dashboard_login_v1', secscan_client_ip(), 10, 900);
    if ($setupError !== '') {
        $loginError = $setupError;
    } elseif (!$loginRate['allowed']) {
        $loginError = 'Terlalu banyak cubaan login. Cuba semula kemudian.';
        header('Retry-After: ' . $loginRate['retry_after']);
    }

    $pw = $_POST['password'] ?? '';
    if ($loginError === '' && $pw !== '' && password_verify($pw, DASHBOARD_PASSWORD_HASH)) {
        session_regenerate_id(true);
        $_SESSION['auth']        = true;
        $_SESSION['last_active'] = time();
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
header("Content-Security-Policy: default-src 'self'; script-src 'nonce-{$nonce}'; style-src 'self' 'nonce-{$nonce}'; style-src-attr 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'");

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
$pageSize    = 50;
$page        = max(1, (int)($_GET['p'] ?? 1));

if ($isLoggedIn) {
    $loggerPath = __DIR__ . '/logger.php';
    if (is_file($loggerPath)) {
        require_once $loggerPath;
        $logger      = new ScanLogger();
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

$totalPages = (int)ceil($totalCount / $pageSize);
$totalScans = (int)($summary['total_scans'] ?? 0);
$avgScore = is_numeric($summary['avg_score'] ?? null) ? (float)$summary['avg_score'] : null;
$avgGrade = scoreToGrade($avgScore);
$criticalTotal = (int)($summary['total_critical'] ?? 0);
$criticalScans = (int)($summary['scans_with_criticals'] ?? 0);
$uniqueIps = (int)($summary['unique_ips'] ?? 0);
$domainTotal = count($topDomains);
$blockedProbes = (int)($summary['scan_blocked_total'] ?? 0);
if ($blockedProbes === 0) {
    $blockedProbes = array_reduce($recentScans, static fn($sum, $scan) => $sum + ((int)($scan['scan_blocked'] ?? 0) === 1 ? 1 : 0), 0);
}
if ($cdnDomains === []) {
    $cdnMap = [];
    foreach ($recentScans as $scan) {
        if ((int)($scan['is_cloudflare'] ?? 0) !== 1) continue;
        $host = (string)($scan['hostname'] ?? '');
        if ($host === '') continue;
        if (!isset($cdnMap[$host])) {
            $cdnMap[$host] = [
                'hostname' => $host,
                'scan_count' => 0,
                'last_scan' => (string)($scan['scanned_at'] ?? ''),
                'avg_score' => 0,
                '_score_sum' => 0,
            ];
        }
        $cdnMap[$host]['scan_count']++;
        $cdnMap[$host]['_score_sum'] += (float)($scan['score'] ?? 0);
        if (strcmp((string)($scan['scanned_at'] ?? ''), (string)$cdnMap[$host]['last_scan']) > 0) {
            $cdnMap[$host]['last_scan'] = (string)$scan['scanned_at'];
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
    <?php if ($loginError): ?>
      <div class="login-error"><?= htmlspecialchars($loginError) ?></div>
    <?php endif; ?>
    <form method="POST" autocomplete="off">
      <div class="field">
        <label>PASSWORD</label>
        <input type="password" name="password" autofocus required placeholder="••••••••••••"/>
      </div>
      <button class="btn-login" type="submit">MASUK →</button>
    </form>
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
        <a class="nav-link" href="dashboard.php">Dashboard</a>
        <div class="theme-control" role="group" aria-label="Theme">
          <button class="theme-choice" type="button" data-theme-choice="light">Light</button>
          <button class="theme-choice" type="button" data-theme-choice="dark">Dark</button>
        </div>
        <a class="nav-link" href="?logout=1">Log Keluar</a>
      </div>
    </header>

    <section class="dashboard-header">
      <div>
        <h1>Security operations overview for authorized web scans.</h1>
        <p>Monitor scan activity, blocked probes, high-risk findings, CMS exposure, PCI readiness, and scanner IP accountability.</p>
      </div>
      <div class="dashboard-actions">
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
                  <th>CMS</th>
                  <th>CDN</th>
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
                  } elseif ((int)$s['is_cloudflare'] === 1) {
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
                ?>
                <tr>
                  <td>
                    <div class="domain">
                      <strong><?= htmlspecialchars($s['hostname']) ?></strong>
                      <a class="target-url" href="<?= htmlspecialchars($targetUrl) ?>" target="_blank" rel="noopener noreferrer"><?= htmlspecialchars($targetUrl) ?></a>
                    </div>
                  </td>
                  <td><strong><?= htmlspecialchars($s['client_ip'] ?: '-') ?></strong></td>
                  <td><?= htmlspecialchars($cmsText) ?></td>
                  <td><span class="pill <?= (int)$s['is_cloudflare'] === 1 ? 'warn' : 'info' ?>"><?= (int)$s['is_cloudflare'] === 1 ? 'Cloudflare' : 'Direct' ?></span></td>
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
              <p class="panel-sub">Domain yang dikesan melalui CDN atau edge protection.</p>
            </div>
            <span class="pill warn"><?= number_format($cdnDomainTotal) ?> domain</span>
          </div>
          <div class="cdn-list">
            <?php if (!empty($cdnDomains)): ?>
              <?php foreach ($cdnDomains as $cdn): ?>
              <div class="cdn-row">
                <div class="cdn-domain">
                  <strong><?= htmlspecialchars($cdn['hostname']) ?></strong>
                  <span><?= number_format((int)$cdn['scan_count']) ?> scan · skor purata <?= htmlspecialchars((string)$cdn['avg_score']) ?></span>
                </div>
                <div class="cdn-provider">
                  <span class="cdn-dot" aria-hidden="true"></span>
                  <span class="pill warn">Cloudflare</span>
                </div>
              </div>
              <?php endforeach; ?>
            <?php else: ?>
              <div class="empty-state">Belum ada domain CDN direkodkan.</div>
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
})();

// Auto-refresh summary cards setiap 60 saat
setTimeout(() => location.reload(), 60000);
</script>

<?php endif; ?>
</body>
</html>
