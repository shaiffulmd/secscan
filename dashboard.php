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
$isHttps = (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off')
    || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https')
    || (($_SERVER['HTTP_CF_VISITOR'] ?? '') && str_contains((string)$_SERVER['HTTP_CF_VISITOR'], 'https'));
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
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$isLoggedIn) {
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
header("Content-Security-Policy: default-src 'self'; script-src 'nonce-{$nonce}'; style-src 'self' 'nonce-{$nonce}'; img-src 'self' data:; frame-ancestors 'none'");

if (!empty($_SERVER['HTTPS'])) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

// ----------------------------------------------------------------
//  Load data (only when logged in)
// ----------------------------------------------------------------

$summary     = [];
$grades      = [];
$dailyScans  = [];
$topDomains  = [];
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

function relTime(string $dt): string {
    $diff = time() - strtotime($dt);
    if ($diff < 60)  return $diff . 's ago';
    if ($diff < 3600) return (int)($diff / 60) . 'm ago';
    if ($diff < 86400) return (int)($diff / 3600) . 'h ago';
    return (int)($diff / 86400) . 'd ago';
}

$totalPages = (int)ceil($totalCount / $pageSize);
?>
<!DOCTYPE html>
<html lang="ms">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>SecScan Dashboard</title>
<style nonce="<?= htmlspecialchars($nonce, ENT_QUOTES) ?>">
:root {
  --void:    #020508; --base: #050d18; --surface: #091525;
  --elevated:#0e1f33; --high: #132840;
  --border:  rgba(0,220,180,.08); --border2: rgba(0,220,180,.18); --border3: rgba(0,220,180,.32);
  --t1: #cde8f8; --t2: #5a8aaa; --t3: #2a4560;
  --mint: #00ffcc; --mint2: rgba(0,255,204,.08);
  --sky:  #38bdf8; --rose: #f43f5e; --amber: #f59e0b; --green: #22c55e;
  --f-title: system-ui, -apple-system, sans-serif;
  --f-mono:  'Courier New', monospace;
  --r-sm: 6px; --r-md: 12px; --r-lg: 18px;
  --ease: cubic-bezier(.4,0,.2,1);
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { font-size: 16px; }
body { font-family: var(--f-mono); background: var(--base); color: var(--t1);
       min-height: 100vh; overflow-x: hidden; }
a { color: var(--mint); text-decoration: none; }
button, input { font-family: inherit; }

/* ── Header ── */
.topbar { position: sticky; top: 0; z-index: 100;
          background: rgba(5,13,24,.9); backdrop-filter: blur(14px);
          border-bottom: 1px solid var(--border); }
.topbar-inner { max-width: 1280px; margin: 0 auto; padding: 0 24px;
                height: 56px; display: flex; align-items: center; gap: 14px; }
.logo-text { font-family: var(--f-title); font-weight: 800; font-size: .95rem;
             letter-spacing: .05em; }
.logo-sub  { font-size: .52rem; letter-spacing: .2em; color: var(--mint); opacity: .7; margin-top: 1px; }
.spacer { flex: 1; }
.badge-live { display: flex; align-items: center; gap: 5px; font-family: var(--f-title);
              font-size: .55rem; font-weight: 700; letter-spacing: .16em; color: var(--mint);
              background: var(--mint2); border: 1px solid var(--border2);
              border-radius: 999px; padding: 4px 10px; }
.dot-live { width: 6px; height: 6px; border-radius: 50%; background: var(--mint);
            animation: blink 1.8s infinite; }
@keyframes blink { 0%,100%{opacity:1}50%{opacity:.25} }
.btn-logout { font-size: .65rem; font-family: var(--f-title); font-weight: 600;
              letter-spacing: .1em; color: var(--t2); background: var(--elevated);
              border: 1px solid var(--border2); border-radius: var(--r-sm);
              padding: 6px 14px; cursor: pointer; transition: all .2s; }
.btn-logout:hover { color: var(--rose); border-color: rgba(244,63,94,.4); }

/* ── Login ── */
.login-wrap { min-height: 100vh; display: grid; place-items: center; padding: 24px; }
.login-card { background: var(--surface); border: 1px solid var(--border2);
              border-radius: var(--r-lg); padding: 44px 40px; width: 100%; max-width: 380px;
              box-shadow: 0 32px 64px rgba(0,0,0,.5); }
.login-icon { width: 52px; height: 52px; background: var(--mint2); border: 1px solid var(--border2);
              border-radius: var(--r-md); display: grid; place-items: center; margin: 0 auto 20px; }
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
        padding: 20px; transition: border-color .2s, background .2s; }
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
              border-radius: var(--r-md); padding: 22px; }
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
              border-radius: var(--r-md); overflow: hidden; margin-bottom: 32px; }
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
tr:hover td { background: rgba(14,31,51,.6); }
.td-host { color: var(--t1); font-weight: 600; max-width: 200px; }
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
</style>
</head>
<body>

<?php if (!$isLoggedIn): ?>
<!-- ═══════════════════════════════ LOGIN PAGE ═══════════════════════════════ -->
<div class="login-wrap">
  <div class="login-card">
    <div class="login-icon">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#00ffcc" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
      </svg>
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

<div class="topbar">
  <div class="topbar-inner">
    <div>
      <div class="logo-text">SecScan</div>
      <div class="logo-sub">DASHBOARD</div>
    </div>
    <div class="spacer"></div>
    <div class="badge-live"><span class="dot-live"></span>LIVE</div>
    <a href="?logout=1"><button class="btn-logout">Log Keluar</button></a>
  </div>
</div>

<div class="main">

  <!-- Summary Cards -->
  <div class="section-title">Ringkasan Keseluruhan</div>
  <div class="cards">
    <div class="card">
      <div class="card-val c-mint"><?= number_format((int)($summary['total_scans'] ?? 0)) ?></div>
      <div class="card-label">JUMLAH SCAN</div>
    </div>
    <div class="card">
      <div class="card-val c-sky"><?= number_format((int)($summary['scans_today'] ?? 0)) ?></div>
      <div class="card-label">SCAN HARI INI</div>
    </div>
    <div class="card">
      <div class="card-val c-amber"><?= $summary['avg_score'] ?? '—' ?></div>
      <div class="card-label">PURATA SKOR</div>
    </div>
    <div class="card">
      <div class="card-val c-green"><?= number_format((int)($summary['unique_ips'] ?? 0)) ?></div>
      <div class="card-label">UNIQUE IP</div>
    </div>
    <div class="card">
      <div class="card-val c-mint"><?= $summary['avg_duration_s'] ?? '—' ?>s</div>
      <div class="card-label">PURATA MASA SCAN</div>
    </div>
    <div class="card">
      <div class="card-val c-rose"><?= number_format((int)($summary['scans_with_criticals'] ?? 0)) ?></div>
      <div class="card-label">SCAN ADA CRITICAL</div>
    </div>
  </div>

  <!-- Score Distribution -->
  <div class="section-title">Taburan Skor</div>
  <div class="chart-card" style="margin-bottom:32px">
    <div class="score-dist">
      <?php $totalS = (int)($summary['total_scans'] ?? 1) ?: 1; ?>
      <div class="sd-card">
        <div class="sd-val" style="color:var(--mint)"><?= (int)($scoreDist['s90'] ?? 0) ?></div>
        <div class="sd-label">90–100 (A/A+)</div>
        <div style="font-size:.55rem;color:var(--t3);margin-top:2px"><?= pct((int)($scoreDist['s90']??0),$totalS) ?>%</div>
      </div>
      <div class="sd-card">
        <div class="sd-val" style="color:var(--sky)"><?= (int)($scoreDist['s70'] ?? 0) ?></div>
        <div class="sd-label">70–89 (B/C)</div>
        <div style="font-size:.55rem;color:var(--t3);margin-top:2px"><?= pct((int)($scoreDist['s70']??0),$totalS) ?>%</div>
      </div>
      <div class="sd-card">
        <div class="sd-val" style="color:var(--amber)"><?= (int)($scoreDist['s50'] ?? 0) ?></div>
        <div class="sd-label">50–69 (D)</div>
        <div style="font-size:.55rem;color:var(--t3);margin-top:2px"><?= pct((int)($scoreDist['s50']??0),$totalS) ?>%</div>
      </div>
      <div class="sd-card">
        <div class="sd-val" style="color:var(--rose)"><?= (int)($scoreDist['s0'] ?? 0) ?></div>
        <div class="sd-label">0–49 (F)</div>
        <div style="font-size:.55rem;color:var(--t3);margin-top:2px"><?= pct((int)($scoreDist['s0']??0),$totalS) ?>%</div>
      </div>
    </div>
  </div>

  <!-- Charts row -->
  <div class="charts-row">

    <!-- Daily Scans chart -->
    <div class="chart-card">
      <div class="chart-title">Scan Harian (30 Hari Lepas)</div>
      <?php if (!empty($dailyScans) && array_sum($dailyScans) > 0):
        $maxD = maxVal($dailyScans);
        $keys = array_keys($dailyScans);
      ?>
      <div class="daily-bars">
        <?php foreach ($dailyScans as $day => $cnt):
          $h = max(4, (int)round($cnt / $maxD * 80));
          $short = date('j/n', strtotime($day));
        ?>
        <div class="daily-bar"
             style="height:<?= $h ?>px;background:<?= $cnt > 0 ? 'linear-gradient(to top,#00ffcc,#38bdf8)' : 'var(--elevated)' ?>;opacity:<?= $cnt > 0 ? '0.85' : '0.3' ?>"
             data-tip="<?= htmlspecialchars($day) ?>: <?= $cnt ?> scan"></div>
        <?php endforeach; ?>
      </div>
      <div class="daily-labels">
        <span><?= htmlspecialchars($keys[0] ?? '') ?></span>
        <span><?= htmlspecialchars($keys[array_key_last($keys)] ?? '') ?></span>
      </div>
      <?php else: ?><div class="no-data">Belum ada data</div><?php endif; ?>
    </div>

    <!-- Grade Distribution -->
    <div class="chart-card">
      <div class="chart-title">Taburan Gred</div>
      <?php if (!empty($grades)):
        $maxG = maxVal($grades);
        $gradeOrder = ['A+','A','B','C','D','F'];
      ?>
      <div class="bar-list">
        <?php foreach ($gradeOrder as $g):
          $cnt = $grades[$g] ?? 0;
          $w   = (int)round($cnt / $maxG * 100);
        ?>
        <div class="bar-row">
          <div class="bar-label <?= gradeTextClass($g) ?>"><?= $g ?></div>
          <div class="bar-track">
            <div class="bar-fill" style="width:<?= $w ?>%;background:<?= gradeColor($g) ?>"></div>
          </div>
          <div class="bar-count"><?= $cnt ?></div>
        </div>
        <?php endforeach; ?>
      </div>
      <?php else: ?><div class="no-data">Belum ada data</div><?php endif; ?>
    </div>

  </div>

  <!-- Peak Hours + Top Issues -->
  <div class="charts-row">

    <!-- Peak Hours Heatmap -->
    <div class="chart-card">
      <div class="chart-title">Waktu Puncak Penggunaan (MYT)</div>
      <?php if (!empty($peakHours) && array_sum($peakHours) > 0):
        $maxH = maxVal($peakHours);
      ?>
      <div class="hours-grid">
        <?php for ($h = 0; $h < 24; $h++):
          $cnt = $peakHours[$h] ?? 0;
          $alpha = $cnt > 0 ? max(.12, $cnt / $maxH) : .04;
          $bg = "rgba(0,255,204,{$alpha})";
        ?>
        <div class="hour-cell" style="background:<?= $bg ?>"
             data-tip="<?= sprintf('%02d:00',$h) ?>: <?= $cnt ?> scan"></div>
        <?php endfor; ?>
      </div>
      <div class="hours-labels">
        <span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>23:00</span>
      </div>
      <?php else: ?><div class="no-data">Belum ada data</div><?php endif; ?>
    </div>

    <!-- Top Issues -->
    <div class="chart-card">
      <div class="chart-title">Isu Paling Kerap Dijumpai</div>
      <?php if (!empty($topIssues)):
        $maxI = maxVal(array_column($topIssues, 'cnt'));
      ?>
      <div class="bar-list">
        <?php foreach ($topIssues as $issue):
          $w = (int)round($issue['cnt'] / $maxI * 100);
        ?>
        <div class="bar-row">
          <div class="bar-label bar-label-left" title="<?= htmlspecialchars($issue['check']) ?>">
            <?= htmlspecialchars(substr($issue['check'], 0, 24)) ?>
          </div>
          <div class="bar-track">
            <div class="bar-fill" style="width:<?= $w ?>%;background:linear-gradient(90deg,#f43f5e,#fb923c)"></div>
          </div>
          <div class="bar-count"><?= $issue['cnt'] ?></div>
        </div>
        <?php endforeach; ?>
      </div>
      <?php else: ?><div class="no-data">Belum ada data</div><?php endif; ?>
    </div>

  </div>

  <!-- Top Domains -->
  <div class="section-title">Domain Paling Kerap Discan</div>
  <div class="table-card" style="margin-bottom:32px">
    <?php if (!empty($topDomains)): ?>
    <table>
      <thead><tr>
        <th>#</th><th>Domain</th><th>Bilangan Scan</th>
        <th>Purata Skor</th><th>Scan Terakhir</th>
      </tr></thead>
      <tbody>
        <?php foreach ($topDomains as $i => $row): ?>
        <tr>
          <td style="color:var(--t3)"><?= $i + 1 ?></td>
          <td class="td-host"><?= htmlspecialchars($row['hostname']) ?></td>
          <td><?= number_format($row['cnt']) ?></td>
          <td style="color:var(--sky)"><?= $row['avg_score'] ?></td>
          <td style="color:var(--t3)"><?= relTime($row['last_scan']) ?></td>
        </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
    <?php else: ?>
      <div class="empty-state">Belum ada scan direkodkan</div>
    <?php endif; ?>
  </div>

  <!-- Recent Scans -->
  <div class="section-title">Log Scan Terbaru</div>
  <div class="table-card">
    <div class="table-head">
      <span style="font-family:var(--f-title);font-size:.72rem;font-weight:700">
        <?= number_format($totalCount) ?> scan direkodkan
      </span>
      <span style="font-size:.62rem;color:var(--t3)">Halaman <?= $page ?>/<?= max(1,$totalPages) ?></span>
    </div>
    <?php if (!empty($recentScans)): ?>
    <div style="overflow-x:auto">
    <table>
      <thead><tr>
        <th>Masa</th><th>Domain</th><th>Gred</th><th>Skor</th>
        <th>Lulus</th><th>Amaran</th><th>Kritikal</th>
        <th>Tempoh</th><th>TLS</th><th>CDN</th>
      </tr></thead>
      <tbody>
        <?php foreach ($recentScans as $s): ?>
        <tr>
          <td style="color:var(--t3);font-size:.62rem"><?= relTime($s['scanned_at']) ?></td>
          <td class="td-host"><?= htmlspecialchars($s['hostname']) ?></td>
          <td class="td-grade <?= gradeTextClass($s['grade']) ?>"><?= htmlspecialchars($s['grade']) ?></td>
          <td style="color:var(--sky)"><?= $s['score'] ?></td>
          <td class="td-pass"><?= $s['passed'] ?></td>
          <td class="td-warn"><?= $s['warnings'] ?></td>
          <td class="td-crit"><?= $s['critical'] ?></td>
          <td style="color:var(--t3)"><?= number_format($s['duration_ms'] / 1000, 1) ?>s</td>
          <td style="color:var(--t2);font-size:.62rem"><?= htmlspecialchars($s['tls_protocol'] ?: '—') ?></td>
          <td style="color:var(--t3)"><?= $s['is_cloudflare'] ? '☁' : '—' ?></td>
        </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
    </div>

    <!-- Pagination -->
    <?php if ($totalPages > 1): ?>
    <div class="pagination">
      <?php if ($page > 1): ?>
        <a href="?p=<?= $page - 1 ?>"><div class="pg-btn">← Sebelum</div></a>
      <?php endif; ?>
      <?php
      $start = max(1, $page - 2);
      $end   = min($totalPages, $page + 2);
      for ($i = $start; $i <= $end; $i++): ?>
        <a href="?p=<?= $i ?>"><div class="pg-btn <?= $i === $page ? 'active' : '' ?>"><?= $i ?></div></a>
      <?php endfor; ?>
      <?php if ($page < $totalPages): ?>
        <a href="?p=<?= $page + 1 ?>"><div class="pg-btn">Seterusnya →</div></a>
      <?php endif; ?>
    </div>
    <?php endif; ?>

    <?php else: ?>
      <div class="empty-state">Belum ada scan direkodkan. Scan mana-mana domain untuk mulakan.</div>
    <?php endif; ?>
  </div>

</div><!-- .main -->

<script nonce="<?= htmlspecialchars($nonce, ENT_QUOTES) ?>">
// Auto-refresh summary cards setiap 60 saat
setTimeout(() => location.reload(), 60000);
</script>

<?php endif; ?>
</body>
</html>
