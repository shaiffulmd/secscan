<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/src/RateLimiter.php';

header_remove('X-Powered-By');
$requestMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if (!in_array($requestMethod, ['GET', 'HEAD', 'POST'], true)) {
    header('Allow: GET, HEAD, POST');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store');
    http_response_code(405);
    exit;
}

ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
session_name('secscan_contact');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => secscan_is_https(),
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();
if (empty($_SESSION['contact_csrf'])) $_SESSION['contact_csrf'] = bin2hex(random_bytes(32));

header_remove('X-Powered-By');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()');
header('Cache-Control: no-store, private, max-age=0');
if (secscan_is_https()) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}
header("Content-Security-Policy: default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com data:; style-src 'self' https://fonts.googleapis.com; script-src 'self'; form-action 'self'");
secscan_send_operational_security_headers();

$notice = '';
$noticeTone = '';
$key = base64_decode((string)secscan_config('contact_encryption_key'), true);
$contactEnabled = is_string($key) && strlen($key) === 32 && extension_loaded('openssl');

if ($requestMethod === 'POST') {
    $csrf = is_string($_POST['csrf_token'] ?? null) ? $_POST['csrf_token'] : '';
    $name = trim((string)($_POST['name'] ?? ''));
    $email = trim((string)($_POST['email'] ?? ''));
    $subject = trim((string)($_POST['subject'] ?? ''));
    $message = trim((string)($_POST['message'] ?? ''));
    $contentLength = filter_var($_SERVER['CONTENT_LENGTH'] ?? null, FILTER_VALIDATE_INT);
    if (is_int($contentLength) && $contentLength > (int)secscan_config('max_request_bytes')) {
        http_response_code(413);
        $notice = 'Permintaan terlalu besar. Sila pendekkan mesej dan cuba lagi.'; $noticeTone = 'bad';
    } elseif (!hash_equals((string)$_SESSION['contact_csrf'], $csrf)) {
        $notice = 'Permintaan tidak sah. Sila muat semula halaman dan cuba lagi.'; $noticeTone = 'bad';
    } elseif (!$contactEnabled) {
        $notice = 'Borang hubungan belum dikonfigurasi dengan kunci penyulitan.'; $noticeTone = 'bad';
    } elseif ($name === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || $subject === '' || $message === ''
        || mb_strlen($name) > 120 || mb_strlen($email) > 254
        || mb_strlen($subject) > 180 || mb_strlen($message) > 6000) {
        $notice = 'Sila isi nama, e-mel, subjek dan mesej yang sah.'; $noticeTone = 'bad';
    } else {
        $rate = RateLimiter::consume('contact_form_v1', secscan_client_ip(), 5, 3600);
        if (!empty($rate['storage_failed'])) {
            http_response_code(503);
            $notice = 'Perkhidmatan had mesej tidak tersedia. Sila cuba lagi kemudian.'; $noticeTone = 'bad';
        } elseif (empty($rate['allowed'])) {
            $notice = 'Terlalu banyak mesej daripada rangkaian ini. Cuba lagi kemudian.'; $noticeTone = 'bad';
        } else {
            require_once __DIR__ . '/logger.php';
            $logger = new ScanLogger();
            $id = $logger->storeContactMessage([
                'name' => $name, 'email' => $email, 'subject' => $subject, 'message' => $message,
                'client_ip_hash' => hash('sha256', secscan_client_ip() . (string)secscan_config('ip_hash_salt')),
            ], $key);
            if ($id === null) {
                $notice = 'Mesej tidak dapat disimpan. Sila cuba lagi kemudian.'; $noticeTone = 'bad';
            } else {
                $to = trim((string)secscan_config('contact_mail_to'));
                $from = trim((string)secscan_config('contact_mail_from'));
                if (filter_var($to, FILTER_VALIDATE_EMAIL) && filter_var($from, FILTER_VALIDATE_EMAIL)) {
                    $headers = "From: {$from}\r\nContent-Type: text/plain; charset=UTF-8";
                    if (@mail($to, 'SecScan Contact #' . $id . ': ' . preg_replace('/[\r\n]+/', ' ', $subject), "Mesej baharu telah disimpan dalam dashboard SecScan.\nID: {$id}", $headers)) {
                        $logger->markContactMailSent($id);
                    }
                }
                $_SESSION['contact_csrf'] = bin2hex(random_bytes(32));
                $notice = 'Terima kasih. Mesej anda disulitkan dan disimpan untuk pasukan SecScan.'; $noticeTone = 'good';
            }
        }
    }
}
$appVersion = secscan_app_version();
?>
<!doctype html><html lang="ms"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Tentang SecScan</title>
<link rel="icon" type="image/svg+xml" href="favicon.svg"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&amp;family=Lora:wght@500;600&amp;family=JetBrains+Mono:wght@400;500&amp;display=swap" rel="stylesheet">
<link rel="stylesheet" href="assets/app.css?v=<?= rawurlencode((string)filemtime(__DIR__ . '/assets/app.css')) ?>"><link rel="stylesheet" href="assets/enterprise.css?v=<?= rawurlencode((string)filemtime(__DIR__ . '/assets/enterprise.css')) ?>"><script src="assets/theme.js?v=<?= rawurlencode((string)filemtime(__DIR__ . '/assets/theme.js')) ?>"></script>
</head><body class="enterprise-ui about-page"><div class="app">
<header class="header"><div class="header-inner"><a href="index.php" class="logo"><div class="logo-icon"><img src="secscan-logo.svg" alt=""></div><div><div class="logo-name">SecScan</div><div class="logo-sub">Pengimbas Keselamatan Enterprise</div></div></a><div class="header-actions"><a class="dashboard-link" href="index.php">Scanner</a><a class="dashboard-link" href="faqs.php">FAQ</a><a class="dashboard-link" href="dashboard.php">Papan Pemuka</a><button type="button" class="theme-toggle" id="themeToggle" aria-label="Tukar tema">◐</button></div></div></header>
<main class="about-main">
  <section class="about-hero"><p class="faq-eyebrow">TENTANG SECSCAN</p><h1>Keselamatan web yang lebih mudah difahami.</h1><p>SecScan membantu pemilik sistem melihat risiko pada permukaan web awam, membuktikan dapatan, dan mengutamakan pembetulan tanpa mengelirukan masalah capaian sebagai kelemahan.</p></section>
  <section class="about-grid"><article><p class="faq-overline">TUJUAN</p><h2>Dari isyarat ke tindakan.</h2><p>SecScan menilai TLS, headers, DNS, CMS, WAF, pendedahan biasa dan indikator SEO poisoning. Ia menyusun bukti supaya pasukan boleh mengenal pasti apa yang perlu diperbaiki dahulu.</p></article><article><p class="faq-overline">PRINSIP</p><h2>Jujur tentang had scan.</h2><p>Jika WAF, captcha atau kegagalan rangkaian menghalang pemeriksaan, hasil ialah N/A — bukannya gred F tanpa bukti yang mencukupi.</p></article></section>
  <section class="about-history"><div><p class="faq-overline">SEJARAH SECSCAN</p><h2>Dibina untuk audit yang praktikal.</h2></div><ol><li><strong>Permulaan</strong><span>SecScan bermula sebagai pemeriksaan ringkas untuk asas HTTPS dan security headers.</span></li><li><strong>Berkembang</strong><span>Ia menambah TLS, DNS, CMS, WAF, CVE, audit server dan rekod dashboard.</span></li><li><strong>Hari ini</strong><span>Pengesanan SEO poisoning dan status N/A membantu dapatan kekal tepat apabila target tidak dapat dinilai.</span></li></ol></section>
  <section class="about-contact" id="contact"><div><p class="faq-overline">HUBUNGI KAMI</p><h2>Perlukan bantuan atau ingin berkongsi maklum balas?</h2><p>Mesej ini disulitkan menggunakan AES-256-GCM sebelum disimpan. Ia hanya boleh dibaca oleh pentadbir dashboard yang mempunyai kunci penyulitan server.</p></div><form method="post" class="contact-form" novalidate><input type="hidden" name="csrf_token" value="<?= htmlspecialchars((string)$_SESSION['contact_csrf'], ENT_QUOTES) ?>"><?php if ($notice): ?><p class="contact-notice <?= htmlspecialchars($noticeTone) ?>"><?= htmlspecialchars($notice) ?></p><?php endif; ?><label>Nama<input name="name" maxlength="120" required></label><label>E-mel<input name="email" type="email" maxlength="254" required></label><label>Subjek<input name="subject" maxlength="180" required></label><label>Mesej<textarea name="message" rows="6" maxlength="6000" required></textarea></label><button class="faq-primary" type="submit" <?= $contactEnabled ? '' : 'disabled' ?>>Hantar mesej</button><?php if (!$contactEnabled): ?><p class="contact-help">Pentadbir perlu menetapkan <code>SECSCAN_CONTACT_ENCRYPTION_KEY</code> untuk mengaktifkan borang.</p><?php endif; ?></form></section>
</main><footer class="footer"><span>© 2026 SecScan Enterprise.</span><span class="footer-version">Versi <?= htmlspecialchars($appVersion, ENT_QUOTES) ?></span><nav class="footer-links"><a href="faqs.php">FAQ</a><a href="dashboard.php">Papan Pemuka</a></nav></footer></div></body></html>
