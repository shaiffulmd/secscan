<?php
// ================================================================
//  faqs.php — SecScan Frequently Asked Questions
// ================================================================

require_once __DIR__ . '/config.php';

if (!headers_sent()) {
    header_remove('X-Powered-By');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    header("Content-Security-Policy: default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com data:; style-src 'self' https://fonts.googleapis.com; script-src 'self'; report-to default; report-uri /reporting.php");
    secscan_send_operational_security_headers();
    if (secscan_is_https()) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
    }
}

$appVersion = secscan_app_version();
?>
<!DOCTYPE html>
<html lang="ms">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"/>
  <meta name="theme-color" content="#F4F7FB" media="(prefers-color-scheme: light)"/>
  <meta name="theme-color" content="#080D14" media="(prefers-color-scheme: dark)"/>
  <meta name="description" content="Jawapan kepada soalan lazim tentang keputusan SecScan, termasuk status N/A, WAF, CMS dan SEO poisoning."/>
  <title>FAQ SecScan — Keputusan N/A, WAF dan Keselamatan Web</title>
  <link rel="icon" type="image/svg+xml" href="favicon.svg"/>
  <link rel="shortcut icon" href="favicon.svg"/>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&amp;family=Lora:wght@500;600&amp;family=JetBrains+Mono:wght@400;500&amp;display=swap" rel="stylesheet"/>
  <link rel="stylesheet" href="assets/app.css?v=<?= rawurlencode((string)filemtime(__DIR__ . '/assets/app.css')) ?>"/>
  <link rel="stylesheet" href="assets/enterprise.css?v=<?= rawurlencode((string)filemtime(__DIR__ . '/assets/enterprise.css')) ?>"/>
  <script src="assets/theme.js?v=<?= rawurlencode((string)filemtime(__DIR__ . '/assets/theme.js')) ?>"></script>
</head>
<body class="enterprise-ui faq-page">
  <div class="app">
    <header class="header">
      <div class="header-inner">
        <a href="index.php" class="logo">
          <div class="logo-icon"><img src="secscan-logo.svg" alt="" aria-hidden="true"/></div>
          <div>
            <div class="logo-name">SecScan</div>
            <div class="logo-sub">Pengimbas Keselamatan Enterprise</div>
          </div>
        </a>
        <div class="header-actions">
          <a class="dashboard-link" href="index.php">Scanner</a>
          <a class="dashboard-link" href="server-audit.php">Audit Server</a>
          <a class="dashboard-link" href="dashboard.php">Papan Pemuka</a>
          <a class="dashboard-link" href="about.php">Tentang</a>
          <button type="button" class="theme-toggle" id="themeToggle" aria-label="Tukar tema">
            <svg class="icon-moon" width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
            <svg class="icon-sun" width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="4" stroke="currentColor" stroke-width="1.8"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
          </button>
        </div>
      </div>
    </header>

    <main class="faq-main">
      <section class="faq-hero" aria-labelledby="faqTitle">
        <div class="sa-kicker">Pusat bantuan</div>
        <p class="faq-eyebrow">JAWAPAN YANG JELAS UNTUK HASIL SCAN</p>
        <h1 id="faqTitle">Soalan lazim SecScan</h1>
        <p class="faq-intro">Fahami keputusan scan, status <strong>N/A / Tidak dinilai</strong>, WAF, CMS dan indikator SEO poisoning sebelum membuat keputusan pembetulan.</p>
      </section>

      <p class="faq-na-chip">N/A bukan gred gagal</p>

      <section class="faq-na-guide" aria-labelledby="naTitle">
        <div class="faq-guide-heading">
          <p class="faq-overline">MEMAHAMI KEPUTUSAN N/A</p>
          <h2 id="naTitle">N/A bukan gred gagal.</h2>
          <p>Ia bermaksud SecScan tidak menerima bukti yang cukup untuk memberi penilaian yang adil.</p>
        </div>
        <ol class="faq-guide-steps">
          <li><span>01</span><div><h3>Akses disekat</h3><p>WAF, captcha, rate limit atau firewall menghantar respons selain laman sebenar.</p></div></li>
          <li><span>02</span><div><h3>Scan tidak lengkap</h3><p>Timeout, DNS, ralat server atau redirect menghalang pemeriksaan penuh.</p></div></li>
          <li><span>03</span><div><h3>Gred tidak dikira</h3><p>Tanpa bukti mencukupi, SecScan memaparkan N/A — bukan F.</p></div></li>
        </ol>
      </section>

      <div class="faq-layout">
        <nav class="faq-topics" aria-label="Topik FAQ">
          <p class="faq-overline">TOPIK</p>
          <a class="is-current" href="#na"><span>01</span>Keputusan N/A</a>
          <a href="#scan"><span>02</span>Proses &amp; skor scan</a>
          <a href="#detection"><span>03</span>CMS, WAF &amp; SEO</a>
          <a href="#privacy"><span>04</span>Akses &amp; tindakan</a>
        </nav>

        <div class="faq-content">
          <section class="faq-section" id="na" aria-labelledby="naHeading">
            <div class="faq-section-heading">
              <p class="faq-overline">01 / KEPUTUSAN</p>
              <h2 id="naHeading">Keputusan N/A / Tidak dinilai</h2>
              <p>Apabila scan tidak dapat menilai laman sebenar dengan yakin.</p>
            </div>
            <div class="faq-list">
          <details open>
            <summary>Apakah maksud N/A atau “Tidak dinilai”?</summary>
            <div class="faq-answer"><p>SecScan tidak mengeluarkan skor atau gred kerana scan tidak lengkap. Keadaan ini biasanya berlaku apabila sambungan gagal, server memulangkan halaman ralat, atau scanner menerima captcha/WAF challenge dan bukannya kandungan laman sebenar.</p></div>
          </details>
          <details>
            <summary>Kenapa N/A lebih tepat daripada terus beri gred F?</summary>
            <div class="faq-answer"><p>Gred F memberi isyarat bahawa banyak kawalan keselamatan telah diperiksa dan gagal. Jika scanner tidak dapat sampai ke laman sebenar, ia tidak mempunyai bukti untuk membuat kesimpulan itu. N/A membezakan masalah capaian atau perlindungan bot daripada kelemahan keselamatan yang disahkan.</p></div>
          </details>
          <details>
            <summary>Apa punca paling biasa keputusan N/A?</summary>
            <div class="faq-answer"><ul><li>HTTP 401, 403, 429 atau 5xx, termasuk rate limit dan halaman ralat.</li><li>Captcha, browser verification, WAF atau bot protection.</li><li>DNS, firewall, timeout rangkaian atau port 443 tidak boleh dicapai dari server scanner.</li><li>Redirect tidak selamat atau redirect yang tidak dapat diselesaikan.</li><li>Scan ke halaman dalaman yang memerlukan login.</li></ul></div>
          </details>
          <details>
            <summary>Bagaimana saya boleh dapatkan scan penuh selepas N/A?</summary>
            <div class="faq-answer"><ol><li>Semak mesej sebab pada hasil scan atau dashboard.</li><li>Allowlist IP/server scanner pada WAF, firewall atau bot protection.</li><li>Pastikan URL awam boleh dicapai melalui HTTPS dan tidak memulangkan captcha kepada scanner.</li><li>Jika laman memerlukan login, gunakan authenticated scan dengan sesi yang sah apabila fungsi itu dibenarkan oleh pentadbir.</li><li>Scan semula selepas perubahan dibuat.</li></ol></div>
          </details>
          <details>
            <summary>Adakah N/A masih direkodkan dalam dashboard?</summary>
            <div class="faq-answer"><p>Ya. Ia direkodkan sebagai N/A bersama sebab penilaian tidak dapat dibuat. Rekod tersebut tidak dikira sebagai skor 0, gred F, purata skor, julat risiko atau critical finding keselamatan dalam analitik dashboard.</p></div>
          </details>
            </div>
          </section>

          <section class="faq-section" id="scan" aria-labelledby="scanHeading">
            <div class="faq-section-heading"><p class="faq-overline">02 / SCAN</p><h2 id="scanHeading">Proses dan skor scan</h2><p>Bagaimana SecScan menilai permukaan web awam.</p></div>
            <div class="faq-list">
          <details><summary>Adakah SecScan menjalankan scan yang selamat?</summary><div class="faq-answer"><p>SecScan direka untuk pemerhatian keselamatan web yang dibenarkan. Ia menguji respons HTTP/HTTPS, headers, TLS, DNS, CMS dan endpoint biasa secara terkawal. Jalankan hanya terhadap domain yang anda miliki, uruskan atau mempunyai kebenaran bertulis untuk diuji.</p></div></details>
          <details><summary>Bagaimana skor dan gred dikira?</summary><div class="faq-answer"><p>Hanya dapatan yang boleh diskor digunakan. Dapatan pass, info, warning dan critical mempunyai pemberat berbeza; jumlahnya membentuk skor 0 hingga 100. Gred A+ hingga F kemudian diberikan, dengan perlindungan tambahan supaya beberapa dapatan kritikal tidak kelihatan terlalu ringan.</p></div></details>
          <details><summary>Adakah satu warning bermaksud laman telah digodam?</summary><div class="faq-answer"><p>Tidak semestinya. Warning ialah konfigurasi atau signal yang memerlukan semakan, seperti header yang tiada atau versi teknologi terdedah. Semak bukti, konteks aplikasi dan cadangan pembetulan sebelum membuat kesimpulan.</p></div></details>
          <details><summary>Kenapa keputusan boleh berubah antara scan?</summary><div class="faq-answer"><p>CDN, WAF, cache, DNS, penggiliran server, rate limit dan perubahan konfigurasi boleh menghasilkan respons berbeza. Bandingkan dapatan penting dan masa scan, bukan gred sahaja. Jika kerap berubah, scan dari rangkaian yang dibenarkan atau gunakan tetingkap penyelenggaraan.</p></div></details>
            </div>
          </section>

          <section class="faq-section" id="detection" aria-labelledby="detectionHeading">
            <div class="faq-section-heading"><p class="faq-overline">03 / PENGESANAN</p><h2 id="detectionHeading">CMS, WAF dan SEO poisoning</h2><p>Had dan bukti bagi pengesanan automatik.</p></div>
            <div class="faq-list">
          <details><summary>Kenapa CMS saya tidak dikesan?</summary><div class="faq-answer"><p>CMS boleh disembunyikan oleh WAF, cache, headless frontend, hardening atau halaman login. SecScan menggunakan tanda pada HTML, headers, cookies dan aset; “Tidak dikesan” bermaksud tiada bukti mencukupi daripada respons yang diterima, bukannya pengesahan bahawa CMS tidak digunakan.</p></div></details>
          <details><summary>Apakah maksud WAF atau captcha dikesan?</summary><div class="faq-answer"><p>Ini menunjukkan respons mempunyai fingerprint perlindungan edge, firewall aplikasi atau halaman pengesahan. Ia bukan kelemahan. Namun, ia boleh menghadkan pemeriksaan kandungan dan menyebabkan hasil N/A jika laman sebenar tidak dihantar kepada scanner.</p></div></details>
          <details><summary>Bagaimana SecScan mengesan SEO poisoning?</summary><div class="faq-answer"><p>Ia mencari indikator seperti spam tersembunyi, keyword stuffing, spam dalam metadata atau sitemap, external meta-refresh dan kandungan spam yang hanya dihantar kepada Googlebot atau Bingbot. Ia juga meliputi frasa judi, pharma dan Japanese keyword hack yang biasa digunakan dalam kompromi SEO.</p></div></details>
          <details><summary>Jika SEO poisoning tidak dikesan, adakah laman pasti bersih?</summary><div class="faq-answer"><p>Tidak. Semakan ini ialah indikator pasif dan bergantung pada respons awam ketika scan. Penyerang boleh menyasar IP, negara, masa atau sesi tertentu. Jika ada syak wasangka, semak Google Search Console, log web server, CMS users, cron jobs, fail yang baru berubah dan sitemap penuh.</p></div></details>
            </div>
          </section>

          <section class="faq-section" id="privacy" aria-labelledby="privacyHeading">
            <div class="faq-section-heading"><p class="faq-overline">04 / TINDAKAN</p><h2 id="privacyHeading">Akses, privasi dan tindakan susulan</h2><p>Gunakan scanner dengan kebenaran dan konteks yang betul.</p></div>
            <div class="faq-list">
          <details><summary>Adakah authenticated scan selamat digunakan?</summary><div class="faq-answer"><p>Gunakan hanya akaun atau sesi scan yang minimum dan khusus. Credentials hanya patut dihantar kepada origin HTTPS yang sama; jangan gunakan akaun pentadbir utama jika akaun audit berkeizinan rendah mencukupi. Tamatkan sesi selepas audit jika perlu.</p></div></details>
          <details><summary>Adakah SecScan membaiki isu secara automatik?</summary><div class="faq-answer"><p>Tidak. SecScan melaporkan bukti dan cadangan. Pembetulan perlu dibuat oleh pemilik sistem selepas menilai kesan kepada aplikasi, cache, CDN, integrasi dan polisi organisasi.</p></div></details>
          <details><summary>Apakah langkah pertama selepas jumpa critical finding?</summary><div class="faq-answer"><ol><li>Sahkan dapatan pada target dan semak sama ada ia benar-benar terdedah.</li><li>Hadkan akses atau tutup pendedahan segera jika perlu.</li><li>Baiki konfigurasi atau kemas kini komponen terjejas.</li><li>Scan semula dan simpan bukti sebelum/selepas untuk audit.</li></ol></div></details>
          <details><summary>Di mana saya boleh lihat sejarah scan?</summary><div class="faq-answer"><p>Papan Pemuka menyimpan sejarah target, masa scan, gred, status WAF, CMS dan dapatan utama. Rekod N/A dipisahkan supaya kegagalan capaian tidak menurunkan metrik keselamatan sebenar.</p></div></details>
            </div>
          </section>
        </div>
      </div>

      <section class="faq-cta" aria-label="Tindakan seterusnya">
        <div><h2>Masih perlukan semakan?</h2><p>Mulakan scan baharu selepas capaian scanner dibenarkan, atau semak audit pelayan Ubuntu untuk lapisan host.</p></div>
        <div class="faq-cta-actions"><a class="faq-primary" href="index.php">Buka Scanner</a><a class="faq-secondary" href="server-audit.php">Audit Server</a></div>
      </section>
    </main>

    <footer class="footer">
      <span>© 2026 SecScan Enterprise. Hak cipta terpelihara.</span>
      <span class="footer-version">Versi <?= htmlspecialchars($appVersion, ENT_QUOTES, 'UTF-8') ?></span>
      <nav class="footer-links" aria-label="Pautan SecScan">
        <a href="index.php">Scanner</a>
        <a href="server-audit.php">Audit Server</a>
        <a href="dashboard.php">Papan Pemuka</a>
        <a href="about.php">Tentang</a>
      </nav>
    </footer>
  </div>
</body>
</html>
