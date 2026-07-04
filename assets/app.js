  (function () {
    'use strict';

    const scanForm       = document.getElementById('scanForm');
    const urlInput       = document.getElementById('urlInput');
    const scanBtn        = document.getElementById('scanBtn');
    const termStatus     = document.getElementById('termStatus');
    const errorBox       = document.getElementById('errorBox');
    const errorMsg       = document.getElementById('errorMsg');
    const progressSec    = document.getElementById('progressSection');
    const progressFill   = document.getElementById('progressFill');
    const progressLabel  = document.getElementById('progressLabel');
    const progressPct    = document.getElementById('progressPct');
    const progressText   = document.getElementById('progressText');
    const resultsSec     = document.getElementById('resultsSection');
    const termsModal     = document.getElementById('termsModal');
    const termsAgreeBtn  = document.getElementById('termsAgreeBtn');
    const termsCancelBtn = document.getElementById('termsCancelBtn');
    const legalModal     = document.getElementById('legalModal');
    const legalModalTitle = document.getElementById('legalModalTitle');
    const legalModalBody = document.getElementById('legalModalBody');
    const legalModalCloseBtn = document.getElementById('legalModalCloseBtn');
    const legalLinks     = document.querySelectorAll('[data-legal-modal]');

    const targetName     = document.getElementById('targetName');
    const targetUrl      = document.getElementById('targetUrl');
    const targetMetaGrid = document.getElementById('targetMetaGrid');

    const tabSecurity    = document.getElementById('tabSecurity');
    const tabPci         = document.getElementById('tabPci');
    const printA4Btn     = document.getElementById('printA4Btn');
    const saveA4Btn      = document.getElementById('saveA4Btn');
    const copyResultBtn  = document.getElementById('copyResultBtn');
    const tabSecurityBadge = document.getElementById('tabSecurityBadge');
    const tabPciBadge      = document.getElementById('tabPciBadge');
    const securityTabPanel = document.getElementById('securityTabPanel');
    const pciTabPanel      = document.getElementById('pciTabPanel');

    const securityMiniMeta = document.getElementById('securityMiniMeta');
    const pciMiniMeta      = document.getElementById('pciMiniMeta');
    const securityOverview = document.getElementById('securityOverview');
    const pciOverview      = document.getElementById('pciOverview');
    const findingsCont     = document.getElementById('findingsContainer');
    const recommendationsCont = document.getElementById('recommendationsContainer');
    const categoryScoresCont  = document.getElementById('categoryScoresContainer');
    const pciControlsCont  = document.getElementById('pciControlsContainer');

    // Live Exposure Intelligence card (hero aside) — filled from real scan data.
    const intelWaf       = document.getElementById('intelWaf');
    const intelGradeCard = document.getElementById('intelGradeCard');
    const intelGrade     = document.getElementById('intelGrade');
    const intelGradeTitle= document.getElementById('intelGradeTitle');
    const intelGradeDesc = document.getElementById('intelGradeDesc');
    const intelScale     = document.getElementById('intelScale');
    const intelCms       = document.getElementById('intelCms');
    const intelProbe     = document.getElementById('intelProbe');
    const intelIp        = document.getElementById('intelIp');

    let isScanning = false;
    let progressInterval = null;
    let lastReport = null;
    let pendingScanUrl = '';
    const TERMS_COOKIE = 'secscan_terms_accepted';
    const TERMS_VERSION = 'v1';
    const TERMS_MAX_AGE = 60 * 60 * 24 * 30;
    const legalContent = {
      terms: {
        title: 'Terma Penggunaan',
        body: `
          <p>SecScan hanya boleh digunakan untuk domain, aplikasi, atau sistem yang anda miliki, urus, atau telah mendapat kebenaran bertulis untuk diuji.</p>
          <ul>
            <li>Setiap scan direkod bersama masa, target, dan IP pengguna untuk tujuan audit.</li>
            <li>Pengguna bertanggungjawab memastikan aktiviti scan mematuhi polisi organisasi dan undang-undang berkaitan.</li>
            <li>Jangan gunakan SecScan untuk menguji sistem pihak ketiga tanpa kebenaran rasmi.</li>
          </ul>
        `
      },
      privacy: {
        title: 'Privasi',
        body: `
          <p>SecScan menyimpan maklumat minimum yang diperlukan untuk operasi keselamatan dan audit dalaman.</p>
          <ul>
            <li>Data scan seperti URL, keputusan keselamatan, status WAF, CMS, dan IP pengimbas boleh disimpan dalam rekod sistem.</li>
            <li>Kuki persetujuan digunakan untuk mengingati penerimaan terma selama 30 hari pada pelayar ini.</li>
            <li>Maklumat tidak bertujuan dijual atau dikongsi di luar organisasi tanpa asas operasi yang sah.</li>
          </ul>
        `
      },
      disclaimer: {
        title: 'Penafian',
        body: `
          <p>Keputusan scan ialah petunjuk teknikal berdasarkan semakan automatik dan tidak menggantikan penilaian keselamatan penuh oleh pasukan berkelayakan.</p>
          <ul>
            <li>Sesetengah kawalan, captcha, WAF, atau konfigurasi rangkaian boleh mengehadkan ketepatan keputusan.</li>
            <li>Gunakan laporan sebagai panduan tindakan susulan, bukan sebagai jaminan bahawa sistem bebas risiko.</li>
            <li>Jalankan pengesahan manual untuk isu kritikal sebelum membuat keputusan operasi.</li>
          </ul>
        `
      }
    };

    function switchResultTab(tab) {
      const isSecurity = tab === 'security';
      tabSecurity.classList.toggle('active', isSecurity);
      tabPci.classList.toggle('active', !isSecurity);
      securityTabPanel.classList.toggle('active', isSecurity);
      pciTabPanel.classList.toggle('active', !isSecurity);
    }

    function copyResults() {
      if (!lastReport) { showError('Tiada result untuk disalin.'); return; }
      const text = buildPlainReport(lastReport.data, lastReport.pci);
      copyToClipboard(text);
    }

    function saveA4Report() {
      if (!lastReport) { showError('Tiada result untuk disimpan.'); return; }
      const html = buildA4Html(lastReport.data, lastReport.pci);
      const filename = 'secscan-report-' + safeFilename(lastReport.data.hostname || 'target') + '.html';
      const blobUrl = URL.createObjectURL(new Blob([html], { type: 'text/html;charset=utf-8' }));
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(blobUrl), 1200);
    }

    function printA4Report() {
      if (!lastReport) { showError('Tiada result untuk dicetak.'); return; }

      // Elak popup blocker: jangan guna window.open().
      // Hidden iframe lebih stabil kerana tidak mencipta tab/window baharu.
      const html = buildA4Html(lastReport.data, lastReport.pci, true);
      const oldFrame = document.getElementById('secscanPrintFrame');
      if (oldFrame) oldFrame.remove();

      const frame = document.createElement('iframe');
      frame.id = 'secscanPrintFrame';
      frame.title = 'SecScan A4 Print Frame';
      frame.setAttribute('aria-hidden', 'true');
      frame.style.position = 'fixed';
      frame.style.right = '0';
      frame.style.bottom = '0';
      frame.style.width = '0';
      frame.style.height = '0';
      frame.style.border = '0';
      frame.style.opacity = '0';
      frame.style.pointerEvents = 'none';
      document.body.appendChild(frame);

      let printBlobUrl = '';
      try {
        printBlobUrl = URL.createObjectURL(new Blob([html], { type: 'text/html;charset=utf-8' }));
        frame.src = printBlobUrl;
      } catch (err) {
        frame.remove();
        showError('Gagal menyediakan dokumen cetakan. Cuba SAVE HTML dan print manual.');
        return;
      }

      let printed = false;
      const cleanup = () => {
        setTimeout(() => {
          const f = document.getElementById('secscanPrintFrame');
          if (f) f.remove();
          if (printBlobUrl) URL.revokeObjectURL(printBlobUrl);
        }, 1200);
      };

      const doPrint = () => {
        if (printed) return;
        printed = true;
        try {
          frame.contentWindow.focus();
          frame.contentWindow.print();
          cleanup();
        } catch (err) {
          console.error(err);
          cleanup();
          showError('Gagal buka dialog print. Cuba SAVE HTML dan print manual.');
        }
      };

      // Beri masa CSS @page A4 dan table layout render sebelum dialog print.
      frame.onload = () => setTimeout(doPrint, 250);
      setTimeout(doPrint, 700); // fallback untuk browser yang tidak trigger iframe onload
    }

    tabSecurity.addEventListener('click', () => switchResultTab('security'));
    tabPci.addEventListener('click', () => switchResultTab('pci'));
    printA4Btn.addEventListener('click', printA4Report);
    saveA4Btn.addEventListener('click', saveA4Report);
    copyResultBtn.addEventListener('click', copyResults);

    // Live-intel card starts in a neutral idle state until the first scan.
    resetIntelCard();

    if (termsAgreeBtn) {
      termsAgreeBtn.addEventListener('click', () => {
        rememberTermsAcceptance();
        const url = pendingScanUrl;
        hideTermsModal();
        if (url) startScan(url);
      });
    }
    if (termsCancelBtn) {
      termsCancelBtn.addEventListener('click', hideTermsModal);
    }
    if (termsModal) {
      termsModal.addEventListener('click', e => {
        if (e.target === termsModal) hideTermsModal();
      });
    }
    legalLinks.forEach(link => {
      link.addEventListener('click', e => {
        e.preventDefault();
        showLegalModal(link.getAttribute('data-legal-modal'));
      });
    });
    if (legalModalCloseBtn) {
      legalModalCloseBtn.addEventListener('click', hideLegalModal);
    }
    if (legalModal) {
      legalModal.addEventListener('click', e => {
        if (e.target === legalModal) hideLegalModal();
      });
    }

    // Delegated toggle for the collapsible ecosystem-CVE block. Findings are
    // re-rendered on each scan, so a single listener on the container is enough.
    findingsCont.addEventListener('click', (e) => {
      const btn = e.target.closest('.cve-toggle');
      if (!btn || !findingsCont.contains(btn)) return;
      const panel = btn.parentElement.querySelector('.cve-hidden');
      if (!panel) return;
      const opening = panel.hasAttribute('hidden');
      if (opening) panel.removeAttribute('hidden');
      else panel.setAttribute('hidden', '');
      btn.setAttribute('aria-expanded', opening ? 'true' : 'false');
      btn.classList.toggle('open', opening);
      const count = panel.getAttribute('data-count') || '';
      const label = btn.querySelector('.cve-toggle-label');
      if (label) {
        label.textContent = opening
          ? `Sembunyikan ${count} CVE ekosistem (info)`
          : `Tunjuk ${count} CVE ekosistem (info — belum disahkan terpasang)`;
      }
    });

    urlInput.addEventListener('input', () => {
      hideError();
      termStatus.textContent = urlInput.value.trim() ? 'Menaip…' : '';
    });

    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' && legalModal && !legalModal.hasAttribute('hidden')) {
        hideLegalModal();
        return;
      }
      if (e.key === 'Escape' && termsModal && !termsModal.hasAttribute('hidden')) {
        hideTermsModal();
        return;
      }
      if (e.key === 'Escape' && !isScanning) {
        urlInput.value = '';
        hideError();
        termStatus.textContent = '';
        urlInput.focus();
      }
    });

    scanForm.addEventListener('submit', function (e) {
      e.preventDefault();
      if (isScanning) return;
      const url = urlInput.value.trim();
      if (!url) { showError('Sila masukkan URL atau domain.'); return; }
      if (!hasAcceptedTerms()) {
        showTermsModal(url);
        return;
      }
      startScan(url);
    });

    initIncomingScan();

    function showTermsModal(url) {
      if (!termsModal) {
        startScan(url);
        return;
      }
      pendingScanUrl = url;
      hideError();
      termsModal.hidden = false;
      termsModal.classList.add('show');
      setTimeout(() => termsAgreeBtn && termsAgreeBtn.focus(), 0);
    }

    function hideTermsModal() {
      pendingScanUrl = '';
      if (!termsModal) return;
      termsModal.classList.remove('show');
      termsModal.hidden = true;
      if (!isScanning) urlInput.focus();
    }

    function showLegalModal(type) {
      if (!legalModal || !legalModalTitle || !legalModalBody) return;
      const content = legalContent[type] || legalContent.terms;
      legalModalTitle.textContent = content.title;
      legalModalBody.innerHTML = content.body;
      legalModal.hidden = false;
      legalModal.classList.add('show');
      setTimeout(() => legalModalCloseBtn && legalModalCloseBtn.focus(), 0);
    }

    function hideLegalModal() {
      if (!legalModal) return;
      legalModal.classList.remove('show');
      legalModal.hidden = true;
    }

    function hasAcceptedTerms() {
      return getCookie(TERMS_COOKIE) === TERMS_VERSION;
    }

    function rememberTermsAcceptance() {
      const secure = window.location.protocol === 'https:' ? '; Secure' : '';
      document.cookie = `${TERMS_COOKIE}=${TERMS_VERSION}; Max-Age=${TERMS_MAX_AGE}; Path=/; SameSite=Lax${secure}`;
    }

    function getCookie(name) {
      const needle = encodeURIComponent(name) + '=';
      return document.cookie
        .split(';')
        .map(part => part.trim())
        .find(part => part.startsWith(needle))
        ?.slice(needle.length) || '';
    }

    function initIncomingScan() {
      const params = new URLSearchParams(window.location.search);
      const incomingUrl = (params.get('url') || params.get('target') || '').trim();
      if (!incomingUrl) return;

      urlInput.value = incomingUrl;
      hideError();
      termStatus.textContent = params.get('rescan') === '1'
        ? 'Rescan dari dashboard...'
        : 'URL dari dashboard dimuatkan.';

      if (params.get('rescan') !== '1') return;
      params.delete('rescan');
      const nextQuery = params.toString();
      const nextUrl = window.location.pathname + (nextQuery ? '?' + nextQuery : '') + window.location.hash;
      window.history.replaceState(null, '', nextUrl);
      setTimeout(() => scanForm.requestSubmit(), 120);
    }

    function startScan(url) {
      isScanning = true;
      scanBtn.classList.add('loading');
      scanBtn.disabled = true;
      hideError();
      hideResults();
      resetIntelCard();
      showProgress();
      termStatus.textContent = 'Mengimbas…';

      let pct = 0;
      const steps = [
        'Menyambung ke server...',
        'Memeriksa TLS dan sijil...',
        'Menganalisa security headers...',
        'Semak DNS, SPF dan DMARC...',
        'Mengesan exposure dan open ports...',
        'Menyusun laporan akhir...'
      ];
      let stepIdx = 0;
      progressInterval = setInterval(() => {
        pct = Math.min(pct + Math.random() * 11, 92);
        setProgress(pct, steps[stepIdx] || 'Memproses...');
        stepIdx = Math.min(stepIdx + 1, steps.length - 1);
      }, 650);

      const payload = { url };
      // Optional authenticated-scan fields (only present when the feature is enabled).
      const cookieEl = document.getElementById('authCookie');
      const headersEl = document.getElementById('authHeaders');
      if (cookieEl && cookieEl.value.trim() !== '') {
        payload.auth_cookie = cookieEl.value.trim();
      }
      if (headersEl && headersEl.value.trim() !== '') {
        payload.auth_headers = headersEl.value
          .split('\n')
          .map(l => l.trim())
          .filter(l => l !== '' && l.includes(':'));
      }

      fetch(window.location.pathname, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        body: JSON.stringify(payload)
      })
      .then(async r => {
        let data;
        try { data = await r.json(); }
        catch (_) { throw new Error('Response bukan JSON yang sah.'); }
        if (!r.ok && !data.error) throw new Error('HTTP ' + r.status);
        return data;
      })
      .then(data => {
        clearInterval(progressInterval);
        setProgress(100, 'Selesai!');
        setTimeout(() => {
          hideProgress();
          if (data.error) showError(data.error);
          else renderResults(data);
          resetBtn();
        }, 450);
      })
      .catch(err => {
        clearInterval(progressInterval);
        hideProgress();
        showError('Ralat rangkaian / render: ' + err.message);
        resetBtn();
      });
    }

    function resetBtn() {
      isScanning = false;
      scanBtn.classList.remove('loading');
      scanBtn.disabled = false;
      termStatus.textContent = '';
    }

    function showProgress() { progressSec.classList.add('show'); setProgress(0, 'Memulakan scan...'); }
    function hideProgress() { progressSec.classList.remove('show'); }
    function setProgress(pct, text) {
      progressFill.style.width = pct + '%';
      progressLabel.textContent = 'SCANNING';
      progressPct.textContent = Math.round(pct) + '%';
      progressText.textContent = text;
    }

    function showError(msg) { errorMsg.textContent = msg; errorBox.classList.add('show'); }
    function hideError() { errorBox.classList.remove('show'); }
    function hideResults() { resultsSec.classList.remove('show'); lastReport = null; }

    function renderResults(raw) {
      const data = normalizeScannerResult(raw || {});
      const pci = buildPciModel(data);
      lastReport = { data, pci, raw };

      renderTargetBanner(data);
      renderIntelCard(data);
      securityMiniMeta.textContent = `${data.duration || '-'} · ${data.total_checks} semakan`;
      pciMiniMeta.textContent = `${pci.total} kawalan · ${pci.status}`;
      tabSecurityBadge.textContent = data.total_checks;
      tabPciBadge.textContent = pci.total;

      securityOverview.innerHTML = renderAssessmentBody({
        label: 'Gred keselamatan',
        score: data.score,
        grade: data.grade,
        counts: { critical: data.critical, warning: data.warnings, info: data.info, pass: data.passed },
        total: data.total_checks,
        scoreLabel: `Skor: ${data.score}/100`,
        barLabel: 'Skor'
      });

      pciOverview.innerHTML = renderAssessmentBody({
        label: 'PCI DSS LITE',
        score: pci.score,
        grade: pci.grade,
        counts: pci.counts,
        total: pci.total,
        scoreLabel: `Skor: ${pci.score}/100`,
        barLabel: 'Pematuhan'
      });

      animateAssessment(securityOverview, data.score);
      animateAssessment(pciOverview, pci.score);

      recommendationsCont.innerHTML = renderScanBlockedPanel(data) + renderEbookPanel(data) + renderRecommendations(data.recommendations);
      categoryScoresCont.innerHTML = renderCategoryScores(data.category_scores);
      categoryScoresCont.querySelectorAll('.catscore-fill').forEach(el => {
        const sc = Number(el.getAttribute('data-score')) || 0;
        el.style.width = sc + '%';
        el.style.background = barGradient(sc);
      });
      findingsCont.innerHTML = renderCategoryCards(data.categories);
      pciControlsCont.innerHTML = renderPciControls(pci.controls);

      switchResultTab('security');
      resultsSec.classList.add('show');
      resultsSec.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function renderTargetBanner(data) {
      targetName.textContent = data.hostname || data.url || '—';
      targetUrl.textContent = data.url || '—';
      const target = data.target || {};
      const ipv4 = (target.ipv4 || []).length ? target.ipv4.join(', ') : 'Tidak dikesan';
      const ipv6 = (target.ipv6 || []).length ? target.ipv6.join(', ') : 'Tidak dikesan';
      const cms = data.detected_cms
        ? data.detected_cms + (data.detected_cms_version ? ' ' + data.detected_cms_version : '')
        : (data.scan_blocked ? 'Disekat captcha / validation' : 'Tidak dikesan');
      const scannerIp = data.scan_client_ip || 'Tidak dikesan';
      const items = [
        ['Protokol', (target.scheme || '').toUpperCase() || detectScheme(data.url)],
        ['CMS', cms],
        ['Masa scan', data.scan_time || '—'],
        ['IP pengguna scan', scannerIp],
        ['IPv4', ipv4],
        ['IPv6', ipv6],
      ];
      targetMetaGrid.innerHTML = items.map(([label,value]) => `
        <div class="target-chip">
          <div class="target-chip-label">${escHtml(label)}</div>
          <div class="target-chip-value">${escHtml(value)}</div>
        </div>
      `).join('');
    }

    function gradeTone(score) {
      score = Number(score || 0);
      if (score >= 70) return 'good';
      if (score >= 45) return 'warn';
      return 'bad';
    }

    function setGradeScale(score, tone) {
      if (!intelScale) return;
      const active = Math.max(0, Math.min(5, Math.ceil(Number(score || 0) / 20)));
      const stepClass = tone === 'bad' ? 'bad' : (tone === 'warn' ? 'warn' : 'active');
      intelScale.querySelectorAll('span').forEach((span, i) => {
        span.className = i < active ? stepClass : '';
      });
    }

    function resetIntelCard() {
      if (!intelGradeCard) return;
      if (intelWaf) { intelWaf.textContent = 'Menunggu scan'; intelWaf.className = 'intel-badge'; }
      intelGradeCard.className = 'security-grade-card tone-idle';
      if (intelGrade) intelGrade.innerHTML = '&ndash;';
      if (intelGradeTitle) intelGradeTitle.innerHTML = 'Gred Keselamatan: &mdash;';
      if (intelGradeDesc) intelGradeDesc.textContent = 'Masukkan URL dan jalankan scan untuk melihat gred keselamatan, CMS, dan status WAF secara langsung.';
      if (intelScale) intelScale.querySelectorAll('span').forEach(s => { s.className = ''; });
      if (intelCms) intelCms.innerHTML = '&mdash;';
      if (intelProbe) intelProbe.innerHTML = '&mdash;';
      if (intelIp) intelIp.innerHTML = '&mdash;';
    }

    function renderIntelCard(data) {
      if (!intelGradeCard) return;
      const score = Math.max(0, Math.min(100, Number(data.score || 0)));
      const grade = data.grade || gradeFromScore(score);
      const tone = gradeTone(score);

      intelGradeCard.className = 'security-grade-card tone-' + tone;
      if (intelGrade) intelGrade.textContent = grade;
      if (intelGradeTitle) intelGradeTitle.textContent = 'Gred Keselamatan: ' + grade;
      if (intelGradeDesc) {
        intelGradeDesc.textContent =
          `${data.critical} kritikal · ${data.warnings} amaran · skor ${score}/100 daripada ${data.total_checks} semakan.`;
      }
      setGradeScale(score, tone);

      // WAF / captcha badge + active probe row.
      if (data.scan_blocked) {
        const blockType = data.scan_blocked_type || 'Captcha / WAF';
        if (intelWaf) { intelWaf.textContent = 'WAF dikesan'; intelWaf.className = 'intel-badge warn'; }
        if (intelProbe) intelProbe.textContent = blockType.charAt(0).toUpperCase() + blockType.slice(1) + ' disekat';
      } else {
        if (intelWaf) { intelWaf.textContent = 'Tiada sekatan dikesan'; intelWaf.className = 'intel-badge'; }
        if (intelProbe) intelProbe.textContent = 'Lulus';
      }

      // CMS fingerprint.
      const cms = data.detected_cms
        ? data.detected_cms + (data.detected_cms_version ? ' ' + data.detected_cms_version : '')
        : (data.scan_blocked ? 'Disekat captcha' : 'Tidak dikesan');
      if (intelCms) intelCms.textContent = cms;
      if (intelIp) intelIp.textContent = data.scan_client_ip || 'Tidak dikesan';
    }

    function renderScanBlockedPanel(data) {
      if (!data.scan_blocked) return '';
      const detail = data.scan_blocked_detail || {};
      const title = detail.title || 'Scan disekat oleh captcha / validation page';
      const message = detail.message || 'Server tidak memulangkan HTML sebenar laman web kepada scanner.';
      const actions = Array.isArray(detail.actions) && detail.actions.length
        ? detail.actions
        : [
            'Allowlist IP/server scanner di WAF atau bot protection.',
            'Jalankan authenticated scan dengan cookie/session yang sudah melepasi captcha.',
            'Cuba semula selepas validation page dimatikan untuk endpoint scanner.'
          ];
      return `
        <div class="blocked-panel">
          <div class="blocked-icon" aria-hidden="true">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
              <path d="M12 3 3.8 7v5.6c0 4.2 2.7 7.9 8.2 9.4 5.5-1.5 8.2-5.2 8.2-9.4V7L12 3Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>
              <path d="M8.5 12h7M12 8.5v7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
            </svg>
          </div>
          <div class="blocked-main">
            <div class="blocked-kicker">Perlu tindakan sebelum scan lengkap</div>
            <div class="blocked-title">${escHtml(title)}</div>
            <div class="blocked-msg">${escHtml(message)}</div>
            <div class="blocked-steps">
              ${actions.map((action, i) => `
                <div class="blocked-step">
                  <span>${i + 1}</span>
                  <p>${escHtml(action)}</p>
                </div>`).join('')}
            </div>
          </div>
        </div>`;
    }

    function renderAssessmentBody(model) {
      const counts = model.counts || {};
      const total = Math.max(1, Number(model.total || 1));
      const cards = ['critical','warning','info','pass'].map(key => {
        const count = Number(counts[key] || 0);
        const pct = ((count / total) * 100).toFixed(1).replace('.0','');
        return `
          <div class="metric-card ${key}">
            <div class="metric-head">
              <div class="metric-icon">${severityIcon(key)}</div>
              <div class="metric-label">${sevLabel(key)}</div>
            </div>
            <div class="metric-main">
              <div class="metric-value">${count}</div>
              <div class="metric-sub">${pct}% daripada semakan</div>
            </div>
          </div>`;
      }).join('');

      const safeScore = Math.max(0, Math.min(100, Number(model.score || 0)));
      return `
        <div class="grade-card" data-score="${safeScore}">
          <div class="grade-card-title">${escHtml(model.label || 'Gred')}</div>
          <div class="score-ring">
            <div class="score-ring-inner">
              <div class="score-grade">${escHtml(model.grade || 'F')}</div>
              <div class="score-ring-sub">Gred</div>
            </div>
          </div>
          <div class="score-pill">${safeScore}%</div>
          <div class="grade-stats">
            <div class="grade-stats-row">
              <div class="grade-stat-label">${escHtml(model.barLabel || 'Skor')}</div>
              <div class="grade-stat-value">${escHtml(model.scoreLabel || '')}</div>
            </div>
            <div class="grade-progress"><div class="grade-progress-fill"></div></div>
          </div>
        </div>
        <div class="status-grid">${cards}</div>
      `;
    }

    function animateAssessment(container, score) {
      const ring = container.querySelector('.score-ring');
      const bar = container.querySelector('.grade-progress-fill');
      const safeScore = Math.max(0, Math.min(100, Number(score || 0)));
      setTimeout(() => {
        if (ring) {
          ring.style.setProperty('--score', safeScore);
          ring.style.setProperty('--ring-color', ringColor(safeScore));
          const grade = ring.querySelector('.score-grade');
          if (grade) grade.style.color = ringColor(safeScore);
        }
        if (bar) {
          bar.style.width = safeScore + '%';
          bar.style.background = barGradient(safeScore);
        }
      }, 80);
    }

    // Panel ebook — hanya muncul bila WordPress atau Joomla dikesan.
    // Jika CMS lain / tiada dikesan, kembalikan '' (link tersembunyi).
    const EBOOKS = {
      wordpress: { file: 'ebooks/wordpress-hardening-secscan.pdf', label: 'WordPress' },
      joomla:    { file: 'ebooks/joomla-hardening-secscan.pdf',    label: 'Joomla' }
    };
    function renderEbookPanel(data) {
      const key = String(data.detected_cms || '').trim().toLowerCase();
      const book = EBOOKS[key];
      if (!book) return '';
      const ver = data.detected_cms_version ? ` ${escHtml(data.detected_cms_version)}` : '';
      return `
        <div class="recs-panel ebook-panel">
          <div class="recs-head">
            <span class="recs-title">Panduan pengukuhan ${escHtml(book.label)} dikesan</span>
          </div>
          <div class="ebook-body">
            <div class="ebook-icon" aria-hidden="true">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
                <path d="M4 5.5A1.5 1.5 0 0 1 5.5 4H18a2 2 0 0 1 2 2v13a1 1 0 0 1-1 1H6a2 2 0 0 1-2-2V5.5Z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/>
                <path d="M8 4v13m-2 0h12" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>
              </svg>
            </div>
            <div class="ebook-text">
              <div class="ebook-title">Laman anda menggunakan ${escHtml(book.label)}${ver}</div>
              <div class="ebook-sub">Ebook percuma (PDF) — amalan pengukuhan rasmi ${escHtml(book.label)} dipetakan kepada setiap semakan SecScan, termasuk senarai semak pantas.</div>
            </div>
            <a class="ebook-btn" href="${escHtml(book.file)}" download>
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none">
                <path d="M12 3v12m0 0 4-4m-4 4-4-4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                <path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
              </svg>
              Muat turun ebook
            </a>
          </div>
        </div>`;
    }

    function renderRecommendations(recs) {
      const list = Array.isArray(recs) ? recs : [];
      if (!list.length) {
        return `
          <div class="recs-panel recs-clean">
            <div class="recs-head"><span class="recs-title">Utamakan pembetulan ini</span></div>
            <div class="recs-empty">Tiada isu critical atau warning dikesan. Bagus!</div>
          </div>`;
      }
      const rows = list.map(r => {
        const sev = normalizeSeverity(r.severity);
        const refs = (Array.isArray(r.references) && r.references.length)
          ? `<div class="rec-refs">${r.references.map((u, i) => `<a href="${escHtml(u)}" target="_blank" rel="noopener noreferrer">Rujukan ${i + 1}</a>`).join(' · ')}</div>`
          : '';
        const quick = r.quick_win ? `<span class="rec-quickwin">Tindakan pantas</span>` : '';
        return `
          <div class="rec-row rec-${sev}">
            <div class="rec-rank">${Number(r.priority) || ''}</div>
            <div class="rec-main">
              <div class="rec-line1">
                <span class="finding-badge badge-${sev}">${sevLabel(sev)}</span>
                <span class="rec-check">${escHtml(r.check || '')}</span>
                <span class="rec-cat">${escHtml(r.category || '')}</span>
                ${quick}
              </div>
              <div class="rec-issue">${escHtml(r.issue || '')}</div>
              <div class="rec-action">${escHtml(r.action || '')}</div>
              ${refs}
            </div>
          </div>`;
      }).join('');
      return `
        <div class="recs-panel">
          <div class="recs-head"><span class="recs-title">Utamakan pembetulan ini</span><span class="recs-count">${list.length} isu</span></div>
          <div class="recs-body">${rows}</div>
        </div>`;
    }

    function renderCategoryScores(scores) {
      const entries = Object.entries(scores || {});
      if (!entries.length) return '';
      const rows = entries.map(([cat, info]) => {
        const sc = Number(info && info.score) || 0;
        const grade = (info && info.grade) || gradeFromScore(sc);
        const checks = Number(info && info.checks) || 0;
        return `
          <div class="catscore-row">
            <div class="catscore-name">${escHtml(cat)}</div>
            <div class="catscore-track"><div class="catscore-fill" data-score="${sc}"></div></div>
            <div class="catscore-val"><strong>${sc}</strong><span class="catscore-grade grade-${String(grade).replace('+','plus')}">${escHtml(grade)}</span><span class="catscore-checks">${checks} semakan</span></div>
          </div>`;
      }).join('');
      return `
        <div class="recs-panel">
          <div class="recs-head"><span class="recs-title">Skor mengikut kategori</span></div>
          <div class="catscore-body">${rows}</div>
        </div>`;
    }

    // An ecosystem CVE is one that the scanner listed as intelligence only —
    // not fingerprinted as installed on this site. These are collapsed by
    // default so confirmed/installed findings stay front-and-centre.
    function isUnconfirmedCve(f) {
      return /^CVE-\d{4}-\d+$/i.test(String(f.check || '').trim())
          && /not confirmed installed|ecosystem cve/i.test(String(f.message || ''));
    }

    function renderFindingRow(f) {
      const sev = normalizeSeverity(f.severity);
      return `
            <div class="finding-row">
              <div class="finding-badge badge-${sev}">${sevLabel(sev)}</div>
              <div class="finding-content">
                <div class="finding-check">${escHtml(f.check || 'Semakan tidak diketahui')}</div>
                <div class="finding-msg">${escHtml(f.message || '')}</div>
                ${f.recommendation ? `<div class="finding-rec">${escHtml(f.recommendation)}</div>` : ''}
                ${(Array.isArray(f.references) && f.references.length) ? `<div class="finding-refs">${f.references.map((u, i) => `<a href="${escHtml(u)}" target="_blank" rel="noopener noreferrer">Rujukan ${i + 1}</a>`).join(' · ')}</div>` : ''}
              </div>
            </div>`;
    }

    function renderCategoryCards(categories) {
      const severityOrder = { critical: 0, warning: 1, info: 2, pass: 3 };
      const entries = Object.entries(categories || {});
      if (!entries.length) return '<div class="category-card"><div class="category-body"><div class="finding-msg">Tiada dapatan diterima daripada pengimbas.</div></div></div>';

      return entries.map(([category, list]) => {
        const all = list || [];
        const counts = { critical:0, warning:0, info:0, pass:0 };
        all.forEach(f => counts[normalizeSeverity(f.severity)]++);

        // Split: confirmed/normal findings stay visible; unconfirmed ecosystem
        // CVEs go into a collapsed block revealed on click.
        const visible = [];
        const hiddenCves = [];
        all.forEach(f => (isUnconfirmedCve(f) ? hiddenCves : visible).push(f));

        const sortFn = (a,b) => (severityOrder[normalizeSeverity(a.severity)] ?? 9) - (severityOrder[normalizeSeverity(b.severity)] ?? 9);
        const rows = [...visible].sort(sortFn).map(renderFindingRow).join('');

        let hiddenBlock = '';
        if (hiddenCves.length) {
          const hiddenRows = hiddenCves.map(renderFindingRow).join('');
          hiddenBlock = `
            <div class="cve-collapse">
              <button type="button" class="cve-toggle" aria-expanded="false">
                <span class="cve-toggle-icon">▸</span>
                <span class="cve-toggle-label">Tunjuk ${hiddenCves.length} CVE ekosistem (info — belum disahkan terpasang)</span>
              </button>
              <div class="cve-hidden" data-count="${hiddenCves.length}" hidden>${hiddenRows}</div>
            </div>`;
        }

        const dots = ['critical','warning','info','pass']
          .filter(k => counts[k] > 0)
          .map(k => `<span class="severity-dot ${k}">${counts[k]} ${sevLabel(k)}</span>`)
          .join('');

        return `
          <div class="category-card">
            <div class="category-head">
              <div class="category-title-wrap">
                <div class="category-title">${escHtml(category)}</div>
                <div class="category-meta">${all.length} semakan</div>
              </div>
              <div class="severity-dots">${dots}</div>
            </div>
            <div class="category-body">${rows}${hiddenBlock}</div>
          </div>`;
      }).join('');
    }

    function renderPciControls(controls) {
      return (controls || []).map(c => `
        <div class="pci-control-card">
          <div class="pci-control-badge ${normalizeSeverity(c.severity)}">${sevLabel(c.severity)}</div>
          <div class="pci-control-body">
            <div class="pci-control-title">${escHtml(c.title)}</div>
            <div class="pci-control-msg">${escHtml(c.message)}</div>
            ${c.recommendation ? `<div class="pci-control-rec">${escHtml(c.recommendation)}</div>` : ''}
          </div>
        </div>`).join('');
    }

    function normalizeScannerResult(data) {
      const categories = data.categories && typeof data.categories === 'object'
        ? data.categories
        : groupLegacyFindings(Array.isArray(data.findings) ? data.findings : []);

      const normalizedCategories = {};
      const findings = [];
      Object.keys(categories || {}).forEach(category => {
        const list = Array.isArray(categories[category]) ? categories[category] : [];
        normalizedCategories[category] = list.map(f => ({
          category,
          check: f.check || 'Unknown check',
          severity: normalizeSeverity(f.severity),
          message: f.message || '',
          recommendation: f.recommendation || '',
          references: Array.isArray(f.references) ? f.references : []
        }));
        findings.push(...normalizedCategories[category]);
      });

      const counts = { critical:0, warnings:0, info:0, passed:0 };
      findings.forEach(f => {
        if (f.severity === 'critical') counts.critical++;
        else if (f.severity === 'warning') counts.warnings++;
        else if (f.severity === 'pass') counts.passed++;
        else counts.info++;
      });

      const cmsInfo = normalizeDetectedCms(data, findings);
      const target = data.target || {};
      const serverIp = data.server_ip || {};
      target.ipv4 = Array.isArray(target.ipv4) ? target.ipv4 : (Array.isArray(serverIp.ipv4) ? serverIp.ipv4 : []);
      target.ipv6 = Array.isArray(target.ipv6) ? target.ipv6 : (Array.isArray(serverIp.ipv6) ? serverIp.ipv6 : []);
      target.scheme = target.scheme || (String(data.url || '').startsWith('https://') ? 'https' : 'http');
      target.hostname = target.hostname || data.hostname || data.host || '';

      return {
        url: data.url || target.url || '',
        hostname: data.hostname || data.host || target.hostname || '—',
        score: Number(data.score ?? 0),
        grade: String(data.grade || gradeFromScore(Number(data.score || 0))),
        total_checks: Number(data.total_checks || findings.length || 0),
        passed: Number(data.passed ?? counts.passed),
        info: Number(data.info ?? counts.info),
        warnings: Number(data.warnings ?? data.warning ?? counts.warnings),
        critical: Number(data.critical ?? counts.critical),
        scan_time: data.scan_time || data.scanTime || '',
        duration: data.duration || '',
        scan_client_ip: String(data.scan_client_ip || data.client_ip || (data.request && data.request.client_ip) || '').trim(),
        detected_cms: cmsInfo.name,
        detected_cms_version: cmsInfo.version,
        detected_cms_signals: Array.isArray(data.detected_cms_signals) ? data.detected_cms_signals : [],
        scan_blocked: Boolean(data.scan_blocked),
        scan_blocked_type: String(data.scan_blocked_type || ''),
        scan_blocked_detail: (data.scan_blocked_detail && typeof data.scan_blocked_detail === 'object') ? data.scan_blocked_detail : {},
        categories: normalizedCategories,
        category_scores: (data.category_scores && typeof data.category_scores === 'object') ? data.category_scores : {},
        recommendations: Array.isArray(data.recommendations) ? data.recommendations : [],
        findings,
        target
      };
    }

    function normalizeDetectedCms(data, findings) {
      const directName = String(data.detected_cms || data.detectedCms || '').trim();
      const directVersion = String(data.detected_cms_version || data.detectedCmsVersion || '').trim();
      if (directName) return { name: directName, version: directVersion };

      const cmsFinding = (findings || []).find(f =>
        f.category === 'Technology'
        && /^CMS Detected/i.test(String(f.check || ''))
        && /CMS:\s*/i.test(String(f.message || ''))
      );
      if (!cmsFinding) return { name: '', version: '' };

      const match = String(cmsFinding.message || '').match(/CMS:\s*([A-Za-z][A-Za-z0-9 ._-]*?)(?:\.|,|$)/);
      if (!match) return { name: '', version: '' };

      const known = ['WordPress', 'Joomla', 'Drupal', 'Shopify', 'Wix', 'Squarespace', 'Ghost'];
      const detected = match[1].trim();
      const name = known.find(cms => detected.toLowerCase().startsWith(cms.toLowerCase())) || detected;
      const version = detected.slice(name.length).trim();
      return { name, version };
    }

    function buildPciModel(data) {
      const findings = Array.isArray(data.findings) ? data.findings : [];
      const controls = [
        makePciControl('Penghantaran Selamat (HTTPS/TLS)', matchFindings(findings, f => ['Transport','TLS/SSL'].includes(f.category) || /HTTPS|HSTS|Certificate|Protocol|Cipher|TLS|SSL/i.test(f.check)), 'Pastikan semua data dihantar melalui HTTPS/TLS yang kuat.'),
        makePciControl('Pengepala Keselamatan Pelayar', matchFindings(findings, f => f.category === 'Headers' && /Content-Security-Policy|Strict-Transport-Security|X-Frame-Options|X-Content-Type-Options|Referrer-Policy|Permissions-Policy/i.test(f.check)), 'Aktifkan pengepala keselamatan yang sesuai untuk halaman pembayaran.'),
        makePciControl('Kebersihan Cookie & Sesi', matchFindings(findings, f => /Cookie/i.test(f.check) || /HttpOnly|SameSite|Secure/i.test(f.message)), 'Gunakan Secure, HttpOnly dan SameSite pada cookie sesi.'),
        makePciControl('Pengukuhan Halaman Pembayaran Sisi Klien', matchFindings(findings, f => f.category === 'HTML' && /Mixed Content|Subresource Integrity|Insecure Form Action|Meta CSP/i.test(f.check)), 'Kuatkan halaman pembayaran daripada kandungan bercampur dan skrip tidak terkawal.'),
        makePciControl('Kawalan Akses CORS', matchFindings(findings, f => f.category === 'CORS'), 'Hadkan akses rentas origin kepada origin yang dipercayai sahaja.'),
        makePciControl('Perlindungan Domain DNS / Emel', matchFindings(findings, f => f.category === 'DNS'), 'Kuatkan DNS, SPF dan DMARC untuk kurangkan risiko pemalsuan.'),
        makePciControl('Pendedahan Fail Sensitif', matchFindings(findings, f => f.category === 'Exposed Files'), 'Pastikan fail sensitif, sandaran dan konfigurasi tidak boleh dicapai awam.'),
        makePciControl('Pendedahan Servis / Port Awam', matchFindings(findings, f => f.category === 'Ports'), 'Tutup port awam yang tidak perlu dan lindungi akses servis.'),
        makePciControl('Pendedahan Maklumat', matchFindings(findings, f => /Server|Technology|Version|Leak/i.test(f.check) || /Server Leak/i.test(f.category)), 'Kurangkan maklumat pelayan/teknologi yang terdedah.'),
        makePciControl('Kesediaan Operasi Keselamatan', matchFindings(findings, f => /security.txt|Robots|HTTP Versions|Reachability/i.test(f.check) || ['Connection'].includes(f.category)), 'Pastikan operasi keselamatan, saluran pendedahan dan pengurusan permukaan jelas.'),
      ];

      const counts = { critical:0, warning:0, info:0, pass:0 };
      controls.forEach(c => counts[c.severity]++);
      const weights = { pass: 100, info: 70, warning: 35, critical: 0 };
      const score = Math.round(controls.reduce((sum, c) => sum + weights[c.severity], 0) / Math.max(1, controls.length));
      return {
        controls,
        total: controls.length,
        counts,
        score,
        grade: gradeFromScore(score),
        status: score >= 85 ? 'Good alignment' : (score >= 65 ? 'Partial alignment' : 'Action required')
      };
    }

    function makePciControl(title, relatedFindings, defaultRecommendation) {
      if (!relatedFindings.length) {
        return {
          title,
          severity: 'pass',
          message: 'Tiada signal negatif dikesan untuk kawalan ini berdasarkan scan luaran semasa.',
          recommendation: defaultRecommendation
        };
      }
      const sorted = [...relatedFindings].sort((a,b) => severityRank(a.severity) - severityRank(b.severity));
      const top = sorted[0];
      return {
        title,
        severity: normalizeSeverity(top.severity),
        message: top.message || 'Signal kawalan memerlukan perhatian.',
        recommendation: top.recommendation || defaultRecommendation
      };
    }

    function buildPlainReport(data, pci) {
      const lines = [];
      lines.push('SECSCAN REPORT');
      lines.push('Target: ' + (data.hostname || '-'));
      lines.push('URL: ' + (data.url || '-'));
      lines.push('Scan Time: ' + (data.scan_time || '-'));
      lines.push('Duration: ' + (data.duration || '-'));
      lines.push('IP pengimbas: ' + (data.scan_client_ip || '-'));
      if (data.scan_blocked) {
        const detail = data.scan_blocked_detail || {};
        lines.push('Status scan: ' + (detail.title || 'Disekat oleh captcha / halaman pengesahan'));
        lines.push('Tindakan: ' + (detail.message || 'Pengimbas tidak menerima HTML laman sebenar.'));
      }
      lines.push('');
      lines.push('SCAN KESELAMATAN');
      lines.push(`Skor: ${data.score}/100 | Gred: ${data.grade} | Semakan: ${data.total_checks}`);
      lines.push(`Kritikal: ${data.critical} | Amaran: ${data.warnings} | Info: ${data.info} | Lulus: ${data.passed}`);
      lines.push('');
      lines.push('PCI DSS LITE');
      lines.push(`Skor: ${pci.score}/100 | Gred: ${pci.grade} | Status: ${pci.status}`);
      lines.push(`Kritikal: ${pci.counts.critical} | Amaran: ${pci.counts.warning} | Info: ${pci.counts.info} | Lulus: ${pci.counts.pass}`);
      lines.push('');
      lines.push('DAPATAN');
      Object.entries(data.categories || {}).forEach(([cat, list]) => {
        lines.push('');
        lines.push('[' + cat + ']');
        (list || []).forEach(f => {
          lines.push(`- ${String(f.severity || '').toUpperCase()} | ${f.check}: ${f.message}`);
          if (f.recommendation) lines.push(`  Cadangan: ${f.recommendation}`);
        });
      });
      lines.push('');
      lines.push('PCI CONTROLS');
      (pci.controls || []).forEach(c => {
        lines.push(`- ${c.severity.toUpperCase()} | ${c.title}: ${c.message}`);
        if (c.recommendation) lines.push(`  Cadangan: ${c.recommendation}`);
      });
      return lines.join('\n');
    }

    function buildA4Html(data, pci, autoPrint = false) {
      const securityRows = Object.entries(data.categories || {}).flatMap(([cat, list]) =>
        (list || []).map(f => `<tr><td>${escHtml(cat)}</td><td>${escHtml(String(f.severity || '').toUpperCase())}</td><td><strong>${escHtml(f.check)}</strong><br>${escHtml(f.message)}${f.recommendation ? '<br><em>Cadangan: ' + escHtml(f.recommendation) + '</em>' : ''}</td></tr>`)
      ).join('');

      const pciRows = (pci.controls || []).map(c =>
        `<tr><td>${escHtml(String(c.severity || '').toUpperCase())}</td><td><strong>${escHtml(c.title)}</strong><br>${escHtml(c.message)}${c.recommendation ? '<br><em>Cadangan: ' + escHtml(c.recommendation) + '</em>' : ''}</td></tr>`
      ).join('');

      const ip4 = (data.target?.ipv4 || []).join(', ') || '-';
      const ip6 = (data.target?.ipv6 || []).join(', ') || '-';
      const scannerIp = data.scan_client_ip || '-';

      return `<!doctype html>
<html lang="ms">
<head>
<meta charset="utf-8">
<title>SecScan Report - ${escHtml(data.hostname)}</title>
<style>
  @page { size: A4; margin: 10mm; }
  * { box-sizing: border-box; }
  body { font-family: Arial, Helvetica, sans-serif; color:#111827; margin:0; font-size:10px; line-height:1.35; }
  h1 { font-size:16px; margin:0 0 3px; }
  h2 { font-size:12px; margin:12px 0 6px; border-bottom:1px solid #111827; padding-bottom:3px; }
  .muted { color:#4b5563; }
  .top { display:flex; justify-content:space-between; gap:12px; border-bottom:2px solid #111827; padding-bottom:8px; margin-bottom:8px; }
  .boxgrid { display:grid; grid-template-columns: repeat(4, 1fr); gap:5px; margin:6px 0 8px; }
  .box { border:1px solid #d1d5db; padding:5px 6px; border-radius:4px; min-height:34px; }
  .box b { display:block; font-size:11px; }
  .summary { display:grid; grid-template-columns: 1fr 1fr; gap:8px; }
  table { width:100%; border-collapse:collapse; page-break-inside:auto; }
  tr { page-break-inside:avoid; page-break-after:auto; }
  th,td { border:1px solid #d1d5db; padding:4px 5px; vertical-align:top; }
  th { background:#f3f4f6; text-align:left; font-size:9px; text-transform:uppercase; letter-spacing:.04em; }
  em { color:#374151; }
  .small { font-size:9px; }
  .footer { margin-top:10px; font-size:9px; color:#6b7280; border-top:1px solid #d1d5db; padding-top:5px; }
</style>
</head>
<body>
  <div class="top">
    <div>
      <h1>Laporan SecScan</h1>
      <div class="muted">${escHtml(data.hostname || '-')}</div>
      <div class="small">${escHtml(data.url || '-')}</div>
    </div>
    <div class="small">
      Scan: ${escHtml(data.scan_time || '-')}<br>
      Tempoh: ${escHtml(data.duration || '-')}<br>
      IP pengimbas: ${escHtml(scannerIp)}<br>
      IPv4: ${escHtml(ip4)}<br>
      IPv6: ${escHtml(ip6)}
    </div>
  </div>

  <div class="summary">
    <div>
      <h2>Scan Keselamatan</h2>
      <div class="boxgrid">
        <div class="box"><span>Gred</span><b>${escHtml(data.grade)}</b></div>
        <div class="box"><span>Skor</span><b>${data.score}/100</b></div>
        <div class="box"><span>Semakan</span><b>${data.total_checks}</b></div>
        <div class="box"><span>Lulus</span><b>${data.passed}</b></div>
      </div>
      <div class="boxgrid">
        <div class="box"><span>Kritikal</span><b>${data.critical}</b></div>
        <div class="box"><span>Amaran</span><b>${data.warnings}</b></div>
        <div class="box"><span>Info</span><b>${data.info}</b></div>
        <div class="box"><span>Lulus</span><b>${data.passed}</b></div>
      </div>
    </div>
    <div>
      <h2>PCI DSS Lite</h2>
      <div class="boxgrid">
        <div class="box"><span>Gred</span><b>${escHtml(pci.grade)}</b></div>
        <div class="box"><span>Skor</span><b>${pci.score}/100</b></div>
        <div class="box"><span>Kawalan</span><b>${pci.total}</b></div>
        <div class="box"><span>Status</span><b>${escHtml(pci.status)}</b></div>
      </div>
      <div class="boxgrid">
        <div class="box"><span>Kritikal</span><b>${pci.counts.critical}</b></div>
        <div class="box"><span>Amaran</span><b>${pci.counts.warning}</b></div>
        <div class="box"><span>Info</span><b>${pci.counts.info}</b></div>
        <div class="box"><span>Lulus</span><b>${pci.counts.pass}</b></div>
      </div>
    </div>
  </div>

  <h2>Dapatan Keselamatan</h2>
  <table>
    <thead><tr><th style="width:18%">Kategori</th><th style="width:12%">Keutamaan</th><th>Dapatan & Cadangan</th></tr></thead>
    <tbody>${securityRows || '<tr><td colspan="3">Tiada dapatan.</td></tr>'}</tbody>
  </table>

  <h2>Kawalan PCI DSS Lite</h2>
  <table>
    <thead><tr><th style="width:12%">Keutamaan</th><th>Kawalan & Cadangan</th></tr></thead>
    <tbody>${pciRows || '<tr><td colspan="2">Tiada kawalan.</td></tr>'}</tbody>
  </table>

  <div class="footer">Nota: PCI DSS Lite ialah signal luaran ringkas, bukan pensijilan PCI rasmi / ASV / QSA assessment.</div>
</body>
</html>`;
    }

    function copyToClipboard(text) {
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text)
          .then(() => alert('Result berjaya disalin.'))
          .catch(() => fallbackCopy(text));
      } else {
        fallbackCopy(text);
      }
    }

    function fallbackCopy(text) {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      try {
        document.execCommand('copy');
        alert('Result berjaya disalin.');
      } catch (_) {
        alert('Gagal salin. Sila copy manual.');
      }
      document.body.removeChild(ta);
    }

    function matchFindings(findings, predicate) { return findings.filter(predicate); }
    function severityRank(sev) {
      const map = { critical:0, warning:1, info:2, pass:3 };
      return map[normalizeSeverity(sev)] ?? 9;
    }
    function gradeFromScore(score) {
      score = Number(score || 0);
      if (score >= 90) return 'A+';
      if (score >= 80) return 'A';
      if (score >= 70) return 'B';
      if (score >= 60) return 'C';
      if (score >= 45) return 'D';
      return 'F';
    }
    function groupLegacyFindings(findings) {
      return findings.reduce((acc, f) => {
        const category = f.category || 'General';
        if (!acc[category]) acc[category] = [];
        acc[category].push(f);
        return acc;
      }, {});
    }
    function normalizeSeverity(severity) {
      severity = String(severity || 'info').toLowerCase();
      if (['high', 'medium', 'low', 'warn', 'warning'].includes(severity)) return 'warning';
      if (['ok', 'success', 'passed'].includes(severity)) return 'pass';
      if (severity === 'critical' || severity === 'pass' || severity === 'info') return severity;
      return 'info';
    }
    function sevLabel(sev) {
      const labels = { critical: 'Kritikal', warning: 'Amaran', info: 'Info', pass: 'Lulus' };
      return labels[normalizeSeverity(sev)] || 'Info';
    }
    function severityIcon(type) {
      const icons = {
        critical: '<svg viewBox="0 0 24 24" fill="none"><path d="M12 8v5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="16.5" r="1.2" fill="currentColor"/><path d="M10.4 3.8 3.8 15.1a2 2 0 0 0 1.72 3h13a2 2 0 0 0 1.73-3L13.6 3.8a2 2 0 0 0-3.2 0Z" stroke="currentColor" stroke-width="1.8" fill="none" stroke-linejoin="round"/></svg>',
        warning: '<svg viewBox="0 0 24 24" fill="none"><path d="M12 8v5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="16.5" r="1.2" fill="currentColor"/><path d="M10.4 3.8 3.8 15.1a2 2 0 0 0 1.72 3h13a2 2 0 0 0 1.73-3L13.6 3.8a2 2 0 0 0-3.2 0Z" stroke="currentColor" stroke-width="1.8" fill="none" stroke-linejoin="round"/></svg>',
        info: '<svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="8.5" stroke="currentColor" stroke-width="1.8"/><circle cx="12" cy="8.2" r="1.1" fill="currentColor"/><path d="M12 11v5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
        pass: '<svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="8.5" stroke="currentColor" stroke-width="1.8"/><path d="M7.5 12.5 10.5 15.4 16.7 9.2" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>'
      };
      return icons[type] || icons.info;
    }
    function barGradient(score) {
      return ringColor(score);
    }
    function ringColor(score) {
      score = Number(score || 0);
      if (score >= 80) return '#5B9E62';
      if (score >= 60) return '#4E8FC7';
      if (score >= 40) return '#C08A3E';
      return '#C75B52';
    }
    function detectScheme(url) {
      return String(url || '').toLowerCase().startsWith('https://') ? 'HTTPS' : 'HTTP';
    }
    function safeFilename(str) {
      return String(str || 'target').replace(/[^a-z0-9.-]+/gi, '-').replace(/^-+|-+$/g, '').toLowerCase() || 'target';
    }
    function escHtml(str) {
      return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }
  })();
