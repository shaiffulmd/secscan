// SecScan theme: auto (ikut sistem) + override manual via localStorage
(function () {
  var KEY = 'secscan-theme';
  var root = document.documentElement;

  function stored() {
    try { return localStorage.getItem(KEY); } catch (_) { return null; }
  }

  function apply(theme) {
    if (theme === 'light' || theme === 'dark') {
      root.setAttribute('data-theme', theme);
    } else {
      root.removeAttribute('data-theme');
    }
  }

  function effective() {
    var s = stored();
    if (s === 'light' || s === 'dark') return s;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  apply(stored());

  document.addEventListener('DOMContentLoaded', function () {
    var btn = document.getElementById('themeToggle');
    if (btn) {
      btn.addEventListener('click', function () {
        var next = effective() === 'dark' ? 'light' : 'dark';
        try { localStorage.setItem(KEY, next); } catch (_) {}
        apply(next);
      });
    }

    var copyBtn = document.getElementById('saCopyBtn');
    var curl = document.getElementById('saCurl');
    if (copyBtn && curl) {
      copyBtn.addEventListener('click', function () {
        var text = curl.textContent.trim();
        var done = function () {
          copyBtn.textContent = 'Disalin';
          copyBtn.classList.add('copied');
          setTimeout(function () {
            copyBtn.textContent = 'Salin';
            copyBtn.classList.remove('copied');
          }, 1800);
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(done).catch(fallback);
        } else {
          fallback();
        }
        function fallback() {
          var r = document.createRange();
          r.selectNodeContents(curl);
          var s = window.getSelection();
          s.removeAllRanges();
          s.addRange(r);
          try { document.execCommand('copy'); done(); } catch (_) {}
          s.removeAllRanges();
        }
      });
    }
  });
})();
