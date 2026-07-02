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
    if (!btn) return;
    btn.addEventListener('click', function () {
      var next = effective() === 'dark' ? 'light' : 'dark';
      try { localStorage.setItem(KEY, next); } catch (_) {}
      apply(next);
    });
  });
})();
