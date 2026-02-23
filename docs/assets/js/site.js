(function () {
  function ready(fn) {
    if (document.readyState !== 'loading') {
      fn();
    } else {
      document.addEventListener('DOMContentLoaded', fn);
    }
  }

  ready(function () {
    var btn = document.querySelector('[data-nav-toggle]');
    var nav = document.querySelector('[data-nav]');
    if (!btn || !nav) return;

    btn.addEventListener('click', function () {
      nav.classList.toggle('open');
      var expanded = nav.classList.contains('open') ? 'true' : 'false';
      btn.setAttribute('aria-expanded', expanded);
    });

    // Close menu when navigating
    nav.addEventListener('click', function (e) {
      if (e.target && e.target.tagName === 'A') {
        nav.classList.remove('open');
        btn.setAttribute('aria-expanded', 'false');
      }
    });
  });
})();
