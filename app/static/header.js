(function(){
  function setActive() {
    var here = location.pathname;
    document.querySelectorAll("nav a[data-path]").forEach(function(a){
      if (a.getAttribute("data-path") === here) a.classList.add("active");
    });
  }
  function ensureHeader() {
    var hdr = document.getElementById("header");
<<<<<<< HEAD
    if (!hdr) return;
=======
    if (!hdr) return; // page may provide its own header
>>>>>>> 3cd270663acd16b2f2f143be7d63e11505082bcb
    var html = [
      '<div class="brand"><a href="/" data-path="/">Timeboard</a></div>',
      '<nav>',
      '  <a href="/" data-path="/">Dashboard</a>',
      '  <a href="/new" data-path="/new">New Task</a>',
      '  <a href="/about" data-path="/about">About</a>',
          '  <a href="/admin" data-path="/admin">Admin</a>',
      '</nav>'
    ].join("");
    hdr.innerHTML = html;
  }
  ensureHeader();
  setActive();
})();
