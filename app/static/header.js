(function(){
  function setActive() {
    var here = location.pathname;
    document.querySelectorAll("nav a[data-path]").forEach(function(a){
      if (a.getAttribute("data-path") === here) a.classList.add("active");
    });
  }
  function ensureHeader() {
    var hdr = document.getElementById("header");
    if (!hdr) return;
    var html = [
      '<div class="brand"><a href="/" data-path="/">Timeboard</a></div>',
      '<nav>',
      '  <a href="/" data-path="/">Dashboard</a>',
      '  <a href="/new" data-path="/new">New Task</a>',
      '  <a href="/about" data-path="/about">About</a>',
      '</nav>'
    ].join("");
    hdr.innerHTML = html;
  }
  ensureHeader();
  setActive();
})();
