(async function(){
  function esc(s){ return String(s||""); }
  var meta = {};
  try {
    var r = await fetch("/api/meta");
    meta = await r.json();
  } catch(e){ meta = {}; }
  var v = {};
  try {
    var r2 = await fetch("/assets/version.json");
    v = await r2.json();
  } catch(e){ v = {}; }

  var el = document.getElementById("footer");
  if (!el) return;
  el.classList.add("site-footer");
  var version = esc(v.version || meta.release || "dev");
  var repo = esc(meta.repository_url || "#");
  var powered = esc(meta.powered_by || "");
  el.innerHTML = [
    '<div class="left">&copy; 2025</div>',
    '<div class="right">',
    '  <span class="version-badge">', version, '</span>',
    powered ? ' &nbsp;|&nbsp; <span class="powered-by">Powered by '+powered+'</span>' : '',
<<<<<<< HEAD
    repo && repo !== "#" ? ' &nbsp;|&nbsp; <a href="'+repo+'" target="_blank" rel="noopener">Repository</a>' : '',
=======
    ' &nbsp;|&nbsp; <a href="', repo, '" target="_blank" rel="noopener">Repository</a>',
>>>>>>> 3cd270663acd16b2f2f143be7d63e11505082bcb
    '</div>'
  ].join("");
})();
