(async function(){
  let meta = {};
  try { const r = await fetch('/api/meta'); meta = await r.json(); } catch(e){}
  // fetch version.json
  let v = { version: meta.release || 'dev'};
  try { const r = await fetch('/assets/version.json'); v = await r.json(); } catch(e){}
  const powered = meta.powered_by ? `Powered by ${meta.powered_by}` : '';
  const el = document.getElementById('footer');
  if (!el) return;
  el.classList.add('site-footer');
  el.innerHTML = `
    <div class="left">&copy; 2025</div>
    <div class="right">
      <span class="version-badge">{v.version || meta.release || 'dev'}</span>
      &nbsp;|&nbsp; <span class="powered-by">{powered}</span>
      &nbsp;|&nbsp; <a href="{meta.repository_url || '#'}" target="_blank" rel="noopener">Repository</a>
    </div>`;
})();
