let meta = { tz:'UTC', release:'dev', repository_url:'#' };
async function getMeta(){ const r = await fetch('/api/meta'); meta = await r.json(); document.getElementById('footer').innerHTML = `v${meta.release} · <a href="${meta.repository_url}" target="_blank">repo</a>`; document.getElementById('tzLabel').textContent = `(${meta.tz})`; document.getElementById('cronTz').value = meta.tz; }
getMeta();

const form = document.getElementById('taskForm');
const modeSel = document.getElementById('modeSel');
const blocks = { none:document.getElementById('modeNone'), after:document.getElementById('modeAfter'), cron:document.getElementById('modeCron'), set:document.getElementById('modeSet') };
function showMode(m){ for (const k in blocks) blocks[k].style.display = (k===m? 'grid':'none'); }
modeSel.addEventListener('change', ()=> showMode(modeSel.value));
showMode(modeSel.value);

form.addEventListener('submit', async (e)=>{
  e.preventDefault();
  const fd = new FormData(form);
  const data = {
    name: fd.get('name').trim(),
    type: fd.get('type')||null,
    subtype: fd.get('subtype')||null,
    url: fd.get('url')||null,
    description: fd.get('description')||null,
    tags: (fd.get('tags')||'').split(',').map(x=>x.trim()).filter(Boolean),
    recurrence_mode: fd.get('recurrence_mode')
  };
  if (!data.name) { alert('Name is required'); return; }
  if (data.url && !/^https?:\/\//i.test(data.url)) { alert('URL must start with http or https'); return; }

  if (data.recurrence_mode==='none'){
    data.due_at = (fd.get('due_at')||'').trim();
    if (!/^\d{2,4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(data.due_at)) { alert('Use 24h format: YYYY-MM-DD HH:MM:SS'); return; }
  } else if (data.recurrence_mode==='after'){
    const interval = parseInt(fd.get('interval')||'1',10);
    const unit = fd.get('unit');
    if (!(interval>0)) { alert('Interval must be positive'); return; }
    data.recurrence_params = { interval, unit };
  } else if (data.recurrence_mode==='cron'){
    const cron = (fd.get('cron')||'').trim();
    const tz = (fd.get('tz')||meta.tz);
    if (!cron) { alert('Cron expression required'); return; }
    data.recurrence_params = { cron, tz };
  } else if (data.recurrence_mode==='set'){
    const lines = (fd.get('times')||'').split(/\n+/).map(s=>s.trim()).filter(Boolean);
    if (!lines.length) { alert('At least one time required'); return; }
    data.recurrence_params = { times: lines, tz: meta.tz };
  }

  const res = await fetch('/api/tasks', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data) });
  if (!res.ok){ const t = await res.text(); alert('Create failed: '+t); return; }
  window.location.href = '/';
});
