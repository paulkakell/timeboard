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


function getIdFromQuery(){ const m = location.search.match(/[?&]id=(\d+)/); return m? parseInt(m[1],10): null; }

async function loadForEdit(id){
  const r = await fetch('/api/tasks'); // simple fetch and filter
  const rows = await r.json();
  const t = rows.find(x=>x.id===id);
  if (!t) return;
  // Fill form fields
  form.querySelector('[name="name"]').value = t.name || '';
  form.querySelector('[name="type"]').value = t.type || '';
  form.querySelector('[name="subtype"]').value = t.subtype || '';
  form.querySelector('[name="url"]').value = t.url || '';
  form.querySelector('[name="description"]').value = t.description || '';
  form.querySelector('[name="tags"]').value = (t.tags||[]).join(',');
  if (t.recurrence_mode){
    modeSel.value = t.recurrence_mode;
    showMode(modeSel.value);
    if (t.recurrence_mode==='none'){
      form.querySelector('[name="due"]').value = (t.due_at||'').replace('T',' ').slice(0,19);
    } else if (t.recurrence_mode==='after'){
      form.querySelector('[name="interval"]').value = t.recurrence_params?.interval || 1;
      form.querySelector('[name="unit"]').value = t.recurrence_params?.unit || 'days';
    } else if (t.recurrence_mode==='cron'){
      form.querySelector('[name="cron"]').value = t.recurrence_params?.cron || '';
      document.getElementById('cronTz').value = t.recurrence_params?.tz || meta.tz;
    } else if (t.recurrence_mode==='set'){
      const lines = (t.recurrence_params?.times||[]).join('\n');
      form.querySelector('[name="times"]').value = lines;
    }
  }
  // Change title and submit behavior
  document.title = 'Edit Task';
  const submitBtn = form.querySelector('button[type="submit"]');
  submitBtn.textContent = 'Save Changes';
  // Add delete button
  const del = document.createElement('button');
  del.className='btn danger';
  del.type='button';
  del.textContent='Delete';
  del.addEventListener('click', async ()=>{
    if (!confirm('Delete this task?')) return;
    const rr = await fetch(`/api/tasks/${id}`, {{ method:'DELETE' }});
    if (!rr.ok) alert('Delete failed'); else window.location.href='/';
  });
  form.appendChild(del);

  form.addEventListener('submit', async (e)=>{ e.preventDefault();
    const fd = new FormData(form);
    // Reuse creation payload logic by triggering current handler to build 'data'
  });
}

// Intercept submit to switch to PUT when editing
const origSubmit = form.onsubmit;
form.addEventListener('submit', async function override(e){
  const id = getIdFromQuery();
  if (!id) return; // use default POST
  e.preventDefault();
  const fd = new FormData(form);
  const payload = { name: fd.get('name').trim(),
    type: fd.get('type')||null, subtype: fd.get('subtype')||null, url: fd.get('url')||null,
    description: fd.get('description')||null, tags: (fd.get('tags')||'').split(',').map(s=>s.trim()).filter(Boolean) };
  payload.recurrence_mode = fd.get('recurrence_mode');
  if (payload.recurrence_mode==='none'){
    const due = (fd.get('due')||'').trim();
    payload.due_at = due;
  } else if (payload.recurrence_mode==='after'){
    payload.recurrence_params = { interval: parseInt(fd.get('interval')||'1',10), unit: fd.get('unit') };
  } else if (payload.recurrence_mode==='cron'){
    payload.recurrence_params = { cron: (fd.get('cron')||'').trim(), tz: (fd.get('tz')||meta.tz) };
  } else if (payload.recurrence_mode==='set'){
    const lines = (fd.get('times')||'').split(/\n+/).map(s=>s.trim()).filter(Boolean);
    payload.recurrence_params = { times: lines, tz: meta.tz };
  }
  const res = await fetch(`/api/tasks/${id}`, {{ method:'PUT', headers: {{'Content-Type':'application/json'}}, body: JSON.stringify(payload) }});
  if (!res.ok) {{ const t = await res.text(); alert('Update failed: '+t); return; }}
  window.location.href = '/';
}, true);

// If editing, load item
const editId = getIdFromQuery();
if (editId) loadForEdit(editId);
