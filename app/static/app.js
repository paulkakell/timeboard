const API = "/api/tasks";
let meta = { tz: "UTC", release: "dev", repository_url: "#" };

async function getMeta(){ const r = await fetch('/api/meta'); meta = await r.json(); document.getElementById('footer').innerHTML = `v${meta.release} · <a href="${meta.repository_url}" target="_blank">repo</a>`; }
getMeta();

const searchEl = document.getElementById('search');
const tbody = document.getElementById('taskBody');

function searchParse(q){
  const tokens = q.trim().split(/\s+/).filter(Boolean);
  const groups = [];
  let cur = [];
  function push(tok){
    const m = tok.match(/^(\w+):(.*)$/i);
    if (m) cur.push({field:m[1].toLowerCase(), value:m[2].toLowerCase()});
    else cur.push({field:'*', value:tok.toLowerCase()});
  }
  for (const t of tokens){
    if (t.toUpperCase()==='OR'){ if(cur.length){groups.push({terms:cur}); cur=[];} continue; }
    if (t.toUpperCase()==='AND'){ if(cur.length){groups.push({terms:cur}); cur=[];} continue; }
    push(t);
  }
  if (cur.length) groups.push({terms:cur});
  return groups;
}

function matches(task, groups){
  if (!groups.length) return true;
  return groups.every(g => g.terms.some(({field,value}) => {
    if (field==='name') return task.name.toLowerCase().includes(value);
    if (field==='type') return (task.type||'').toLowerCase().includes(value);
    if (field==='tag' || field==='tags') return task.tags.join(',').toLowerCase().includes(value);
    if (field==='*') return JSON.stringify(task).toLowerCase().includes(value);
    return false;
  }));
}

async function listTasks(){ const r = await fetch(API); if(!r.ok) throw new Error('Failed to load'); return r.json(); }
async function advanceTask(id){ const r = await fetch(`${API}/${id}/advance`, {method:'POST'}); if(!r.ok) throw new Error('Advance failed'); return r.json(); }
async function deleteTask(id){ const r = await fetch(`${API}/${id}`, {method:'DELETE'}); if(!r.ok) throw new Error('Delete failed'); return r.json(); }

function renderRow(t){
  const tags = t.tags.map(x=>`<span class='badge'>${x}</span>`).join('');
  let tl = '';
  if (t.time_left_ms != null){
    const s = Math.max(0, Math.floor(t.time_left_ms/1000));
    const d = Math.floor(s/86400), h = Math.floor((s%86400)/3600), m = Math.floor((s%3600)/60);
    tl = `${d}d ${h}h ${m}m`;
  }
  return `<tr>
    <td>${t.name}</td>
    <td>${t.type||''}</td>
    <td>${tags}</td>
    <td>${t.next_due_at||t.due_at||''}</td>
    <td>${tl}</td>
    <td>
      <button class='btn' data-act='advance' data-id='${t.id}'>Advance</button>
      <button class='btn danger' data-act='delete' data-id='${t.id}'>Delete</button>
    </td>
  </tr>`;
}

async function refresh(){
  const rows = await listTasks();
  const groups = searchParse(searchEl.value||'');
  const filtered = rows.filter(r=>matches(r, groups));
  tbody.innerHTML = filtered.map(renderRow).join('');
}
refresh();
setInterval(refresh, 20000);
searchEl.addEventListener('input', ()=>{ refresh(); });
document.getElementById('taskTable').addEventListener('click', async (e)=>{
  const btn = e.target.closest('button[data-act]');
  if (!btn) return;
  const id = btn.getAttribute('data-id');
  const act = btn.getAttribute('data-act');
  if (act==='advance'){ await advanceTask(id); await refresh(); }
  if (act==='delete'){ if (confirm('Delete task?')) { await deleteTask(id); await refresh(); } }
});
