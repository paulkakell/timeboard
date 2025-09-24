const API = "/api/tasks";
let meta = { tz: "UTC", release: "dev", repository_url: "#" };

async function getMeta(){
<<<<<<< HEAD
  try { const r = await fetch("/api/meta"); meta = await r.json(); } catch(e){}
=======
  try {
    const r = await fetch("/api/meta");
    meta = await r.json();
  } catch(e){}
>>>>>>> 3cd270663acd16b2f2f143be7d63e11505082bcb
}
getMeta();

const searchEl = document.getElementById("search");
const tbody = document.getElementById("taskBody");

<<<<<<< HEAD
function esc(s){
  return String(s||"").replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function timeLeft(ms){
  if (ms == null) return "";
  if (ms < 0) return "past due";
  const s = Math.floor(ms/1000);
  const d = Math.floor(s/86400);
  const h = Math.floor((s%86400)/3600);
  const m = Math.floor((s%3600)/60);
  const parts = [];
  if (d) parts.push(d+"d");
  if (h) parts.push(h+"h");
  if (m || parts.length===0) parts.push(m+"m");
  return parts.join(" ");
}

function render(rows){
  tbody.innerHTML = "";
  for (const t of rows){
    const tr = document.createElement("tr");
    const tags = (t.tags||[]).map(esc).join(", ");
    tr.innerHTML = `
      <td>${esc(t.name||"")}</td>
      <td>${esc([t.type,t.subtype].filter(Boolean).join(" / "))}</td>
      <td>${tags}</td>
      <td>${esc(t.next_due_at||t.due_at||"")}</td>
      <td>${esc(timeLeft(t.time_left_ms))}</td>
      <td>
        <button class="btn" data-act="edit" data-id="${t.id}">Edit</button>
        <button class="btn" data-act="advance" data-id="${t.id}">Advance</button>
        <button class="btn danger" data-act="delete" data-id="${t.id}">Delete</button>
      </td>`;
    tbody.appendChild(tr);
  }
}

async function fetchTasks(){
  const r = await fetch(API);
  if (!r.ok) throw new Error("list failed");
  return await r.json();
}

function parseQuery(q){
  const tokens = (q||"").trim().split(/\s+/).filter(Boolean);
  const filters = [];
  for (const tok of tokens){
    const m = tok.match(/^(\w+):(.*)$/);
    if (m) filters.push({field:m[1].toLowerCase(), value:m[2].toLowerCase()});
    else filters.push({field:"name", value:tok.toLowerCase()});
  }
  return filters;
}

function matches(t, filters){
  if (!filters.length) return true;
  for (const f of filters){
    let hay = "";
    if (f.field==="name") hay = (t.name||"");
    else if (f.field==="type") hay = (t.type||"") + " " + (t.subtype||"");
    else if (f.field==="tag" || f.field==="tags") hay = (t.tags||[]).join(" ");
    else hay = JSON.stringify(t||{});
    if (!hay.toLowerCase().includes(f.value)) return false;
  }
=======
function timeLeft(ms){
  if (ms == null) return "";
  if (ms < 0) return "past due";
  const s = Math.floor(ms/1000);
  const d = Math.floor(s/86400);
  const h = Math.floor((s%86400)/3600);
  const m = Math.floor((s%3600)/60);
  const parts = [];
  if (d) parts.push(d+"d");
  if (h) parts.push(h+"h");
  if (m || parts.length===0) parts.push(m+"m");
  return parts.join(" ");
}

function render(rows){
  tbody.innerHTML = "";
  for (const t of rows){
    const tr = document.createElement("tr");
    const tags = (t.tags||[]).join(", ");
    tr.innerHTML = `
      <td>${t.name||""}</td>
      <td>${[t.type,t.subtype].filter(Boolean).join(" / ")}</td>
      <td>${tags}</td>
      <td>${t.next_due_at||t.due_at||""}</td>
      <td>${timeLeft(t.time_left_ms)}</td>
      <td>
        <button class="btn" data-act="edit" data-id="${t.id}">Edit</button>
        <button class="btn" data-act="advance" data-id="${t.id}">Advance</button>
        <button class="btn danger" data-act="delete" data-id="${t.id}">Delete</button>
      </td>`;
    tbody.appendChild(tr);
  }
}

async function fetchTasks(){
  const r = await fetch(API);
  if (!r.ok) throw new Error("list failed");
  return await r.json();
}

function parseQuery(q){
  const tokens = q.trim().split(/\s+/).filter(Boolean);
  const filters = [];
  for (const tok of tokens){
    const m = tok.match(/^(\w+):(.*)$/);
    if (m) filters.push({field:m[1].toLowerCase(), value:m[2].toLowerCase()});
    else filters.push({field:"name", value:tok.toLowerCase()});
  }
  return filters;
}

function matches(t, filters){
  if (!filters.length) return true;
  for (const f of filters){
    let hay = "";
    if (f.field==="name") hay = (t.name||"");
    else if (f.field==="type") hay = (t.type||"") + " " + (t.subtype||"");
    else if (f.field==="tag" || f.field==="tags") hay = (t.tags||[]).join(" ");
    else hay = JSON.stringify(t||{});
    if (!hay.toLowerCase().includes(f.value)) return false;
  }
>>>>>>> 3cd270663acd16b2f2f143be7d63e11505082bcb
  return true;
}

async function refresh(){
  const all = await fetchTasks();
  const q = (searchEl && searchEl.value) ? searchEl.value : "";
  const filters = parseQuery(q);
  const rows = all.filter(t => matches(t, filters));
  render(rows);
}

if (searchEl){
  searchEl.addEventListener("input", ()=>{ refresh(); });
}

async function advanceTask(id){
  await fetch(`/api/tasks/${id}/advance`, { method:"POST" });
}
async function deleteTask(id){
  await fetch(`/api/tasks/${id}`, { method:"DELETE" });
}

document.addEventListener("click", async (e)=>{
  const btn = e.target.closest("button[data-act]");
  if (!btn) return;
  const act = btn.getAttribute("data-act");
  const id = btn.getAttribute("data-id");
  if (act==="edit"){ location.href = `/new?id=${id}`; return; }
  if (act==="advance"){ await advanceTask(id); await refresh(); return; }
  if (act==="delete"){
    if (!confirm("Delete this task?")) return;
    await deleteTask(id);
    await refresh();
  }
});

refresh();
