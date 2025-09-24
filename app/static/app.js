const API = "/api/tasks";
let tasks = [];
let sortKey = "time_left_ms";
let sortDir = "asc";
let formMode = "create"; // create | edit
let editingId = null;

// ===== Search logic (unchanged) =====
function parseQuery(q) {
  const tokens = q.trim().split(/\s+/).filter(Boolean);
  const clauses = [];
  let currentOr = [];
  function pushTerm(tok) {
    const m = tok.match(/^(\w+):(.*)$/i);
    if (m) currentOr.push({field:m[1].toLowerCase(), value:m[2].toLowerCase()});
    else currentOr.push({field:"*", value:tok.toLowerCase()});
  }
  for (const t of tokens) {
    if (t.toUpperCase() === "OR") { if (currentOr.length) { clauses.push({terms:currentOr}); currentOr=[]; } continue; }
    if (t.toUpperCase() === "AND") { if (currentOr.length) { clauses.push({terms:currentOr}); currentOr=[]; } continue; }
    pushTerm(t);
  }
  if (currentOr.length) clauses.push({terms:currentOr});
  return {groups:clauses};
}
function fieldMatches(task, term) {
  const has = (h)=> (h||"").toString().toLowerCase().includes(term.value);
  if (term.field === "*") return has(task.name)||has(task.type)||has(task.subtype)||has(task.description)||has(task.url)||has(task.recurrenceText)||(task.tags||[]).some(t=>t.toLowerCase().includes(term.value));
  if (term.field === "tag" || term.field === "tags") return (task.tags||[]).some(t=>t.toLowerCase().includes(term.value));
  return has(task[term.field]);
}
function matches(task, ast){ if(!ast||!ast.groups.length) return true; return ast.groups.every(g=>g.terms.some(t=>fieldMatches(task,t))); }

// ===== Time and color helpers =====
function msToParts(ms) {
  let rest = Math.max(0, ms);
  const minutes = Math.floor(rest / 60000);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  const months = Math.floor(days / 30);
  const remDays = days - months*30;
  const remHours = hours - days*24;
  const remMinutes = minutes - hours*60;
  const parts = [];
  if (months) parts.push(`${months} mo`);
  if (remDays) parts.push(`${remDays} d`);
  if (remHours) parts.push(`${remHours} h`);
  parts.push(`${remMinutes} m`);
  return parts.join(", ");
}
function lerp(a,b,t){ return Math.round(a + (b-a)*t); }
function hex(c){ return c.toString(16).padStart(2,"0"); }
function gradientColor(ratio) { const r=lerp(0xFF,0x00,ratio), g=lerp(0x00,0xFF,ratio), b=lerp(0x0D,0x00,ratio); return `#${hex(r)}${hex(g)}${hex(b)}`; }
function textGradient(ratio) { const r=lerp(0xFF,0x00,ratio), g=lerp(0xFF,0x00,ratio), b=0; return `#${hex(r)}${hex(g)}${hex(b)}`; }
function recurrenceToText(t) {
  if (t.recurrence_mode === "none") return `One-time @ ${t.due_at ? new Date(t.due_at).toLocaleString() : "n/a"}`;
  if (t.recurrence_mode === "after") return `Every ${t.recurrence_params?.value} ${t.recurrence_params?.unit} after complete`;
  if (t.recurrence_mode === "cron") return `Cron ${t.recurrence_params?.cron}`;
  if (t.recurrence_mode === "set") return `Specific times (${(t.recurrence_params?.crons||[]).length})`;
  return "";
}

// ===== API =====
async function fetchTasks() {
  const res = await fetch(API);
  const list = await res.json();
  for (const t of list) {
    t.recurrenceText = recurrenceToText(t);
    t.truncDesc = (t.description||"").length > 100 ? (t.description.slice(0,100)+"…") : (t.description||"");
  }
  tasks = list;
  render();
}
async function createTask(payload){
  const res = await fetch(API,{method:"POST", headers:{ "content-type":"application/json"}, body:JSON.stringify(payload)});
  if(!res.ok) throw new Error(await res.text());
  return res.json();
}
async function updateTask(id,payload){
  const res = await fetch(`${API}/${id}`,{method:"PUT", headers:{ "content-type":"application/json"}, body:JSON.stringify(payload)});
  if(!res.ok) throw new Error(await res.text());
  return res.json();
}
async function deleteTask(id){
  const res = await fetch(`${API}/${id}`,{method:"DELETE"});
  if(!res.ok) throw new Error(await res.text());
  return res.json();
}

// ===== Render =====
function sortData(arr) {
  const s = [...arr];
  s.sort((a,b)=>{
    const ak = a[sortKey] ?? "";
    const bk = b[sortKey] ?? "";
    if (ak < bk) return sortDir === "asc" ? -1 : 1;
    if (ak > bk) return sortDir === "asc" ? 1 : -1;
    return 0;
  });
  return s;
}
function render() {
  const q = document.getElementById("search").value.trim();
  const ast = parseQuery(q);
  const filtered = tasks.filter(t=>matches(t, ast));
  const maxMs = Math.max(1, ...filtered.map(t=>t.time_left_ms));
  const rows = sortData(filtered);
  const tb = document.querySelector("#taskTable tbody");
  tb.innerHTML = "";
  for (const t of rows) {
    const tr = document.createElement("tr");
    const ratio = Math.min(1, Math.max(0, t.time_left_ms / maxMs));
    const bg = gradientColor(ratio);
    const fg = textGradient(ratio);
    function td(label, html) { const el=document.createElement("td"); el.setAttribute("data-label",label); el.innerHTML=html; return el; }

    const doneBtn = `<button class="small" data-done="${t.id}">Complete</button>`;
    tr.appendChild(td("Done", doneBtn));

    const openBtn = t.url ? `<a class="small" target="_blank" rel="noopener" href="${t.url}"><button class="small">Open</button></a>` : "";
    tr.appendChild(td("Open", openBtn));

    const timeStr = msToParts(t.time_left_ms);
    const timeHtml = `<span class="timecell" style="background:${bg}; color:${fg};">${timeStr}</span>`;
    tr.appendChild(td("Time Left", timeHtml));

    tr.appendChild(td("Name", t.name || ""));
    tr.appendChild(td("Type", t.type || ""));
    tr.appendChild(td("Subtype", t.subtype || ""));
    tr.appendChild(td("Task Instructions", t.truncDesc || ""));
    const tagHtml = (t.tags||[]).map(x=>`<span class="badge">${x}</span>`).join("");
    tr.appendChild(td("Tags", tagHtml));
    tr.appendChild(td("Recurrence", t.recurrenceText));

    const actions = `
      <button class="small" data-edit="${t.id}">Edit</button>
      <button class="small" data-del="${t.id}">Delete</button>
    `;
    tr.appendChild(td("Actions", actions));

    tb.appendChild(tr);
  }

  document.querySelectorAll("button[data-done]").forEach(btn=>{
    btn.onclick = async () => {
      const id = btn.getAttribute("data-done");
      const res = await fetch(`${API}/${id}/complete`, {method:"POST"});
      const j = await res.json();
      if (j.status === "deleted" || j.status === "advanced") fetchTasks();
    };
  });
  document.querySelectorAll("button[data-edit]").forEach(btn=>{
    btn.onclick = () => openForm("edit", btn.getAttribute("data-edit"));
  });
  document.querySelectorAll("button[data-del]").forEach(btn=>{
    btn.onclick = async () => {
      if (!confirm("Delete this task?")) return;
      try { await deleteTask(btn.getAttribute("data-del")); fetchTasks(); } catch(e){ alert(e.message); }
    };
  });
}

// ===== Modal form =====
const modal = document.getElementById("taskModal");
const backdrop = document.getElementById("modalBackdrop");
const form = document.getElementById("taskForm");
const formMsg = document.getElementById("formMsg");
const deleteBtn = document.getElementById("deleteBtn");
document.getElementById("newTaskBtn").onclick = ()=> openForm("create");
document.getElementById("closeModal").onclick = closeForm;
backdrop.onclick = closeForm;

function openForm(mode, id=null){
  formMode = mode;
  editingId = id ? Number(id) : null;
  document.getElementById("modalTitle").textContent = mode === "create" ? "New task" : "Edit task";
  deleteBtn.classList.toggle("hidden", mode !== "edit");
  form.reset();
  // default radio
  form.querySelector('input[name="recurrence_mode"][value="none"]').checked = true;
  showRecurrenceFields("none");
  formMsg.textContent = "";
  if (mode === "edit") {
    const t = tasks.find(x=>x.id === editingId);
    if (t) populateForm(t);
  }
  modal.classList.remove("hidden");
  backdrop.classList.remove("hidden");
}
function closeForm(){
  modal.classList.add("hidden");
  backdrop.classList.add("hidden");
}

function populateForm(t){
  form.elements.name.value = t.name || "";
  form.elements.type.value = t.type || "";
  form.elements.subtype.value = t.subtype || "";
  form.elements.url.value = t.url || "";
  form.elements.tags.value = (t.tags||[]).join(", ");
  form.elements.description.value = t.description || "";
  form.querySelector(`input[name="recurrence_mode"][value="${t.recurrence_mode}"]`).checked = true;
  showRecurrenceFields(t.recurrence_mode);
  if (t.recurrence_mode === "none") form.elements.due_at.value = t.due_at ? t.due_at : "";
  if (t.recurrence_mode === "after") {
    form.elements.after_interval_value.value = t.recurrence_params?.value ?? "";
    form.elements.after_interval_unit.value = t.recurrence_params?.unit ?? "hours";
  }
  if (t.recurrence_mode === "cron") form.elements.cron.value = t.recurrence_params?.cron ?? "";
  if (t.recurrence_mode === "set") form.elements.cron_set.value = (t.recurrence_params?.crons||[]).join("\n");
}

Array.from(form.querySelectorAll('input[name="recurrence_mode"]')).forEach(r=>{
  r.addEventListener("change", ()=> showRecurrenceFields(r.value));
});
function showRecurrenceFields(mode){
  document.querySelectorAll(".recurrence-fields").forEach(el=>{
    el.classList.toggle("hidden", el.getAttribute("data-mode") !== mode);
  });
}

function readPayload(){
  const mode = form.querySelector('input[name="recurrence_mode"]:checked').value;
  const tags = (form.elements.tags.value || "").split(",").map(s=>s.trim()).filter(Boolean);
  const payload = {
    name: form.elements.name.value.trim(),
    type: form.elements.type.value.trim() || null,
    subtype: form.elements.subtype.value.trim() || null,
    url: form.elements.url.value.trim() || null,
    description: form.elements.description.value || null,
    tags,
    recurrence_mode: mode,
    due_at: null,
    after_interval_value: null,
    after_interval_unit: null,
    cron: null,
    cron_set: null
  };
  if (mode === "none") payload.due_at = form.elements.due_at.value || null;
  if (mode === "after") {
    payload.after_interval_value = Number(form.elements.after_interval_value.value || 0);
    payload.after_interval_unit = form.elements.after_interval_unit.value;
  }
  if (mode === "cron") payload.cron = form.elements.cron.value || null;
  if (mode === "set") {
    const lines = (form.elements.cron_set.value || "").split("\n").map(s=>s.trim()).filter(Boolean);
    payload.cron_set = lines;
  }
  return payload;
}

form.addEventListener("submit", async (e)=>{
  e.preventDefault();
  formMsg.textContent = "";
  const payload = readPayload();
  try {
    if (formMode === "create") await createTask(payload);
    else await updateTask(editingId, payload);
    closeForm();
    fetchTasks();
  } catch(err){
    formMsg.textContent = parseError(err.message);
  }
});

deleteBtn.onclick = async ()=>{
  if (!editingId) return;
  if (!confirm("Delete this task?")) return;
  try {
    await deleteTask(editingId);
    closeForm();
    fetchTasks();
  } catch(err){
    formMsg.textContent = parseError(err.message);
  }
};

function parseError(t){
  try { const j = JSON.parse(t); if (j.detail) return Array.isArray(j.detail)? j.detail.map(d=>d.msg).join("; "): j.detail; } catch(_) {}
  return t;
}

// Sorting and refresh
document.getElementById("search").addEventListener("input", render);
document.querySelectorAll("thead th[data-sort]").forEach(th=>{
  th.onclick = () => {
    const key = th.getAttribute("data-sort");
    if (sortKey === key) sortDir = sortDir === "asc" ? "desc" : "asc";
    else { sortKey = key; sortDir = "asc"; }
    render();
  };
});

// Kickoff
fetchTasks();
setInterval(fetchTasks, 30000);
