let meta = { tz:"UTC", release:"dev", repository_url:"#"};
async function getMeta(){
  try {
    const r = await fetch("/api/meta");
    meta = await r.json();
  } catch(e){}
  const cronTz = document.getElementById("cronTz");
  if (cronTz) cronTz.value = meta.tz || "UTC";
}
getMeta();

const form = document.getElementById("taskForm");
const modeSel = document.getElementById("modeSel");
const blocks = {
  none: document.getElementById("modeNone"),
  after: document.getElementById("modeAfter"),
  cron: document.getElementById("modeCron"),
  set: document.getElementById("modeSet")
};
function showMode(m){
  Object.keys(blocks).forEach(k=>{ if (blocks[k]) blocks[k].style.display = (k===m ? "grid" : "none"); });
}
if (modeSel){
  modeSel.addEventListener("change", ()=> showMode(modeSel.value));
  showMode(modeSel.value || "none");
}

function getIdFromQuery(){
  const m = location.search.match(/[?&]id=(\d+)/);
  return m ? parseInt(m[1],10) : null;
}

function collectPayload(fd){
  const payload = {
    name: (fd.get("name")||"").trim(),
    type: (fd.get("type")||"").trim() || null,
    subtype: (fd.get("subtype")||"").trim() || null,
    url: (fd.get("url")||"").trim() || null,
    description: (fd.get("description")||"").trim() || null,
<<<<<<< HEAD
    tags: (fd.get("tags")||"").split(",").map(s=>s.trim()).filter(Boolean).slice(0,20),
=======
    tags: (fd.get("tags")||"").split(",").map(s=>s.trim()).filter(Boolean),
>>>>>>> 3cd270663acd16b2f2f143be7d63e11505082bcb
    recurrence_mode: fd.get("recurrence_mode")
  };
  if (payload.recurrence_mode === "none"){
    const due = (fd.get("due")||"").trim();
    payload.due_at = due || null;
  } else if (payload.recurrence_mode === "after"){
    payload.recurrence_params = {
<<<<<<< HEAD
      interval: Math.max(1, parseInt(fd.get("interval")||"1",10)),
=======
      interval: parseInt(fd.get("interval")||"1",10),
>>>>>>> 3cd270663acd16b2f2f143be7d63e11505082bcb
      unit: fd.get("unit") || "days"
    };
  } else if (payload.recurrence_mode === "cron"){
    payload.recurrence_params = {
      cron: (fd.get("cron")||"").trim(),
      tz: (fd.get("tz")||meta.tz||"UTC")
    };
  } else if (payload.recurrence_mode === "set"){
    const lines = (fd.get("times")||"").split(/\n+/).map(s=>s.trim()).filter(Boolean);
<<<<<<< HEAD
    payload.recurrence_params = { times: lines.slice(0,200), tz: meta.tz||"UTC" };
=======
    payload.recurrence_params = { times: lines, tz: meta.tz||"UTC" };
>>>>>>> 3cd270663acd16b2f2f143be7d63e11505082bcb
  }
  return payload;
}

if (form){
  form.addEventListener("submit", async (e)=>{
    e.preventDefault();
    const fd = new FormData(form);
    const payload = collectPayload(fd);
    const id = getIdFromQuery();
    const url = id ? `/api/tasks/${id}` : `/api/tasks`;
    const method = id ? "PUT" : "POST";
    const res = await fetch(url, { method, headers: { "Content-Type":"application/json" }, body: JSON.stringify(payload) });
    if (!res.ok){
      const t = await res.text();
      alert("Save failed: " + t);
      return;
    }
    location.href = "/";
  }, true);
}

async function loadForEdit(id){
  const r = await fetch(`/api/tasks/${id}`);
  if (!r.ok) return;
  const t = await r.json();
  form.querySelector('[name="name"]').value = t.name||"";
  form.querySelector('[name="type"]').value = t.type||"";
  form.querySelector('[name="subtype"]').value = t.subtype||"";
  form.querySelector('[name="url"]').value = t.url||"";
  form.querySelector('[name="tags"]').value = (t.tags||[]).join(", ");
  form.querySelector('[name="description"]').value = t.description||"";
  modeSel.value = t.recurrence_mode || "none";
  showMode(modeSel.value);
  if (t.recurrence_mode === "none"){
    const due = t.due_at || "";
<<<<<<< HEAD
    form.querySelector('[name="due"]').value = due?.replace("T"," ").slice(0,19);
=======
<<<<<<< HEAD
    form.querySelector('[name="due"]').value = due ? due.replace("T"," ").slice(0,19) : "";
=======
    form.querySelector('[name="due"]').value = due.replace("T"," ").slice(0,19);
>>>>>>> 3cd270663acd16b2f2f143be7d63e11505082bcb
>>>>>>> c12f6754ab679429516c92e84fa106cf949a473f
  } else if (t.recurrence_mode === "after"){
    const p = t.recurrence_params||{};
    form.querySelector('[name="interval"]').value = p.interval||1;
    form.querySelector('[name="unit"]').value = p.unit||"days";
  } else if (t.recurrence_mode === "cron"){
    const p = t.recurrence_params||{};
    form.querySelector('[name="cron"]').value = p.cron||"";
    const tzEl = form.querySelector('[name="tz"]');
    if (tzEl) tzEl.value = p.tz || meta.tz || "UTC";
  } else if (t.recurrence_mode === "set"){
    const p = t.recurrence_params||{};
    const lines = (p.times||[]).join("\n");
    form.querySelector('[name="times"]').value = lines;
  }
  const submit = form.querySelector('button[type="submit"]');
  if (submit) submit.textContent = "Save";
  document.title = "Edit Task";
}

const editId = getIdFromQuery();
if (editId) loadForEdit(editId);
