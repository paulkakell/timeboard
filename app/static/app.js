const API = "/api/tasks";
let tasks = [];
let sortKey = "time_left_ms";
let sortDir = "asc";
let formMode = "create"; // create | edit
let editingId = null;

// ---------- UI elements ----------
const searchEl = document.getElementById("search");
const modal = document.getElementById("taskModal");
const backdrop = document.getElementById("modalBackdrop");
const form = document.getElementById("taskForm");
const formMsg = document.getElementById("formMsg");
const deleteBtn = document.getElementById("deleteBtn");

document.getElementById("newTaskBtn").onclick = () => openForm("create");
document.getElementById("closeModal").onclick = closeForm;
backdrop.onclick = closeForm;

// ---------- Search ----------
function parseQuery(q) {
  const tokens = q.trim().split(/\s+/).filter(Boolean);
  const clauses = [];
  let currentOr = [];
  function pushTerm(tok) {
    const m = tok.match(/^(\w+):(.*)$/i);
    if (m) currentOr.push({ field: m[1].toLowerCase(), value: m[2].toLowerCase() });
    else currentOr.push({ field: "*", value: tok.toLowerCase() });
  }
  for (const t of tokens) {
    if (t.toUpperCase() === "OR") { if (currentOr.length) { clauses.push({ terms: currentOr }); currentOr = []; } continue; }
    if (t.toUpperCase() === "AND") { if (currentOr.length) { clauses.push({ terms: currentOr }); currentOr = []; } continue; }
    pushTerm(t);
  }
  if (currentOr.length) clauses.push({ terms: currentOr });
  return { groups: clauses };
}
function fieldMatches(task, term) {
  const has = (h) => (h || "").toString().toLowerCase().includes(term.value);
  if (term.field === "*") return has(task.name) || has(task.type) || has(task.subtype) || has(task.description) || has(task.url) || has(task.recurrenceText) || (task.tags || []).some(t => t.toLowerCase().includes(term.value));
  if (term.field === "tag" || term.field === "tags") return (task.tags || []).some(t => t.toLowerCase().includes(term.value));
  return has(task[term.field]);
}
function matches(task, ast) { if (!ast || !ast.groups.length) return true; return ast.groups.every(g => g.terms.some(t => fieldMatches(task, t))); }

// ---------- Time and color ----------
function msToParts(ms) {
  let rest = Math.max(0, ms);
  const minutes = Math.floor(rest / 60000);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  const months = Math.floor(days / 30);
  const remDays = days - months * 30;
  const remHours = hours - days * 24;
  const remMinutes = minutes - hours * 60;
  const parts = [];
  if (months) parts.push(`${months} mo`);
  if (remDays) parts.push(`${remDays} d`);
  if (remHours) parts.push(`${remHours} h`);
  parts.push(`${remMinutes} m`);
  return parts.join(", ");
}
function lerp(a, b, t) { return Math.round(a + (b - a) * t); }
function hex(c) { return c.toString(16).padStart(2, "0"); }
function gradientColor(ratio) { const r = lerp(0xFF, 0x00, ratio), g = lerp(0x00, 0xFF, ratio), b = lerp(0x0D, 0x00, ratio); return `#${hex(r)}${hex(g)}${hex(b)}`; }
function textGradient(ratio) { const r = lerp(0xFF, 0x00, ratio), g = lerp(0xFF, 0x00, ratio), b = 0; return `#${hex(r)}${hex(g)}${hex(b)}`; }
function recurrenceToText(t) {
  if (t.recurrence_mode === "none") return `One-time @ ${t.due_at ? new Date(t.due_at).toLocaleString() : "n/a"}`;
  if (t.recurrence_mode === "after") return `Every ${t.recurrence_params?.value} ${t.recurrence_params?.unit} after complete`;
  if (t.recurrence_mode === "cron") return `Cron ${t.recurrence_params?.cron}`;
  if (t.recurrence_mode === "set") return `Specific times (${(t.recurrence_params?.crons || []).length})`;
  return "";
}

// ---------- API ----------
async function fetchJSON(url, opts) {
  const res = await fetch(url, opts);
  const txt = await res.text();
  let data;
  try { data = txt ? JSON.parse(txt) : null; } catch { data = null; }
  if (!res.ok) {
    const msg = extractErrorMessage(data) || `Request failed with ${res.status}`;
    throw new Error(msg);
  }
  return data;
}
function extractErrorMessage(data) {
  if (!data) return null;
  if (Array.isArray(data.detail)) return data.detail.join("; ");
  if (typeof data.detail === "string") return data.detail;
  if (data.message) return data.message;
  return null;
}

async function listTasks() { return fetchJSON(API); }
async function createTask(payload) {
  return fetchJSON(API, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
}
async function updateTask(id, payload) {
  return fetchJSON(`${API}/${id}`, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
}
async function removeTask(id) { return fetchJSON(`${API}/${id}`, { method: "DELETE" }); }

// ---------- Render table ----------
function sortData(arr) {
  const s = [...arr];
  s.sort((a, b) => {
    const ak = a[sortKey] ?? "";
    const bk = b[sortKey] ?? "";
    if (ak < bk) return sortDir === "asc" ? -1 : 1;
    if (ak > bk) return sortDir === "asc" ? 1 : -1;
    return 0;
  });
  return s;
}
function render() {
  const q = searchEl.value.trim();
  const ast = parseQuery(q);
  const filtered = tasks.filter(t => matches(t, ast));
  const maxMs = Math.max(1, ...filtered.map(t => t.time_left_ms));
  const rows = sortData(filtered);
  const tb = document.querySelector("#taskTable tbody");
  tb.innerHTML = "";
  for (const t of rows) {
    const tr = document.createElement("tr");
    const ratio = Math.min(1, Math.max(0, t.time_left_ms / maxMs));
    const bg = gradientColor(ratio);
    const fg = textGradient(ratio);
    function td(label, html) { const el = document.createElement("td"); el.setAttribute("data-label", label); el.innerHTML = html; return el; }

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
    const desc = (t.description || "");
    const trunc = desc.length > 100 ? desc.slice(0, 100) + "…" : desc;
    tr.appendChild(td("Task Instructions", trunc));
    const tagHtml = (t.tags || []).map(x => `<span class="badge">${x}</span>`).join("");
    tr.appendChild(td("Tags", tagHtml));
    tr.appendChild(td("Recurrence", recurrenceToText(t)));

    const actions = `
      <button class="small" data-edit="${t.id}">Edit</button>
      <button class="small" data-del="${t.id}">Delete</button>
    `;
    tr.appendChild(td("Actions", actions));

    tb.appendChild(tr);
  }

  document.querySelectorAll("button[data-done]").forEach(btn => {
    btn.onclick = async () => {
      const id = btn.getAttribute("data-done");
      try {
        const res = await fetch(`${API}/${id}/complete`, { method: "POST" });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(extractErrorMessage(data) || "Could not complete the task.");
        await fetchTasks();
      } catch (e) { alert(e.message); }
    };
  });
  document.querySelectorAll("button[data-edit]").forEach(btn => { btn.onclick = () => openForm("edit", btn.getAttribute("data-edit")); });
  document.querySelectorAll("button[data-del]").forEach(btn => {
    btn.onclick = async () => {
      if (!confirm("Delete this task?")) return;
      try { await removeTask(btn.getAttribute("data-del")); await fetchTasks(); } catch (e) { alert(e.message); }
    };
  });
}

// ---------- Modal form ----------
function openForm(mode, id = null) {
  formMode = mode;
  editingId = id ? Number(id) : null;
  document.getElementById("modalTitle").textContent = mode === "create" ? "New task" : "Edit task";
  deleteBtn.classList.toggle("hidden", mode !== "edit");
  form.reset();
  form.querySelector('input[name="recurrence_mode"][value="none"]').checked = true;
  showRecurrenceFields("none");
  formMsg.textContent = "";
  if (mode === "edit") {
    const t = tasks.find(x => x.id === editingId);
    if (t) populateForm(t);
  }
  modal.classList.remove("hidden");
  backdrop.classList.remove("hidden");
}
function closeForm() {
  modal.classList.add("hidden");
  backdrop.classList.add("hidden");
}
function populateForm(t) {
  form.elements.name.value = t.name || "";
  form.elements.type.value = t.type || "";
  form.elements.subtype.value = t.subtype || "";
  form.elements.url.value = t.url || "";
  form.elements.tags.value = (t.tags || []).join(", ");
  form.elements.description.value = t.description || "";
  form.querySelector(`input[name="recurrence_mode"][value="${t.recurrence_mode}"]`).checked = true;
  showRecurrenceFields(t.recurrence_mode);
  if (t.recurrence_mode === "none") form.elements.due_at.value = t.due_at ? t.due_at : "";
  if (t.recurrence_mode === "after") {
    form.elements.after_interval_value.value = t.recurrence_params?.value ?? "";
    form.elements.after_interval_unit.value = t.recurrence_params?.unit ?? "hours";
  }
  if (t.recurrence_mode === "cron") form.elements.cron.value = t.recurrence_params?.cron ?? "";
  if (t.recurrence_mode === "set") form.elements.cron_set.value = (t.recurrence_params?.crons || []).join("\n");
}
Array.from(form.querySelectorAll('input[name="recurrence_mode"]')).forEach(r => {
  r.addEventListener("change", () => showRecurrenceFields(r.value));
});
function showRecurrenceFields(mode) {
  document.querySelectorAll(".recurrence-fields").forEach(el => {
    el.classList.toggle("hidden", el.getAttribute("data-mode") !== mode);
  });
}

// ---------- Client-side validation ----------
function readPayload() {
  const mode = form.querySelector('input[name="recurrence_mode"]:checked').value;
  const tags = (form.elements.tags.value || "").split(",").map(s => s.trim()).filter(Boolean);
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

  if (!payload.name) throw new Error("Name is required.");
  if (payload.url && !/^https?:\/\//i.test(payload.url)) throw new Error("URL must start with http:// or https://.");

  if (mode === "none") {
    const due = form.elements.due_at.value.trim();
    if (!due) throw new Error("Due at is required for one-time tasks. Example 2025-12-01T12:00:00Z.");
    // Light ISO check
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(due)) throw new Error("Due at must be ISO 8601 UTC. Example 2025-12-01T12:00:00Z.");
    payload.due_at = due;
  }

  if (mode === "after") {
    const v = Number(form.elements.after_interval_value.value || 0);
    const u = form.elements.after_interval_unit.value;
    if (!Number.isInteger(v) || v < 1) throw new Error("Interval must be an integer greater than or equal to 1.");
    if (!["minutes", "hours", "days", "months"].includes(u)) throw new Error("Interval unit must be minutes, hours, days, or months.");
    payload.after_interval_value = v;
    payload.after_interval_unit = u;
  }

  if (mode === "cron") {
    const c = form.elements.cron.value.trim();
    if (!c) throw new Error("Cron is required. Example daily at noon: 0 12 * * *.");
    payload.cron = c;
  }

  if (mode === "set") {
    const lines = (form.elements.cron_set.value || "").split("\n").map(s => s.trim()).filter(Boolean);
    if (!lines.length) throw new Error("Enter at least one cron line for specific-times tasks.");
    payload.cron_set = lines;
  }

  return payload;
}

// Submit
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  formMsg.textContent = "";
  try {
    const payload = readPayload();
    if (formMode === "create") await createTask(payload);
    else await updateTask(editingId, payload);
    closeForm();
    await fetchTasks();
  } catch (err) {
    formMsg.textContent = err.message || "Validation error. Please review your inputs.";
  }
});

// Delete from modal
deleteBtn.onclick = async () => {
  if (!editingId) return;
  if (!confirm("Delete this task?")) return;
  try {
    await removeTask(editingId);
    closeForm();
    await fetchTasks();
  } catch (err) {
    formMsg.textContent = err.message || "Could not delete the task.";
  }
};

// Sorting and refresh
searchEl.addEventListener("input", render);
document.querySelectorAll("thead th[data-sort]").forEach(th => {
  th.onclick = () => {
    const key = th.getAttribute("data-sort");
    if (!key) return;
    if (sortKey === key) sortDir = sortDir === "asc" ? "desc" : "asc";
    else { sortKey = key; sortDir = "asc"; }
    render();
  };
});

// Data lifecycle
async function fetchTasks() {
  try {
    const list = await listTasks();
    for (const t of list) t.recurrenceText = recurrenceToText(t);
    tasks = list;
    render();
  } catch (e) {
    alert(e.message || "Could not load tasks.");
  }
}
fetchTasks();
setInterval(fetchTasks, 30000);
