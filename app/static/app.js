const API = "/api/tasks";
let tasks = [];
let sortKey = "time_left_ms";
let sortDir = "asc"; // asc | desc

// Boolean search parser: supports AND / OR, field:value, tag:value
function parseQuery(q) {
  const tokens = q.trim().split(/\s+/);
  const clauses = [];
  let currentOr = [];
  let mode = "AND";

  function pushTerm(tok) {
    const m = tok.match(/^(\w+):(.*)$/i);
    if (m) currentOr.push({field:m[1].toLowerCase(), value:m[2].toLowerCase()});
    else currentOr.push({field:"*", value:tok.toLowerCase()});
  }

  for (const t of tokens) {
    if (t.toUpperCase() === "OR") {
      mode = "OR";
      continue;
    }
    if (t.toUpperCase() === "AND") {
      if (currentOr.length) { clauses.push({mode:"OR", terms:currentOr}); currentOr=[]; }
      mode = "AND";
      continue;
    }
    pushTerm(t);
  }
  if (currentOr.length) clauses.push({mode:"OR", terms:currentOr});
  return {mode:"AND", groups:clauses};
}

function fieldMatches(task, term) {
  function has(hay) { return (hay||"").toString().toLowerCase().includes(term.value); }
  if (term.field === "*") {
    return has(task.name) || has(task.type) || has(task.subtype) || has(task.description) ||
           has(task.url) || has(task.recurrenceText) || (task.tags||[]).some(t=>t.toLowerCase().includes(term.value));
  }
  if (term.field === "tag" || term.field === "tags") {
    return (task.tags||[]).some(t=>t.toLowerCase().includes(term.value));
  }
  return has(task[term.field]);
}

function matches(task, queryAst) {
  if (!queryAst || !queryAst.groups.length) return true;
  // AND across groups; OR inside group
  for (const g of queryAst.groups) {
    let ok = false;
    for (const term of g.terms) {
      if (fieldMatches(task, term)) { ok = true; break; }
    }
    if (!ok) return false;
  }
  return true;
}

function msToParts(ms) {
  let rest = Math.max(0, ms);
  const minutes = Math.floor(rest / 60000); rest -= minutes*60000;
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

// Linear gradient between #FF000D and #00FF00, text between #FFFF00 and #000000
function lerp(a,b,t){ return Math.round(a + (b-a)*t); }
function hex(c){ return c.toString(16).padStart(2,"0"); }

function gradientColor(ratio) {
  const r = lerp(0xFF, 0x00, ratio);
  const g = lerp(0x00, 0xFF, ratio);
  const b = lerp(0x0D, 0x00, ratio);
  return `#${hex(r)}${hex(g)}${hex(b)}`;
}
function textGradient(ratio) {
  const r = lerp(0xFF, 0x00, ratio);
  const g = lerp(0xFF, 0x00, ratio);
  const b = lerp(0x00, 0x00, ratio);
  return `#${hex(r)}${hex(g)}${hex(b)}`;
}

function recurrenceToText(t) {
  if (t.recurrence_mode === "none") return `One-time @ ${t.due_at ? new Date(t.due_at).toLocaleString() : "n/a"}`;
  if (t.recurrence_mode === "after") {
    const v = t.recurrence_params?.value, u = t.recurrence_params?.unit;
    return `Every ${v} ${u} after complete`;
  }
  if (t.recurrence_mode === "cron") {
    return `Cron ${t.recurrence_params?.cron}`;
  }
  if (t.recurrence_mode === "set") {
    const n = (t.recurrence_params?.crons || []).length;
    return `Specific times (${n})`;
  }
  return "";
}

async function fetchTasks() {
  const res = await fetch(API);
  const list = await res.json();
  // decorate
  for (const t of list) {
    t.recurrenceText = recurrenceToText(t);
    t.truncDesc = (t.description||"").length > 100 ? (t.description.slice(0,100)+"…") : (t.description||"");
  }
  tasks = list;
  render();
}

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

    function td(label, html) {
      const el = document.createElement("td");
      el.setAttribute("data-label", label);
      el.innerHTML = html;
      return el;
    }

    // Done button
    const doneBtn = `<button class="small" data-done="${t.id}">Complete</button>`;
    tr.appendChild(td("Done", doneBtn));

    // Open button
    const openBtn = t.url ? `<a class="small" target="_blank" rel="noopener" href="${t.url}"><button class="small">Open</button></a>` : "";
    tr.appendChild(td("Open", openBtn));

    // Time Left
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

    tb.appendChild(tr);
  }

  // wire complete buttons
  document.querySelectorAll("button[data-done]").forEach(btn=>{
    btn.onclick = async () => {
      const id = btn.getAttribute("data-done");
      const res = await fetch(`${API}/${id}/complete`, {method:"POST"});
      const j = await res.json();
      if (j.status === "deleted" || j.status === "advanced") {
        fetchTasks();
      }
    };
  });
}

document.getElementById("search").addEventListener("input", render);

document.querySelectorAll("thead th").forEach(th=>{
  th.onclick = () => {
    const key = th.getAttribute("data-sort");
    if (!key) return;
    if (sortKey === key) sortDir = sortDir === "asc" ? "desc" : "asc";
    else { sortKey = key; sortDir = "asc"; }
    render();
  };
});

fetchTasks();
setInterval(fetchTasks, 30000);
