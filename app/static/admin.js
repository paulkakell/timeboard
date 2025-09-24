
function humanBytes(n){ if(n==null) return "unknown"; const u=["B","KB","MB","GB","TB"]; let i=0,v=Number(n); while(v>=1024&&i<u.length-1){v/=1024;i++;} return v.toFixed(i?1:0)+" "+u[i]; }
function token(){ return localStorage.getItem("adminToken")||""; }
function headers(){ const h={}; const t=token(); if(t) h["X-Admin-Token"]=t; return h; }
async function loadInfo(){
  const r = await fetch("/api/admin/info", { headers: headers() });
  if(!r.ok){ document.getElementById("dbInfo").textContent="Failed to load. Check token."; return; }
  const j = await r.json();
  const parts=[];
  parts.push("Dialect: "+j.dialect);
  if(j.sqlite_file) parts.push("SQLite file: "+j.sqlite_file);
  if(j.size_bytes!=null) parts.push("Size: "+humanBytes(j.size_bytes));
  parts.push("Version: "+j.current_version+" required "+j.required_version+(j.obsolete?" (obsolete)":""));
  document.getElementById("dbInfo").textContent = parts.join(" | ");
  document.getElementById("exportSqlite").style.display = j.sqlite_file ? "inline-block" : "none";
  document.getElementById("runUpgrade").style.display = j.obsolete ? "inline-block" : "none";
}
document.getElementById("saveToken").addEventListener("click", ()=>{ localStorage.setItem("adminToken", document.getElementById("admToken").value.trim()); loadInfo(); });
document.getElementById("exportJson").addEventListener("click", async ()=>{
  const r = await fetch("/api/admin/export/json", { headers: headers() });
  if(!r.ok){ alert("Export failed"); return; }
  const blob = await r.blob(); const url = URL.createObjectURL(blob); const a=document.createElement("a"); a.href=url; a.download="timeboard-export.json"; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
});
document.getElementById("exportSqlite").addEventListener("click", async ()=>{
  const r = await fetch("/api/admin/export/sqlite", { headers: headers() });
  if(!r.ok){ alert("Export failed"); return; }
  const blob = await r.blob(); const url = URL.createObjectURL(blob); const a=document.createElement("a"); a.href=url; a.download="timeboard.db"; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
});
document.getElementById("importFile").addEventListener("change", async (ev)=>{
  const f = ev.target.files[0]; if(!f) return; const text = await f.text(); const replace = document.getElementById("importReplace").checked ? "1":"0";
  const r = await fetch("/api/admin/import/json?replace="+replace, { method:"POST", headers:Object.assign({"Content-Type":"application/json"}, headers()), body:text });
  if(!r.ok){ alert("Import failed"); return; } alert("Import ok"); loadInfo();
});
document.getElementById("runUpgrade").addEventListener("click", async ()=>{
  if(!confirm("Upgrade the database schema now?")) return;
  const r = await fetch("/api/admin/upgrade", { method:"POST", headers: headers() });
  if(!r.ok){ alert("Upgrade failed"); return; } alert("Upgrade complete"); loadInfo();
});
loadInfo();
