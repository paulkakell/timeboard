<<<<<<< HEAD
<will be replaced>
=======
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, AnyUrl, field_validator
from typing import Optional, List, Literal, Any, Dict
from datetime import datetime, timedelta
from croniter import croniter, CroniterBadCronError
from sqlalchemy.orm import Session
from sqlalchemy import select
from zoneinfo import ZoneInfo
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
import json, os
from pathlib import Path
>>>>>>> c12f6754ab679429516c92e84fa106cf949a473f

def require_admin(request: Request):
    if not ADMIN_TOKEN:
        return
    provided = request.headers.get("X-Admin-Token") or request.query_params.get("token")
    if provided != ADMIN_TOKEN:
        raise HTTPException(401, "admin token required")

<<<<<<< HEAD
def db_file_info():
    url = str(engine.url)
    if engine.dialect.name == "sqlite":
        path = engine.url.database
        if path and path != ":memory:" and os.path.exists(path):
            try:
                size = os.path.getsize(path)
            except Exception:
                size = None
            return {"type":"sqlite","path":path,"size_bytes":size}
        return {"type":"sqlite","path":engine.url.database,"size_bytes":None}
    if engine.dialect.name.startswith("postgres"):
        with engine.begin() as conn:
            try:
                sz = conn.execute(text("SELECT pg_database_size(current_database())")).scalar()
            except Exception:
                sz = None
        return {"type":"postgres","size_bytes":int(sz) if sz is not None else None}
    if engine.dialect.name.startswith("mysql"):
        with engine.begin() as conn:
            try:
                sz = conn.execute(text("SELECT SUM(data_length + index_length) FROM information_schema.tables WHERE table_schema = DATABASE()")).scalar()
            except Exception:
                sz = None
        return {"type":"mysql","size_bytes":int(sz) if sz is not None else None}
    return {"type":engine.dialect.name,"size_bytes":None}

def get_db_version_conn(conn) -> int:
    try:
        cur = conn.execute(text("SELECT value FROM meta WHERE key='db_version'"))
        row = cur.first()
        if row and row[0]:
            return int(row[0])
    except Exception:
        pass
    try:
        cols = {c['name'] for c in inspect(conn).get_columns('tasks')}
        if 'last_done_at' in cols and 'created_at' in cols and 'updated_at' in cols:
            return 2
    except Exception:
        pass
    return 1

def set_db_version_conn(conn, v: int):
    try:
        cur = conn.execute(text("SELECT 1 FROM meta WHERE key='db_version'"))
        if cur.first():
            conn.execute(text("UPDATE meta SET value=:v WHERE key='db_version'"), {"v": str(v)})
        else:
            conn.execute(text("INSERT INTO meta(key,value) VALUES('db_version', :v)"), {"v": str(v)})
    except Exception:
        pass

def migrate_to_required():
    with engine.begin() as conn:
        current = get_db_version_conn(conn)
        if current >= REQUIRED_DB_VERSION:
            return {"migrated": False, "from": current, "to": current}
        if current < 2:
            dialect = conn.dialect.name
            def coltype():
                return "TEXT" if dialect == "sqlite" else "TIMESTAMPTZ"
            try:
                conn.execute(text(f"ALTER TABLE tasks ADD COLUMN IF NOT EXISTS last_done_at {coltype()}"))
            except Exception:
                conn.execute(text(f"ALTER TABLE tasks ADD COLUMN last_done_at {coltype()}"))
            default_sql = "DEFAULT (CURRENT_TIMESTAMP)" if dialect == "sqlite" else "DEFAULT NOW()"
            try:
                conn.execute(text(f"ALTER TABLE tasks ADD COLUMN IF NOT EXISTS created_at {coltype()} {default_sql}"))
            except Exception:
                conn.execute(text(f"ALTER TABLE tasks ADD COLUMN created_at {coltype()} {default_sql}"))
            try:
                conn.execute(text(f"ALTER TABLE tasks ADD COLUMN IF NOT EXISTS updated_at {coltype()}"))
            except Exception:
                conn.execute(text(f"ALTER TABLE tasks ADD COLUMN updated_at {coltype()}"))
            set_db_version_conn(conn, 2)
            current = 2
        return {"migrated": True, "from": current, "to": REQUIRED_DB_VERSION}


@app.get("/admin", response_class=FileResponse)
def admin_page():
    return FileResponse(STATIC_DIR / "admin.html")

@app.get("/api/admin/info")
def admin_info(request: Request):
    require_admin(request)
    info = db_file_info()
    with engine.begin() as conn:
        cur = get_db_version_conn(conn)
    obsolete = cur < REQUIRED_DB_VERSION
    return {
        "dialect": engine.dialect.name,
        "db_url": str(engine.url).split('@')[-1],
        "size_bytes": info.get("size_bytes"),
        "sqlite_file": info.get("path") if info.get("type") == "sqlite" else None,
        "current_version": cur,
        "required_version": REQUIRED_DB_VERSION,
        "obsolete": obsolete
    }

@app.post("/api/admin/upgrade")
def admin_upgrade(request: Request):
    require_admin(request)
    return migrate_to_required()

@app.get("/api/admin/export/json")
def export_json(request: Request):
    require_admin(request)
    with engine.begin() as conn:
        rows = list(conn.execute(text("SELECT id,name,type,subtype,url,description,tags,recurrence_mode,recurrence_params,due_at,next_due_at,last_done_at,created_at,updated_at FROM tasks")))
        tasks = []
        for r in rows:
            tasks.append({k: r[i].isoformat() if hasattr(r[i], 'isoformat') and r[i] is not None else r[i]
                          for i, k in enumerate(["id","name","type","subtype","url","description","tags","recurrence_mode","recurrence_params","due_at","next_due_at","last_done_at","created_at","updated_at"])})
        try:
            meta = list(conn.execute(text("SELECT key,value FROM meta")))
            meta = [{"key": k, "value": v} for (k, v) in meta]
        except Exception:
            meta = []
        payload = {
            "exported_at": datetime.utcnow().isoformat()+"Z",
            "dialect": engine.dialect.name,
            "current_version": get_db_version_conn(conn),
            "required_version": REQUIRED_DB_VERSION,
            "tasks": tasks,
            "meta": meta
        }
    buf = io.BytesIO(json.dumps(payload, separators=(",",":")).encode("utf-8"))
    return StreamingResponse(buf, media_type="application/json", headers={"Content-Disposition":"attachment; filename=timeboard-export.json"})

@app.get("/api/admin/export/sqlite")
def export_sqlite(request: Request):
    require_admin(request)
    info = db_file_info()
    if info.get("type") != "sqlite" or not info.get("path") or not os.path.exists(info["path"]):
        raise HTTPException(400, "Not a file-based SQLite database")
    return FileResponse(info["path"], filename="timeboard.db")

@app.post("/api/admin/import/json")
async def import_json(request: Request):
    require_admin(request)
    replace = request.query_params.get("replace") in {"1","true","yes"}
    try:
        body = await request.body()
        data = json.loads(body.decode("utf-8"))
    except Exception:
        raise HTTPException(400, "Invalid JSON")
    if not isinstance(data, dict) or "tasks" not in data:
        raise HTTPException(400, "Invalid export format")
    tasks = data.get("tasks") or []
    meta = data.get("meta") or []
    with engine.begin() as conn:
        if replace:
            try:
                conn.execute(text("DELETE FROM tasks"))
            except Exception:
                pass
            try:
                conn.execute(text("DELETE FROM meta"))
            except Exception:
                pass
        for m in meta:
            k = m.get("key"); v = m.get("value")
            if not k: continue
            try:
                conn.execute(text("INSERT INTO meta(key,value) VALUES(:k,:v) ON CONFLICT(key) DO UPDATE SET value=excluded.value")), {"k":k,"v":v}
            except Exception:
                try:
                    exists = conn.execute(text("SELECT 1 FROM meta WHERE key=:k"), {"k":k}).first()
                    if exists:
                        conn.execute(text("UPDATE meta SET value=:v WHERE key=:k"), {"k":k,"v":v})
                    else:
                        conn.execute(text("INSERT INTO meta(key,value) VALUES(:k,:v)"), {"k":k,"v":v})
                except Exception:
                    pass
        for t in tasks:
            fields = ["id","name","type","subtype","url","description","tags","recurrence_mode","recurrence_params","due_at","next_due_at","last_done_at","created_at","updated_at"]
            vals = {k: t.get(k) for k in fields}
            for k in ["due_at","next_due_at","last_done_at","created_at","updated_at"]:
                if vals.get(k):
                    try:
                        vals[k] = datetime.fromisoformat(vals[k].replace("Z","+00:00"))
                    except Exception:
                        vals[k] = None
            cols = ",".join([k for k in fields if vals.get(k) is not None and k != "id"])
            params = {k: v for k,v in vals.items() if v is not None and k != "id"}
            if replace and vals.get("id") is not None:
                cols = "id," + cols
                params["id"] = vals["id"]
            placeholders = ",".join([f":{k}" for k in params.keys()])
            try:
                conn.execute(text(f"INSERT INTO tasks ({cols}) VALUES ({placeholders})"), params)
            except Exception:
                conn.execute(text("INSERT INTO tasks (name,recurrence_mode) VALUES (:name,:mode)"), {"name": vals.get("name") or "Imported", "mode": vals.get("recurrence_mode") or "none"})
    return {"status":"ok"}

@app.get("/admin/docs", response_class=FileResponse)
def admin_docs_page_alias():
    return FileResponse(STATIC_DIR / "admin_docs.html")

@app.get("/admin/db", response_class=FileResponse)
def admin_db_page():
    return FileResponse(STATIC_DIR / "admin_db.html")
=======
# ------------------ Settings ------------------
def _split_env(name: str) -> List[str]:
    val = os.getenv(name, "").strip()
    if not val:
        return []
    return [p.strip() for p in val.split(",") if p.strip()]

ALLOWED_HOSTS = _split_env("ALLOWED_HOSTS") or ["*"]
CORS_ALLOW_ORIGINS = _split_env("CORS_ALLOW_ORIGINS")
ENABLE_HSTS = os.getenv("ENABLE_HSTS", "0") == "1"
MAX_REQUEST_BYTES = int(os.getenv("MAX_REQUEST_BYTES", "65536"))  # 64 KiB
DEFAULT_TZ = os.getenv("TIMEBOARD_TZ") or os.getenv("TZ") or "UTC"
STATIC_DIR = Path(__file__).resolve().parent / "static"

# ------------------ Schemas ------------------
class TaskIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    type: Optional[str] = Field(None, max_length=100)
    subtype: Optional[str] = Field(None, max_length=100)
    url: Optional[AnyUrl] = None
    description: Optional[str] = Field(None, max_length=8000)
    tags: List[str] = Field(default_factory=list)
    recurrence_mode: Literal["none","after","cron","set"]
    due_at: Optional[str] = None  # 'none' mode
    recurrence_params: Optional[Dict[str, Any]] = None

    @field_validator("tags")
    @classmethod
    def _clean_tags(cls, v: List[str]) -> List[str]:
        out: List[str] = []
        for s in v or []:
            s = (s or "").strip()
            if not s:
                continue
            if len(s) > 60:
                s = s[:60]
            out.append(s)
            if len(out) >= 20:
                break
        return out

class TaskOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    type: Optional[str] = None
    subtype: Optional[str] = None
    url: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = []
    recurrence_mode: str
    recurrence_params: Optional[Dict[str, Any]] = None
    due_at: Optional[str] = None
    next_due_at: Optional[str] = None
    time_left_ms: Optional[int] = None

    @classmethod
    def from_model(cls, t: Task, tz: ZoneInfo):
        def dt_str(x):
            if not x: return None
            return x.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")
        tags = [s.strip() for s in (t.tags or "").split(",") if s.strip()]
        try:
            rp = json.loads(t.recurrence_params) if t.recurrence_params else None
        except Exception:
            rp = None
        target = t.next_due_at or t.due_at
        tl = None
        if target:
            tl = int((target - datetime.now(ZoneInfo("UTC"))).total_seconds() * 1000)
        return cls(
            id=t.id, name=t.name, type=t.type, subtype=t.subtype, url=t.url,
            description=t.description, tags=tags, recurrence_mode=t.recurrence_mode,
            recurrence_params=rp, due_at=dt_str(t.due_at), next_due_at=dt_str(t.next_due_at),
            time_left_ms=tl
        )

# ------------------ App ------------------
app = FastAPI(title="Timeboard API")
Base.metadata.create_all(bind=engine)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Security middlewares
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)
if CORS_ALLOW_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ALLOW_ORIGINS,
        allow_methods=["GET","POST","PUT","DELETE","OPTIONS"],
        allow_headers=["*"],
    )

@app.middleware("http")
async def security_headers(request: Request, call_next):
    # Basic request size guard
    try:
        clen = request.headers.get("content-length")
        if clen and int(clen) > MAX_REQUEST_BYTES:
            return JSONResponse({"detail":"Request too large"}, status_code=413)
    except Exception:
        pass

    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    csp = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    resp.headers["Content-Security-Policy"] = os.getenv("SECURITY_CSP", csp)
    if ENABLE_HSTS:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp

# Helpers
def get_tz():
    try:
        return ZoneInfo(DEFAULT_TZ)
    except Exception:
        return ZoneInfo("UTC")

def parse_due_str(s: Optional[str], tz: ZoneInfo):
    if not s: return None
    s = s.strip()
    try:
        if "T" in s or "Z" in s:
            dt = datetime.fromisoformat(s.replace("Z","+00:00"))
        else:
            dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
            dt = dt.replace(tzinfo=tz)
        return dt.astimezone(ZoneInfo("UTC"))
    except Exception:
        return None

def validate_payload(pl: TaskIn):
    # Validate mode-specific params
    rp = pl.recurrence_params or {}
    if pl.recurrence_mode == "none":
        return
    if pl.recurrence_mode == "after":
        interval = int((rp or {}).get("interval", 1))
        if interval <= 0 or interval > 10**6:
            raise HTTPException(400, "Invalid interval")
        unit = (rp or {}).get("unit", "days")
        if unit not in {"minutes","hours","days","weeks","months","years"}:
            raise HTTPException(400, "Invalid unit")
    if pl.recurrence_mode == "cron":
        expr = (rp or {}).get("cron") or ""
        if not expr:
            raise HTTPException(400, "Missing cron expression")
        try:
            croniter(expr, datetime.now())
        except CroniterBadCronError:
            raise HTTPException(400, "Invalid cron expression")
    if pl.recurrence_mode == "set":
        times = (rp or {}).get("times") or []
        if not isinstance(times, list) or len(times) == 0:
            raise HTTPException(400, "Missing times for set mode")

def compute_next_due(mode: str, rp: Optional[Dict[str, Any]], due_at: Optional[datetime], now_utc: datetime):
    tz = get_tz()
    if mode == "none":
        return due_at
    if mode == "after":
        interval = int((rp or {}).get("interval", 1))
        unit = (rp or {}).get("unit", "days")
        seconds = {
            "minutes": 60,
            "hours": 3600,
            "days": 86400,
            "weeks": 604800,
            "months": 2592000,  # approx
            "years": 31536000,
        }.get(unit, 86400)
        return now_utc + timedelta(seconds=interval * seconds)
    if mode == "cron":
        expr = (rp or {}).get("cron") or "* * * * *"
        rtz = (rp or {}).get("tz") or "UTC"
        try:
            tzinfo = ZoneInfo(rtz)
        except Exception:
            tzinfo = ZoneInfo("UTC")
        base_local = now_utc.astimezone(tzinfo).replace(second=0, microsecond=0)
        it = croniter(expr, base_local)
        nxt_local = it.get_next(datetime)
        return nxt_local.astimezone(ZoneInfo("UTC"))
    if mode == "set":
        times = (rp or {}).get("times") or []
        rtz = (rp or {}).get("tz") or "UTC"
        try:
            tzinfo = ZoneInfo(rtz)
        except Exception:
            tzinfo = ZoneInfo("UTC")
        future = []
        for s in times:
            dt = parse_due_str(s, tzinfo)
            if not dt:
                continue
            if dt > now_utc:
                future.append(dt)
        return min(future) if future else None
    return None

def serialize_rp(rp: Optional[Dict[str, Any]]):
    return json.dumps(rp or {}, separators=(",",":"))

# ------------------ Routes ------------------
@app.get("/", response_class=FileResponse)
def index():
    return FileResponse(STATIC_DIR / "index.html")

@app.get("/new", response_class=FileResponse)
def new_task_page():
    return FileResponse(STATIC_DIR / "new.html")

@app.get("/about", response_class=FileResponse)
def about_page():
    return FileResponse(STATIC_DIR / "about.html")

@app.get("/healthz")
def healthz():
    return {"ok": True}

@app.get("/api/meta")
def meta():
    repo = os.getenv("REPOSITORY_URL") or ""
    release = os.getenv("RELEASE") or "dev"
    return {"tz": str(get_tz().key), "repository_url": repo, "release": release, "powered_by": "FastAPI"}

@app.get("/api/tasks", response_model=List[TaskOut])
def list_tasks(db: Session = Depends(get_db)):
    rows = list(db.execute(select(Task)).scalars())
    rows = sorted(rows, key=lambda t: ((t.next_due_at is None), t.next_due_at or datetime.max, t.id))
    tz = get_tz()
    return [TaskOut.from_model(r, tz) for r in rows]

@app.post("/api/tasks", response_model=TaskOut)
def create_task(payload: TaskIn, db: Session = Depends(get_db)):
    validate_payload(payload)
    tz = get_tz()
    rp = payload.recurrence_params or {}
    if payload.recurrence_mode == "none":
        due = parse_due_str(payload.due_at, tz)
        if not due:
            raise HTTPException(400, "Invalid or missing due_at")
        next_due = due
    else:
        due = None
        next_due = compute_next_due(payload.recurrence_mode, rp, None, datetime.now(ZoneInfo("UTC")))
    t = Task(
        name=payload.name.strip(),
        type=(payload.type or None),
        subtype=(payload.subtype or None),
        url=(str(payload.url) if payload.url else None),
        description=(payload.description or None),
        tags=",".join(payload.tags or []),
        recurrence_mode=payload.recurrence_mode,
        recurrence_params=serialize_rp(rp),
        due_at=due,
        next_due_at=next_due,
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    return TaskOut.from_model(t, tz)

@app.get("/api/tasks/{task_id}", response_model=TaskOut)
def get_task(task_id: int, db: Session = Depends(get_db)):
    row = db.get(Task, task_id)
    if not row:
        raise HTTPException(404, "Not found")
    return TaskOut.from_model(row, get_tz())

@app.put("/api/tasks/{task_id}", response_model=TaskOut)
def update_task(task_id: int, payload: TaskIn, db: Session = Depends(get_db)):
    validate_payload(payload)
    t = db.get(Task, task_id)
    if not t:
        raise HTTPException(404, "Not found")
    tz = get_tz()
    t.name = payload.name.strip()
    t.type = payload.type or None
    t.subtype = payload.subtype or None
    t.url = str(payload.url) if payload.url else None
    t.description = payload.description or None
    t.tags = ",".join(payload.tags or [])
    t.recurrence_mode = payload.recurrence_mode
    rp = payload.recurrence_params or {}
    t.recurrence_params = serialize_rp(rp)
    if t.recurrence_mode == "none":
        t.due_at = parse_due_str(payload.due_at, tz)
        t.next_due_at = t.due_at
    else:
        t.due_at = None
        t.next_due_at = compute_next_due(t.recurrence_mode, rp, None, datetime.now(ZoneInfo("UTC")))
    db.commit()
    db.refresh(t)
    return TaskOut.from_model(t, tz)

@app.post("/api/tasks/{task_id}/advance", response_model=TaskOut)
def advance_task(task_id: int, db: Session = Depends(get_db)):
    t = db.get(Task, task_id)
    if not t:
        raise HTTPException(404, "Not found")
    now = datetime.now(ZoneInfo("UTC"))
    try:
        rp = json.loads(t.recurrence_params or "{}") or {}
    except Exception:
        rp = {}
    if t.recurrence_mode == "none":
        t.last_done_at = now
        t.due_at = None
        t.next_due_at = None
    elif t.recurrence_mode == "after":
        t.last_done_at = now
        t.next_due_at = compute_next_due("after", rp, None, now)
    elif t.recurrence_mode == "cron":
        t.last_done_at = now
        t.next_due_at = compute_next_due("cron", rp, None, now + timedelta(seconds=1))
    elif t.recurrence_mode == "set":
        times = (rp.get("times") or [])
        tzname = rp.get("tz") or "UTC"
        try:
            tzinfo = ZoneInfo(tzname)
        except Exception:
            tzinfo = ZoneInfo("UTC")
        new_times = []
        for s in times:
            try:
                if "T" in s or "Z" in s:
                    dt = datetime.fromisoformat(s.replace("Z","+00:00"))
                else:
                    dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=tzinfo)
                dt = dt.astimezone(ZoneInfo("UTC"))
            except Exception:
                continue
            if dt > now:
                new_times.append(s)
        rp["times"] = new_times
        t.recurrence_params = serialize_rp(rp)
        t.last_done_at = now
        t.next_due_at = compute_next_due("set", rp, None, now + timedelta(seconds=1))
    db.commit()
    db.refresh(t)
    return TaskOut.from_model(t, get_tz())

@app.delete("/api/tasks/{task_id}")
def delete_task(task_id: int, db: Session = Depends(get_db)):
    t = db.get(Task, task_id)
    if not t:
        raise HTTPException(404, "Task not found")
    db.delete(t)
    db.commit()
    return {"status": "deleted"}

@app.get("/assets/version.json")
def version_json():
    f = STATIC_DIR / "version.json"
    if f.exists():
        try:
            return JSONResponse(json.loads(f.read_text()))
        except Exception:
            pass
    return {"version":"dev","summary":"Timeboard","changes":[]}
>>>>>>> c12f6754ab679429516c92e84fa106cf949a473f
