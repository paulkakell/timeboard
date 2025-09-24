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

from .db import Base, engine, get_db
from .models import Task

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
