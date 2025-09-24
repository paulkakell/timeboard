from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, List, Literal, Any
from datetime import datetime, timedelta
from croniter import croniter
from sqlalchemy.orm import Session
from sqlalchemy import select
import json, os
from zoneinfo import ZoneInfo

from .db import Base, engine, get_db
from .models import Task

Base.metadata.create_all(bind=engine)

# env
TZ = os.getenv("TIMEBOARD_TZ", "UTC")
RELEASE_VERSION = os.getenv("RELEASE_VERSION", "dev")
REPOSITORY_URL = os.getenv("REPOSITORY_URL", "https://github.com/owner/repo")

def parse_due_str(s: Optional[str], tz: str) -> Optional[datetime]:
    if not s:
        return None
    s = s.strip()
    # Support "YYYY-MM-DD HH:MM:SS" and "YY-MM-DD HH:MM:SS"
    try:
        if len(s.split()[0].split("-")[0]) == 2:
            # YY-MM-DD
            dt = datetime.strptime(s, "%y-%m-%d %H:%M:%S")
            year = 2000 + dt.year  # naive mapping 00..99 -> 2000..2099
            dt = dt.replace(year=year)
        else:
            dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        raise HTTPException(status_code=422, detail="Use 24h format: YYYY-MM-DD HH:MM:SS")
    # interpret in user tz, then convert to UTC for storage
    tzinfo = ZoneInfo(tz)
    local = dt.replace(tzinfo=tzinfo)
    return local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)

def to_user_tz(dt: Optional[datetime], tz: str) -> Optional[str]:
    if not dt:
        return None
    local = dt.replace(tzinfo=ZoneInfo("UTC")).astimezone(ZoneInfo(tz))
    return local.strftime("%Y-%m-%d %H:%M:%S")

def compute_next_due_after(params: dict, from_dt: datetime) -> datetime:
    unit = params.get("unit", "days")
    interval = int(params.get("interval", 1))
    if unit == "minutes":
        return from_dt + timedelta(minutes=interval)
    if unit == "hours":
        return from_dt + timedelta(hours=interval)
    if unit == "days":
        return from_dt + timedelta(days=interval)
    if unit == "weeks":
        return from_dt + timedelta(weeks=interval)
    if unit == "months":
        # naive month add: 30 days per month
        return from_dt + timedelta(days=30*interval)
    if unit == "years":
        return from_dt + timedelta(days=365*interval)
    return from_dt + timedelta(days=interval)

def compute_next_due(task: Task, now: datetime) -> Optional[datetime]:
    mode = task.recurrence_mode
    params = json.loads(task.recurrence_params) if task.recurrence_params else {}
    if mode == "none":
        return task.due_at
    if mode == "after":
        base = task.last_completed_at or now
        return compute_next_due_after(params, base)
    if mode == "cron":
        expr = params.get("cron", "* * * * *")
        tz = params.get("tz") or TZ
        tzinfo = ZoneInfo(tz)
        # Use last_completed or now as base
        base_local = (task.last_completed_at or now).replace(tzinfo=ZoneInfo("UTC")).astimezone(tzinfo)
        it = croniter(expr, base_local)
        next_local = it.get_next(datetime)
        next_utc = next_local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
        return next_utc
    if mode == "set":
        # explicit list of datetimes in user tz
        items = params.get("times", [])
        tz = params.get("tz") or TZ
        candidates = []
        for s in items:
            try:
                dt = parse_due_str(s, tz)
                if dt and dt > now:
                    candidates.append(dt)
            except HTTPException:
                continue
        return min(candidates) if candidates else None
    return None

class TaskIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    type: Optional[str] = None
    subtype: Optional[str] = None
    url: Optional[HttpUrl] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    recurrence_mode: Literal["none","after","cron","set"]
    due_at: Optional[str] = None
    recurrence_params: Optional[dict] = None

class TaskOut(BaseModel):
    id: int
    name: str
    type: Optional[str]
    subtype: Optional[str]
    url: Optional[str]
    description: Optional[str]
    tags: List[str] = []
    recurrence_mode: str
    recurrence_params: dict = {}
    due_at: Optional[str] = None
    last_completed_at: Optional[str] = None
    next_due_at: Optional[str] = None
    time_left_ms: Optional[int] = None
    created_at: str
    updated_at: str

    @staticmethod
    def from_model(t: Task, tz: str) -> "TaskOut":
        now = datetime.utcnow()
        due = to_user_tz(t.due_at, tz)
        next_due = to_user_tz(t.next_due_at, tz)
        last = to_user_tz(t.last_completed_at, tz)
        tl = None
        if t.next_due_at:
            delta = t.next_due_at - now
            tl = int(delta.total_seconds()*1000)
        return TaskOut(
            id=t.id,
            name=t.name,
            type=t.type,
            subtype=t.subtype,
            url=t.url,
            description=t.description,
            tags=[x for x in (t.tags or "").split(",") if x],
            recurrence_mode=t.recurrence_mode,
            recurrence_params=json.loads(t.recurrence_params) if t.recurrence_params else {},
            due_at=due,
            last_completed_at=last,
            next_due_at=next_due,
            time_left_ms=tl,
            created_at=to_user_tz(t.created_at, tz) or "",
            updated_at=to_user_tz(t.updated_at, tz) or "",
        )

app = FastAPI()

app.mount("/static", StaticFiles(directory=str((Path(__file__).parent / "static").resolve())), name="static")

from pathlib import Path
STATIC_DIR = Path(__file__).parent / "static"

@app.get("/")
def index():
    return FileResponse(str(STATIC_DIR / "index.html"))

@app.get("/new")
def new_page():
    return FileResponse(str(STATIC_DIR / "new.html"))

@app.get("/api/meta")
def meta():
    return {"tz": TZ, "release": RELEASE_VERSION, "repository_url": REPOSITORY_URL}

@app.get("/api/tasks", response_model=List[TaskOut])
def list_tasks(db: Session = Depends(get_db)):
    tz = TZ
    stmt = select(Task).order_by(Task.next_due_at.is_(None), Task.next_due_at.asc(), Task.id.asc())
    rows = db.execute(stmt).scalars().all()
    return [TaskOut.from_model(t, tz) for t in rows]

@app.post("/api/tasks", response_model=TaskOut)
def create_task(payload: TaskIn, db: Session = Depends(get_db)):
    tz = TZ
    tags = ",".join(payload.tags or [])
    due_at = parse_due_str(payload.due_at, tz) if payload.recurrence_mode == "none" else None
    rec_params = payload.recurrence_params or {}
    # write default tz into recurrence params when helpful
    if payload.recurrence_mode in ("cron","set") and not rec_params.get("tz"):
        rec_params["tz"] = tz
    t = Task(
        name=payload.name.strip(),
        type=(payload.type or "").strip() or None,
        subtype=(payload.subtype or "").strip() or None,
        url=str(payload.url) if payload.url else None,
        description=payload.description or None,
        tags=tags,
        recurrence_mode=payload.recurrence_mode,
        recurrence_params=json.dumps(rec_params),
        due_at=due_at,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    # precompute next_due_at
    t.next_due_at = compute_next_due(t, datetime.utcnow())
    db.add(t)
    db.commit()
    db.refresh(t)
    return TaskOut.from_model(t, tz)

@app.put("/api/tasks/{task_id}", response_model=TaskOut)
def update_task(task_id: int, payload: TaskIn, db: Session = Depends(get_db)):
    tz = TZ
    t = db.get(Task, task_id)
    if not t:
        raise HTTPException(status_code=404, detail="Task not found")
    t.name = payload.name.strip()
    t.type = (payload.type or "").strip() or None
    t.subtype = (payload.subtype or "").strip() or None
    t.url = str(payload.url) if payload.url else None
    t.description = payload.description or None
    t.tags = ",".join(payload.tags or [])
    t.recurrence_mode = payload.recurrence_mode
    t.recurrence_params = json.dumps(payload.recurrence_params or {})
    t.due_at = parse_due_str(payload.due_at, tz) if payload.recurrence_mode == "none" else None
    t.updated_at = datetime.utcnow()
    t.next_due_at = compute_next_due(t, datetime.utcnow())
    db.commit()
    db.refresh(t)
    return TaskOut.from_model(t, tz)

@app.post("/api/tasks/{task_id}/advance")
def advance(task_id: int, db: Session = Depends(get_db)):
    t = db.get(Task, task_id)
    if not t:
        raise HTTPException(status_code=404, detail="Task not found")
    now = datetime.utcnow()
    t.last_completed_at = now
    t.next_due_at = compute_next_due(t, now)
    t.updated_at = now
    db.commit()
    return {"status": "advanced", "next_due_at": to_user_tz(t.next_due_at, TZ)}

@app.delete("/api/tasks/{task_id}")
def delete_task(task_id: int, db: Session = Depends(get_db)):
    t = db.get(Task, task_id)
    if not t:
        raise HTTPException(status_code=404, detail="Task not found")
    db.delete(t)
    db.commit()
    return {"status": "deleted"}
