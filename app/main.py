from fastapi import FastAPI, Depends, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Literal, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import select, delete
from croniter import croniter
import json

from .db import Base, engine, get_db
from .models import Task

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Timeboard")

app.mount("/static", StaticFiles(directory="app/static"), name="static")

@app.get("/", include_in_schema=False)
def root():
    return FileResponse("app/static/index.html")

# ---------- Schemas ----------
RecurrenceMode = Literal["none","after","cron","set"]

class TaskIn(BaseModel):
    name: str
    type: Optional[str] = None
    subtype: Optional[str] = None
    url: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

    recurrence_mode: RecurrenceMode
    # for "none": provide due_at
    due_at: Optional[datetime] = None

    # for "after": every interval after completion
    after_interval_value: Optional[int] = None        # e.g., 15
    after_interval_unit: Optional[Literal["minutes","hours","days","months"]] = None

    # for "cron": a single cron string like "0 12 * * *"
    cron: Optional[str] = None

    # for "set": list of cron strings
    cron_set: Optional[List[str]] = None

class TaskOut(BaseModel):
    id: int
    name: str
    type: Optional[str]
    subtype: Optional[str]
    url: Optional[str]
    description: Optional[str]
    tags: List[str]
    recurrence_mode: RecurrenceMode
    recurrence_params: Any
    due_at: Optional[datetime]
    last_completed_at: Optional[datetime]
    next_due_at: Optional[datetime]
    time_left_ms: int

    class Config:
        from_attributes = True

# ---------- Helpers ----------
def months_add(dt: datetime, n: int) -> datetime:
    # naive month add: 30 days per month approximation
    return dt + timedelta(days=30*n)

def compute_next_due_now(recurrence_mode: str, params: dict, now: datetime, due_at: Optional[datetime]) -> Optional[datetime]:
    if recurrence_mode == "none":
        return due_at
    if recurrence_mode == "after":
        val = int(params.get("value", 0))
        unit = params.get("unit")
        if unit == "minutes":
            return now + timedelta(minutes=val)
        if unit == "hours":
            return now + timedelta(hours=val)
        if unit == "days":
            return now + timedelta(days=val)
        if unit == "months":
            return months_add(now, val)
        return None
    if recurrence_mode == "cron":
        cron = params.get("cron")
        if not cron:
            return None
        return croniter(cron, now).get_next(datetime)
    if recurrence_mode == "set":
        crons = params.get("crons", [])
        candidates = []
        for c in crons:
            try:
                candidates.append(croniter(c, now).get_next(datetime))
            except Exception:
                pass
        return min(candidates) if candidates else None
    return None

def to_tags_str(tags: List[str]) -> str:
    return ",".join([t.strip() for t in tags if t.strip()])

def to_tags_list(s: Optional[str]) -> List[str]:
    if not s:
        return []
    return [t.strip() for t in s.split(",") if t.strip()]

def pack_params(data: TaskIn) -> dict:
    if data.recurrence_mode == "after":
        return {"value": data.after_interval_value, "unit": data.after_interval_unit}
    if data.recurrence_mode == "cron":
        return {"cron": data.cron}
    if data.recurrence_mode == "set":
        return {"crons": data.cron_set or []}
    return {}

def compute_time_left_ms(next_due_at: Optional[datetime], now: datetime) -> int:
    if not next_due_at:
        return 0
    delta = next_due_at - now
    return max(0, int(delta.total_seconds() * 1000))

def task_to_out(task: Task, now: datetime) -> TaskOut:
    rp = {}
    try:
        rp = json.loads(task.recurrence_params) if task.recurrence_params else {}
    except Exception:
        rp = {}
    return TaskOut(
        id=task.id,
        name=task.name,
        type=task.type,
        subtype=task.subtype,
        url=task.url,
        description=task.description,
        tags=to_tags_list(task.tags),
        recurrence_mode=task.recurrence_mode,
        recurrence_params=rp,
        due_at=task.due_at,
        last_completed_at=task.last_completed_at,
        next_due_at=task.next_due_at,
        time_left_ms=compute_time_left_ms(task.next_due_at, now)
    )

# ---------- API ----------
@app.get("/api/tasks", response_model=List[TaskOut])
def list_tasks(db: Session = Depends(get_db)):
    now = datetime.utcnow()
    tasks = db.scalars(select(Task)).all()
    return [task_to_out(t, now) for t in tasks]

@app.post("/api/tasks", response_model=TaskOut)
def create_task(payload: TaskIn, db: Session = Depends(get_db)):
    now = datetime.utcnow()
    params = pack_params(payload)
    next_due = compute_next_due_now(payload.recurrence_mode, params, now, payload.due_at)
    if payload.recurrence_mode == "none" and not next_due:
        raise HTTPException(status_code=400, detail="due_at required when recurrence_mode is 'none'.")

    t = Task(
        name=payload.name.strip(),
        type=payload.type,
        subtype=payload.subtype,
        url=payload.url,
        description=payload.description,
        tags=to_tags_str(payload.tags),
        recurrence_mode=payload.recurrence_mode,
        recurrence_params=json.dumps(params),
        due_at=payload.due_at,
        next_due_at=next_due,
        created_at=now,
        updated_at=now
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    return task_to_out(t, now)

@app.put("/api/tasks/{task_id}", response_model=TaskOut)
def update_task(task_id: int, payload: TaskIn, db: Session = Depends(get_db)):
    now = datetime.utcnow()
    t = db.get(Task, task_id)
    if not t:
        raise HTTPException(status_code=404, detail="Not found")
    params = pack_params(payload)
    t.name = payload.name.strip()
    t.type = payload.type
    t.subtype = payload.subtype
    t.url = payload.url
    t.description = payload.description
    t.tags = to_tags_str(payload.tags)
    t.recurrence_mode = payload.recurrence_mode
    t.recurrence_params = json.dumps(params)
    t.due_at = payload.due_at
    t.next_due_at = compute_next_due_now(payload.recurrence_mode, params, now, payload.due_at)
    t.updated_at = now
    db.commit()
    db.refresh(t)
    return task_to_out(t, now)

@app.post("/api/tasks/{task_id}/complete")
def complete_task(task_id: int, db: Session = Depends(get_db)):
    now = datetime.utcnow()
    t = db.get(Task, task_id)
    if not t:
        raise HTTPException(status_code=404, detail="Not found")

    if t.recurrence_mode == "none":
        db.execute(delete(Task).where(Task.id == task_id))
        db.commit()
        return {"status":"deleted"}

    params = {}
    try:
        params = json.loads(t.recurrence_params) if t.recurrence_params else {}
    except Exception:
        params = {}

    # Advance to the next due time relative to now.
    t.last_completed_at = now
    t.next_due_at = compute_next_due_now(t.recurrence_mode, params, now, t.due_at)
    t.updated_at = now
    db.commit()
    return {"status":"advanced","next_due_at": t.next_due_at}

@app.delete("/api/tasks/{task_id}")
def delete_task(task_id: int, db: Session = Depends(get_db)):
    t = db.get(Task, task_id)
    if not t:
        raise HTTPException(status_code=404, detail="Not found")
    db.delete(t)
    db.commit()
    return {"status":"deleted"}
