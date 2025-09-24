from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field, HttpUrl, ValidationError
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

# -------------- Error helpers --------------
@app.exception_handler(ValidationError)
async def pydantic_error_handler(request: Request, exc: ValidationError):
    # Flatten Pydantic errors into friendly messages
    details = []
    for e in exc.errors():
        loc = ".".join([str(x) for x in e.get("loc", []) if x != "__root__"])
        msg = e.get("msg", "Invalid value")
        details.append(f"{loc}: {msg}" if loc else msg)
    return JSONResponse(status_code=422, content={"detail": details})

def http_400(msg: str):
    raise HTTPException(status_code=400, detail=msg)

# -------------- Schemas --------------
RecurrenceMode = Literal["none", "after", "cron", "set"]
VALID_UNITS = {"minutes", "hours", "days", "months"}

class TaskIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    type: Optional[str] = Field(default=None, max_length=100)
    subtype: Optional[str] = Field(default=None, max_length=100)
    url: Optional[HttpUrl] = None
    description: Optional[str] = Field(default=None, max_length=4000)
    tags: List[str] = Field(default_factory=list)

    recurrence_mode: RecurrenceMode

    # mode none
    due_at: Optional[datetime] = None

    # mode after
    after_interval_value: Optional[int] = Field(default=None, ge=1)
    after_interval_unit: Optional[Literal["minutes", "hours", "days", "months"]] = None

    # mode cron
    cron: Optional[str] = None

    # mode set
    cron_set: Optional[List[str]] = None

    # Cross-field validation
    def validate_for_mode(self):
        if self.recurrence_mode == "none":
            if not self.due_at:
                http_400("For one-time tasks, Due at is required. Use ISO 8601 UTC, for example 2025-12-01T12:00:00Z.")
        elif self.recurrence_mode == "after":
            if self.after_interval_value is None or self.after_interval_unit is None:
                http_400("For after-completion tasks, provide an interval value and unit.")
            if self.after_interval_unit not in VALID_UNITS:
                http_400("Interval unit must be one of minutes, hours, days, months.")
        elif self.recurrence_mode == "cron":
            if not self.cron:
                http_400("For fixed-time tasks, provide a cron string. Example daily noon: 0 12 * * *.")
        elif self.recurrence_mode == "set":
            if not self.cron_set or not len(self.cron_set):
                http_400("For specific-times tasks, provide at least one cron string, one per line.")
        # Tags cleanup
        self.tags = [t.strip() for t in self.tags if t and t.strip()]

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

# -------------- Helpers --------------
def months_add(dt: datetime, n: int) -> datetime:
    return dt + timedelta(days=30 * n)

def pack_params(data: TaskIn) -> dict:
    if data.recurrence_mode == "after":
        return {"value": data.after_interval_value, "unit": data.after_interval_unit}
    if data.recurrence_mode == "cron":
        return {"cron": data.cron}
    if data.recurrence_mode == "set":
        return {"crons": data.cron_set or []}
    return {}

def compute_next_due_now_safe(recurrence_mode: str, params: dict, now: datetime, due_at: Optional[datetime]) -> Optional[datetime]:
    try:
        if recurrence_mode == "none":
            return due_at
        if recurrence_mode == "after":
            val = int(params.get("value", 0))
            unit = params.get("unit")
            if val < 1 or unit not in VALID_UNITS:
                http_400("After-completion settings are invalid. Interval must be at least 1 and unit one of minutes, hours, days, months.")
            if unit == "minutes":
                return now + timedelta(minutes=val)
            if unit == "hours":
                return now + timedelta(hours=val)
            if unit == "days":
                return now + timedelta(days=val)
            if unit == "months":
                return months_add(now, val)
        if recurrence_mode == "cron":
            cron = params.get("cron")
            if not cron:
                http_400("Cron string is required, for example 0 12 * * * for daily at noon.")
            return croniter(cron, now).get_next(datetime)
        if recurrence_mode == "set":
            crons = params.get("crons", [])
            if not crons:
                http_400("Enter at least one cron string for specific-times tasks.")
            candidates = []
            for c in crons:
                try:
                    candidates.append(croniter(c, now).get_next(datetime))
                except Exception:
                    http_400(f"Invalid cron in list: {c}")
            return min(candidates)
        http_400("Unknown recurrence mode.")
    except HTTPException:
        raise
    except Exception as e:
        http_400(f"Could not compute next due time. Details: {str(e)}")

def compute_time_left_ms(next_due_at: Optional[datetime], now: datetime) -> int:
    if not next_due_at:
        return 0
    delta = next_due_at - now
    return max(0, int(delta.total_seconds() * 1000))

def to_tags_str(tags: List[str]) -> str:
    return ",".join([t.strip() for t in tags if t.strip()])

def to_tags_list(s: Optional[str]) -> List[str]:
    if not s:
        return []
    return [t.strip() for t in s.split(",") if t.strip()]

def task_to_out(task: Task, now: datetime) -> TaskOut:
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
        time_left_ms=compute_time_left_ms(task.next_due_at, now),
    )

# -------------- API --------------
@app.get("/api/tasks", response_model=List[TaskOut])
def list_tasks(db: Session = Depends(get_db)):
    now = datetime.utcnow()
    tasks = db.scalars(select(Task)).all()
    return [task_to_out(t, now) for t in tasks]

@app.post("/api/tasks", response_model=TaskOut)
def create_task(payload: TaskIn, db: Session = Depends(get_db)):
    now = datetime.utcnow()
    payload.validate_for_mode()
    params = pack_params(payload)
    next_due = compute_next_due_now_safe(payload.recurrence_mode, params, now, payload.due_at)
    if payload.recurrence_mode == "none" and not next_due:
        http_400("Due at is required for one-time tasks.")
    t = Task(
        name=payload.name.strip(),
        type=payload.type,
        subtype=payload.subtype,
        url=str(payload.url) if payload.url else None,
        description=payload.description,
        tags=to_tags_str(payload.tags),
        recurrence_mode=payload.recurrence_mode,
        recurrence_params=json.dumps(params),
        due_at=payload.due_at,
        next_due_at=next_due,
        created_at=now,
        updated_at=now,
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
        raise HTTPException(status_code=404, detail="Task not found.")
    payload.validate_for_mode()
    params = pack_params(payload)
    t.name = payload.name.strip()
    t.type = payload.type
    t.subtype = payload.subtype
    t.url = str(payload.url) if payload.url else None
    t.description = payload.description
    t.tags = to_tags_str(payload.tags)
    t.recurrence_mode = payload.recurrence_mode
    t.recurrence_params = json.dumps(params)
    t.due_at = payload.due_at
    t.next_due_at = compute_next_due_now_safe(payload.recurrence_mode, params, now, payload.due_at)
    t.updated_at = now
    db.commit()
    db.refresh(t)
    return task_to_out(t, now)

@app.post("/api/tasks/{task_id}/complete")
def complete_task(task_id: int, db: Session = Depends(get_db)):
    now = datetime.utcnow()
    t = db.get(Task, task_id)
    if not t:
        raise HTTPException(status_code=404, detail="Task not found.")
    if t.recurrence_mode == "none":
        db.execute(delete(Task).where(Task.id == task_id))
        db.commit()
        return {"status": "deleted"}
    try:
        params = json.loads(t.recurrence_params) if t.recurrence_params else {}
    except Exception:
        params = {}
    t.last_completed_at = now
    t.next_due_at = compute_next_due_now_safe(t.recurrence_mode, params, now, t.due_at)
    t.updated_at = now
    db.commit()
    return {"status": "advanced", "next_due_at": t.next_due_at}

@app.delete("/api/tasks/{task_id}")
def delete_task(task_id: int, db: Session = Depends(get_db)):
    t = db.get(Task, task_id)
    if not t:
        raise HTTPException(status_code=404, detail="Task not found.")
    db.delete(t)
    db.commit()
    return {"status": "deleted"}
