from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

from .models import RecurrenceType, Theme


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserBase(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=256)
    email: Optional[str] = Field(default=None, max_length=255)
    is_admin: bool = False


class UserOut(UserBase):
    id: int
    email: Optional[str] = None
    is_admin: bool
    theme: str
    purge_days: int

    class Config:
        from_attributes = True


class UserMeUpdate(BaseModel):
    theme: Optional[str] = Field(default=None)
    purge_days: Optional[int] = Field(default=None, ge=1, le=3650)
    email: Optional[str] = Field(default=None, max_length=255)
    current_password: Optional[str] = Field(default=None)
    new_password: Optional[str] = Field(default=None, min_length=8, max_length=256)


class UserAdminUpdate(BaseModel):
    email: Optional[str] = Field(default=None, max_length=255)
    is_admin: Optional[bool] = Field(default=None)


class TagOut(BaseModel):
    id: int
    name: str

    class Config:
        from_attributes = True


class TaskBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    task_type: str = Field(..., min_length=1, max_length=128)
    description: Optional[str] = None
    url: Optional[str] = Field(default=None, max_length=2048)

    # Allow tasks with no due date. If omitted, the server uses the creation time.
    due_date: Optional[datetime] = Field(default=None)

    recurrence_type: str = Field(default=RecurrenceType.none.value)
    recurrence_interval: Optional[str] = Field(
        default=None,
        description=(
            "For post_completion: a human duration like '8h', '30m', '1d 2h'. "
            "For fixed_clock: either a duration OR a calendar rule like 'Every Tuesday', 'Mon Wed Fri', "
            "'10th of every month', 'First Monday', 'January 5'."
        ),
    )
    recurrence_times: Optional[str] = Field(
        default=None,
        description=(
            "For multi_slot_daily: comma-separated list of daily times like '08:00, 15:00, 23:00' "
            "(or '8:00 am, 3:00 pm'). "
            "For fixed_clock calendar rules, the server stores an RRULE-like string here internally."
        ),
    )

    tags: List[str] = Field(default_factory=list)


class TaskCreate(TaskBase):
    pass


class TaskUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    task_type: Optional[str] = Field(default=None, min_length=1, max_length=128)
    description: Optional[str] = None
    url: Optional[str] = Field(default=None, max_length=2048)
    due_date: Optional[datetime] = None

    recurrence_type: Optional[str] = None
    recurrence_interval: Optional[str] = None
    recurrence_times: Optional[str] = None

    tags: Optional[List[str]] = None


class TaskOut(BaseModel):
    id: int
    user_id: int
    name: str
    task_type: str
    description: Optional[str]
    url: Optional[str]
    due_date_utc: datetime

    recurrence_type: str
    recurrence_interval_seconds: Optional[int]
    recurrence_times: Optional[str]

    status: str
    completed_at_utc: Optional[datetime]
    deleted_at_utc: Optional[datetime]

    tags: List[TagOut] = []

    class Config:
        from_attributes = True


class TaskCompleteResponse(BaseModel):
    completed_task: TaskOut
    spawned_task: Optional[TaskOut] = None
