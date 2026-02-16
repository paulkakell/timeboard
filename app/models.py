from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import (
    Column,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


class Theme(str, enum.Enum):
    light = "light"
    dark = "dark"
    system = "system"


class TaskStatus(str, enum.Enum):
    active = "active"
    completed = "completed"
    deleted = "deleted"


class RecurrenceType(str, enum.Enum):
    none = "none"
    post_completion = "post_completion"  # interval after completion
    multi_slot_daily = "multi_slot_daily"  # list of times each day
    fixed_clock = "fixed_clock"  # anchored interval regardless of completion


# Many-to-many association table
TaskTag = Table(
    "task_tags",
    Base.metadata,
    Column("task_id", ForeignKey("tasks.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("username", name="uq_users_username"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    theme: Mapped[str] = mapped_column(String(16), default=Theme.system.value, nullable=False)
    purge_days: Mapped[int] = mapped_column(Integer, default=15, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    tasks: Mapped[list["Task"]] = relationship(
        "Task",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Tag(Base):
    __tablename__ = "tags"
    __table_args__ = (UniqueConstraint("name", name="uq_tags_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)

    tasks: Mapped[list["Task"]] = relationship(
        "Task",
        secondary=TaskTag,
        back_populates="tags",
    )


class Task(Base):
    __tablename__ = "tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    task_type: Mapped[str] = mapped_column(String(128), nullable=False)

    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    url: Mapped[str | None] = mapped_column(String(2048), nullable=True)

    due_date_utc: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)

    recurrence_type: Mapped[str] = mapped_column(
        Enum(RecurrenceType),
        default=RecurrenceType.none,
        nullable=False,
    )

    # For post_completion or fixed_clock interval recurrence.
    recurrence_interval_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # For multi_slot_daily: comma-separated list of HH:MM times (24h).
    recurrence_times: Mapped[str | None] = mapped_column(String(255), nullable=True)

    status: Mapped[str] = mapped_column(Enum(TaskStatus), default=TaskStatus.active, nullable=False, index=True)

    completed_at_utc: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    deleted_at_utc: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    user: Mapped[User] = relationship("User", back_populates="tasks")

    tags: Mapped[list[Tag]] = relationship(
        "Tag",
        secondary=TaskTag,
        back_populates="tasks",
    )

    def archived_at_utc(self) -> datetime | None:
        if self.status == TaskStatus.completed:
            return self.completed_at_utc
        if self.status == TaskStatus.deleted:
            return self.deleted_at_utc
        return None
