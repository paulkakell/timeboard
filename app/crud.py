from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.orm import Session, joinedload

from .auth import hash_password, verify_password
from .config import get_settings
from .models import RecurrenceType, Tag, Task, TaskStatus, Theme, User
from .recurrence import (
    RecurrenceError,
    compute_next_due_utc,
    parse_duration_to_seconds,
    parse_fixed_calendar_rule,
    parse_times_csv,
)
from .utils.time_utils import from_local_to_utc_naive


def normalize_datetime_to_utc_naive(dt: datetime) -> datetime:
    """Normalize a datetime to naive UTC.

    - If `dt` is timezone-aware, convert to UTC and drop tzinfo.
    - If `dt` is naive, interpret it in app timezone and convert to UTC.
    """
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return from_local_to_utc_naive(dt)


# ---------------------- Users ----------------------


def get_user_by_username(db: Session, username: str) -> Optional[User]:
    return db.query(User).filter(User.username == username).first()


def get_user(db: Session, user_id: int) -> Optional[User]:
    return db.query(User).filter(User.id == user_id).first()


def list_users(db: Session) -> list[User]:
    return db.query(User).order_by(User.username.asc()).all()


def create_user(db: Session, *, username: str, password: str, is_admin: bool = False) -> User:
    settings = get_settings()
    user = User(
        username=username,
        hashed_password=hash_password(password),
        is_admin=bool(is_admin),
        purge_days=int(settings.purge.default_days),
        theme=Theme.system.value,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def delete_user(db: Session, *, user_id: int) -> None:
    user = get_user(db, user_id)
    if not user:
        return
    db.delete(user)
    db.commit()


def update_user_me(
    db: Session,
    *,
    user: User,
    theme: Optional[str] = None,
    purge_days: Optional[int] = None,
    current_password: Optional[str] = None,
    new_password: Optional[str] = None,
) -> User:
    if theme is not None:
        if theme not in {Theme.light.value, Theme.dark.value, Theme.system.value}:
            raise ValueError("Invalid theme")
        user.theme = theme

    if purge_days is not None:
        if purge_days < 1 or purge_days > 3650:
            raise ValueError("purge_days must be between 1 and 3650")
        user.purge_days = int(purge_days)

    if new_password is not None:
        if not current_password:
            raise ValueError("current_password is required to change password")
        if not verify_password(current_password, user.hashed_password):
            raise ValueError("current_password is incorrect")
        user.hashed_password = hash_password(new_password)

    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# ---------------------- Tags ----------------------


def _normalize_tag_name(tag: str) -> str:
    return tag.strip().lower()


def get_or_create_tags(db: Session, tag_names: Iterable[str]) -> list[Tag]:
    tags: list[Tag] = []
    for raw in tag_names:
        name = _normalize_tag_name(raw)
        if not name:
            continue
        existing = db.query(Tag).filter(func.lower(Tag.name) == name).first()
        if existing:
            tags.append(existing)
            continue
        t = Tag(name=name)
        db.add(t)
        db.flush()
        tags.append(t)
    return tags


def list_tags_for_user(db: Session, *, user: User) -> list[Tag]:
    # Only tags that appear on the user's tasks.
    q = (
        db.query(Tag)
        .join(Tag.tasks)
        .filter(Task.user_id == user.id)
        .distinct()
        .order_by(Tag.name.asc())
    )
    return q.all()


# ---------------------- Tasks ----------------------


def _apply_recurrence_fields(
    *,
    recurrence_type: str,
    recurrence_interval: Optional[str],
    recurrence_times: Optional[str],
) -> tuple[str, Optional[int], Optional[str]]:
    try:
        rtype = RecurrenceType(recurrence_type)
    except Exception as e:
        raise ValueError("Invalid recurrence_type") from e

    if rtype == RecurrenceType.post_completion:
        if not recurrence_interval:
            raise ValueError("recurrence_interval is required for this recurrence type")
        seconds = parse_duration_to_seconds(recurrence_interval)
        return rtype.value, seconds, None

    if rtype == RecurrenceType.fixed_clock:
        # Fixed clock scheduling supports two formats:
        #   1) Legacy interval: "8h", "1d", "2 weeks"...
        #   2) Fixed calendar rule: "Every Tuesday", "Mon, Wed, Fri", "10th of every month", "First Monday", "January 5"
        if (recurrence_interval is None or not str(recurrence_interval).strip()) and (
            recurrence_times is None or not str(recurrence_times).strip()
        ):
            raise ValueError("recurrence_interval is required for fixed_clock")

        # Prefer recurrence_interval for backwards compatibility with existing clients/UI.
        raw = (recurrence_interval or "").strip() if recurrence_interval is not None else ""

        if raw:
            try:
                seconds = parse_duration_to_seconds(raw)
                return rtype.value, seconds, None
            except RecurrenceError:
                # Not a duration; treat it as a fixed calendar rule.
                rule_canonical = parse_fixed_calendar_rule(raw)
                return rtype.value, None, rule_canonical

        # Fallback: allow supplying the rule in recurrence_times for API clients.
        rule_canonical = parse_fixed_calendar_rule(str(recurrence_times))
        return rtype.value, None, rule_canonical

    if rtype == RecurrenceType.multi_slot_daily:
        if not recurrence_times:
            raise ValueError("recurrence_times is required for multi_slot_daily")
        canonical = parse_times_csv(recurrence_times)
        return rtype.value, None, canonical

    # none
    return RecurrenceType.none.value, None, None


def create_task(
    db: Session,
    *,
    owner: User,
    name: str,
    task_type: str,
    due_date: datetime,
    description: Optional[str] = None,
    url: Optional[str] = None,
    recurrence_type: str = RecurrenceType.none.value,
    recurrence_interval: Optional[str] = None,
    recurrence_times: Optional[str] = None,
    tags: Optional[Iterable[str]] = None,
) -> Task:
    due_utc = normalize_datetime_to_utc_naive(due_date)
    rtype, interval_seconds, times_canonical = _apply_recurrence_fields(
        recurrence_type=recurrence_type,
        recurrence_interval=recurrence_interval,
        recurrence_times=recurrence_times,
    )

    task = Task(
        user_id=owner.id,
        name=name,
        task_type=task_type,
        description=description,
        url=url,
        due_date_utc=due_utc,
        recurrence_type=rtype,
        recurrence_interval_seconds=interval_seconds,
        recurrence_times=times_canonical,
        status=TaskStatus.active,
    )

    if tags:
        task.tags = get_or_create_tags(db, tags)

    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def get_task(db: Session, *, task_id: int) -> Optional[Task]:
    return (
        db.query(Task)
        .options(joinedload(Task.tags))
        .filter(Task.id == task_id)
        .first()
    )


def list_tasks(
    db: Session,
    *,
    current_user: User,
    include_archived: bool = False,
    tag: Optional[str] = None,
    user_id: Optional[int] = None,
) -> list[Task]:
    q = db.query(Task).options(joinedload(Task.tags), joinedload(Task.user)).order_by(Task.due_date_utc.asc())

    if current_user.is_admin:
        if user_id:
            q = q.filter(Task.user_id == int(user_id))
    else:
        q = q.filter(Task.user_id == current_user.id)

    if not include_archived:
        q = q.filter(Task.status == TaskStatus.active)

    if tag:
        tnorm = _normalize_tag_name(tag)
        q = q.join(Task.tags).filter(func.lower(Tag.name) == tnorm)

    return q.all()


def update_task(
    db: Session,
    *,
    task: Task,
    current_user: User,
    name: Optional[str] = None,
    task_type: Optional[str] = None,
    description: Optional[str] = None,
    url: Optional[str] = None,
    due_date: Optional[datetime] = None,
    recurrence_type: Optional[str] = None,
    recurrence_interval: Optional[str] = None,
    recurrence_times: Optional[str] = None,
    tags: Optional[Iterable[str]] = None,
) -> Task:
    if not current_user.is_admin and task.user_id != current_user.id:
        raise PermissionError("Not allowed")

    if name is not None:
        task.name = name
    if task_type is not None:
        task.task_type = task_type
    if description is not None:
        task.description = description
    if url is not None:
        task.url = url
    if due_date is not None:
        task.due_date_utc = normalize_datetime_to_utc_naive(due_date)

    if recurrence_type is not None:
        rtype, interval_seconds, times_canonical = _apply_recurrence_fields(
            recurrence_type=recurrence_type,
            recurrence_interval=recurrence_interval,
            recurrence_times=recurrence_times,
        )
        task.recurrence_type = rtype
        task.recurrence_interval_seconds = interval_seconds
        task.recurrence_times = times_canonical

    if tags is not None:
        task.tags = get_or_create_tags(db, tags)

    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def soft_delete_task(db: Session, *, task: Task, current_user: User, when_utc: datetime) -> Task:
    if not current_user.is_admin and task.user_id != current_user.id:
        raise PermissionError("Not allowed")

    task.status = TaskStatus.deleted
    task.deleted_at_utc = when_utc

    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def complete_task(
    db: Session,
    *,
    task: Task,
    current_user: User,
    when_utc: datetime,
) -> tuple[Task, Optional[Task]]:
    if not current_user.is_admin and task.user_id != current_user.id:
        raise PermissionError("Not allowed")

    # Mark complete
    task.status = TaskStatus.completed
    task.completed_at_utc = when_utc

    spawned: Optional[Task] = None
    try:
        next_due = compute_next_due_utc(task, when_utc)
    except RecurrenceError:
        next_due = None

    if next_due is not None:
        spawned = Task(
            user_id=task.user_id,
            name=task.name,
            task_type=task.task_type,
            description=task.description,
            url=task.url,
            due_date_utc=next_due,
            recurrence_type=task.recurrence_type,
            recurrence_interval_seconds=task.recurrence_interval_seconds,
            recurrence_times=task.recurrence_times,
            status=TaskStatus.active,
        )
        spawned.tags = list(task.tags)
        db.add(spawned)

    db.add(task)
    db.commit()
    db.refresh(task)
    if spawned:
        db.refresh(spawned)

    return task, spawned


# ---------------------- Purge ----------------------


def purge_archived_tasks(db: Session) -> int:
    """Permanently delete archived tasks older than each user's purge window."""
    now = datetime.utcnow().replace(tzinfo=None)
    users = db.query(User).all()
    total_deleted = 0
    for u in users:
        cutoff = now - timedelta(days=int(u.purge_days))
        q = (
            db.query(Task)
            .filter(Task.user_id == u.id)
            .filter(Task.status.in_([TaskStatus.completed, TaskStatus.deleted]))
            .filter(or_(Task.completed_at_utc < cutoff, Task.deleted_at_utc < cutoff))
        )
        # Bulk delete
        count = q.delete(synchronize_session=False)
        total_deleted += int(count or 0)
    db.commit()
    return total_deleted
