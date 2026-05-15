from __future__ import annotations

import os
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict

import yaml
from pydantic import BaseModel, Field


ENV_PREFIX = "TIMEBOARDAPP"
# Backward-compatibility: accept the legacy prefix (without the "APP" suffix).
LEGACY_ENV_PREFIX = ENV_PREFIX[:-3]

def _env(suffix: str) -> str | None:
    """Return env var value for TIMEBOARDAPP_* with fallback to the legacy prefix vars."""

    key = f"{ENV_PREFIX}_{suffix}"
    legacy_key = f"{LEGACY_ENV_PREFIX}_{suffix}"
    return os.environ.get(key) or os.environ.get(legacy_key)


DEFAULT_SETTINGS_PATH = _env("SETTINGS") or "/data/settings.yml"


class AppSettings(BaseModel):
    name: str = "TimeboardApp"
    timezone: str = "UTC"
    host: str = "0.0.0.0"  # nosec B104
    port: int = 8888
    base_url: str = ""


class SecuritySettings(BaseModel):
    session_secret: str = "CHANGE_ME_SESSION_SECRET"
    jwt_secret: str = "CHANGE_ME_JWT_SECRET"


class DatabaseSettings(BaseModel):
    path: str = "/data/timeboardapp.db"


class PurgeSettings(BaseModel):
    default_days: int = 15
    interval_minutes: int = 60


class EmailSettings(BaseModel):
    # When disabled, password reset and reminders are not sent.
    enabled: bool = False

    # Delivery provider: "smtp" or "sendgrid".
    provider: str = "smtp"

    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""

    smtp_from: str = "timeboardapp@localhost"

    # If True, use STARTTLS.
    use_tls: bool = True

    # SendGrid v3 API key (used when provider == "sendgrid").
    sendgrid_api_key: str = ""

    # Overdue reminder cadence.
    reminder_interval_minutes: int = 60

    # Password reset token TTL.
    reset_token_minutes: int = 60


class LoggingSettings(BaseModel):
    level: str = "INFO"


class DemoSettings(BaseModel):
    # When enabled, the application behaves as an always-resetting demo instance.
    enabled: bool = False

    # How often to purge + rebuild demo data.
    # Set to 0 to disable automatic resets.
    reset_interval_minutes: int = 360

    # Prevent abuse by disabling outbound notifications/webhooks/email.
    disable_external_apis: bool = True


class Settings(BaseModel):
    app: AppSettings = Field(default_factory=AppSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    purge: PurgeSettings = Field(default_factory=PurgeSettings)
    email: EmailSettings = Field(default_factory=EmailSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    demo: DemoSettings = Field(default_factory=DemoSettings)


def _ensure_settings_file(path: str) -> None:
    p = Path(path)
    if p.exists():
        return

    # Optional: preserve completed tasks by reassigning them before deleting the user.
    if reassign_completed_to_user_id is not None:
        target = get_user(db, user_id=int(reassign_completed_to_user_id))
        if not target:
            raise ValueError("Reassignment target user not found")

        (
            db.query(Task)
            .filter(Task.user_id == int(user_id))
            .filter(Task.status == TaskStatus.completed)
            .update(
                {
                    Task.user_id: int(target.id),
                    # Detach from any hierarchy to avoid referencing tasks
                    # that will be deleted with the user.
                    Task.parent_task_id: None,
                },
                synchronize_session=False,
            )
        )
        db.commit()

    db.delete(user)
    db.commit()


def update_user_me(
    db: Session,
    *,
    user: User,
    username: Optional[str] = None,
    theme: Optional[str] = None,
    purge_days: Optional[int] = None,
    email: Optional[str] = None,
    current_password: Optional[str] = None,
    new_password: Optional[str] = None,
) -> User:
    if username is not None:
        uname = (username or "").strip()
        if not uname:
            raise ValueError("Username is required")
        if len(uname) > 64:
            raise ValueError("Username must be 64 characters or less")
        existing_username = db.query(User).filter(User.username == uname).filter(User.id != user.id).first()
        if existing_username:
            raise ValueError("Username already exists")
        user.username = uname

    if theme is not None:
        if theme not in {Theme.light.value, Theme.dark.value, Theme.system.value}:
            raise ValueError("Invalid theme")
        user.theme = theme

    if purge_days is not None:
        if purge_days < 1 or purge_days > 3650:
            raise ValueError("purge_days must be between 1 and 3650")
        user.purge_days = int(purge_days)

    # Copy sample settings into place while replacing secret placeholders.
    session_secret = secrets.token_urlsafe(32)
    jwt_secret = secrets.token_urlsafe(32)
    sample = Path(__file__).resolve().parent.parent / "settings.sample.yml"
    if sample.exists():
        text = sample.read_text(encoding="utf-8")
        text = text.replace("CHANGE_ME_SESSION_SECRET", session_secret)
        text = text.replace("CHANGE_ME_JWT_SECRET", jwt_secret)
        p.write_text(text, encoding="utf-8")
    else:
        # Minimal fallback
        p.write_text(
            "app:\n  name: 'TimeboardApp'\n  timezone: 'UTC'\n  host: '0.0.0.0'\n  port: 8888\n"
            f"security:\n  session_secret: '{session_secret}'\n  jwt_secret: '{jwt_secret}'\n"
            "database:\n  path: '/data/timeboardapp.db'\n"
            "purge:\n  default_days: 15\n  interval_minutes: 60\n"
            "demo:\n  enabled: false\n  reset_interval_minutes: 360\n  disable_external_apis: true\n"
            "email:\n  enabled: false\n  provider: 'smtp'\n  smtp_host: ''\n  smtp_port: 587\n  smtp_username: ''\n  smtp_password: ''\n  smtp_from: 'timeboardapp@localhost'\n  use_tls: true\n  sendgrid_api_key: ''\n  reminder_interval_minutes: 60\n  reset_token_minutes: 60\n"
        )


def list_tasks(
    db: Session,
    *,
    current_user: User,
    include_archived: bool = False,
    search: Optional[str] = None,
    tag: Optional[str] = None,
    user_id: Optional[int] = None,
    task_type: Optional[str] = None,
    status: Optional[str] = None,
    sort: str = "due_date",
    include_assigned_by_me: bool = False,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
) -> list[Task]:
    # Base query
    q = _tasks_base_query(
        db,
        current_user=current_user,
        include_archived=include_archived,
        search=search,
        tag=tag,
        user_id=user_id,
        task_type=task_type,
        status=status,
        include_assigned_by_me=include_assigned_by_me,
    ).options(joinedload(Task.tags), joinedload(Task.user))

    # Sorting
    desc = False
    key = (sort or "").strip()
    if key.startswith("-"):
        desc = True
        key = key[1:]

    if key in {"task_type", "type"}:
        primary = Task.task_type
        secondary = Task.due_date_utc
    elif key in {"name"}:
        primary = Task.name
        secondary = Task.due_date_utc
    elif key in {"archived_at"}:
        # Archived sort: use completed_at_utc/deleted_at_utc where available.
        # Fall back to updated_at.
        # Note: SQLite lacks GREATEST across NULLs reliably; order by updated_at.
        primary = Task.updated_at
        secondary = Task.due_date_utc
    else:
        primary = Task.due_date_utc
        secondary = Task.task_type

    if desc:
        q = q.order_by(primary.desc(), secondary.desc())
    else:
        q = q.order_by(primary.asc(), secondary.asc())

    if offset is not None:
        try:
            o = int(offset)
            if o > 0:
                q = q.offset(o)
        except Exception:
            pass

    if limit is not None:
        try:
            l = int(limit)
            if l > 0:
                q = q.limit(l)
        except Exception:
            pass

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

    # Capture old tags so updates that remove a subscribed tag can still trigger
    # a notification.
    try:
        old_tag_ids = {int(t.id) for t in (task.tags or [])}
    except Exception:
        old_tag_ids = set()

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

    try:
        new_tag_ids = {int(t.id) for t in (task.tags or [])}
    except Exception:
        new_tag_ids = set()
    relevant = set(old_tag_ids) | set(new_tag_ids)

    try:
        notify_task_event(db, task=task, event_type=EVENT_UPDATED, relevant_tag_ids=relevant)
    except Exception:
        logger.exception("Failed to send task-updated notification")

    # In-app follow notifications (manager/subordinate).
    try:
        _notify_task_followers_in_app(db, task=task, event_type="updated")
    except Exception:
        logger.exception("Failed to create in-app follower notifications")
    return task


def soft_delete_task(
    db: Session,
    *,
    task: Task,
    current_user: User,
    when_utc: datetime,
    cascade_subtasks: bool = False,
) -> Task:
    if not current_user.is_admin and task.user_id != current_user.id:
        raise PermissionError("Not allowed")

    open_desc = list_open_descendant_tasks(db, root_task_id=int(task.id))
    if open_desc and not cascade_subtasks:
        raise OpenSubtasksError(open_desc)

    if open_desc and cascade_subtasks:
        # Archive open descendants first.
        for ch in open_desc:
            ch.status = TaskStatus.deleted
            ch.deleted_at_utc = when_utc
            db.add(ch)
        db.commit()
        # Best-effort notifications for cascaded descendants.
        for ch in open_desc:
            try:
                notify_task_event(db, task=ch, event_type=EVENT_ARCHIVED)
            except Exception:
                logger.exception("Failed to send cascaded subtask-archived notification")
            try:
                _notify_task_followers_in_app(db, task=ch, event_type="deleted")
            except Exception:
                logger.exception("Failed to create cascaded follower notifications")

    task.status = TaskStatus.deleted
    task.deleted_at_utc = when_utc

    db.add(task)
    db.commit()
    db.refresh(task)

    try:
        notify_task_event(db, task=task, event_type=EVENT_ARCHIVED)
    except Exception:
        logger.exception("Failed to send task-archived notification")

    try:
        _notify_task_followers_in_app(db, task=task, event_type="deleted")
    except Exception:
        logger.exception("Failed to create in-app follower notifications")
    return task


def restore_task(db: Session, *, task: Task, current_user: User) -> Task:
    if not current_user.is_admin and task.user_id != current_user.id:
        raise PermissionError("Not allowed")

    task.status = TaskStatus.active
    task.completed_at_utc = None
    task.deleted_at_utc = None

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
    cascade_subtasks: bool = False,
    spawn_recurrence: bool = True,
) -> tuple[Task, Optional[Task]]:
    if not current_user.is_admin and task.user_id != current_user.id:
        raise PermissionError("Not allowed")

    open_desc = list_open_descendant_tasks(db, root_task_id=int(task.id))
    if open_desc and not cascade_subtasks:
        raise OpenSubtasksError(open_desc)

    if open_desc and cascade_subtasks:
        # Complete open descendants first, but do not spawn recurrence tasks for
        # them. Parent recurrence (if any) will rebuild the child tree.
        for ch in open_desc:
            ch.status = TaskStatus.completed
            ch.completed_at_utc = when_utc
            db.add(ch)
        db.commit()
        for ch in open_desc:
            try:
                notify_task_event(db, task=ch, event_type=EVENT_COMPLETED)
            except Exception:
                logger.exception("Failed to send cascaded subtask-completed notification")
            try:
                _notify_task_followers_in_app(db, task=ch, event_type="completed")
            except Exception:
                logger.exception("Failed to create cascaded follower notifications")

    # Mark complete
    task.status = TaskStatus.completed
    task.completed_at_utc = when_utc

    spawned: Optional[Task] = None
    next_due = None
    if spawn_recurrence:
        try:
            next_due = compute_next_due_utc(task, when_utc)
        except RecurrenceError:
            next_due = None

    if next_due is not None:
        spawned = Task(
            user_id=task.user_id,
            parent_task_id=(int(task.parent_task_id) if getattr(task, "parent_task_id", None) else None),
            assigned_by_user_id=(int(task.assigned_by_user_id) if getattr(task, "assigned_by_user_id", None) else None),
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

    try:
        notify_task_event(db, task=task, event_type=EVENT_COMPLETED)
    except Exception:
        logger.exception("Failed to send task-completed notification")

    try:
        _notify_task_followers_in_app(db, task=task, event_type="completed")
    except Exception:
        logger.exception("Failed to create in-app follower notifications")

    if spawned is not None:
        try:
            notify_task_event(db, task=spawned, event_type=EVENT_CREATED)
        except Exception:
            logger.exception("Failed to send recurrence task-created notification")

        # Rebuild full child task tree when recurring.
        try:
            # Shift all descendant due dates by the delta between the old and new
            # parent due dates.
            try:
                delta = spawned.due_date_utc - task.due_date_utc
            except Exception:
                delta = timedelta(0)

            children = (
                db.query(Task)
                .options(joinedload(Task.tags))
                .filter(Task.parent_task_id == int(task.id))
                .order_by(Task.id.asc())
                .all()
            )
            for ch in children:
                clone_task_tree(
                    db,
                    source_task=ch,
                    new_owner_user_id=int(spawned.user_id),
                    new_parent_task_id=int(spawned.id),
                    due_date_delta=delta,
                    name_suffix="",
                )
        except Exception:
            logger.exception("Failed to rebuild subtask tree for recurring task")

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

        # Purge cleared in-app notifications on the same retention window.
        try:
            ncount = (
                db.query(NotificationEvent)
                .filter(NotificationEvent.user_id == int(u.id))
                .filter(NotificationEvent.service_type == IN_APP_SERVICE_TYPE)
                .filter(NotificationEvent.cleared_at_utc.is_not(None))
                .filter(NotificationEvent.cleared_at_utc < cutoff)
                .delete(synchronize_session=False)
            )
            total_deleted += int(ncount or 0)
        except Exception:
            # If the notification schema isn't present yet, ignore.
            pass
    db.commit()
    return total_deleted
