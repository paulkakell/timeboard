from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy import text
from sqlalchemy.orm import Session

from .models import AppMeta, Tag, Task, TaskTag, User
from .version import APP_VERSION


def _dt(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def export_db_json(db: Session) -> Dict[str, Any]:
    """Export core tables as a JSON-serializable dict."""
    meta_rows = db.query(AppMeta).all()
    meta = {m.key: m.value for m in meta_rows}

    users = []
    for u in db.query(User).order_by(User.id.asc()).all():
        users.append(
            {
                "id": int(u.id),
                "username": u.username,
                "email": u.email,
                "hashed_password": u.hashed_password,
                "is_admin": bool(u.is_admin),
                "theme": u.theme,
                "purge_days": int(u.purge_days),
                "created_at": _dt(u.created_at),
                "updated_at": _dt(u.updated_at),
            }
        )

    tags = []
    for t in db.query(Tag).order_by(Tag.id.asc()).all():
        tags.append({"id": int(t.id), "name": t.name})

    tasks = []
    for t in db.query(Task).order_by(Task.id.asc()).all():
        tasks.append(
            {
                "id": int(t.id),
                "user_id": int(t.user_id),
                "name": t.name,
                "task_type": t.task_type,
                "description": t.description,
                "url": t.url,
                "due_date_utc": _dt(t.due_date_utc),
                "recurrence_type": t.recurrence_type,
                "recurrence_interval_seconds": t.recurrence_interval_seconds,
                "recurrence_times": t.recurrence_times,
                "status": t.status,
                "completed_at_utc": _dt(t.completed_at_utc),
                "deleted_at_utc": _dt(t.deleted_at_utc),
                "created_at": _dt(t.created_at),
                "updated_at": _dt(t.updated_at),
            }
        )

    # task_tags association
    assoc: List[Dict[str, int]] = []
    rows = db.execute(text("SELECT task_id, tag_id FROM task_tags ORDER BY task_id, tag_id")).fetchall()
    for r in rows:
        assoc.append({"task_id": int(r[0]), "tag_id": int(r[1])})

    return {
        "exported_at_utc": datetime.utcnow().replace(tzinfo=None).isoformat(),
        "app_version": APP_VERSION,
        "db_meta": meta,
        "users": users,
        "tags": tags,
        "tasks": tasks,
        "task_tags": assoc,
    }


def import_db_json(db: Session, payload: Dict[str, Any], *, replace: bool = True) -> None:
    """Import a JSON export into the database.

    By default this *replaces* existing data.
    """
    if not isinstance(payload, dict):
        raise ValueError("Invalid import payload")

    users = payload.get("users")
    tags = payload.get("tags")
    tasks = payload.get("tasks")
    task_tags = payload.get("task_tags")
    db_meta = payload.get("db_meta") or {}

    if not isinstance(users, list) or not isinstance(tags, list) or not isinstance(tasks, list) or not isinstance(task_tags, list):
        raise ValueError("Invalid import payload structure")

    if replace:
        # Delete in dependency order.
        db.execute(text("DELETE FROM task_tags"))
        db.execute(text("DELETE FROM tasks"))
        db.execute(text("DELETE FROM tags"))
        db.execute(text("DELETE FROM users"))
        db.execute(text("DELETE FROM app_meta"))
        db.commit()

    # Insert users
    for u in users:
        if not isinstance(u, dict):
            continue
        db.add(
            User(
                id=int(u["id"]),
                username=str(u["username"]),
                email=u.get("email"),
                hashed_password=str(u["hashed_password"]),
                is_admin=bool(u.get("is_admin", False)),
                theme=str(u.get("theme") or "system"),
                purge_days=int(u.get("purge_days") or 15),
                created_at=datetime.fromisoformat(u["created_at"]) if u.get("created_at") else datetime.utcnow(),
                updated_at=datetime.fromisoformat(u["updated_at"]) if u.get("updated_at") else datetime.utcnow(),
            )
        )
    db.flush()

    # Insert tags
    for t in tags:
        if not isinstance(t, dict):
            continue
        db.add(Tag(id=int(t["id"]), name=str(t["name"])))
    db.flush()

    # Insert tasks
    for t in tasks:
        if not isinstance(t, dict):
            continue
        db.add(
            Task(
                id=int(t["id"]),
                user_id=int(t["user_id"]),
                name=str(t["name"]),
                task_type=str(t["task_type"]),
                description=t.get("description"),
                url=t.get("url"),
                due_date_utc=datetime.fromisoformat(t["due_date_utc"]) if t.get("due_date_utc") else datetime.utcnow(),
                recurrence_type=str(t.get("recurrence_type") or "none"),
                recurrence_interval_seconds=t.get("recurrence_interval_seconds"),
                recurrence_times=t.get("recurrence_times"),
                status=str(t.get("status") or "active"),
                completed_at_utc=datetime.fromisoformat(t["completed_at_utc"]) if t.get("completed_at_utc") else None,
                deleted_at_utc=datetime.fromisoformat(t["deleted_at_utc"]) if t.get("deleted_at_utc") else None,
                created_at=datetime.fromisoformat(t["created_at"]) if t.get("created_at") else datetime.utcnow(),
                updated_at=datetime.fromisoformat(t["updated_at"]) if t.get("updated_at") else datetime.utcnow(),
            )
        )
    db.flush()

    # Insert associations
    for a in task_tags:
        if not isinstance(a, dict):
            continue
        db.execute(TaskTag.insert().values(task_id=int(a["task_id"]), tag_id=int(a["tag_id"])))

    # Restore app_meta
    if isinstance(db_meta, dict):
        for k, v in db_meta.items():
            if k is None or v is None:
                continue
            db.add(AppMeta(key=str(k), value=str(v)))

    db.commit()
