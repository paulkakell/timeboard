from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from .crud import normalize_email
from .models import AppMeta, RecurrenceType, Tag, Task, TaskStatus, TaskTag, Theme, User
from .version import APP_VERSION


DEFAULT_BACKUPS_DIR = Path("/data/backups")

# app_meta keys (stored in the database)
AUTO_BACKUP_FREQUENCY_KEY = "auto_backup.frequency"
AUTO_BACKUP_RETENTION_DAYS_KEY = "auto_backup.retention_days"

# Allowed auto-backup frequencies (UI + scheduler).
# NOTE: These are strings (stored in app_meta) so they can be extended later
# without schema changes.
AUTO_BACKUP_FREQUENCIES = {
    "disabled",  # no automated backups
    "hourly",
    "6h",
    "12h",
    "daily",
    "weekly",
}


def _dt(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _timestamp_utc(now: datetime | None = None) -> str:
    n = now or datetime.utcnow().replace(tzinfo=None)
    return n.strftime("%Y%m%dT%H%M%SZ")


def _safe_filename_token(value: str | None, *, default: str) -> str:
    """Return a filename-safe token.

    Keeps: A-Z a-z 0-9 _ - .
    """
    raw = (value or "").strip()
    token = "".join([c for c in raw if c.isalnum() or c in {"-", "_", "."}])
    return token or default


def build_user_export_filename(
    *,
    app_version: str = APP_VERSION,
    db_version: str | None = None,
    now: datetime | None = None,
) -> str:
    """Filename for a user-initiated export download."""
    ts = _timestamp_utc(now)
    av = _safe_filename_token(app_version, default="UNKNOWN")
    dv = _safe_filename_token(db_version or app_version, default="UNKNOWN")
    return f"timeboard-userexport-app{av}-db{dv}-{ts}.json"


def build_auto_backup_filename(
    *,
    label: str,
    app_version: str = APP_VERSION,
    db_version: str | None = None,
    now: datetime | None = None,
) -> str:
    """Filename for an automatic backup written under /data/backups."""
    ts = _timestamp_utc(now)
    lab = _safe_filename_token((label or "").upper(), default="BACKUP")
    av = _safe_filename_token(app_version, default="UNKNOWN")
    dv = _safe_filename_token(db_version or app_version, default="UNKNOWN")
    return f"timeboard-autobackup-{lab}-app{av}-db{dv}-{ts}.json"


def _parse_datetime(value: Any, *, field: str) -> datetime | None:
    """Parse a datetime from common JSON export formats.

    The database stores naive UTC datetimes.

    Accepts:
    - None
    - datetime
    - ISO8601 strings, with optional timezone offsets or trailing 'Z'
    """
    if value is None:
        return None

    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        # tolerate trailing Z
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
    else:
        raise ValueError(f"{field} must be an ISO8601 string")

    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    else:
        dt = dt.replace(tzinfo=None)

    return dt


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


def write_backup_json(
    data: Dict[str, Any],
    *,
    prefix: str,
    backups_dir: Path = DEFAULT_BACKUPS_DIR,
) -> Path:
    """Write a JSON backup file to disk.

    The filename includes `prefix` and a UTC timestamp.

    Returns the final backup path.
    """
    backups_dir.mkdir(parents=True, exist_ok=True)

    safe_prefix = "".join([c for c in (prefix or "").upper() if c.isalnum() or c in {"-", "_"}]) or "BACKUP"

    app_version = str(data.get("app_version") or APP_VERSION)
    db_meta = data.get("db_meta") or {}
    db_version = str(db_meta.get("db_version") or db_meta.get("app_version") or app_version)

    filename = build_auto_backup_filename(label=safe_prefix, app_version=app_version, db_version=db_version)

    final_path = backups_dir / filename
    tmp_path = backups_dir / f".{filename}.tmp"

    # Add minimal metadata to backups (does not affect import).
    payload = dict(data)
    payload.setdefault("backup_type", safe_prefix)
    payload.setdefault("backup_written_at_utc", datetime.utcnow().replace(tzinfo=None).isoformat())
    payload.setdefault("backup_origin", "auto")

    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp_path.replace(final_path)
    return final_path


def backup_database_json(
    db: Session,
    *,
    prefix: str,
    backups_dir: Path = DEFAULT_BACKUPS_DIR,
) -> Path:
    """Create a JSON backup of the current database."""
    data = export_db_json(db)
    return write_backup_json(data, prefix=prefix, backups_dir=backups_dir)


def _get_meta_value(db: Session, key: str) -> str | None:
    row = db.query(AppMeta).filter(AppMeta.key == str(key)).first()
    if not row:
        return None
    v = str(row.value or "").strip()
    return v or None


def _set_meta_value(db: Session, key: str, value: str) -> None:
    k = str(key)
    v = str(value)
    row = db.query(AppMeta).filter(AppMeta.key == k).first()
    if row:
        row.value = v
        db.add(row)
    else:
        db.add(AppMeta(key=k, value=v))


def get_auto_backup_settings(db: Session) -> dict[str, Any]:
    """Read auto-backup settings from app_meta.

    Defaults preserve previous behavior:
    - frequency: daily
    - retention_days: 0 (never purge)
    """
    freq = (_get_meta_value(db, AUTO_BACKUP_FREQUENCY_KEY) or "daily").strip().lower()
    if freq not in AUTO_BACKUP_FREQUENCIES:
        freq = "daily"

    retention_days = 0
    raw_rd = _get_meta_value(db, AUTO_BACKUP_RETENTION_DAYS_KEY)
    if raw_rd is not None:
        try:
            retention_days = int(raw_rd)
        except Exception:
            retention_days = 0

    if retention_days < 0:
        retention_days = 0
    if retention_days > 3650:
        retention_days = 3650

    return {
        "frequency": freq,
        "retention_days": retention_days,
    }


def set_auto_backup_settings(
    db: Session,
    *,
    frequency: str,
    retention_days: int,
) -> dict[str, Any]:
    freq = (frequency or "").strip().lower()
    if freq not in AUTO_BACKUP_FREQUENCIES:
        raise ValueError("Invalid backup frequency")

    try:
        rd = int(retention_days)
    except Exception as e:
        raise ValueError("Invalid retention_days") from e

    if rd < 0 or rd > 3650:
        raise ValueError("retention_days must be between 0 and 3650")

    _set_meta_value(db, AUTO_BACKUP_FREQUENCY_KEY, freq)
    _set_meta_value(db, AUTO_BACKUP_RETENTION_DAYS_KEY, str(rd))
    db.commit()

    return {
        "frequency": freq,
        "retention_days": rd,
    }


def purge_backup_files(
    *,
    retention_days: int,
    backups_dir: Path = DEFAULT_BACKUPS_DIR,
    now: datetime | None = None,
) -> int:
    """Delete backup files older than `retention_days`.

    Uses file modification time (mtime) as the age source.
    Returns the number of deleted files.

    If retention_days is 0, no files are deleted.
    """
    try:
        days = int(retention_days)
    except Exception:
        days = 0

    if days <= 0:
        return 0

    cutoff = (now or datetime.utcnow().replace(tzinfo=None)) - timedelta(days=days)

    if not backups_dir.exists() or not backups_dir.is_dir():
        return 0

    deleted = 0
    for p in backups_dir.iterdir():
        if not p.is_file():
            continue
        if p.name.startswith("."):
            # Ignore temp files (including .*.tmp)
            continue
        if p.suffix.lower() != ".json":
            continue

        try:
            mtime = datetime.utcfromtimestamp(p.stat().st_mtime).replace(tzinfo=None)
            if mtime < cutoff:
                p.unlink(missing_ok=True)
                deleted += 1
        except Exception:
            # Best-effort purge; ignore files we can't stat/delete.
            continue

    return deleted


def validate_import_payload(payload: Any) -> Tuple[List[str], List[str]]:
    """Validate an import JSON payload.

    Returns (errors, warnings).

    Validation is intentionally strict so imports fail *before* any database
    changes are applied.
    """
    errors: List[str] = []
    warnings: List[str] = []

    if not isinstance(payload, dict):
        return (["Root JSON must be an object"], warnings)

    users = payload.get("users")
    tags = payload.get("tags")
    tasks = payload.get("tasks")
    task_tags = payload.get("task_tags")

    if not isinstance(users, list):
        errors.append("Missing or invalid 'users' list")
    if not isinstance(tags, list):
        errors.append("Missing or invalid 'tags' list")
    if not isinstance(tasks, list):
        errors.append("Missing or invalid 'tasks' list")
    if not isinstance(task_tags, list):
        errors.append("Missing or invalid 'task_tags' list")

    db_meta = payload.get("db_meta")
    if db_meta is not None and not isinstance(db_meta, dict):
        warnings.append("'db_meta' should be an object; ignoring")

    src_version = payload.get("app_version")
    if src_version is not None and not isinstance(src_version, str):
        warnings.append("'app_version' should be a string")
    elif isinstance(src_version, str) and src_version.strip() and src_version.strip() != APP_VERSION:
        warnings.append(f"Import file app_version is {src_version.strip()} (current app is {APP_VERSION})")

    if errors:
        return errors, warnings

    allowed_themes = {Theme.light.value, Theme.dark.value, Theme.system.value}
    allowed_statuses = {s.value for s in TaskStatus}
    allowed_recurrence = {r.value for r in RecurrenceType}

    # ---- users ----
    user_ids: set[int] = set()
    usernames: set[str] = set()
    emails: set[str] = set()
    admin_count = 0

    for i, u in enumerate(users):
        ctx = f"users[{i}]"
        if not isinstance(u, dict):
            errors.append(f"{ctx}: must be an object")
            continue

        # id
        try:
            uid = int(u.get("id"))
        except Exception:
            errors.append(f"{ctx}: 'id' must be an integer")
            continue

        if uid in user_ids:
            errors.append(f"{ctx}: duplicate user id {uid}")
        user_ids.add(uid)

        username = str(u.get("username") or "").strip()
        if not username:
            errors.append(f"{ctx}: 'username' is required")
        elif username in usernames:
            errors.append(f"{ctx}: duplicate username '{username}'")
        else:
            usernames.add(username)

        hp = str(u.get("hashed_password") or "").strip()
        if not hp:
            errors.append(f"{ctx}: 'hashed_password' is required")

        is_admin = bool(u.get("is_admin", False))
        if is_admin:
            admin_count += 1

        email_norm = normalize_email(u.get("email"))
        if not is_admin and not email_norm:
            errors.append(f"{ctx}: email is required for non-admin users")
        if email_norm:
            if email_norm in emails:
                errors.append(f"{ctx}: duplicate email '{email_norm}'")
            emails.add(email_norm)

        theme = u.get("theme")
        if theme is not None:
            theme_str = str(theme)
            if theme_str not in allowed_themes:
                warnings.append(f"{ctx}: unknown theme '{theme_str}'")

        purge_days = u.get("purge_days")
        if purge_days is not None:
            try:
                pd = int(purge_days)
                if pd < 1 or pd > 3650:
                    warnings.append(f"{ctx}: purge_days {pd} is out of range (1-3650)")
            except Exception:
                warnings.append(f"{ctx}: purge_days should be an integer")

        # created_at / updated_at
        for dt_field in ("created_at", "updated_at"):
            if u.get(dt_field) is None:
                continue
            try:
                _parse_datetime(u.get(dt_field), field=f"{ctx}.{dt_field}")
            except Exception:
                errors.append(f"{ctx}: '{dt_field}' is not a valid ISO8601 datetime")

    if admin_count == 0:
        warnings.append("No admin users found in import; an admin account will be auto-created on the next login attempt")

    # ---- tags ----
    tag_ids: set[int] = set()
    tag_names: set[str] = set()

    for i, t in enumerate(tags):
        ctx = f"tags[{i}]"
        if not isinstance(t, dict):
            errors.append(f"{ctx}: must be an object")
            continue

        try:
            tid = int(t.get("id"))
        except Exception:
            errors.append(f"{ctx}: 'id' must be an integer")
            continue

        if tid in tag_ids:
            errors.append(f"{ctx}: duplicate tag id {tid}")
        tag_ids.add(tid)

        name = str(t.get("name") or "").strip()
        if not name:
            errors.append(f"{ctx}: 'name' is required")
            continue

        name_norm = name.strip().lower()
        if name_norm in tag_names:
            errors.append(f"{ctx}: duplicate tag name '{name}'")
        tag_names.add(name_norm)

    # ---- tasks ----
    task_ids: set[int] = set()

    for i, t in enumerate(tasks):
        ctx = f"tasks[{i}]"
        if not isinstance(t, dict):
            errors.append(f"{ctx}: must be an object")
            continue

        try:
            tid = int(t.get("id"))
        except Exception:
            errors.append(f"{ctx}: 'id' must be an integer")
            continue

        if tid in task_ids:
            errors.append(f"{ctx}: duplicate task id {tid}")
        task_ids.add(tid)

        try:
            uid = int(t.get("user_id"))
        except Exception:
            errors.append(f"{ctx}: 'user_id' must be an integer")
            continue

        if uid not in user_ids:
            errors.append(f"{ctx}: user_id {uid} does not exist in users list")

        name = str(t.get("name") or "").strip()
        if not name:
            errors.append(f"{ctx}: 'name' is required")

        task_type = str(t.get("task_type") or "").strip()
        if not task_type:
            errors.append(f"{ctx}: 'task_type' is required")

        rec = str(t.get("recurrence_type") or RecurrenceType.none.value)
        if rec not in allowed_recurrence:
            errors.append(f"{ctx}: recurrence_type '{rec}' is invalid")

        status = str(t.get("status") or TaskStatus.active.value)
        if status not in allowed_statuses:
            errors.append(f"{ctx}: status '{status}' is invalid")

        # Required datetime fields
        for dt_field in ("due_date_utc", "created_at", "updated_at"):
            if not t.get(dt_field):
                errors.append(f"{ctx}: '{dt_field}' is required")
                continue
            try:
                _parse_datetime(t.get(dt_field), field=f"{ctx}.{dt_field}")
            except Exception:
                errors.append(f"{ctx}: '{dt_field}' is not a valid ISO8601 datetime")

        # Optional datetime fields
        for dt_field in ("completed_at_utc", "deleted_at_utc"):
            if not t.get(dt_field):
                continue
            try:
                _parse_datetime(t.get(dt_field), field=f"{ctx}.{dt_field}")
            except Exception:
                errors.append(f"{ctx}: '{dt_field}' is not a valid ISO8601 datetime")

        # recurrence_interval_seconds
        if t.get("recurrence_interval_seconds") is not None:
            try:
                int(t.get("recurrence_interval_seconds"))
            except Exception:
                errors.append(f"{ctx}: recurrence_interval_seconds must be an integer")

    # ---- task_tags ----
    assoc: set[tuple[int, int]] = set()

    for i, a in enumerate(task_tags):
        ctx = f"task_tags[{i}]"
        if not isinstance(a, dict):
            errors.append(f"{ctx}: must be an object")
            continue

        try:
            task_id = int(a.get("task_id"))
            tag_id = int(a.get("tag_id"))
        except Exception:
            errors.append(f"{ctx}: task_id and tag_id must be integers")
            continue

        if task_id not in task_ids:
            errors.append(f"{ctx}: task_id {task_id} does not exist in tasks list")
        if tag_id not in tag_ids:
            errors.append(f"{ctx}: tag_id {tag_id} does not exist in tags list")

        key = (task_id, tag_id)
        if key in assoc:
            errors.append(f"{ctx}: duplicate association task_id={task_id} tag_id={tag_id}")
        assoc.add(key)

    return errors, warnings


def import_db_json(db: Session, payload: Dict[str, Any], *, replace: bool = True) -> None:
    """Import a JSON export into the database.

    By default this *replaces* existing data.

    Import is performed as a single transaction. If any error occurs, the
    transaction is rolled back so the existing database contents remain intact.
    """
    errors, _warnings = validate_import_payload(payload)
    if errors:
        raise ValueError("Import validation failed: " + "; ".join(errors))

    if not isinstance(payload, dict):
        raise ValueError("Invalid import payload")

    users = payload.get("users")
    tags = payload.get("tags")
    tasks = payload.get("tasks")
    task_tags = payload.get("task_tags")
    db_meta = payload.get("db_meta") or {}

    if not isinstance(users, list) or not isinstance(tags, list) or not isinstance(tasks, list) or not isinstance(task_tags, list):
        raise ValueError("Invalid import payload structure")

    try:
        if replace:
            # Delete in dependency order.
            db.execute(text("DELETE FROM task_tags"))
            db.execute(text("DELETE FROM tasks"))
            db.execute(text("DELETE FROM tags"))
            db.execute(text("DELETE FROM users"))
            db.execute(text("DELETE FROM app_meta"))

        # Insert users
        for u in users:
            if not isinstance(u, dict):
                continue

            is_admin = bool(u.get("is_admin", False))
            email_norm = normalize_email(u.get("email"))
            if not is_admin and not email_norm:
                raise ValueError(f"User '{u.get('username')}' is missing email (required for non-admin users)")

            created_at = _parse_datetime(u.get("created_at"), field="users.created_at") or datetime.utcnow().replace(tzinfo=None)
            updated_at = _parse_datetime(u.get("updated_at"), field="users.updated_at") or datetime.utcnow().replace(tzinfo=None)

            theme = str(u.get("theme") or Theme.system.value)
            if theme not in {Theme.light.value, Theme.dark.value, Theme.system.value}:
                theme = Theme.system.value

            db.add(
                User(
                    id=int(u["id"]),
                    username=str(u["username"]).strip(),
                    email=email_norm,
                    hashed_password=str(u["hashed_password"]),
                    is_admin=is_admin,
                    theme=theme,
                    purge_days=int(u.get("purge_days") or 15),
                    created_at=created_at,
                    updated_at=updated_at,
                )
            )
        db.flush()

        # Insert tags
        for t in tags:
            if not isinstance(t, dict):
                continue
            db.add(Tag(id=int(t["id"]), name=str(t["name"]).strip()))
        db.flush()

        # Insert tasks
        for t in tasks:
            if not isinstance(t, dict):
                continue

            due_dt = _parse_datetime(t.get("due_date_utc"), field="tasks.due_date_utc")
            if due_dt is None:
                raise ValueError(f"Task '{t.get('name')}' is missing due_date_utc")

            created_at = _parse_datetime(t.get("created_at"), field="tasks.created_at") or datetime.utcnow().replace(tzinfo=None)
            updated_at = _parse_datetime(t.get("updated_at"), field="tasks.updated_at") or datetime.utcnow().replace(tzinfo=None)

            db.add(
                Task(
                    id=int(t["id"]),
                    user_id=int(t["user_id"]),
                    name=str(t["name"]).strip(),
                    task_type=str(t["task_type"]).strip(),
                    description=t.get("description"),
                    url=t.get("url"),
                    due_date_utc=due_dt,
                    recurrence_type=str(t.get("recurrence_type") or RecurrenceType.none.value),
                    recurrence_interval_seconds=(
                        None
                        if t.get("recurrence_interval_seconds") is None
                        else int(t.get("recurrence_interval_seconds"))
                    ),
                    recurrence_times=t.get("recurrence_times"),
                    status=str(t.get("status") or TaskStatus.active.value),
                    completed_at_utc=_parse_datetime(t.get("completed_at_utc"), field="tasks.completed_at_utc"),
                    deleted_at_utc=_parse_datetime(t.get("deleted_at_utc"), field="tasks.deleted_at_utc"),
                    created_at=created_at,
                    updated_at=updated_at,
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

    except Exception:
        db.rollback()
        raise
