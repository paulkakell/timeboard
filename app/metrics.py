from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Iterable

from sqlalchemy import func
from sqlalchemy.orm import Session

from .models import NotificationEvent, Task, TaskStatus, User, UserNotificationService
from .version import APP_VERSION


def utc_now() -> datetime:
    return datetime.utcnow().replace(tzinfo=None)


def _dt(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    try:
        return value.replace(tzinfo=None)
    except Exception:
        return None


def _iso(value: datetime | None) -> str | None:
    value = _dt(value)
    return value.isoformat() + "Z" if value else None


def _round(value: float | None, digits: int = 3) -> float | None:
    if value is None:
        return None
    if math.isnan(value) or math.isinf(value):
        return None
    return round(float(value), int(digits))


def _safe_div(num: int | float, den: int | float) -> float | None:
    try:
        den_f = float(den)
        if den_f == 0:
            return None
        return float(num) / den_f
    except Exception:
        return None


def _count(q) -> int:
    try:
        return int(q.count() or 0)
    except Exception:
        return 0


def _avg(values: Iterable[float]) -> float | None:
    arr = [float(v) for v in values]
    if not arr:
        return None
    return sum(arr) / len(arr)


def _percent(value: float | None) -> float | None:
    return _round(None if value is None else value * 100.0, 2)


def _status_counts(db: Session, *, user_id: int | None = None) -> dict[str, int]:
    q = db.query(Task.status, func.count(Task.id)).group_by(Task.status)
    if user_id is not None:
        q = q.filter(Task.user_id == int(user_id))
    counts = {((status.value if hasattr(status, "value") else str(status))): int(count or 0) for status, count in q.all()}
    active = int(counts.get(TaskStatus.active.value, 0))
    completed = int(counts.get(TaskStatus.completed.value, 0))
    deleted = int(counts.get(TaskStatus.deleted.value, 0))
    return {
        "total": active + completed + deleted,
        "active": active,
        "completed": completed,
        "deleted": deleted,
        "archived": completed + deleted,
    }


def _active_due_counts(db: Session, *, now: datetime, user_id: int | None = None) -> dict[str, int]:
    base = db.query(Task).filter(Task.status == TaskStatus.active)
    if user_id is not None:
        base = base.filter(Task.user_id == int(user_id))
    in_8h = now + timedelta(hours=8)
    in_24h = now + timedelta(hours=24)
    past_due = _count(base.filter(Task.due_date_utc < now))
    due_0_8h = _count(base.filter(Task.due_date_utc >= now, Task.due_date_utc < in_8h))
    due_8_24h = _count(base.filter(Task.due_date_utc >= in_8h, Task.due_date_utc < in_24h))
    due_over_24h = _count(base.filter(Task.due_date_utc >= in_24h))
    return {
        "past_due": past_due,
        "due_in_0_8h": due_0_8h,
        "due_in_8_24h": due_8_24h,
        "due_in_over_24h": due_over_24h,
        "all_upcoming_due": due_0_8h + due_8_24h + due_over_24h,
    }


def _activity_counts(db: Session, *, now: datetime, user_id: int | None = None) -> dict[str, int]:
    q = db.query(Task)
    if user_id is not None:
        q = q.filter(Task.user_id == int(user_id))
    since_7d = now - timedelta(days=7)
    since_30d = now - timedelta(days=30)
    return {
        "created_7d": _count(q.filter(Task.created_at >= since_7d)),
        "created_30d": _count(q.filter(Task.created_at >= since_30d)),
        "completed_7d": _count(q.filter(Task.completed_at_utc >= since_7d)),
        "completed_30d": _count(q.filter(Task.completed_at_utc >= since_30d)),
        "deleted_7d": _count(q.filter(Task.deleted_at_utc >= since_7d)),
        "deleted_30d": _count(q.filter(Task.deleted_at_utc >= since_30d)),
    }


def _completion_time_stats(db: Session, *, now: datetime, user_id: int | None = None) -> dict[str, Any]:
    since_30d = now - timedelta(days=30)
    q = (
        db.query(Task.completed_at_utc, Task.due_date_utc, Task.created_at)
        .filter(Task.status == TaskStatus.completed)
        .filter(Task.completed_at_utc.is_not(None))
        .filter(Task.completed_at_utc >= since_30d)
    )
    if user_id is not None:
        q = q.filter(Task.user_id == int(user_id))

    deltas: list[float] = []
    late_deltas: list[float] = []
    early_deltas: list[float] = []
    created_to_completed: list[float] = []
    on_time = 0
    late = 0

    for completed_at, due_at, created_at in q.all():
        completed = _dt(completed_at)
        due = _dt(due_at)
        created = _dt(created_at)
        if completed and due:
            delta = (completed - due).total_seconds()
            deltas.append(delta)
            if delta <= 0:
                on_time += 1
                early_deltas.append(abs(delta))
            else:
                late += 1
                late_deltas.append(delta)
        if completed and created:
            created_to_completed.append(max(0.0, (completed - created).total_seconds()))

    total = on_time + late
    return {
        "completed_30d_on_time": on_time,
        "completed_30d_late": late,
        "on_time_completion_rate_30d": _percent(_safe_div(on_time, total)),
        "average_completion_delta_seconds_30d": _round(_avg(deltas), 2),
        "average_late_seconds_30d": _round(_avg(late_deltas), 2),
        "average_early_seconds_30d": _round(_avg(early_deltas), 2),
        "average_created_to_completed_seconds_30d": _round(_avg(created_to_completed), 2),
    }


def _active_overdue_time(db: Session, *, now: datetime, user_id: int | None = None) -> dict[str, Any]:
    q = db.query(Task.due_date_utc).filter(Task.status == TaskStatus.active).filter(Task.due_date_utc < now)
    if user_id is not None:
        q = q.filter(Task.user_id == int(user_id))
    total_seconds = 0.0
    max_seconds = 0.0
    for (due_at,) in q.all():
        due = _dt(due_at)
        if not due:
            continue
        overdue_seconds = max(0.0, (now - due).total_seconds())
        total_seconds += overdue_seconds
        max_seconds = max(max_seconds, overdue_seconds)
    return {
        "active_overdue_seconds_total": int(total_seconds),
        "active_overdue_hours_total": _round(total_seconds / 3600.0, 2),
        "oldest_active_overdue_seconds": int(max_seconds),
    }


def _task_dates(db: Session, *, user_id: int | None = None) -> dict[str, str | None]:
    active_q = db.query(Task.due_date_utc).filter(Task.status == TaskStatus.active)
    completed_q = db.query(Task.completed_at_utc).filter(Task.status == TaskStatus.completed).filter(Task.completed_at_utc.is_not(None))
    if user_id is not None:
        active_q = active_q.filter(Task.user_id == int(user_id))
        completed_q = completed_q.filter(Task.user_id == int(user_id))
    next_due = active_q.order_by(Task.due_date_utc.asc()).limit(1).scalar()
    last_completed = completed_q.order_by(Task.completed_at_utc.desc()).limit(1).scalar()
    return {
        "next_due_at_utc": _iso(next_due),
        "last_completed_at_utc": _iso(last_completed),
    }


def _notification_counts(db: Session, *, now: datetime, user_id: int | None = None) -> dict[str, Any]:
    services_q = db.query(UserNotificationService)
    events_q = db.query(NotificationEvent)
    if user_id is not None:
        services_q = services_q.filter(UserNotificationService.user_id == int(user_id))
        events_q = events_q.filter(NotificationEvent.user_id == int(user_id))

    services = services_q.all()
    by_type: Counter[str] = Counter(str(s.service_type or "unknown") for s in services)
    enabled_by_type: Counter[str] = Counter(str(s.service_type or "unknown") for s in services if bool(s.enabled))
    since_24h = now - timedelta(hours=24)
    events_24h = events_q.filter(NotificationEvent.created_at >= since_24h).count()
    failed_24h = events_q.filter(NotificationEvent.created_at >= since_24h).filter(NotificationEvent.delivery_status == "failed").count()
    unread_in_app = events_q.filter(NotificationEvent.service_type == "in_app").filter(NotificationEvent.cleared_at_utc.is_(None)).count()
    return {
        "services_total": int(len(services)),
        "services_enabled": int(sum(1 for s in services if bool(s.enabled))),
        "services_by_type": dict(sorted(by_type.items())),
        "services_enabled_by_type": dict(sorted(enabled_by_type.items())),
        "events_24h": int(events_24h or 0),
        "events_failed_24h": int(failed_24h or 0),
        "in_app_unread": int(unread_in_app or 0),
    }


def build_user_metrics(db: Session, *, user: User, now_utc: datetime | None = None) -> dict[str, Any]:
    now = (now_utc or utc_now()).replace(tzinfo=None)
    uid = int(user.id)
    status_counts = _status_counts(db, user_id=uid)
    due_counts = _active_due_counts(db, now=now, user_id=uid)
    activity = _activity_counts(db, now=now, user_id=uid)
    completion_stats = _completion_time_stats(db, now=now, user_id=uid)
    overdue = _active_overdue_time(db, now=now, user_id=uid)
    dates = _task_dates(db, user_id=uid)
    notifications = _notification_counts(db, now=now, user_id=uid)

    return {
        "scope": "user",
        "app_version": APP_VERSION,
        "generated_at_utc": _iso(now),
        "user": {
            "id": uid,
            "username": str(user.username),
            "email_set": bool(getattr(user, "email", None)),
            "is_admin": bool(user.is_admin),
            "created_at_utc": _iso(getattr(user, "created_at", None)),
        },
        "tasks": {
            **status_counts,
            **due_counts,
            **activity,
            **dates,
        },
        "completion": completion_stats,
        "time": overdue,
        "notifications": notifications,
    }


def build_deployment_metrics(
    db: Session,
    *,
    now_utc: datetime | None = None,
    started_at_utc: datetime | None = None,
) -> dict[str, Any]:
    now = (now_utc or utc_now()).replace(tzinfo=None)
    users = db.query(User).order_by(User.id.asc()).all()
    status_counts = _status_counts(db)
    due_counts = _active_due_counts(db, now=now)
    activity = _activity_counts(db, now=now)
    completion_stats = _completion_time_stats(db, now=now)
    overdue = _active_overdue_time(db, now=now)
    notifications = _notification_counts(db, now=now)

    started = _dt(started_at_utc)
    uptime_seconds = int(max(0, (now - started).total_seconds())) if started else None

    return {
        "scope": "deployment",
        "app_version": APP_VERSION,
        "generated_at_utc": _iso(now),
        "runtime": {
            "started_at_utc": _iso(started),
            "uptime_seconds": uptime_seconds,
        },
        "users": {
            "total": len(users),
            "admins": sum(1 for u in users if bool(u.is_admin)),
            "non_admins": sum(1 for u in users if not bool(u.is_admin)),
        },
        "tasks": {
            **status_counts,
            **due_counts,
            **activity,
        },
        "completion": completion_stats,
        "time": overdue,
        "notifications": notifications,
    }


def build_all_user_metrics(db: Session, *, now_utc: datetime | None = None) -> list[dict[str, Any]]:
    now = (now_utc or utc_now()).replace(tzinfo=None)
    return [build_user_metrics(db, user=u, now_utc=now) for u in db.query(User).order_by(User.username.asc()).all()]


def flatten_metric_numbers(metrics: dict[str, Any], *, prefix: str = "") -> dict[str, float | int]:
    out: dict[str, float | int] = {}

    def walk(obj: Any, path: list[str]) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in {"user", "runtime"}:
                    # User/runtime fields are generally labels or timestamps, not numeric metrics.
                    for inner_key, inner_value in (value or {}).items():
                        if isinstance(inner_value, (int, float)) and not isinstance(inner_value, bool):
                            out["_".join(path + [str(key), str(inner_key)])] = inner_value
                    continue
                walk(value, path + [str(key)])
            return
        if isinstance(obj, bool):
            return
        if isinstance(obj, (int, float)) and obj is not None:
            out["_".join(path)] = obj

    walk(metrics, [prefix] if prefix else [])
    return out


def _prom_label_value(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _prom_line(name: str, value: int | float | None, labels: dict[str, Any] | None = None) -> str | None:
    if value is None:
        return None
    label_text = ""
    if labels:
        label_text = "{" + ",".join(f'{k}="{_prom_label_value(v)}"' for k, v in sorted(labels.items())) + "}"
    return f"{name}{label_text} {float(value)}"


def render_prometheus_metrics(deployment: dict[str, Any], users: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    lines.append("# HELP timeboardapp_info Application version marker.")
    lines.append("# TYPE timeboardapp_info gauge")
    lines.append(_prom_line("timeboardapp_info", 1, {"version": deployment.get("app_version", "unknown")}) or "")

    dep_nums = flatten_metric_numbers(deployment)
    for key, value in sorted(dep_nums.items()):
        metric_name = "timeboardapp_" + key.lower()
        lines.append(_prom_line(metric_name, value, {"scope": "deployment"}) or "")

    for user_metrics in users:
        user = user_metrics.get("user", {}) if isinstance(user_metrics.get("user"), dict) else {}
        labels = {
            "scope": "user",
            "user_id": user.get("id", ""),
            "username": user.get("username", ""),
        }
        for key, value in sorted(flatten_metric_numbers(user_metrics).items()):
            metric_name = "timeboardapp_" + key.lower()
            lines.append(_prom_line(metric_name, value, labels) or "")
    return "\n".join([ln for ln in lines if ln]) + "\n"


def _influx_tag(value: Any) -> str:
    return str(value).replace(" ", "\\ ").replace(",", "\\,").replace("=", "\\=")


def _influx_field_value(value: int | float) -> str:
    if isinstance(value, int) and not isinstance(value, bool):
        return f"{value}i"
    return str(float(value))


def _influx_line(measurement: str, tags: dict[str, Any], fields: dict[str, int | float]) -> str | None:
    if not fields:
        return None
    tag_text = "".join([f",{_influx_tag(k)}={_influx_tag(v)}" for k, v in sorted(tags.items()) if v is not None])
    field_text = ",".join([f"{_influx_tag(k)}={_influx_field_value(v)}" for k, v in sorted(fields.items()) if v is not None])
    if not field_text:
        return None
    return f"{_influx_tag(measurement)}{tag_text} {field_text}"


def render_influx_lines(deployment: dict[str, Any], users: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    dep_nums = flatten_metric_numbers(deployment)
    dep_line = _influx_line(
        "timeboardapp_deployment",
        {"version": deployment.get("app_version", "unknown")},
        dep_nums,
    )
    if dep_line:
        lines.append(dep_line)
    for user_metrics in users:
        user = user_metrics.get("user", {}) if isinstance(user_metrics.get("user"), dict) else {}
        user_line = _influx_line(
            "timeboardapp_user",
            {"user_id": user.get("id", ""), "username": user.get("username", "")},
            flatten_metric_numbers(user_metrics),
        )
        if user_line:
            lines.append(user_line)
    return "\n".join(lines) + ("\n" if lines else "")


def metrics_endpoint_catalog() -> list[dict[str, str]]:
    return [
        {
            "method": "GET",
            "path": "/api/metrics/catalog",
            "scope": "authenticated user",
            "format": "json",
            "description": "Lists machine-consumable metrics endpoints and intended scrape scope.",
        },
        {
            "method": "GET",
            "path": "/api/metrics/me",
            "scope": "authenticated user",
            "format": "json",
            "description": "Current user's task, completion-time, overdue-time, and notification metrics.",
        },
        {
            "method": "GET",
            "path": "/api/metrics/users",
            "scope": "admin",
            "format": "json",
            "description": "All users with individual user metrics for each account.",
        },
        {
            "method": "GET",
            "path": "/api/metrics/users/{user_id}",
            "scope": "admin or same user",
            "format": "json",
            "description": "Metrics for one user.",
        },
        {
            "method": "GET",
            "path": "/api/metrics/deployment",
            "scope": "admin",
            "format": "json",
            "description": "Deployment-wide users, task, completion, overdue, notification, and runtime metrics.",
        },
        {
            "method": "GET",
            "path": "/api/metrics/prometheus",
            "scope": "admin",
            "format": "text/plain",
            "description": "Prometheus-compatible text exposition for deployment and per-user metrics.",
        },
        {
            "method": "GET",
            "path": "/api/metrics/influx",
            "scope": "admin",
            "format": "text/plain",
            "description": "InfluxDB line protocol for deployment and per-user metrics.",
        },
        {
            "method": "GET",
            "path": "/api/homepage/summary",
            "scope": "authenticated user",
            "format": "json",
            "description": "Compact top-level fields intended for GetHomepage customapi block widgets.",
        },
        {
            "method": "GET",
            "path": "/api/homepage/deployment",
            "scope": "admin",
            "format": "json",
            "description": "Compact deployment fields intended for GetHomepage customapi widgets.",
        },
        {
            "method": "GET",
            "path": "/api/homepage/users",
            "scope": "admin",
            "format": "json",
            "description": "Dynamic-list friendly user summary for GetHomepage customapi.",
        },
    ]
