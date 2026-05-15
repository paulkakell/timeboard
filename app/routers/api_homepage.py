from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..auth import get_current_user_api, require_admin_api
from ..db import get_db
from ..metrics import build_all_user_metrics, build_deployment_metrics, build_user_metrics, utc_now
from ..models import User
from ..version import APP_VERSION

router = APIRouter()


def _as_number(value, default=0):
    if value is None:
        return default
    return value


def _started_at(request: Request):
    value = getattr(request.app.state, "started_at_utc", None)
    try:
        return value.replace(tzinfo=None)
    except Exception:
        return None


def _homepage_user_summary(metrics: dict) -> dict:
    tasks = metrics.get("tasks", {}) if isinstance(metrics.get("tasks"), dict) else {}
    completion = metrics.get("completion", {}) if isinstance(metrics.get("completion"), dict) else {}
    time_data = metrics.get("time", {}) if isinstance(metrics.get("time"), dict) else {}
    user = metrics.get("user", {}) if isinstance(metrics.get("user"), dict) else {}
    return {
        "status": "ok",
        "version": APP_VERSION,
        "scope": "user",
        "user_id": user.get("id"),
        "username": user.get("username"),
        "active": _as_number(tasks.get("active")),
        "past_due": _as_number(tasks.get("past_due")),
        "upcoming": _as_number(tasks.get("all_upcoming_due")),
        "completed_7d": _as_number(tasks.get("completed_7d")),
        "completed_30d": _as_number(tasks.get("completed_30d")),
        "completion_rate_30d": completion.get("on_time_completion_rate_30d"),
        "overdue_hours": _as_number(time_data.get("active_overdue_hours_total"), 0.0),
        "next_due_at_utc": tasks.get("next_due_at_utc"),
        "generated_at_utc": metrics.get("generated_at_utc") or (utc_now().isoformat() + "Z"),
    }


def _homepage_deployment_summary(metrics: dict) -> dict:
    users = metrics.get("users", {}) if isinstance(metrics.get("users"), dict) else {}
    tasks = metrics.get("tasks", {}) if isinstance(metrics.get("tasks"), dict) else {}
    notifications = metrics.get("notifications", {}) if isinstance(metrics.get("notifications"), dict) else {}
    runtime = metrics.get("runtime", {}) if isinstance(metrics.get("runtime"), dict) else {}
    return {
        "status": "ok",
        "version": APP_VERSION,
        "scope": "deployment",
        "users": _as_number(users.get("total")),
        "admins": _as_number(users.get("admins")),
        "active": _as_number(tasks.get("active")),
        "past_due": _as_number(tasks.get("past_due")),
        "completed_7d": _as_number(tasks.get("completed_7d")),
        "completed_30d": _as_number(tasks.get("completed_30d")),
        "notifications_24h": _as_number(notifications.get("events_24h")),
        "notification_failures_24h": _as_number(notifications.get("events_failed_24h")),
        "uptime_seconds": runtime.get("uptime_seconds"),
        "generated_at_utc": metrics.get("generated_at_utc") or (utc_now().isoformat() + "Z"),
    }


@router.get("/summary")
def homepage_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_api),
):
    return _homepage_user_summary(build_user_metrics(db, user=current_user))


@router.get("/deployment")
def homepage_deployment(
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin_api),
):
    return _homepage_deployment_summary(build_deployment_metrics(db, started_at_utc=_started_at(request)))


@router.get("/users")
def homepage_users(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin_api),
):
    rows = []
    for metrics in build_all_user_metrics(db):
        summary = _homepage_user_summary(metrics)
        rows.append(
            {
                "id": str(summary.get("user_id") or ""),
                "name": str(summary.get("username") or "user"),
                "label": f"{summary.get('active', 0)} active / {summary.get('past_due', 0)} overdue",
                "active": summary.get("active", 0),
                "past_due": summary.get("past_due", 0),
                "completed_7d": summary.get("completed_7d", 0),
            }
        )
    return {
        "status": "ok",
        "version": APP_VERSION,
        "generated_at_utc": utc_now().isoformat() + "Z",
        "users": rows,
    }
