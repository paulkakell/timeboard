from __future__ import annotations

import logging
import secrets
from datetime import datetime
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .config import get_settings
from .crud import create_user, purge_archived_tasks
from .db import Base, SessionLocal, engine
from .emailer import build_overdue_reminder_email, email_enabled, send_email
from .migrations import ensure_db_schema
from .models import Task, TaskStatus, User
from .routers import api_auth, api_tags, api_tasks, api_users, ui
from .utils.time_utils import format_dt_display, to_local
from .version import APP_VERSION


settings = get_settings()

logging.basicConfig(level=getattr(logging, settings.logging.level.upper(), logging.INFO))
logger = logging.getLogger("timeboard")


app = FastAPI(title=settings.app.name, version=APP_VERSION)

app.add_middleware(SessionMiddleware, secret_key=settings.security.session_secret)

# Static files
static_path = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

# Routers
app.include_router(api_auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(api_users.router, prefix="/api/users", tags=["users"])
app.include_router(api_tasks.router, prefix="/api/tasks", tags=["tasks"])
app.include_router(api_tags.router, prefix="/api/tags", tags=["tags"])

app.include_router(ui.router)


scheduler: BackgroundScheduler | None = None


def _public_base_url() -> str:
    # Prefer configured base_url for email links.
    base = (settings.app.base_url or "").strip().rstrip("/")
    return base


@app.on_event("startup")
def on_startup() -> None:
    global scheduler

    # Ensure DB tables exist.
    Base.metadata.create_all(bind=engine)

    # Lightweight schema migrations (adds new nullable columns/tables).
    report = ensure_db_schema(engine)
    app.state.db_migration_report = report
    if report.applied_steps:
        logger.warning("Database schema upgraded to %s (%s)", report.current_db_version, ", ".join(report.applied_steps))

    # Ensure first-run admin.
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            admin_password = secrets.token_urlsafe(12)
            create_user(db, username="admin", password=admin_password, is_admin=True)
            logger.warning("============================================================")
            logger.warning("Timeboard initial admin account created")
            logger.warning("Username: admin")
            logger.warning("Password: %s", admin_password)
            logger.warning("Please log in and change this password.")
            logger.warning("============================================================")
    finally:
        db.close()

    # Start background scheduler.
    scheduler = BackgroundScheduler(timezone="UTC")

    def _purge_job() -> None:
        dbj = SessionLocal()
        try:
            deleted = purge_archived_tasks(dbj)
            if deleted:
                logger.info("Purged %s archived tasks", deleted)
        except Exception:
            logger.exception("Error while purging archived tasks")
        finally:
            dbj.close()

    scheduler.add_job(
        _purge_job,
        "interval",
        minutes=int(settings.purge.interval_minutes),
        id="purge",
    )

    def _reminder_job() -> None:
        if not email_enabled():
            return
        dbj = SessionLocal()
        try:
            now = datetime.utcnow().replace(tzinfo=None)

            # Find overdue active tasks for users with email addresses.
            q = (
                dbj.query(Task)
                .join(User, User.id == Task.user_id)
                .filter(Task.status == TaskStatus.active)
                .filter(Task.due_date_utc < now)
                .filter(User.email.is_not(None))
            )

            tasks = q.all()
            if not tasks:
                return

            base_url = _public_base_url()
            dashboard_url = f"{base_url}/dashboard" if base_url else ""

            grouped: dict[int, list[Task]] = {}
            for t in tasks:
                grouped.setdefault(int(t.user_id), []).append(t)

            for user_id, items in grouped.items():
                user = dbj.query(User).filter(User.id == user_id).first()
                if not user or not user.email:
                    continue

                task_rows = []
                for t in sorted(items, key=lambda x: x.due_date_utc):
                    task_rows.append(
                        {
                            "name": t.name,
                            "task_type": t.task_type,
                            "due": format_dt_display(t.due_date_utc),
                        }
                    )

                subject, body = build_overdue_reminder_email(
                    username=user.username,
                    tasks=task_rows,
                    dashboard_url=dashboard_url or "(dashboard URL not configured)",
                )

                try:
                    send_email(to_address=user.email, subject=subject, body_text=body)
                except Exception:
                    logger.exception("Failed to send overdue reminder to %s", user.email)

        except Exception:
            logger.exception("Error while sending overdue reminders")
        finally:
            dbj.close()

    scheduler.add_job(
        _reminder_job,
        "interval",
        minutes=int(settings.email.reminder_interval_minutes),
        id="overdue_reminders",
        replace_existing=True,
    )

    scheduler.start()


@app.on_event("shutdown")
def on_shutdown() -> None:
    global scheduler
    if scheduler:
        scheduler.shutdown(wait=False)
        scheduler = None


@app.get("/", include_in_schema=False)
def root(request: Request):
    return RedirectResponse(url="/dashboard")


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok", "version": APP_VERSION}
