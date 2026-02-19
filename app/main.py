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
from .db_admin import backup_database_json, get_auto_backup_settings, purge_backup_files
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


def _configure_auto_backup_jobs(app: FastAPI, sched: BackgroundScheduler) -> None:
    """(Re)configure automated backup + retention jobs.

    Settings are stored in the database (app_meta) so they can be changed from
    the UI without editing settings.yml.
    """

    # Read config from DB.
    dbj = SessionLocal()
    try:
        cfg = get_auto_backup_settings(dbj)
    finally:
        dbj.close()

    freq = str(cfg.get("frequency") or "daily").strip().lower()
    retention_days = int(cfg.get("retention_days") or 0)

    # Remove existing jobs first.
    for job_id in ("auto_backup", "backup_retention"):
        try:
            sched.remove_job(job_id)
        except Exception:
            pass

    def _auto_backup_job() -> None:
        dbx = SessionLocal()
        try:
            # Label backups by frequency for easier inspection.
            label = freq.upper() if freq and freq != "disabled" else "BACKUP"
            path = backup_database_json(dbx, prefix=label)
            logger.info("Auto backup written: %s", path)
        except Exception:
            logger.exception("Error while creating automated backup")
        finally:
            dbx.close()

        # Opportunistic retention purge right after backup creation.
        if retention_days and retention_days > 0:
            try:
                deleted = purge_backup_files(retention_days=retention_days)
                if deleted:
                    logger.info("Purged %s old backup file(s)", deleted)
            except Exception:
                logger.exception("Error while purging old backups")

    def _backup_retention_job() -> None:
        # Read retention_days at runtime so changes apply without restart.
        dbx = SessionLocal()
        try:
            cfgx = get_auto_backup_settings(dbx)
            rd = int(cfgx.get("retention_days") or 0)
        except Exception:
            rd = 0
        finally:
            dbx.close()

        if rd <= 0:
            return

        try:
            deleted = purge_backup_files(retention_days=rd)
            if deleted:
                logger.info("Purged %s old backup file(s)", deleted)
        except Exception:
            logger.exception("Error while purging old backups")

    # Schedule backup job (cron-based) if enabled.
    if freq == "disabled":
        logger.info("Auto backups disabled")
    else:
        tz = settings.app.timezone
        if freq == "hourly":
            sched.add_job(_auto_backup_job, "cron", minute=0, timezone=tz, id="auto_backup", replace_existing=True)
        elif freq == "6h":
            sched.add_job(
                _auto_backup_job,
                "cron",
                hour="*/6",
                minute=0,
                timezone=tz,
                id="auto_backup",
                replace_existing=True,
            )
        elif freq == "12h":
            sched.add_job(
                _auto_backup_job,
                "cron",
                hour="*/12",
                minute=0,
                timezone=tz,
                id="auto_backup",
                replace_existing=True,
            )
        elif freq == "weekly":
            sched.add_job(
                _auto_backup_job,
                "cron",
                day_of_week="mon",
                hour=0,
                minute=0,
                timezone=tz,
                id="auto_backup",
                replace_existing=True,
            )
        else:
            # Default: daily at midnight in app timezone.
            sched.add_job(
                _auto_backup_job,
                "cron",
                hour=0,
                minute=0,
                timezone=tz,
                id="auto_backup",
                replace_existing=True,
            )

        logger.info("Auto backup schedule configured: %s", freq)

    # Schedule retention purge job daily at 00:30 in app timezone.
    # (It will no-op when retention_days == 0.)
    sched.add_job(
        _backup_retention_job,
        "cron",
        hour=0,
        minute=30,
        timezone=settings.app.timezone,
        id="backup_retention",
        replace_existing=True,
    )

    # Expose current config on app.state for UI rendering/debugging.
    app.state.auto_backup_config = {"frequency": freq, "retention_days": retention_days}


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

    # Automated backups (configurable via Admin → Database).
    # Defaults preserve legacy behavior (daily at midnight; no retention purge).
    try:
        _configure_auto_backup_jobs(app, scheduler)
    except Exception:
        logger.exception("Failed to configure automated backup jobs")

    # Make scheduler + configure hook accessible from request handlers.
    app.state.scheduler = scheduler
    app.state.configure_auto_backup_jobs = lambda: _configure_auto_backup_jobs(app, scheduler)
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
