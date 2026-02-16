from __future__ import annotations

import logging
import secrets
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .config import get_settings
from .crud import create_user, purge_archived_tasks
from .db import Base, SessionLocal, engine
from .models import User
from .routers import api_auth, api_tags, api_tasks, api_users, ui


settings = get_settings()

logging.basicConfig(level=getattr(logging, settings.logging.level.upper(), logging.INFO))
logger = logging.getLogger("timeboard")


app = FastAPI(title=settings.app.name)

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


@app.on_event("startup")
def on_startup() -> None:
    global scheduler

    # Ensure DB tables exist.
    Base.metadata.create_all(bind=engine)

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

    # Start purge scheduler.
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

    scheduler.add_job(_purge_job, "interval", minutes=int(settings.purge.interval_minutes), id="purge")
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
    return {"status": "ok"}
