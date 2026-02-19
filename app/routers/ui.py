from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..auth import authenticate_user
from ..config import get_settings
from ..crud import (
    complete_task,
    consume_password_reset_token,
    create_password_reset_token,
    create_task,
    create_user,
    delete_user,
    get_password_reset_token,
    get_task,
    get_user_by_email,
    get_user_by_username,
    list_tasks,
    list_users,
    restore_task,
    soft_delete_task,
    update_task,
    update_user_admin,
    update_user_me,
)
from ..db import SessionLocal, get_db
from ..db_admin import backup_database_json, export_db_json, import_db_json, validate_import_payload
from ..emailer import build_password_reset_email, email_enabled, send_email
from ..models import RecurrenceType, Task, TaskStatus, Theme, User
from ..utils.humanize import humanize_timedelta, time_left_class, seconds_to_duration_str
from ..utils.time_utils import iso_for_datetime_local_input, now_utc, to_local
from ..version import APP_VERSION


router = APIRouter(include_in_schema=False)


templates_dir = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))
# Jinja filters
templates.env.filters["dt_local"] = lambda dt: to_local(dt).strftime("%Y-%m-%d %H:%M") if dt else ""

# Global template vars
templates.env.globals["app_version"] = APP_VERSION
templates.env.globals["github_repo_url"] = "https://github.com/paulkakell/timeboard"

# Cache-busting for static assets.
static_dir = Path(__file__).resolve().parent.parent / "static"
try:
    css_mtime = (static_dir / "css" / "styles.css").stat().st_mtime
    js_mtime = (static_dir / "js" / "main.js").stat().st_mtime
    templates.env.globals["static_version"] = str(int(max(css_mtime, js_mtime)))
except Exception:
    templates.env.globals["static_version"] = "1"


settings = get_settings()
logger = logging.getLogger("timeboard.ui")



def _get_current_user(request: Request, db: Session) -> Optional[User]:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return db.query(User).filter(User.id == int(user_id)).first()


def _redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url=url, status_code=303)


def _parse_tags_csv(text: str) -> list[str]:
    if not text:
        return []
    parts = [p.strip() for p in text.split(",")]
    return [p for p in parts if p]


def _is_mobile_request(request: Request) -> bool:
    ua = (request.headers.get("user-agent") or "").lower()
    if not ua:
        return False
    tokens = ["iphone", "android", "ipad", "ipod", "mobile", "windows phone"]
    return any(t in ua for t in tokens)


def _site_mode(request: Request) -> str:
    forced = request.session.get("site_mode")
    if forced in {"desktop", "mobile"}:
        return forced
    return "mobile" if _is_mobile_request(request) else "desktop"


def _base_url_for_email(request: Request) -> str:
    base = (settings.app.base_url or "").strip().rstrip("/")
    if base:
        return base
    # Fallback to request base URL
    return str(request.base_url).rstrip("/")


def _template_context(request: Request, user: Optional[User], db: Session | None = None, **extra) -> dict:
    report = getattr(request.app.state, "db_migration_report", None)

    # Provide user list for admin navigation dropdowns when a DB session is available.
    if user and getattr(user, "is_admin", False) and "nav_users" not in extra and db is not None:
        try:
            extra["nav_users"] = list_users(db)
        except Exception:
            extra["nav_users"] = []

    return {
        "request": request,
        "current_user": user,
        "app_name": settings.app.name,
        "site_mode": _site_mode(request),
        "db_version": getattr(report, "current_db_version", None),
        "db_previous_version": getattr(report, "previous_db_version", None),
        "db_upgrade_steps": getattr(report, "applied_steps", []),
        **extra,
    }


def _task_form_context(task: Task | None = None) -> dict:
    if not task:
        return {
            "task": None,
            "name": "",
            "task_type": "",
            "description": "",
            "url": "",
            "due_date": "",
            "recurrence_type": RecurrenceType.none.value,
            "recurrence_interval": "",
            "recurrence_times": "",
            "tags": "",
        }

    return {
        "task": task,
        "name": task.name,
        "task_type": task.task_type,
        "description": task.description or "",
        "url": task.url or "",
        "due_date": iso_for_datetime_local_input(task.due_date_utc),
        "recurrence_type": task.recurrence_type,
        "recurrence_interval": ""
        if not task.recurrence_interval_seconds
        else seconds_to_duration_str(int(task.recurrence_interval_seconds)),
        "recurrence_times": task.recurrence_times or "",
        "tags": ", ".join([t.name for t in (task.tags or [])]),
    }


def _effective_user_filter(current_user: User, user_id: int | None) -> int | None:
    """For admin views, translate user_id query param into list_tasks() filter."""
    if not current_user.is_admin:
        return None

    if user_id is None:
        # Default for admins: only their own tasks.
        return int(current_user.id)

    if int(user_id) == 0:
        # 0 means "all tasks".
        return None

    return int(user_id)


def _distinct_task_types(
    db: Session,
    *,
    current_user: User,
    include_archived: bool,
    tag: str | None,
    user_id: int | None,
    status: str | None,
) -> list[str]:
    q = db.query(Task.task_type)

    if current_user.is_admin:
        if user_id:
            q = q.filter(Task.user_id == int(user_id))
    else:
        q = q.filter(Task.user_id == int(current_user.id))

    if status == "archived":
        q = q.filter(Task.status.in_([TaskStatus.completed, TaskStatus.deleted]))
    elif not include_archived:
        q = q.filter(Task.status == TaskStatus.active)

    if tag:
        # Join through association to tags.
        from ..models import Tag  # local import to avoid circulars

        tnorm = tag.strip().lower()
        q = q.join(Task.tags).filter(func.lower(Tag.name) == tnorm)

    rows = q.distinct().order_by(Task.task_type.asc()).all()
    return [r[0] for r in rows if r and r[0]]


@router.get("/site/desktop")
def set_site_desktop(request: Request, next: str | None = None):
    request.session["site_mode"] = "desktop"
    return _redirect(next or request.headers.get("referer") or "/dashboard")


@router.get("/site/mobile")
def set_site_mobile(request: Request, next: str | None = None):
    request.session["site_mode"] = "mobile"
    return _redirect(next or request.headers.get("referer") or "/dashboard")


@router.get("/login", response_class=HTMLResponse)
def login_get(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if user:
        return _redirect("/dashboard")

    success = request.query_params.get("success")

    success_msg = None
    if success == "reset":
        success_msg = "Password updated. You can sign in."
    elif success == "import":
        success_msg = "Import complete. Please sign in again."

    return templates.TemplateResponse(
        "login.html",
        _template_context(
            request,
            user,
            db=db,
            error=None,
            success=success_msg,
        ),
    )


@router.post("/login", response_class=HTMLResponse)
def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = authenticate_user(db, username, password)
    if not user:
        return templates.TemplateResponse(
            "login.html",
            _template_context(
                request,
                None,
                db=db,
                error="Invalid username/email or password",
                success=None,
            ),
            status_code=401,
        )

    request.session["user_id"] = int(user.id)
    return _redirect("/dashboard")


@router.get("/forgot-email", response_class=HTMLResponse)
def forgot_email_get(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if user:
        return _redirect("/dashboard")

    return templates.TemplateResponse(
        "forgot_email.html",
        _template_context(
            request,
            None,
            db=db,
            error=None,
            success=None,
            email_enabled=email_enabled(),
        ),
    )


@router.post("/forgot-email", response_class=HTMLResponse)
def forgot_email_post(
    request: Request,
    identifier: str = Form(...),
    db: Session = Depends(get_db),
):
    if not email_enabled():
        return templates.TemplateResponse(
            "forgot_email.html",
            _template_context(
                request,
                None,
                db=db,
                error="Email sending is not configured on this server.",
                success=None,
                email_enabled=False,
            ),
            status_code=400,
        )

    ident = (identifier or "").strip()

    # Find user by username or email. Do not reveal whether an account exists.
    u = get_user_by_username(db, ident) or get_user_by_email(db, ident)

    if u and u.email:
        token = secrets.token_urlsafe(32)
        expires = datetime.utcnow().replace(tzinfo=None) + timedelta(minutes=int(settings.email.reset_token_minutes))
        create_password_reset_token(db, user=u, token=token, expires_at_utc=expires)

        reset_url = f"{_base_url_for_email(request)}/reset-password?token={token}"
        subject, body = build_password_reset_email(username=u.username, reset_url=reset_url)

        try:
            send_email(to_address=u.email, subject=subject, body_text=body)
        except Exception:
            logger.exception("Failed to send password reset email")
            # Intentionally do not reveal SMTP errors to the end-user.

    return templates.TemplateResponse(
        "forgot_email.html",
        _template_context(
            request,
            None,
            db=db,
            error=None,
            success="If the account has an email address on file, a password reset link has been sent.",
            email_enabled=True,
        ),
    )


@router.get("/reset-password", response_class=HTMLResponse)
def reset_password_get(request: Request, token: str | None = None, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if user:
        return _redirect("/dashboard")

    if not token:
        return _redirect("/login")

    tr = get_password_reset_token(db, token=token)
    now = datetime.utcnow().replace(tzinfo=None)

    valid = False
    if tr and tr.used_at_utc is None and tr.expires_at_utc >= now:
        valid = True

    return templates.TemplateResponse(
        "reset_password.html",
        _template_context(
            request,
            None,
            db=db,
            token=token,
            error=None if valid else "This reset link is invalid or has expired.",
            success=None,
            show_form=valid,
        ),
    )


@router.post("/reset-password", response_class=HTMLResponse)
def reset_password_post(
    request: Request,
    token: str = Form(...),
    new_password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _get_current_user(request, db)
    if user:
        return _redirect("/dashboard")

    if len(new_password or "") < 8:
        return templates.TemplateResponse(
            "reset_password.html",
            _template_context(
                request,
                None,
                db=db,
                token=token,
                error="Password must be at least 8 characters.",
                success=None,
                show_form=True,
            ),
            status_code=400,
        )

    ok = consume_password_reset_token(db, token=token, new_password=new_password, now_utc=datetime.utcnow())
    if not ok:
        return templates.TemplateResponse(
            "reset_password.html",
            _template_context(
                request,
                None,
                db=db,
                token=token,
                error="This reset link is invalid or has expired.",
                success=None,
                show_form=False,
            ),
            status_code=400,
        )

    return _redirect("/login?success=reset")


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return _redirect("/login")


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    tag: str | None = None,
    user_id: int | None = None,
    task_type: str | None = None,
    sort: str | None = None,
    db: Session = Depends(get_db),
):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")

    effective_user_id = _effective_user_filter(user, user_id)

    tasks = list_tasks(
        db,
        current_user=user,
        include_archived=False,
        tag=tag,
        user_id=effective_user_id,
        task_type=task_type,
        sort=sort or "due_date",
    )
    now = now_utc()

    # Admin user selector
    users = list_users(db) if user.is_admin else []

    # Task types for filtering
    task_types = _distinct_task_types(
        db,
        current_user=user,
        include_archived=False,
        tag=tag,
        user_id=effective_user_id,
        status=None,
    )

    # Enrich tasks with UI fields
    rows = []
    for t in tasks:
        seconds = (t.due_date_utc - now).total_seconds()
        rows.append(
            {
                "task": t,
                "time_left": humanize_timedelta(seconds),
                "time_left_class": time_left_class(seconds),
            }
        )

    template_name = "dashboard_mobile.html" if _site_mode(request) == "mobile" else "dashboard.html"

    return templates.TemplateResponse(
        template_name,
        _template_context(
            request,
            user,
            db=db,
            tasks=rows,
            tag_filter=tag,
            user_filter=(0 if user.is_admin and user_id == 0 else (effective_user_id if user.is_admin else None)),
            all_users=users,
            task_type_filter=task_type,
            task_types=task_types,
            sort=sort or "due_date",
        ),
    )


@router.get("/archived", response_class=HTMLResponse)
def archived(
    request: Request,
    tag: str | None = None,
    user_id: int | None = None,
    task_type: str | None = None,
    sort: str | None = None,
    db: Session = Depends(get_db),
):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")

    effective_user_id = _effective_user_filter(user, user_id)

    tasks = list_tasks(
        db,
        current_user=user,
        include_archived=True,
        status="archived",
        tag=tag,
        user_id=effective_user_id,
        task_type=task_type,
        sort=sort or "archived_at",
    )

    # Admin user selector
    users = list_users(db) if user.is_admin else []

    task_types = _distinct_task_types(
        db,
        current_user=user,
        include_archived=True,
        tag=tag,
        user_id=effective_user_id,
        status="archived",
    )

    rows = []
    for t in tasks:
        rows.append(
            {
                "task": t,
                "archived_at": t.archived_at_utc(),
            }
        )

    template_name = "archived_mobile.html" if _site_mode(request) == "mobile" else "archived.html"

    return templates.TemplateResponse(
        template_name,
        _template_context(
            request,
            user,
            db=db,
            tasks=rows,
            tag_filter=tag,
            user_filter=(0 if user.is_admin and user_id == 0 else (effective_user_id if user.is_admin else None)),
            all_users=users,
            task_type_filter=task_type,
            task_types=task_types,
            sort=sort or "archived_at",
        ),
    )


@router.get("/tasks/new", response_class=HTMLResponse)
def task_new_get(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")

    ctx = _task_form_context(None)
    return templates.TemplateResponse(
        "task_form.html",
        _template_context(
            request,
            user,
            db=db,
            mode="new",
            error=None,
            **ctx,
        ),
    )


@router.post("/tasks/new", response_class=HTMLResponse)
def task_new_post(
    request: Request,
    name: str = Form(...),
    task_type: str = Form(...),
    due_date: str = Form(""),
    description: str = Form(""),
    url: str = Form(""),
    recurrence_type: str = Form(RecurrenceType.none.value),
    recurrence_interval: str = Form(""),
    recurrence_times: str = Form(""),
    tags: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")

    due_dt: datetime | None = None
    if due_date and str(due_date).strip():
        try:
            due_dt = datetime.fromisoformat(due_date)
        except ValueError:
            ctx = _task_form_context(None)
            ctx.update(
                {
                    "name": name,
                    "task_type": task_type,
                    "description": description,
                    "url": url,
                    "due_date": due_date,
                    "recurrence_type": recurrence_type,
                    "recurrence_interval": recurrence_interval,
                    "recurrence_times": recurrence_times,
                    "tags": tags,
                }
            )
            return templates.TemplateResponse(
                "task_form.html",
                _template_context(
                    request,
                    user,
                    db=db,
                    mode="new",
                    error="Invalid due date format",
                    **ctx,
                ),
                status_code=400,
            )

    try:
        create_task(
            db,
            owner=user,
            name=name,
            task_type=task_type,
            description=description or None,
            url=url or None,
            due_date=due_dt,
            recurrence_type=recurrence_type,
            recurrence_interval=recurrence_interval or None,
            recurrence_times=recurrence_times or None,
            tags=_parse_tags_csv(tags),
        )
    except Exception as e:
        ctx = {
            "task": None,
            "name": name,
            "task_type": task_type,
            "description": description,
            "url": url,
            "due_date": due_date,
            "recurrence_type": recurrence_type,
            "recurrence_interval": recurrence_interval,
            "recurrence_times": recurrence_times,
            "tags": tags,
        }
        return templates.TemplateResponse(
            "task_form.html",
            _template_context(
                request,
                user,
                db=db,
                mode="new",
                error=str(e),
                **ctx,
            ),
            status_code=400,
        )

    return _redirect("/dashboard")


@router.get("/tasks/{task_id}/edit", response_class=HTMLResponse)
def task_edit_get(request: Request, task_id: int, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")

    task = get_task(db, task_id=task_id)
    if not task:
        return _redirect("/dashboard")
    if not user.is_admin and task.user_id != user.id:
        return _redirect("/dashboard")

    ctx = _task_form_context(task)
    return templates.TemplateResponse(
        "task_form.html",
        _template_context(
            request,
            user,
            db=db,
            mode="edit",
            error=None,
            **ctx,
        ),
    )


@router.post("/tasks/{task_id}/edit", response_class=HTMLResponse)
def task_edit_post(
    request: Request,
    task_id: int,
    name: str = Form(...),
    task_type: str = Form(...),
    due_date: str = Form(""),
    description: str = Form(""),
    url: str = Form(""),
    recurrence_type: str = Form(RecurrenceType.none.value),
    recurrence_interval: str = Form(""),
    recurrence_times: str = Form(""),
    tags: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")

    task = get_task(db, task_id=task_id)
    if not task:
        return _redirect("/dashboard")

    due_dt: datetime | None = None
    if due_date and str(due_date).strip():
        try:
            due_dt = datetime.fromisoformat(due_date)
        except ValueError:
            ctx = {
                **_task_form_context(task),
                "name": name,
                "task_type": task_type,
                "description": description,
                "url": url,
                "due_date": due_date,
                "recurrence_type": recurrence_type,
                "recurrence_interval": recurrence_interval,
                "recurrence_times": recurrence_times,
                "tags": tags,
            }
            return templates.TemplateResponse(
                "task_form.html",
                _template_context(
                    request,
                    user,
                    db=db,
                    mode="edit",
                    error="Invalid due date format",
                    **ctx,
                ),
                status_code=400,
            )

    try:
        update_task(
            db,
            task=task,
            current_user=user,
            name=name,
            task_type=task_type,
            description=description or None,
            url=url or None,
            due_date=due_dt,
            recurrence_type=recurrence_type,
            recurrence_interval=recurrence_interval or None,
            recurrence_times=recurrence_times or None,
            tags=_parse_tags_csv(tags),
        )
    except Exception as e:
        ctx = {
            **_task_form_context(task),
            "name": name,
            "task_type": task_type,
            "description": description,
            "url": url,
            "due_date": due_date,
            "recurrence_type": recurrence_type,
            "recurrence_interval": recurrence_interval,
            "recurrence_times": recurrence_times,
            "tags": tags,
        }
        return templates.TemplateResponse(
            "task_form.html",
            _template_context(
                request,
                user,
                db=db,
                mode="edit",
                error=str(e),
                **ctx,
            ),
            status_code=400,
        )

    return _redirect("/dashboard")


@router.post("/tasks/{task_id}/complete")
def task_complete(request: Request, task_id: int, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")

    task = get_task(db, task_id=task_id)
    if not task:
        return _redirect("/dashboard")

    when = now_utc()
    try:
        complete_task(db, task=task, current_user=user, when_utc=when)
    except Exception:
        logger.exception("Failed to complete task %s", task_id)

    return _redirect("/dashboard")


@router.post("/tasks/{task_id}/delete")
def task_delete(request: Request, task_id: int, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")

    task = get_task(db, task_id=task_id)
    if not task:
        return _redirect("/dashboard")

    when = now_utc()
    try:
        soft_delete_task(db, task=task, current_user=user, when_utc=when)
    except Exception:
        logger.exception("Failed to delete task %s", task_id)

    return _redirect("/dashboard")


@router.post("/tasks/{task_id}/restore")
def task_restore(request: Request, task_id: int, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")

    task = get_task(db, task_id=task_id)
    if not task:
        return _redirect("/archived")

    try:
        restore_task(db, task=task, current_user=user)
    except Exception:
        logger.exception("Failed to restore task %s", task_id)

    return _redirect("/archived")


@router.get("/profile", response_class=HTMLResponse)
def profile_get(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")

    return templates.TemplateResponse(
        "profile.html",
        _template_context(
            request,
            user,
            db=db,
            error=None,
            success=None,
        ),
    )


@router.post("/profile", response_class=HTMLResponse)
def profile_post(
    request: Request,
    theme: str = Form(Theme.system.value),
    purge_days: int = Form(...),
    email: str = Form(""),
    current_password: str = Form(""),
    new_password: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")

    try:
        update_user_me(
            db,
            user=user,
            theme=theme,
            purge_days=int(purge_days),
            email=email,
            current_password=current_password or None,
            new_password=new_password or None,
        )
        db.refresh(user)
        return templates.TemplateResponse(
            "profile.html",
            _template_context(
                request,
                user,
                db=db,
                error=None,
                success="Saved",
            ),
        )
    except Exception as e:
        return templates.TemplateResponse(
            "profile.html",
            _template_context(
                request,
                user,
                db=db,
                error=str(e),
                success=None,
            ),
            status_code=400,
        )


@router.get("/admin/users", response_class=HTMLResponse)
def admin_users_get(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")
    if not user.is_admin:
        return _redirect("/dashboard")

    users = list_users(db)
    return templates.TemplateResponse(
        "user_admin.html",
        _template_context(
            request,
            user,
            db=db,
            users=users,
            error=None,
        ),
    )


@router.post("/admin/users/create", response_class=HTMLResponse)
def admin_users_create(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    email: str = Form(""),
    is_admin: bool = Form(False),
    db: Session = Depends(get_db),
):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")
    if not user.is_admin:
        return _redirect("/dashboard")

    if get_user_by_username(db, username):
        users = list_users(db)
        return templates.TemplateResponse(
            "user_admin.html",
            _template_context(
                request,
                user,
                db=db,
                users=users,
                error="Username already exists",
            ),
            status_code=400,
        )

    try:
        create_user(db, username=username, password=password, is_admin=bool(is_admin), email=email or None)
    except Exception as e:
        users = list_users(db)
        return templates.TemplateResponse(
            "user_admin.html",
            _template_context(
                request,
                user,
                db=db,
                users=users,
                error=str(e),
            ),
            status_code=400,
        )

    return _redirect("/admin/users")


@router.post("/admin/users/{user_id}/toggle-admin")
def admin_users_toggle_admin(request: Request, user_id: int, db: Session = Depends(get_db)):
    admin = _get_current_user(request, db)
    if not admin:
        return _redirect("/login")
    if not admin.is_admin:
        return _redirect("/dashboard")

    if admin.id == user_id:
        return _redirect("/admin/users")

    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        return _redirect("/admin/users")

    try:
        update_user_admin(db, user_id=user_id, is_admin=(not bool(target.is_admin)))
    except Exception:
        logger.exception("Failed to toggle admin for user %s", user_id)

    return _redirect("/admin/users")


@router.post("/admin/users/{user_id}/delete")
def admin_users_delete(request: Request, user_id: int, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")
    if not user.is_admin:
        return _redirect("/dashboard")

    if user.id == user_id:
        return _redirect("/admin/users")

    delete_user(db, user_id=user_id)
    return _redirect("/admin/users")


@router.get("/admin/database", response_class=HTMLResponse)
def admin_database_get(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")
    if not user.is_admin:
        return _redirect("/dashboard")

    return templates.TemplateResponse(
        "db_admin.html",
        _template_context(
            request,
            user,
            db=db,
            error=None,
            success=None,
        ),
    )


@router.get("/admin/database/export")
def admin_database_export(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")
    if not user.is_admin:
        return _redirect("/dashboard")

    data = export_db_json(db)
    return JSONResponse(
        content=data,
        headers={"Content-Disposition": "attachment; filename=timeboard-export.json"},
    )


@router.post("/admin/database/import", response_class=HTMLResponse)
def admin_database_import(request: Request, file: UploadFile, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")
    if not user.is_admin:
        return _redirect("/dashboard")

    # Always create a pre-import backup on any import attempt.
    backup_note: list[str] = []
    try:
        bdb = SessionLocal()
        try:
            backup_path = backup_database_json(bdb, prefix="IMPORT")
            backup_note.append(f"Pre-import backup created: {backup_path.name}")
        finally:
            bdb.close()
    except Exception:
        logger.exception("Failed to create pre-import IMPORT backup")

    # Parse uploaded JSON.
    try:
        raw = file.file.read()
        payload = json.loads(raw.decode("utf-8"))
    except Exception as e:
        # Ensure the session is usable for template rendering.
        try:
            db.rollback()
        except Exception:
            pass
        return templates.TemplateResponse(
            "db_admin.html",
            _template_context(
                request,
                user,
                db=db,
                errors=[f"Invalid JSON file: {e}"],
                warnings=backup_note,
                error=None,
                success=None,
            ),
            status_code=400,
        )

    errors, warnings = validate_import_payload(payload)
    warnings_all = backup_note + list(warnings or [])

    if errors:
        return templates.TemplateResponse(
            "db_admin.html",
            _template_context(
                request,
                user,
                db=db,
                errors=errors,
                warnings=warnings_all,
                error=None,
                success=None,
            ),
            status_code=400,
        )

    try:
        import_db_json(db, payload, replace=True)
    except Exception as e:
        # Reset the session transaction so the UI can continue to function.
        try:
            db.rollback()
        except Exception:
            pass
        return templates.TemplateResponse(
            "db_admin.html",
            _template_context(
                request,
                user,
                db=db,
                errors=[f"Import failed: {e}"],
                warnings=warnings_all,
                error=None,
                success=None,
            ),
            status_code=400,
        )

    # Import replaces the database; clear the session to avoid user-id drift.
    try:
        request.session.clear()
    except Exception:
        pass

    return _redirect("/login?success=import")


@router.get("/help", response_class=HTMLResponse)
def help_page(request: Request, db: Session = Depends(get_db)):
    """Render the in-app help page.

    The help page is accessible without authentication so operators can read
    setup and troubleshooting guidance even before logging in.
    """
    user = _get_current_user(request, db)
    return templates.TemplateResponse(
        "help.html",
        _template_context(
            request,
            user,
            db=db,
        ),
    )
