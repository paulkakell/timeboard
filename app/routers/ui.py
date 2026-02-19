from __future__ import annotations

import json
import logging
import secrets
from urllib.parse import urlencode
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
    count_tasks,
    create_password_reset_token,
    create_task,
    create_user,
    delete_user,
    get_password_reset_token,
    get_task,
    get_user,
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
from ..db_admin import (
    AUTO_BACKUP_FREQUENCIES,
    backup_database_json,
    build_user_export_filename,
    export_db_json,
    get_auto_backup_settings,
    import_db_json,
    set_auto_backup_settings,
    validate_import_payload,
)
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
    page: int | None = 1,
    page_size: int | None = 25,
    db: Session = Depends(get_db),
):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")

    effective_user_id = _effective_user_filter(user, user_id)

    # Pagination (dashboard only)
    allowed_page_sizes = [25, 50, 100, 200]
    try:
        ps = int(page_size or 25)
    except Exception:
        ps = 25
    if ps not in allowed_page_sizes:
        ps = 25

    try:
        pnum = int(page or 1)
    except Exception:
        pnum = 1
    if pnum < 1:
        pnum = 1

    total_count = count_tasks(
        db,
        current_user=user,
        include_archived=False,
        tag=tag,
        user_id=effective_user_id,
        task_type=task_type,
        status=None,
    )

    total_pages = max(1, (total_count + ps - 1) // ps) if total_count else 1
    if pnum > total_pages:
        pnum = total_pages

    offset = (pnum - 1) * ps

    tasks = list_tasks(
        db,
        current_user=user,
        include_archived=False,
        tag=tag,
        user_id=effective_user_id,
        task_type=task_type,
        sort=sort or "due_date",
        limit=ps,
        offset=offset,
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

    # Pagination URLs (preserve current filters)
    base_params: dict[str, str] = {}
    if tag:
        base_params["tag"] = str(tag)
    if task_type:
        base_params["task_type"] = str(task_type)
    if sort:
        base_params["sort"] = str(sort)
    # Always include page_size once pagination is enabled.
    base_params["page_size"] = str(ps)

    if user.is_admin:
        # Preserve the original admin view selection.
        if user_id is None:
            base_params["user_id"] = str(user.id)
        else:
            base_params["user_id"] = str(user_id)

    def _make_url(page_num: int) -> str:
        params = dict(base_params)
        params["page"] = str(int(page_num))
        return f"/dashboard?{urlencode(params)}"

    page_start = 0
    page_end = 0
    if total_count:
        page_start = offset + 1
        page_end = min(total_count, offset + len(tasks))

    def _page_items(current: int, total: int, window: int = 2) -> list[int | None]:
        if total <= 1:
            return []
        pages = {1, total}
        for i in range(current - window, current + window + 1):
            if 1 <= i <= total:
                pages.add(i)
        ordered = sorted(pages)
        items: list[int | None] = []
        last = 0
        for n in ordered:
            if last and n - last > 1:
                items.append(None)
            items.append(n)
            last = n
        return items

    page_links = []
    for item in _page_items(pnum, total_pages):
        if item is None:
            page_links.append({"ellipsis": True})
        else:
            page_links.append({"page": int(item), "url": _make_url(int(item)), "current": int(item) == pnum})

    prev_url = _make_url(pnum - 1) if pnum > 1 else None
    next_url = _make_url(pnum + 1) if pnum < total_pages else None

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
            page=pnum,
            page_size=ps,
            page_size_options=allowed_page_sizes,
            total_count=total_count,
            total_pages=total_pages,
            page_start=page_start,
            page_end=page_end,
            page_links=page_links,
            prev_url=prev_url,
            next_url=next_url,
        ),
    )


@router.get("/calendar", response_class=HTMLResponse)
def calendar_view(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")

    # Calendar always shows tasks for the currently-logged-in user.
    effective_user_id = int(user.id) if user.is_admin else None

    tasks = list_tasks(
        db,
        current_user=user,
        include_archived=True,
        user_id=effective_user_id,
        sort="due_date",
    )

    now = now_utc()
    color_map = {
        "tl-past": {"bg": "#ff0000", "text": "#ffff00"},
        "tl-0-8": {"bg": "#ffa500", "text": "#000000"},
        "tl-8-24": {"bg": "#ffff00", "text": "#000000"},
        "tl-24p": {"bg": "#00ff00", "text": "#000000"},
    }

    events = []
    for t in tasks:
        seconds = (t.due_date_utc - now).total_seconds()
        cls = time_left_class(seconds)

        # Color coding:
        # - Active: based on time-left buckets (consistent with dashboard).
        # - Completed/Deleted: fixed colors.
        if t.status == TaskStatus.completed:
            colors = {"bg": "#6c757d", "text": "#ffffff"}
        elif t.status == TaskStatus.deleted:
            colors = {"bg": "#343a40", "text": "#ffffff"}
        else:
            colors = color_map.get(cls, {"bg": "#0d6efd", "text": "#ffffff"})

        start_local = to_local(t.due_date_utc)
        end_local = start_local + timedelta(minutes=30)

        events.append(
            {
                "id": int(t.id),
                "title": t.name,
                "start": start_local.isoformat(),
                "end": end_local.isoformat(),
                "url": f"/tasks/{int(t.id)}/edit",
                "backgroundColor": colors["bg"],
                "borderColor": colors["bg"],
                "textColor": colors["text"],
                "extendedProps": {
                    "task_type": t.task_type,
                    "status": str(t.status.value if hasattr(t.status, 'value') else t.status),
                    "due_display": start_local.strftime("%Y-%m-%d %H:%M"),
                    "time_left": humanize_timedelta(seconds),
                    "time_left_class": cls,
                },
            }
        )

    # Safer embedding into <script> blocks.
    events_json = json.dumps(events).replace("</", "<\\/")

    return templates.TemplateResponse(
        "calendar.html",
        _template_context(
            request,
            user,
            db=db,
            events_json=events_json,
            app_timezone=settings.app.timezone,
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
    username: str = Form(...),
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
            username=username,
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


@router.get("/admin/users/{user_id}/edit", response_class=HTMLResponse)
def admin_users_edit_get(request: Request, user_id: int, db: Session = Depends(get_db)):
    admin = _get_current_user(request, db)
    if not admin:
        return _redirect("/login")
    if not admin.is_admin:
        return _redirect("/dashboard")

    target = get_user(db, user_id=user_id)
    if not target:
        return _redirect("/admin/users")

    return templates.TemplateResponse(
        "user_edit.html",
        _template_context(
            request,
            admin,
            db=db,
            target=target,
            error=None,
            success=None,
        ),
    )


@router.post("/admin/users/{user_id}/edit", response_class=HTMLResponse)
def admin_users_edit_post(
    request: Request,
    user_id: int,
    username: str = Form(...),
    email: str = Form(""),
    is_admin: bool = Form(False),
    theme: str = Form(Theme.system.value),
    purge_days: int = Form(...),
    new_password: str = Form(""),
    db: Session = Depends(get_db),
):
    admin = _get_current_user(request, db)
    if not admin:
        return _redirect("/login")
    if not admin.is_admin:
        return _redirect("/dashboard")

    target = get_user(db, user_id=user_id)
    if not target:
        return _redirect("/admin/users")

    if admin.id == user_id and not bool(is_admin):
        return templates.TemplateResponse(
            "user_edit.html",
            _template_context(
                request,
                admin,
                db=db,
                target=target,
                error="Cannot remove admin from the currently authenticated user",
                success=None,
            ),
            status_code=400,
        )

    try:
        update_user_admin(
            db,
            user_id=user_id,
            username=username,
            email=email,
            is_admin=bool(is_admin),
            theme=theme,
            purge_days=int(purge_days),
            new_password=(new_password or None),
        )
        db.refresh(target)
        return templates.TemplateResponse(
            "user_edit.html",
            _template_context(
                request,
                admin,
                db=db,
                target=target,
                error=None,
                success="Saved",
            ),
        )
    except Exception as e:
        return templates.TemplateResponse(
            "user_edit.html",
            _template_context(
                request,
                admin,
                db=db,
                target={
                    "id": target.id,
                    "username": username,
                    "email": email,
                    "is_admin": bool(is_admin),
                    "theme": theme,
                    "purge_days": purge_days,
                },
                error=str(e),
                success=None,
            ),
            status_code=400,
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

    cfg = get_auto_backup_settings(db)
    freq_options = [
        ("daily", "Daily"),
        ("weekly", "Weekly"),
        ("12h", "Every 12 hours"),
        ("6h", "Every 6 hours"),
        ("hourly", "Hourly"),
        ("disabled", "Disabled"),
    ]

    # Basic backup directory stats (best-effort).
    backup_dir = Path("/data/backups")
    backup_count = 0
    latest_backup = None
    try:
        if backup_dir.exists() and backup_dir.is_dir():
            files = [p for p in backup_dir.glob("*.json") if p.is_file() and not p.name.startswith(".")]
            backup_count = len(files)
            if files:
                newest = max(files, key=lambda p: p.stat().st_mtime)
                latest_backup = {
                    "name": newest.name,
                    "mtime_utc": datetime.utcfromtimestamp(newest.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S UTC"),
                }
    except Exception:
        backup_count = 0
        latest_backup = None

    return templates.TemplateResponse(
        "db_admin.html",
        _template_context(
            request,
            user,
            db=db,
            error=None,
            success=None,
            auto_backup_frequency=str(cfg.get("frequency") or "daily"),
            auto_backup_retention_days=int(cfg.get("retention_days") or 0),
            auto_backup_frequency_options=freq_options,
            backup_dir=str(backup_dir),
            backup_count=backup_count,
            latest_backup=latest_backup,
        ),
    )


@router.post("/admin/database/auto-backups", response_class=HTMLResponse)
def admin_database_auto_backups_post(
    request: Request,
    frequency: str = Form("daily"),
    retention_days: str = Form("0"),
    db: Session = Depends(get_db),
):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")
    if not user.is_admin:
        return _redirect("/dashboard")

    # Apply and persist settings.
    err = None
    ok = None
    try:
        rd = int(retention_days)
        set_auto_backup_settings(db, frequency=str(frequency), retention_days=rd)
        ok = "Automatic backup settings saved."

        # Reconfigure scheduler in-process (if available).
        cfg_fn = getattr(request.app.state, "configure_auto_backup_jobs", None)
        if callable(cfg_fn):
            try:
                cfg_fn()
            except Exception:
                logger.exception("Failed to reconfigure scheduler after backup settings change")
                ok = "Automatic backup settings saved (scheduler update failed; restart may be required)."
    except Exception as e:
        err = str(e)

    cfg = get_auto_backup_settings(db)
    freq_options = [
        ("daily", "Daily"),
        ("weekly", "Weekly"),
        ("12h", "Every 12 hours"),
        ("6h", "Every 6 hours"),
        ("hourly", "Hourly"),
        ("disabled", "Disabled"),
    ]

    backup_dir = Path("/data/backups")
    backup_count = 0
    latest_backup = None
    try:
        if backup_dir.exists() and backup_dir.is_dir():
            files = [p for p in backup_dir.glob("*.json") if p.is_file() and not p.name.startswith(".")]
            backup_count = len(files)
            if files:
                newest = max(files, key=lambda p: p.stat().st_mtime)
                latest_backup = {
                    "name": newest.name,
                    "mtime_utc": datetime.utcfromtimestamp(newest.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S UTC"),
                }
    except Exception:
        backup_count = 0
        latest_backup = None

    return templates.TemplateResponse(
        "db_admin.html",
        _template_context(
            request,
            user,
            db=db,
            error=err,
            success=ok,
            auto_backup_frequency=str(cfg.get("frequency") or "daily"),
            auto_backup_retention_days=int(cfg.get("retention_days") or 0),
            auto_backup_frequency_options=freq_options,
            backup_dir=str(backup_dir),
            backup_count=backup_count,
            latest_backup=latest_backup,
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

    report = getattr(request.app.state, "db_migration_report", None)
    db_version = getattr(report, "current_db_version", None) or APP_VERSION
    filename = build_user_export_filename(app_version=APP_VERSION, db_version=str(db_version))

    return JSONResponse(
        content=data,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.post("/admin/database/import", response_class=HTMLResponse)
def admin_database_import(request: Request, file: UploadFile, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")
    if not user.is_admin:
        return _redirect("/dashboard")

    cfg = get_auto_backup_settings(db)
    freq_options = [
        ("daily", "Daily"),
        ("weekly", "Weekly"),
        ("12h", "Every 12 hours"),
        ("6h", "Every 6 hours"),
        ("hourly", "Hourly"),
        ("disabled", "Disabled"),
    ]

    backup_dir = Path("/data/backups")
    backup_count = 0
    latest_backup = None
    try:
        if backup_dir.exists() and backup_dir.is_dir():
            files = [p for p in backup_dir.glob("*.json") if p.is_file() and not p.name.startswith(".")]
            backup_count = len(files)
            if files:
                newest = max(files, key=lambda p: p.stat().st_mtime)
                latest_backup = {
                    "name": newest.name,
                    "mtime_utc": datetime.utcfromtimestamp(newest.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S UTC"),
                }
    except Exception:
        backup_count = 0
        latest_backup = None

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
                auto_backup_frequency=str(cfg.get("frequency") or "daily"),
                auto_backup_retention_days=int(cfg.get("retention_days") or 0),
                auto_backup_frequency_options=freq_options,
                backup_dir=str(backup_dir),
                backup_count=backup_count,
                latest_backup=latest_backup,
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
                auto_backup_frequency=str(cfg.get("frequency") or "daily"),
                auto_backup_retention_days=int(cfg.get("retention_days") or 0),
                auto_backup_frequency_options=freq_options,
                backup_dir=str(backup_dir),
                backup_count=backup_count,
                latest_backup=latest_backup,
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
                auto_backup_frequency=str(cfg.get("frequency") or "daily"),
                auto_backup_retention_days=int(cfg.get("retention_days") or 0),
                auto_backup_frequency_options=freq_options,
                backup_dir=str(backup_dir),
                backup_count=backup_count,
                latest_backup=latest_backup,
            ),
            status_code=400,
        )

    # Reconfigure scheduler jobs based on newly-imported settings.
    cfg_fn = getattr(request.app.state, "configure_auto_backup_jobs", None)
    if callable(cfg_fn):
        try:
            cfg_fn()
        except Exception:
            logger.exception("Failed to reconfigure scheduler after import")

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
