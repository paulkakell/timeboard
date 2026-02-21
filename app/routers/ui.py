from __future__ import annotations

import asyncio
import json
import logging
import secrets
from urllib.parse import urlencode
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
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
    list_tags_for_user,
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
from ..logging_setup import list_log_files
from ..meta_settings import (
    get_email_settings,
    get_logging_settings,
    get_wns_settings,
    set_email_settings,
    set_logging_settings,
    set_wns_settings,
)
from ..models import (
    NotificationEvent,
    RecurrenceType,
    Task,
    TaskStatus,
    Theme,
    User,
    UserNotificationChannel,
)
from ..notifications import (
    CHANNEL_BROWSER,
    CHANNEL_DISCORD,
    CHANNEL_EMAIL,
    CHANNEL_GENERIC_API,
    CHANNEL_GOTIFY,
    CHANNEL_NTFY,
    CHANNEL_TYPES,
    CHANNEL_WEBHOOK,
    CHANNEL_WNS,
    create_user_notification_service,
    delete_user_notification_service,
    list_user_notification_services,
    update_user_notification_service,
    user_has_enabled_browser_service,
)
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


# Session key for remembering dashboard filter state.
DASHBOARD_FILTERS_SESSION_KEY = "dashboard_filters"


def _merge_stateful_dashboard_filters(
    *,
    query_params,
    existing_state: dict | None,
    is_admin: bool,
    current_user_id: int,
) -> tuple[dict, dict]:
    """Merge dashboard filters from query params with a prior session state.

    Goal: dashboard filters stay "sticky" across navigation until explicitly
    reset.

    Rules:
      - If a filter appears in query_params, it overwrites the stored value.
      - Missing filters fall back to stored values.
      - Blank strings clear a filter.
      - Page number is intentionally not stored.
    """

    state: dict = dict(existing_state or {}) if isinstance(existing_state, dict) else {}

    def _has(name: str) -> bool:
        try:
            return name in query_params
        except Exception:
            return False

    def _get(name: str) -> str:
        try:
            return str(query_params.get(name) or "")
        except Exception:
            return ""

    def _norm_str(v: str) -> str | None:
        s = str(v or "").strip()
        return s if s else None

    # Tag
    if _has("tag"):
        state["tag"] = _norm_str(_get("tag"))

    # Task type
    if _has("task_type"):
        state["task_type"] = _norm_str(_get("task_type"))

    # Sort
    if _has("sort"):
        # Blank sort resets to default.
        state["sort"] = _norm_str(_get("sort"))

    # Page size
    if _has("page_size"):
        raw = _get("page_size")
        try:
            state["page_size"] = int(raw)
        except Exception:
            # Ignore bad values; keep existing/default.
            pass

    # Admin view selector (user_id)
    if is_admin and _has("user_id"):
        raw = _get("user_id")
        try:
            state["user_id"] = int(raw)
        except Exception:
            # Ignore bad values; keep existing/default.
            pass

    # Defaults
    tag = state.get("tag")
    task_type = state.get("task_type")
    sort = state.get("sort") or "due_date"

    try:
        ps = int(state.get("page_size") or 10)
    except Exception:
        ps = 10

    # Keep page size bounded to expected values.
    allowed_page_sizes = {10, 25, 50, 100, 200}
    if ps not in allowed_page_sizes:
        ps = 10

    selected_user_id: int | None = None
    if is_admin:
        try:
            selected_user_id = int(state.get("user_id")) if state.get("user_id") is not None else None
        except Exception:
            selected_user_id = None
        if selected_user_id is None:
            selected_user_id = int(current_user_id)

    # Normalize what we persist back into the session.
    new_state = {
        "tag": tag,
        "task_type": task_type,
        "sort": sort,
        "page_size": ps,
    }
    if is_admin:
        new_state["user_id"] = int(selected_user_id) if selected_user_id is not None else int(current_user_id)

    effective = {
        "tag": tag,
        "task_type": task_type,
        "sort": sort,
        "page_size": ps,
        "user_id": selected_user_id,
    }
    return effective, new_state



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

    # Database migration notice: show the applied steps only once (after a real
    # upgrade) so the dismissible alert in base.html doesn't reappear on every
    # page.
    applied_steps: list[str] = []
    try:
        applied_steps = list(getattr(report, "applied_steps", []) or [])
    except Exception:
        applied_steps = []

    # Only clear the global report after an admin has had a chance to see it.
    if user and getattr(user, "is_admin", False) and applied_steps:
        try:
            report.applied_steps = []
        except Exception:
            pass

    # Provide user list for admin navigation dropdowns when a DB session is available.
    if user and getattr(user, "is_admin", False) and "nav_users" not in extra and db is not None:
        try:
            extra["nav_users"] = list_users(db)
        except Exception:
            extra["nav_users"] = []

    # Browser notifications enabled (used by base template JS).
    if user and "browser_notifications_enabled" not in extra and db is not None:
        try:
            # New service-based browser notifications.
            enabled = user_has_enabled_browser_service(db, user_id=int(user.id))
            if not enabled:
                # Legacy fallback (pre-service model).
                legacy = (
                    db.query(UserNotificationChannel)
                    .filter(UserNotificationChannel.user_id == int(user.id))
                    .filter(UserNotificationChannel.channel_type == CHANNEL_BROWSER)
                    .filter(UserNotificationChannel.enabled.is_(True))
                    .first()
                )
                enabled = bool(legacy)
            extra["browser_notifications_enabled"] = bool(enabled)
        except Exception:
            extra["browser_notifications_enabled"] = False

    return {
        "request": request,
        "current_user": user,
        "app_name": settings.app.name,
        "site_mode": _site_mode(request),
        "db_version": getattr(report, "current_db_version", None),
        "db_previous_version": getattr(report, "previous_db_version", None),
        "db_upgrade_steps": applied_steps,
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
            email_enabled=email_enabled(db),
        ),
    )


@router.post("/forgot-email", response_class=HTMLResponse)
def forgot_email_post(
    request: Request,
    identifier: str = Form(...),
    db: Session = Depends(get_db),
):
    if not email_enabled(db):
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
        cfg = get_email_settings(db)
        expires = datetime.utcnow().replace(tzinfo=None) + timedelta(minutes=int(cfg.reset_token_minutes))
        create_password_reset_token(db, user=u, token=token, expires_at_utc=expires)

        reset_url = f"{_base_url_for_email(request)}/reset-password?token={token}"
        subject, body = build_password_reset_email(username=u.username, reset_url=reset_url)

        try:
            send_email(to_address=u.email, subject=subject, body_text=body, db=db)
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
    reset: int | None = None,
    page: int | None = 1,
    page_size: int | None = 10,
    db: Session = Depends(get_db),
):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")

    # Stateful dashboard filters: if no query params are provided, fall back to
    # the last-used filter state stored in the session. Explicit reset clears.
    if reset:
        request.session.pop(DASHBOARD_FILTERS_SESSION_KEY, None)

    effective_filters, new_state = _merge_stateful_dashboard_filters(
        query_params=request.query_params,
        existing_state=request.session.get(DASHBOARD_FILTERS_SESSION_KEY),
        is_admin=bool(user.is_admin),
        current_user_id=int(user.id),
    )
    request.session[DASHBOARD_FILTERS_SESSION_KEY] = new_state

    tag = effective_filters.get("tag")
    task_type = effective_filters.get("task_type")
    sort = effective_filters.get("sort")
    page_size = effective_filters.get("page_size")
    # Admin view selector (0 = all tasks); non-admin ignores.
    user_id = effective_filters.get("user_id") if user.is_admin else None

    effective_user_id = _effective_user_filter(user, user_id)

    # Pagination (dashboard only)
    allowed_page_sizes = [10, 25, 50, 100, 200]
    try:
        ps = int(page_size or 10)
    except Exception:
        ps = 10
    if ps not in allowed_page_sizes:
        ps = 10

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


@router.get("/profile/notifications", response_class=HTMLResponse)
def profile_notifications_get(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")

    services = list_user_notification_services(db, user_id=int(user.id))
    for svc in services:
        try:
            cfg = json.loads(svc.config_json) if svc.config_json else {}
            if not isinstance(cfg, dict):
                cfg = {}
        except Exception:
            cfg = {}
        # attach convenience attribute for Jinja
        setattr(svc, "cfg", cfg)
        if svc.service_type == CHANNEL_GENERIC_API and isinstance(cfg.get("headers"), dict):
            setattr(svc, "headers_pretty", json.dumps(cfg.get("headers"), indent=2))
        else:
            setattr(svc, "headers_pretty", "")

    wns_admin = get_wns_settings(db)

    return templates.TemplateResponse(
        "profile_notifications.html",
        _template_context(
            request,
            user,
            db=db,
            error=None,
            success=None,
            services=services,
            wns_admin_enabled=bool(wns_admin.enabled),
        ),
    )


@router.post("/profile/notifications", response_class=HTMLResponse)
async def profile_notifications_post(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")

    form = await request.form()
    action = str(form.get("action") or "").strip().lower()

    def _build_cfg(service_type: str, existing: dict | None) -> dict:
        st = str(service_type or "").strip().lower()
        cfg = dict(existing or {})

        # Browser: no config
        if st == CHANNEL_BROWSER:
            return {}

        if st == CHANNEL_EMAIL:
            to_addr = str(form.get("email_to_address") or "").strip()
            if to_addr:
                cfg["to_address"] = to_addr
            elif existing is None:
                cfg.pop("to_address", None)
            return cfg

        if st == CHANNEL_GOTIFY:
            base_url = str(form.get("gotify_base_url") or "").strip()
            token = str(form.get("gotify_token") or "")
            priority = str(form.get("gotify_priority") or cfg.get("priority") or "5").strip()
            if base_url:
                cfg["base_url"] = base_url
            if token.strip():
                cfg["token"] = token.strip()
            cfg["priority"] = priority
            return cfg

        if st == CHANNEL_NTFY:
            server_url = str(form.get("ntfy_server_url") or "").strip()
            topic = str(form.get("ntfy_topic") or "").strip()
            token = str(form.get("ntfy_token") or "")
            priority = str(form.get("ntfy_priority") or cfg.get("priority") or "").strip()
            if server_url:
                cfg["server_url"] = server_url
            if topic:
                cfg["topic"] = topic
            if token.strip():
                cfg["token"] = token.strip()
            if priority:
                cfg["priority"] = priority
            return cfg

        if st == CHANNEL_DISCORD:
            webhook_url = str(form.get("discord_webhook_url") or "")
            if webhook_url.strip():
                cfg["webhook_url"] = webhook_url.strip()
            return cfg

        if st == CHANNEL_WEBHOOK:
            url = str(form.get("webhook_url") or "").strip()
            secret = str(form.get("webhook_secret") or "")
            if url:
                cfg["url"] = url
            if secret.strip():
                cfg["secret"] = secret.strip()
            return cfg

        if st == CHANNEL_GENERIC_API:
            url = str(form.get("generic_api_url") or "").strip()
            method = str(form.get("generic_api_method") or cfg.get("method") or "POST").strip().upper()
            token = str(form.get("generic_api_token") or "")
            headers_raw = str(form.get("generic_api_headers") or "").strip()
            if url:
                cfg["url"] = url
            cfg["method"] = method
            if token.strip():
                cfg["token"] = token.strip()
            if headers_raw:
                try:
                    hdrs = json.loads(headers_raw)
                    if isinstance(hdrs, dict):
                        cfg["headers"] = hdrs
                except Exception:
                    pass
            return cfg

        if st == CHANNEL_WNS:
            channel_uri = str(form.get("wns_channel_uri") or "")
            if channel_uri.strip():
                cfg["channel_uri"] = channel_uri.strip()
            return cfg

        return cfg

    error: str | None = None
    success: str | None = None

    try:
        if action == "create":
            service_type = str(form.get("service_type") or "").strip().lower()
            name = str(form.get("name") or "").strip() or None
            enabled = form.get("enabled") == "on"
            cfg = _build_cfg(service_type, None)
            create_user_notification_service(
                db,
                user_id=int(user.id),
                service_type=service_type,
                name=name,
                enabled=enabled,
                config=cfg,
            )
            success = "Service added"
        elif action == "update":
            service_id = int(form.get("service_id") or "0")
            svc = (
                db.query(UserNotificationService)
                .filter(UserNotificationService.id == int(service_id))
                .filter(UserNotificationService.user_id == int(user.id))
                .first()
            )
            if not svc:
                raise ValueError("Service not found")
            try:
                existing_cfg = json.loads(svc.config_json) if svc.config_json else {}
                if not isinstance(existing_cfg, dict):
                    existing_cfg = {}
            except Exception:
                existing_cfg = {}
            name = str(form.get("name") or "").strip() or None
            enabled = form.get("enabled") == "on"
            cfg = _build_cfg(str(svc.service_type), existing_cfg)
            update_user_notification_service(
                db,
                user_id=int(user.id),
                service_id=int(service_id),
                name=name,
                enabled=enabled,
                config=cfg,
            )
            success = "Saved"
        elif action == "delete":
            service_id = int(form.get("service_id") or "0")
            ok = delete_user_notification_service(db, user_id=int(user.id), service_id=int(service_id))
            success = "Deleted" if ok else "Not found"
        else:
            raise ValueError("Unknown action")
    except Exception as e:
        error = str(e)

    services = list_user_notification_services(db, user_id=int(user.id))
    for svc in services:
        try:
            cfg = json.loads(svc.config_json) if svc.config_json else {}
            if not isinstance(cfg, dict):
                cfg = {}
        except Exception:
            cfg = {}
        setattr(svc, "cfg", cfg)
        if svc.service_type == CHANNEL_GENERIC_API and isinstance(cfg.get("headers"), dict):
            setattr(svc, "headers_pretty", json.dumps(cfg.get("headers"), indent=2))
        else:
            setattr(svc, "headers_pretty", "")

    wns_admin = get_wns_settings(db)

    return templates.TemplateResponse(
        "profile_notifications.html",
        _template_context(
            request,
            user,
            db=db,
            error=error,
            success=success,
            services=services,
            wns_admin_enabled=bool(wns_admin.enabled),
        ),
    )

@router.get("/notifications/stream")
async def notifications_stream(request: Request):
    """Server-Sent Events stream for browser notifications.

    This is intentionally session-cookie based (UI), not JWT.
    """
    uid = request.session.get("user_id")
    try:
        user_id = int(uid)
    except Exception:
        return JSONResponse({"error": "not_authenticated"}, status_code=401)

    # Verify browser notifications are enabled for this user.
    last_id = 0
    db0 = SessionLocal()
    try:
        enabled = (
            db0.query(UserNotificationService.id)
            .filter(UserNotificationService.user_id == int(user_id))
            .filter(UserNotificationService.service_type == CHANNEL_BROWSER)
            .filter(UserNotificationService.enabled.is_(True))
            .first()
        )
        if not enabled:
            # Legacy fallback (pre-service model).
            enabled = (
                db0.query(UserNotificationChannel.id)
                .filter(UserNotificationChannel.user_id == int(user_id))
                .filter(UserNotificationChannel.channel_type == CHANNEL_BROWSER)
                .filter(UserNotificationChannel.enabled.is_(True))
                .first()
            )
        if not enabled:
            return JSONResponse({"error": "browser_notifications_disabled"}, status_code=404)

        # If the client didn't provide Last-Event-ID, start from the current max
        # so we don't spam old notifications.
        hdr_last = request.headers.get("last-event-id")
        if hdr_last:
            try:
                last_id = int(hdr_last)
            except Exception:
                last_id = 0
        else:
            max_id = (
                db0.query(func.max(NotificationEvent.id))
                .filter(NotificationEvent.user_id == int(user_id))
                .filter(NotificationEvent.service_type == CHANNEL_BROWSER)
                .scalar()
            )
            last_id = int(max_id or 0)
    finally:
        db0.close()

    async def event_generator():
        nonlocal last_id
        while True:
            if await request.is_disconnected():
                break

            dbx = SessionLocal()
            try:
                rows = (
                    dbx.query(NotificationEvent)
                    .filter(NotificationEvent.user_id == int(user_id))
                    .filter(NotificationEvent.service_type == CHANNEL_BROWSER)
                    .filter(NotificationEvent.id > int(last_id))
                    .order_by(NotificationEvent.id.asc())
                    .limit(25)
                    .all()
                )

                for ev in rows:
                    last_id = max(int(last_id), int(ev.id))
                    payload = {
                        "id": int(ev.id),
                        "event_type": ev.event_type,
                        "title": ev.title,
                        "message": ev.message,
                        "task_id": ev.task_id,
                        "created_at": ev.created_at.isoformat() if ev.created_at else None,
                    }
                    data = json.dumps(payload)
                    yield f"id: {payload['id']}\nevent: notification\ndata: {data}\n\n"
            finally:
                dbx.close()

            await asyncio.sleep(3)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
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


@router.get("/admin/email", response_class=HTMLResponse)
def admin_email_get(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user or not user.is_admin:
        return _redirect("/dashboard")

    cfg = get_email_settings(db)
    return templates.TemplateResponse(
        "admin_email.html",
        _template_context(
            request,
            user,
            db=db,
            error=None,
            success=None,
            email_cfg=cfg,
        ),
    )


@router.post("/admin/email", response_class=HTMLResponse)
async def admin_email_post(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user or not user.is_admin:
        return _redirect("/dashboard")

    form = await request.form()
    enabled = form.get("enabled") == "on"
    provider = str(form.get("provider") or "smtp")
    smtp_host = str(form.get("smtp_host") or "")
    smtp_port = int(form.get("smtp_port") or 587)
    smtp_username = str(form.get("smtp_username") or "")
    smtp_password = str(form.get("smtp_password") or "")
    smtp_from = str(form.get("smtp_from") or "")
    use_tls = form.get("use_tls") == "on"
    sendgrid_api_key = str(form.get("sendgrid_api_key") or "")
    reminder_interval_minutes = int(form.get("reminder_interval_minutes") or 60)
    reset_token_minutes = int(form.get("reset_token_minutes") or 60)

    clear_password = form.get("clear_smtp_password") == "on"
    keep_existing_password = (not clear_password) and (smtp_password.strip() == "")
    if clear_password:
        smtp_password = ""

    clear_sendgrid_api_key = form.get("clear_sendgrid_api_key") == "on"
    keep_existing_sendgrid_api_key = (not clear_sendgrid_api_key) and (sendgrid_api_key.strip() == "")
    if clear_sendgrid_api_key:
        sendgrid_api_key = ""

    try:
        cfg = set_email_settings(
            db,
            enabled=enabled,
            provider=provider,
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            smtp_username=smtp_username,
            smtp_password=smtp_password,
            smtp_from=smtp_from,
            use_tls=use_tls,
            sendgrid_api_key=sendgrid_api_key,
            reminder_interval_minutes=reminder_interval_minutes,
            reset_token_minutes=reset_token_minutes,
            keep_existing_password=keep_existing_password,
            keep_existing_sendgrid_api_key=keep_existing_sendgrid_api_key,
        )
        # Reconfigure reminder jobs immediately.
        cfg_fn = getattr(request.app.state, "configure_email_jobs", None)
        if callable(cfg_fn):
            try:
                cfg_fn()
            except Exception:
                logger.exception("Failed to reconfigure email jobs")

        return templates.TemplateResponse(
            "admin_email.html",
            _template_context(
                request,
                user,
                db=db,
                error=None,
                success="Saved",
                email_cfg=cfg,
            ),
        )
    except Exception as e:
        cfg = get_email_settings(db)
        return templates.TemplateResponse(
            "admin_email.html",
            _template_context(
                request,
                user,
                db=db,
                error=str(e),
                success=None,
                email_cfg=cfg,
            ),
            status_code=400,
        )


@router.get("/admin/notifications", response_class=HTMLResponse)
def admin_notifications_get(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user or not user.is_admin:
        return _redirect("/dashboard")

    wns_cfg = get_wns_settings(db)
    return templates.TemplateResponse(
        "admin_notifications.html",
        _template_context(
            request,
            user,
            db=db,
            error=None,
            success=None,
            wns_cfg=wns_cfg,
        ),
    )


@router.post("/admin/notifications", response_class=HTMLResponse)
async def admin_notifications_post(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user or not user.is_admin:
        return _redirect("/dashboard")

    form = await request.form()
    enabled = form.get("wns_enabled") == "on"
    package_sid = str(form.get("wns_package_sid") or "")
    client_secret = str(form.get("wns_client_secret") or "")
    clear_secret = form.get("clear_wns_client_secret") == "on"
    keep_existing_secret = (not clear_secret) and (client_secret.strip() == "")
    if clear_secret:
        client_secret = ""

    try:
        wns_cfg = set_wns_settings(
            db,
            enabled=enabled,
            package_sid=package_sid,
            client_secret=client_secret,
            keep_existing_secret=keep_existing_secret,
        )
        return templates.TemplateResponse(
            "admin_notifications.html",
            _template_context(
                request,
                user,
                db=db,
                error=None,
                success="Saved",
                wns_cfg=wns_cfg,
            ),
        )
    except Exception as e:
        wns_cfg = get_wns_settings(db)
        return templates.TemplateResponse(
            "admin_notifications.html",
            _template_context(
                request,
                user,
                db=db,
                error=str(e),
                success=None,
                wns_cfg=wns_cfg,
            ),
            status_code=400,
        )


def _tail_file(path: Path, max_lines: int = 2000) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        if len(lines) > max_lines:
            lines = lines[-max_lines:]
        return "".join(lines)
    except Exception:
        return ""


@router.get("/admin/logs", response_class=HTMLResponse)
def admin_logs_get(request: Request, file: str | None = None, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user or not user.is_admin:
        return _redirect("/dashboard")

    cfg = get_logging_settings(db)
    files = []
    for p in list_log_files():
        try:
            st = p.stat()
            files.append(
                {
                    "name": p.name,
                    "size_bytes": int(st.st_size),
                    "modified": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                }
            )
        except Exception:
            continue

    selected = None
    content = None
    if file:
        safe_name = Path(file).name
        candidate = Path("/data/logs") / safe_name
        try:
            if candidate.exists() and candidate.is_file() and str(candidate.resolve()).startswith(str(Path("/data/logs").resolve())):
                selected = safe_name
                content = _tail_file(candidate, max_lines=4000)
        except Exception:
            selected = None
            content = None

    return templates.TemplateResponse(
        "admin_logs.html",
        _template_context(
            request,
            user,
            db=db,
            error=None,
            success=None,
            logging_cfg=cfg,
            log_files=files,
            selected_file=selected,
            selected_content=content,
        ),
    )


@router.post("/admin/logs", response_class=HTMLResponse)
async def admin_logs_post(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user or not user.is_admin:
        return _redirect("/dashboard")

    form = await request.form()
    level = str(form.get("level") or "INFO").strip().upper()
    retention_days = int(form.get("retention_days") or 30)

    try:
        cfg = set_logging_settings(db, level=level, retention_days=retention_days)
        cfg_fn = getattr(request.app.state, "configure_logging_jobs", None)
        if callable(cfg_fn):
            try:
                cfg_fn()
            except Exception:
                logger.exception("Failed to reconfigure logging jobs")

        files = []
        for p in list_log_files():
            try:
                st = p.stat()
                files.append(
                    {
                        "name": p.name,
                        "size_bytes": int(st.st_size),
                        "modified": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    }
                )
            except Exception:
                continue

        return templates.TemplateResponse(
            "admin_logs.html",
            _template_context(
                request,
                user,
                db=db,
                error=None,
                success="Saved",
                logging_cfg=cfg,
                log_files=files,
                selected_file=None,
                selected_content=None,
            ),
        )
    except Exception as e:
        cfg = get_logging_settings(db)
        files = []
        for p in list_log_files():
            try:
                st = p.stat()
                files.append(
                    {
                        "name": p.name,
                        "size_bytes": int(st.st_size),
                        "modified": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    }
                )
            except Exception:
                continue

        return templates.TemplateResponse(
            "admin_logs.html",
            _template_context(
                request,
                user,
                db=db,
                error=str(e),
                success=None,
                logging_cfg=cfg,
                log_files=files,
                selected_file=None,
                selected_content=None,
            ),
            status_code=400,
        )


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
