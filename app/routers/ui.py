from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ..auth import authenticate_user
from ..config import get_settings
from ..crud import (
    complete_task,
    create_task,
    create_user,
    delete_user,
    get_task,
    get_user,
    get_user_by_username,
    list_tasks,
    list_users,
    soft_delete_task,
    update_task,
    update_user_me,
)
from ..db import get_db
from ..models import RecurrenceType, Task, TaskStatus, Theme, User
from ..utils.humanize import humanize_timedelta, time_left_class, seconds_to_duration_str
from ..utils.time_utils import iso_for_datetime_local_input, now_utc, to_local


router = APIRouter(include_in_schema=False)


templates_dir = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))
# Jinja filters
templates.env.filters["dt_local"] = lambda dt: to_local(dt).strftime("%Y-%m-%d %H:%M") if dt else ""

# Cache-busting for static assets.
#
# Some deployments (reverse proxies/CDNs) or browsers can aggressively cache
# /static/css/styles.css. The dashboard's time-left colors are purely CSS;
# if the old stylesheet is cached, changes appear to have "no effect".
#
# We version static assets by their file modification times so the URL changes
# on each deploy (e.g. /static/css/styles.css?v=1700000000).
static_dir = Path(__file__).resolve().parent.parent / "static"
try:
    css_mtime = (static_dir / "css" / "styles.css").stat().st_mtime
    js_mtime = (static_dir / "js" / "main.js").stat().st_mtime
    templates.env.globals["static_version"] = str(int(max(css_mtime, js_mtime)))
except Exception:
    templates.env.globals["static_version"] = "1"


settings = get_settings()


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
        "recurrence_interval": "" if not task.recurrence_interval_seconds else seconds_to_duration_str(int(task.recurrence_interval_seconds)),
        "recurrence_times": task.recurrence_times or "",
        "tags": ", ".join([t.name for t in (task.tags or [])]),
    }


@router.get("/login", response_class=HTMLResponse)
def login_get(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if user:
        return _redirect("/dashboard")

    return templates.TemplateResponse(
        "login.html",
        {"request": request, "app_name": settings.app.name, "error": None},
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
            {"request": request, "app_name": settings.app.name, "error": "Invalid username or password"},
            status_code=401,
        )

    request.session["user_id"] = int(user.id)
    return _redirect("/dashboard")


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return _redirect("/login")


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    tag: str | None = None,
    user_id: int | None = None,
    db: Session = Depends(get_db),
):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")

    tasks = list_tasks(db, current_user=user, include_archived=False, tag=tag, user_id=user_id)
    now = now_utc()

    # Admin user selector
    users = list_users(db) if user.is_admin else []

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

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "current_user": user,
            "app_name": settings.app.name,
            "tasks": rows,
            "tag_filter": tag,
            "user_filter": user_id,
            "all_users": users,
        },
    )


@router.get("/tasks/new", response_class=HTMLResponse)
def task_new_get(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")

    ctx = _task_form_context(None)
    return templates.TemplateResponse(
        "task_form.html",
        {
            "request": request,
            "current_user": user,
            "app_name": settings.app.name,
            "mode": "new",
            "error": None,
            **ctx,
        },
    )


@router.post("/tasks/new", response_class=HTMLResponse)
def task_new_post(
    request: Request,
    name: str = Form(...),
    task_type: str = Form(...),
    due_date: str = Form(...),
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

    try:
        due_dt = datetime.fromisoformat(due_date)
    except ValueError:
        ctx = _task_form_context(None)
        ctx.update({
            "name": name,
            "task_type": task_type,
            "description": description,
            "url": url,
            "due_date": due_date,
            "recurrence_type": recurrence_type,
            "recurrence_interval": recurrence_interval,
            "recurrence_times": recurrence_times,
            "tags": tags,
        })
        return templates.TemplateResponse(
            "task_form.html",
            {
                "request": request,
                "current_user": user,
                "app_name": settings.app.name,
                "mode": "new",
                "error": "Invalid due date format",
                **ctx,
            },
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
            {
                "request": request,
                "current_user": user,
                "app_name": settings.app.name,
                "mode": "new",
                "error": str(e),
                **ctx,
            },
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
        {
            "request": request,
            "current_user": user,
            "app_name": settings.app.name,
            "mode": "edit",
            "error": None,
            **ctx,
        },
    )


@router.post("/tasks/{task_id}/edit", response_class=HTMLResponse)
def task_edit_post(
    request: Request,
    task_id: int,
    name: str = Form(...),
    task_type: str = Form(...),
    due_date: str = Form(...),
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
            {
                "request": request,
                "current_user": user,
                "app_name": settings.app.name,
                "mode": "edit",
                "error": "Invalid due date format",
                **ctx,
            },
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
            {
                "request": request,
                "current_user": user,
                "app_name": settings.app.name,
                "mode": "edit",
                "error": str(e),
                **ctx,
            },
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
        pass

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
        pass

    return _redirect("/dashboard")


@router.get("/profile", response_class=HTMLResponse)
def profile_get(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        return _redirect("/login")

    return templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "current_user": user,
            "app_name": settings.app.name,
            "error": None,
            "success": None,
        },
    )


@router.post("/profile", response_class=HTMLResponse)
def profile_post(
    request: Request,
    theme: str = Form(Theme.system.value),
    purge_days: int = Form(...),
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
            current_password=current_password or None,
            new_password=new_password or None,
        )
        db.refresh(user)
        return templates.TemplateResponse(
            "profile.html",
            {
                "request": request,
                "current_user": user,
                "app_name": settings.app.name,
                "error": None,
                "success": "Saved",
            },
        )
    except Exception as e:
        return templates.TemplateResponse(
            "profile.html",
            {
                "request": request,
                "current_user": user,
                "app_name": settings.app.name,
                "error": str(e),
                "success": None,
            },
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
        {
            "request": request,
            "current_user": user,
            "app_name": settings.app.name,
            "users": users,
            "error": None,
        },
    )


@router.post("/admin/users/create", response_class=HTMLResponse)
def admin_users_create(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
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
            {"request": request, "current_user": user, "app_name": settings.app.name, "users": users, "error": "Username already exists"},
            status_code=400,
        )

    try:
        create_user(db, username=username, password=password, is_admin=bool(is_admin))
    except Exception as e:
        users = list_users(db)
        return templates.TemplateResponse(
            "user_admin.html",
            {"request": request, "current_user": user, "app_name": settings.app.name, "users": users, "error": str(e)},
            status_code=400,
        )

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
