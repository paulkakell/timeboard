from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from ..auth import get_current_user_api, require_admin_api
from ..crud import get_user
from ..db import get_db
from ..metrics import (
    build_all_user_metrics,
    build_deployment_metrics,
    build_user_metrics,
    metrics_endpoint_catalog,
    render_influx_lines,
    render_prometheus_metrics,
    utc_now,
)
from ..models import User

router = APIRouter()


def _started_at(request: Request) -> datetime | None:
    value = getattr(request.app.state, "started_at_utc", None)
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    return None


@router.get("/catalog")
def api_metrics_catalog(current_user: User = Depends(get_current_user_api)):
    endpoints = metrics_endpoint_catalog()
    if not bool(current_user.is_admin):
        endpoints = [e for e in endpoints if str(e.get("scope", "")).startswith("authenticated")]
    return {
        "generated_at_utc": utc_now().isoformat() + "Z",
        "endpoints": endpoints,
    }


@router.get("/me")
def api_metrics_me(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_api),
):
    return build_user_metrics(db, user=current_user)


@router.get("/users")
def api_metrics_users(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin_api),
):
    return {
        "generated_at_utc": utc_now().isoformat() + "Z",
        "users": build_all_user_metrics(db),
    }


@router.get("/users/{user_id}")
def api_metrics_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_api),
):
    if not bool(current_user.is_admin) and int(current_user.id) != int(user_id):
        raise HTTPException(status_code=403, detail="Not allowed")
    user = get_user(db, user_id=int(user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return build_user_metrics(db, user=user)


@router.get("/deployment")
def api_metrics_deployment(
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin_api),
):
    return build_deployment_metrics(db, started_at_utc=_started_at(request))


@router.get("/prometheus", response_class=PlainTextResponse)
def api_metrics_prometheus(
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin_api),
):
    now = utc_now()
    deployment = build_deployment_metrics(db, now_utc=now, started_at_utc=_started_at(request))
    users = build_all_user_metrics(db, now_utc=now)
    return PlainTextResponse(render_prometheus_metrics(deployment, users), media_type="text/plain; charset=utf-8")


@router.get("/influx", response_class=PlainTextResponse)
def api_metrics_influx(
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin_api),
):
    now = utc_now()
    deployment = build_deployment_metrics(db, now_utc=now, started_at_utc=_started_at(request))
    users = build_all_user_metrics(db, now_utc=now)
    return PlainTextResponse(render_influx_lines(deployment, users), media_type="text/plain; charset=utf-8")
