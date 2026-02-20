from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from ..auth import require_admin_api
from ..database import get_db
from ..logging_config import list_log_files
from ..meta_settings import (
    get_email_settings,
    get_logging_settings,
    get_wns_settings,
    set_email_settings,
    set_logging_settings,
    set_wns_settings,
)
from ..schemas import (
    AdminEmailSettingsOut,
    AdminEmailSettingsUpdate,
    AdminLoggingSettingsOut,
    AdminLoggingSettingsUpdate,
    AdminWNSSettingsOut,
    AdminWNSSettingsUpdate,
    LogFileOut,
)

router = APIRouter()


def _tail_file(path: Path, max_lines: int = 2000) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        if len(lines) > max_lines:
            lines = lines[-max_lines:]
        return "".join(lines)
    except Exception:
        return ""


@router.get("/email", response_model=AdminEmailSettingsOut)
def get_email(db: Session = Depends(get_db), admin=Depends(require_admin_api)):
    s = get_email_settings(db)
    return AdminEmailSettingsOut(
        enabled=bool(s.enabled),
        smtp_host=str(s.smtp_host),
        smtp_port=int(s.smtp_port),
        smtp_username=str(s.smtp_username),
        smtp_from=str(s.smtp_from),
        use_tls=bool(s.use_tls),
        reminder_interval_minutes=int(s.reminder_interval_minutes),
        reset_token_minutes=int(s.reset_token_minutes),
        smtp_password_set=bool(s.smtp_password),
    )


@router.put("/email", response_model=AdminEmailSettingsOut)
def update_email(payload: AdminEmailSettingsUpdate, db: Session = Depends(get_db), admin=Depends(require_admin_api)):
    smtp_password = payload.smtp_password
    if isinstance(smtp_password, str) and not smtp_password.strip():
        smtp_password = None

    saved = set_email_settings(
        db,
        enabled=payload.enabled,
        smtp_host=payload.smtp_host,
        smtp_port=payload.smtp_port,
        smtp_username=payload.smtp_username,
        smtp_password=smtp_password,
        smtp_from=payload.smtp_from,
        use_tls=payload.use_tls,
        reminder_interval_minutes=payload.reminder_interval_minutes,
        reset_token_minutes=payload.reset_token_minutes,
        keep_existing_password=bool(payload.keep_existing_password),
    )
    return AdminEmailSettingsOut(
        enabled=bool(saved.enabled),
        smtp_host=str(saved.smtp_host),
        smtp_port=int(saved.smtp_port),
        smtp_username=str(saved.smtp_username),
        smtp_from=str(saved.smtp_from),
        use_tls=bool(saved.use_tls),
        reminder_interval_minutes=int(saved.reminder_interval_minutes),
        reset_token_minutes=int(saved.reset_token_minutes),
        smtp_password_set=bool(saved.smtp_password),
    )


@router.get("/logging", response_model=AdminLoggingSettingsOut)
def get_logging(db: Session = Depends(get_db), admin=Depends(require_admin_api)):
    s = get_logging_settings(db)
    return AdminLoggingSettingsOut(level=str(s.level), retention_days=int(s.retention_days))


@router.put("/logging", response_model=AdminLoggingSettingsOut)
def update_logging(payload: AdminLoggingSettingsUpdate, db: Session = Depends(get_db), admin=Depends(require_admin_api)):
    cur = get_logging_settings(db)
    level = str(payload.level).strip().upper() if payload.level is not None else str(cur.level)
    retention_days = int(payload.retention_days) if payload.retention_days is not None else int(cur.retention_days)

    saved = set_logging_settings(db, level=level, retention_days=retention_days)
    return AdminLoggingSettingsOut(level=str(saved.level), retention_days=int(saved.retention_days))


@router.get("/wns", response_model=AdminWNSSettingsOut)
def get_wns(db: Session = Depends(get_db), admin=Depends(require_admin_api)):
    s = get_wns_settings(db)
    return AdminWNSSettingsOut(
        enabled=bool(s.enabled),
        package_sid=str(s.package_sid),
        client_secret_set=bool(s.client_secret),
    )


@router.put("/wns", response_model=AdminWNSSettingsOut)
def update_wns(payload: AdminWNSSettingsUpdate, db: Session = Depends(get_db), admin=Depends(require_admin_api)):
    client_secret = payload.client_secret
    if isinstance(client_secret, str) and not client_secret.strip():
        client_secret = None

    saved = set_wns_settings(
        db,
        enabled=payload.enabled,
        package_sid=payload.package_sid,
        client_secret=client_secret,
        keep_existing_secret=bool(payload.keep_existing_secret),
    )
    return AdminWNSSettingsOut(
        enabled=bool(saved.enabled),
        package_sid=str(saved.package_sid),
        client_secret_set=bool(saved.client_secret),
    )


@router.get("/logs/files", response_model=List[LogFileOut])
def list_logs(db: Session = Depends(get_db), admin=Depends(require_admin_api)):
    out: list[LogFileOut] = []
    for p in list_log_files():
        try:
            st = p.stat()
            out.append(
                LogFileOut(
                    filename=p.name,
                    size_bytes=int(st.st_size),
                    modified_at_iso=datetime.fromtimestamp(st.st_mtime).isoformat(),
                )
            )
        except Exception:
            continue
    return out


@router.get("/logs/files/{filename}")
def read_log_file(
    filename: str,
    db: Session = Depends(get_db),
    admin=Depends(require_admin_api),
    max_lines: int = Query(2000, ge=1, le=20000),
):
    safe_name = Path(filename).name
    candidate = Path("/data/logs") / safe_name
    try:
        if not candidate.exists() or not candidate.is_file():
            raise HTTPException(status_code=404, detail="Not found")
        if not str(candidate.resolve()).startswith(str(Path("/data/logs").resolve())):
            raise HTTPException(status_code=400, detail="Invalid filename")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid filename")

    content = _tail_file(candidate, max_lines=int(max_lines))
    return Response(content=content, media_type="text/plain; charset=utf-8")
