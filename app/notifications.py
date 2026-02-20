from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable
from urllib import parse, request
from urllib.error import HTTPError, URLError

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from .emailer import send_email
from .meta_settings import get_wns_settings
from .models import (
    NotificationEvent,
    Tag,
    Task,
    TaskStatus,
    User,
    UserNotificationChannel,
    UserNotificationTag,
)


logger = logging.getLogger("timeboard.notifications")


EVENT_CREATED = "created"
EVENT_UPDATED = "updated"
EVENT_PAST_DUE = "past_due"
EVENT_COMPLETED = "completed"
EVENT_ARCHIVED = "archived"

EVENT_TYPES = {EVENT_CREATED, EVENT_UPDATED, EVENT_PAST_DUE, EVENT_COMPLETED, EVENT_ARCHIVED}


CHANNEL_BROWSER = "browser"
CHANNEL_EMAIL = "email"
CHANNEL_GOTIFY = "gotify"
CHANNEL_NTFY = "ntfy"
CHANNEL_DISCORD = "discord"
CHANNEL_WEBHOOK = "webhook"
CHANNEL_GENERIC_API = "generic_api"
CHANNEL_WNS = "wns"

CHANNEL_TYPES = {
    CHANNEL_BROWSER,
    CHANNEL_EMAIL,
    CHANNEL_GOTIFY,
    CHANNEL_NTFY,
    CHANNEL_DISCORD,
    CHANNEL_WEBHOOK,
    CHANNEL_GENERIC_API,
    CHANNEL_WNS,
}


def _json_loads(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        v = json.loads(raw)
        return v if isinstance(v, dict) else {}
    except Exception:
        return {}


def get_user_notification_tag_ids(db: Session, *, user_id: int) -> set[int]:
    rows = db.query(UserNotificationTag).filter(UserNotificationTag.user_id == int(user_id)).all()
    return {int(r.tag_id) for r in rows}


def set_user_notification_tag_ids(db: Session, *, user_id: int, tag_ids: Iterable[int]) -> None:
    uid = int(user_id)
    # normalize and de-dup
    ids: set[int] = set()
    for t in tag_ids or []:
        try:
            ids.add(int(t))
        except Exception:
            continue

    db.query(UserNotificationTag).filter(UserNotificationTag.user_id == uid).delete(synchronize_session=False)
    for tid in sorted(ids):
        db.add(UserNotificationTag(user_id=uid, tag_id=int(tid)))
    db.commit()


def get_user_channels(db: Session, *, user_id: int) -> dict[str, UserNotificationChannel]:
    rows = db.query(UserNotificationChannel).filter(UserNotificationChannel.user_id == int(user_id)).all()
    out: dict[str, UserNotificationChannel] = {}
    for r in rows:
        out[str(r.channel_type)] = r
    return out


def upsert_user_channel(
    db: Session,
    *,
    user_id: int,
    channel_type: str,
    enabled: bool,
    config: dict | None = None,
) -> UserNotificationChannel:
    ctype = str(channel_type or "").strip().lower()
    if ctype not in CHANNEL_TYPES:
        raise ValueError("Invalid channel_type")

    row = (
        db.query(UserNotificationChannel)
        .filter(UserNotificationChannel.user_id == int(user_id))
        .filter(UserNotificationChannel.channel_type == ctype)
        .first()
    )

    if row is None:
        row = UserNotificationChannel(
            user_id=int(user_id),
            channel_type=ctype,
            enabled=bool(enabled),
            config_json=json.dumps(config or {}, separators=(",", ":")),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row

    row.enabled = bool(enabled)
    if config is not None:
        row.config_json = json.dumps(config or {}, separators=(",", ":"))
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _format_due(dt: datetime | None) -> str:
    if not dt:
        return ""
    try:
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return str(dt)


def _build_event_text(*, task: Task, event_type: str) -> tuple[str, str, dict]:
    """Return (title, message, payload)."""
    due = _format_due(getattr(task, "due_date_utc", None))
    tags = []
    try:
        tags = [t.name for t in (task.tags or [])]
    except Exception:
        tags = []

    base = {
        "event_type": event_type,
        "task": {
            "id": int(task.id),
            "user_id": int(task.user_id),
            "name": task.name,
            "task_type": task.task_type,
            "status": str(task.status),
            "due_date_utc": getattr(task, "due_date_utc", None).isoformat() if getattr(task, "due_date_utc", None) else None,
            "url": task.url,
        },
        "tags": tags,
        "occurred_at_utc": datetime.utcnow().replace(tzinfo=None).isoformat(),
    }

    if event_type == EVENT_CREATED:
        title = "Task created"
        msg = f"Created: {task.name} ({task.task_type}) due {due}".strip()
    elif event_type == EVENT_UPDATED:
        title = "Task updated"
        msg = f"Updated: {task.name} ({task.task_type}) due {due}".strip()
    elif event_type == EVENT_PAST_DUE:
        title = "Task overdue"
        msg = f"Overdue: {task.name} ({task.task_type}) was due {due}".strip()
    elif event_type == EVENT_COMPLETED:
        title = "Task completed"
        msg = f"Completed: {task.name} ({task.task_type})".strip()
    elif event_type == EVENT_ARCHIVED:
        title = "Task archived"
        msg = f"Archived: {task.name} ({task.task_type})".strip()
    else:
        title = "Task notification"
        msg = f"{event_type}: {task.name} ({task.task_type})".strip()

    if tags:
        msg = msg + f" [tags: {', '.join(tags)}]"
    return title, msg, base


def _http_request(
    *,
    url: str,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    timeout: int = 10,
) -> tuple[int, str]:
    hdrs = {"User-Agent": "Timeboard"}
    if headers:
        for k, v in headers.items():
            if k and v is not None:
                hdrs[str(k)] = str(v)
    req = request.Request(url=str(url), data=data, headers=hdrs, method=str(method).upper())
    with request.urlopen(req, timeout=timeout) as resp:
        body = resp.read() or b""
        return int(getattr(resp, "status", 200)), body.decode("utf-8", errors="replace")


def _send_gotify(*, config: dict, title: str, message: str) -> None:
    base_url = str(config.get("base_url") or "").strip().rstrip("/")
    token = str(config.get("token") or "").strip()
    if not base_url or not token:
        raise ValueError("Gotify requires base_url and token")

    try:
        priority = int(config.get("priority") or 5)
    except Exception:
        priority = 5
    if priority < 0:
        priority = 0
    if priority > 10:
        priority = 10

    url = f"{base_url}/message?token={parse.quote(token)}"
    payload = {"title": title, "message": message, "priority": priority}
    data = json.dumps(payload).encode("utf-8")
    _http_request(url=url, headers={"Content-Type": "application/json"}, data=data)


def _send_ntfy(*, config: dict, title: str, message: str) -> None:
    server = str(config.get("server_url") or "https://ntfy.sh").strip().rstrip("/")
    topic = str(config.get("topic") or "").strip()
    if not topic:
        raise ValueError("ntfy requires topic")

    url = f"{server}/{parse.quote(topic)}"
    headers: dict[str, str] = {
        "Title": title,
        "Content-Type": "text/plain; charset=utf-8",
    }
    token = str(config.get("token") or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    priority = str(config.get("priority") or "")
    if priority:
        headers["Priority"] = priority

    _http_request(url=url, headers=headers, data=(message or "").encode("utf-8"))


def _send_discord(*, config: dict, message: str) -> None:
    webhook_url = str(config.get("webhook_url") or "").strip()
    if not webhook_url:
        raise ValueError("Discord requires webhook_url")
    payload = {"content": message}
    data = json.dumps(payload).encode("utf-8")
    _http_request(url=webhook_url, headers={"Content-Type": "application/json"}, data=data)


def _send_webhook(*, config: dict, payload: dict) -> None:
    url = str(config.get("url") or "").strip()
    if not url:
        raise ValueError("Webhook requires url")

    headers: dict[str, str] = {"Content-Type": "application/json"}
    secret = str(config.get("secret") or "").strip()
    if secret:
        headers["X-Timeboard-Secret"] = secret

    data = json.dumps(payload).encode("utf-8")
    _http_request(url=url, headers=headers, data=data)


def _send_generic_api(*, config: dict, payload: dict) -> None:
    url = str(config.get("url") or "").strip()
    if not url:
        raise ValueError("Generic API requires url")

    method = str(config.get("method") or "POST").strip().upper()
    headers: dict[str, str] = {}
    raw_headers = config.get("headers")
    if isinstance(raw_headers, dict):
        headers.update({str(k): str(v) for k, v in raw_headers.items() if k and v is not None})
    token = str(config.get("token") or "").strip()
    if token:
        headers.setdefault("Authorization", f"Bearer {token}")

    data = None
    if method in {"POST", "PUT", "PATCH"}:
        headers.setdefault("Content-Type", "application/json")
        data = json.dumps(payload).encode("utf-8")

    _http_request(url=url, method=method, headers=headers, data=data)


def _wns_get_access_token(*, package_sid: str, client_secret: str) -> str:
    """Return a WNS access token using OAuth client_credentials."""
    # Documentation endpoint (stable for years): https://login.live.com/accesstoken.srf
    token_url = "https://login.live.com/accesstoken.srf"
    form = {
        "grant_type": "client_credentials",
        "client_id": package_sid,
        "client_secret": client_secret,
        "scope": "notify.windows.com",
    }
    data = parse.urlencode(form).encode("utf-8")
    status, body = _http_request(
        url=token_url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=data,
        timeout=10,
    )
    if status < 200 or status >= 300:
        raise RuntimeError(f"WNS token request failed ({status})")

    try:
        obj = json.loads(body)
        token = str(obj.get("access_token") or "")
        if not token:
            raise RuntimeError("WNS token response missing access_token")
        return token
    except Exception as e:
        raise RuntimeError("Failed to parse WNS token response") from e


def _send_wns_toast(*, channel_uri: str, access_token: str, title: str, message: str) -> None:
    uri = str(channel_uri or "").strip()
    if not uri:
        raise ValueError("WNS requires channel_uri")

    # Minimal toast notification payload.
    toast_xml = (
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<toast>"
        "  <visual>"
        "    <binding template=\"ToastGeneric\">"
        f"      <text>{_xml_escape(title)}</text>"
        f"      <text>{_xml_escape(message)}</text>"
        "    </binding>"
        "  </visual>"
        "</toast>"
    )

    headers = {
        "Content-Type": "text/xml",
        "Authorization": f"Bearer {access_token}",
        "X-WNS-Type": "wns/toast",
    }
    _http_request(url=uri, headers=headers, data=toast_xml.encode("utf-8"), timeout=10)


def _xml_escape(s: str) -> str:
    return (
        (s or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def is_task_notification_relevant(
    db: Session,
    *,
    task_user_id: int,
    task_tag_ids: set[int],
) -> bool:
    if not task_tag_ids:
        return False
    subscribed = get_user_notification_tag_ids(db, user_id=int(task_user_id))
    return bool(subscribed.intersection(task_tag_ids))


def create_notification_event(
    db: Session,
    *,
    user_id: int,
    task_id: int | None,
    event_type: str,
    title: str,
    message: str,
    event_key: str | None = None,
) -> NotificationEvent | None:
    et = str(event_type or "").strip().lower()
    if et not in EVENT_TYPES:
        raise ValueError("Invalid event_type")

    ev = NotificationEvent(
        user_id=int(user_id),
        task_id=(int(task_id) if task_id is not None else None),
        event_type=et,
        event_key=(str(event_key) if event_key else None),
        title=str(title or "Notification"),
        message=str(message or ""),
    )
    db.add(ev)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return None
    db.refresh(ev)
    return ev


def send_notification_via_channels(
    db: Session,
    *,
    user: User,
    task: Task,
    event_type: str,
    title: str,
    message: str,
    payload: dict,
) -> dict[str, str]:
    """Send the event to all enabled channels for the user.

    Returns a dict of {channel_type: "ok"|"error:<msg>"}.
    """
    results: dict[str, str] = {}
    channels = (
        db.query(UserNotificationChannel)
        .filter(UserNotificationChannel.user_id == int(user.id))
        .filter(UserNotificationChannel.enabled.is_(True))
        .all()
    )

    for ch in channels:
        ctype = str(ch.channel_type)
        cfg = _json_loads(ch.config_json)
        try:
            if ctype == CHANNEL_BROWSER:
                # Browser notifications are delivered via SSE from NotificationEvent rows.
                results[ctype] = "ok"
                continue

            if ctype == CHANNEL_EMAIL:
                if not user.email:
                    raise ValueError("User has no email address")
                subject = f"Timeboard: {title}"
                send_email(to_address=user.email, subject=subject, body_text=message, db=db)
                results[ctype] = "ok"
                continue

            if ctype == CHANNEL_GOTIFY:
                _send_gotify(config=cfg, title=title, message=message)
                results[ctype] = "ok"
                continue

            if ctype == CHANNEL_NTFY:
                _send_ntfy(config=cfg, title=title, message=message)
                results[ctype] = "ok"
                continue

            if ctype == CHANNEL_DISCORD:
                _send_discord(config=cfg, message=message)
                results[ctype] = "ok"
                continue

            if ctype == CHANNEL_WEBHOOK:
                _send_webhook(config=cfg, payload=payload)
                results[ctype] = "ok"
                continue

            if ctype == CHANNEL_GENERIC_API:
                _send_generic_api(config=cfg, payload=payload)
                results[ctype] = "ok"
                continue

            if ctype == CHANNEL_WNS:
                wns_cfg = get_wns_settings(db)
                if not wns_cfg.enabled:
                    raise ValueError("WNS is disabled by admin")
                if not wns_cfg.package_sid or not wns_cfg.client_secret:
                    raise ValueError("WNS is not configured (missing package_sid/client_secret)")

                channel_uri = str(cfg.get("channel_uri") or "").strip()
                if not channel_uri:
                    raise ValueError("WNS channel_uri not set")

                token = _wns_get_access_token(package_sid=wns_cfg.package_sid, client_secret=wns_cfg.client_secret)
                _send_wns_toast(channel_uri=channel_uri, access_token=token, title=title, message=message)
                results[ctype] = "ok"
                continue

            results[ctype] = "error:unknown-channel"
        except Exception as e:
            logger.warning("Notification send failed (%s): %s", ctype, e)
            results[ctype] = f"error:{e}"

    return results


def notify_task_event(
    db: Session,
    *,
    task: Task,
    event_type: str,
    relevant_tag_ids: set[int] | None = None,
    event_key: str | None = None,
) -> None:
    """Create a NotificationEvent and deliver via enabled channels.

    A notification is only sent if the task has at least one tag that the task
    owner subscribed to in their notification settings.
    """
    et = str(event_type or "").strip().lower()
    if et not in EVENT_TYPES:
        raise ValueError("Invalid event_type")

    # Load tags if needed.
    if not hasattr(task, "tags"):
        task = db.query(Task).options(joinedload(Task.tags)).filter(Task.id == int(task.id)).first() or task

    tag_ids = relevant_tag_ids
    if tag_ids is None:
        try:
            tag_ids = {int(t.id) for t in (task.tags or [])}
        except Exception:
            tag_ids = set()

    if not is_task_notification_relevant(db, task_user_id=int(task.user_id), task_tag_ids=tag_ids):
        return

    user = db.query(User).filter(User.id == int(task.user_id)).first()
    if not user:
        return

    title, msg, payload = _build_event_text(task=task, event_type=et)

    ev = create_notification_event(
        db,
        user_id=int(user.id),
        task_id=int(task.id) if getattr(task, "id", None) is not None else None,
        event_type=et,
        title=title,
        message=msg,
        event_key=event_key,
    )
    if ev is None:
        # deduped
        return

    # Deliver externally. Browser notifications will be delivered via SSE.
    try:
        send_notification_via_channels(db, user=user, task=task, event_type=et, title=title, message=msg, payload=payload)
    except Exception:
        logger.exception("Unexpected error delivering notifications")
