from __future__ import annotations

import html
import json
import logging
import secrets
from datetime import datetime
from typing import Any
from urllib import parse, request

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from .config import get_settings
from .emailer import send_email
from .meta_settings import get_wns_settings
from .models import (
    NotificationEvent,
    Tag,
    Task,
    User,
    UserNotificationChannel,
    UserNotificationService,
    UserNotificationTag,
)

logger = logging.getLogger("timeboard.notifications")

# ---- Task event types (stable API) -------------------------------------------------

EVENT_CREATED = "created"
EVENT_UPDATED = "updated"
EVENT_PAST_DUE = "past_due"
EVENT_COMPLETED = "completed"
EVENT_ARCHIVED = "archived"

EVENT_TYPES = {
    EVENT_CREATED,
    EVENT_UPDATED,
    EVENT_PAST_DUE,
    EVENT_COMPLETED,
    EVENT_ARCHIVED,
}

# ---- Notification service types ----------------------------------------------------
#
# These strings are persisted in the database.
#
CHANNEL_BROWSER = "browser"
CHANNEL_EMAIL = "email"
CHANNEL_GOTIFY = "gotify"
CHANNEL_NTFY = "ntfy"
CHANNEL_WEBHOOK = "webhook"
CHANNEL_GENERIC_API = "generic_api"
CHANNEL_WNS = "wns"
# Legacy/extra (still supported, not required):
CHANNEL_DISCORD = "discord"

CHANNEL_TYPES = [
    CHANNEL_BROWSER,
    CHANNEL_EMAIL,
    CHANNEL_GOTIFY,
    CHANNEL_NTFY,
    CHANNEL_WEBHOOK,
    CHANNEL_GENERIC_API,
    CHANNEL_WNS,
    CHANNEL_DISCORD,
]

# Notification routing tags created for service entries.
NOTIFY_TAG_PREFIX = "notify:"


def _json_loads(s: str | None) -> dict:
    if not s:
        return {}
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _json_dumps(obj: dict | None) -> str:
    try:
        return json.dumps(obj or {}, separators=(",", ":"), sort_keys=True)
    except Exception:
        return "{}"


def _normalize_service_type(service_type: str) -> str:
    st = str(service_type or "").strip().lower()
    if st not in CHANNEL_TYPES:
        raise ValueError("Invalid service_type")
    return st


def _format_due(dt: datetime | None) -> str:
    if not dt:
        return ""
    try:
        # Keep stable / unambiguous format for notifications.
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return str(dt)


def _event_action(event_type: str) -> str:
    et = str(event_type or "").strip().lower()
    if et == EVENT_CREATED:
        return "CREATED"
    if et == EVENT_UPDATED:
        return "UPDATED"
    if et == EVENT_PAST_DUE:
        return "PAST_DUE"
    if et == EVENT_COMPLETED:
        return "COMPLETED"
    if et == EVENT_ARCHIVED:
        return "ARCHIVED"
    return et.upper() or "EVENT"


def _task_internal_url(task_id: int) -> str:
    settings = get_settings()
    base = str(getattr(settings.app, "base_url", "") or "").strip().rstrip("/")
    if base:
        return f"{base}/tasks/{int(task_id)}/edit"
    return f"/tasks/{int(task_id)}/edit"


def _task_link_url(task: Task) -> str:
    # Prefer user-provided URL if present, otherwise link to the in-app task editor.
    u = str(getattr(task, "url", "") or "").strip()
    if u:
        return u
    tid = getattr(task, "id", None)
    if tid is None:
        return ""
    return _task_internal_url(int(tid))


def _build_task_notification(*, task: Task, event_type: str) -> tuple[str, str, str | None, dict]:
    """Return (title, message_text, message_html, payload)."""
    et = str(event_type or "").strip().lower()
    action = _event_action(et)
    link_url = _task_link_url(task)

    try:
        tags = [t.name for t in (task.tags or [])]
    except Exception:
        tags = []
    tags_str = ", ".join(tags)

    due = _format_due(getattr(task, "due_date_utc", None))

    if et == EVENT_CREATED:
        title = "Task created"
    elif et == EVENT_UPDATED:
        title = "Task updated"
    elif et == EVENT_PAST_DUE:
        title = "Task overdue"
    elif et == EVENT_COMPLETED:
        title = "Task completed"
    elif et == EVENT_ARCHIVED:
        title = "Task archived"
    else:
        title = "Task notification"

    # Canonical text format (works across most services).
    # Template (conceptual): <CHANGE_ACTION>:<URL><TASK_NAME></URL> -<DUE_DATE> [<TAGS>]
    name = str(getattr(task, "name", "") or "")
    message_text = f"{action}:{link_url} {name} -{due} [{tags_str}]".strip()

    # HTML variant (used by email if enabled).
    message_html = None
    if link_url:
        safe_name = html.escape(name)
        safe_url = html.escape(link_url, quote=True)
        message_html = f"<p><strong>{html.escape(action)}</strong>: <a href=\"{safe_url}\">{safe_name}</a> -{html.escape(due)} [{html.escape(tags_str)}]</p>"
    else:
        message_html = f"<p><strong>{html.escape(action)}</strong>: {html.escape(name)} -{html.escape(due)} [{html.escape(tags_str)}]</p>"

    payload: dict[str, Any] = {
        "event_type": et,
        "change_action": action,
        "message_text": message_text,
        "message_html": message_html,
        "url": link_url,
        "due_date_display": due,
        "task": {
            "id": int(task.id) if getattr(task, "id", None) is not None else None,
            "user_id": int(task.user_id) if getattr(task, "user_id", None) is not None else None,
            "name": task.name,
            "task_type": getattr(task, "task_type", None),
            "status": str(getattr(task, "status", "")),
            "due_date_utc": getattr(task, "due_date_utc", None).isoformat() if getattr(task, "due_date_utc", None) else None,
            "url": getattr(task, "url", None),
        },
        "tags": tags,
        "occurred_at_utc": datetime.utcnow().replace(tzinfo=None).isoformat(),
    }

    return title, message_text, message_html, payload


# ---- Service entry management ------------------------------------------------------


def list_user_notification_services(db: Session, *, user_id: int) -> list[UserNotificationService]:
    return (
        db.query(UserNotificationService)
        .filter(UserNotificationService.user_id == int(user_id))
        .order_by(UserNotificationService.id.asc())
        .all()
    )


def user_has_enabled_browser_service(db: Session, *, user_id: int) -> bool:
    row = (
        db.query(UserNotificationService.id)
        .filter(UserNotificationService.user_id == int(user_id))
        .filter(UserNotificationService.service_type == CHANNEL_BROWSER)
        .filter(UserNotificationService.enabled.is_(True))
        .first()
    )
    return bool(row)


def _generate_notification_tag_name(*, user_id: int, service_type: str) -> str:
    st = _normalize_service_type(service_type)
    token = secrets.token_hex(4)
    # Keep tags reasonably short; Tag.name max is 64.
    # Example: notify:u12:ntfy:deadbeef
    return f"{NOTIFY_TAG_PREFIX}u{int(user_id)}:{st}:{token}".lower()


def create_user_notification_service(
    db: Session,
    *,
    user_id: int,
    service_type: str,
    name: str | None = None,
    enabled: bool = True,
    config: dict | None = None,
) -> UserNotificationService:
    """Create a new notification service entry and its routing tag."""
    st = _normalize_service_type(service_type)

    # Create a unique tag.
    tag = None
    for _ in range(10):
        tag_name = _generate_notification_tag_name(user_id=int(user_id), service_type=st)
        tag = Tag(name=tag_name)
        db.add(tag)
        try:
            db.flush()
            break
        except IntegrityError:
            db.rollback()
            tag = None
            continue
    if tag is None or tag.id is None:
        raise RuntimeError("Failed to generate unique notification tag")

    svc = UserNotificationService(
        user_id=int(user_id),
        service_type=st,
        name=(str(name).strip() if name else None),
        enabled=bool(enabled),
        config_json=_json_dumps(config or {}),
        tag_id=int(tag.id),
    )
    db.add(svc)
    db.commit()
    db.refresh(svc)
    return svc


def update_user_notification_service(
    db: Session,
    *,
    user_id: int,
    service_id: int,
    name: str | None = None,
    enabled: bool | None = None,
    config: dict | None = None,
) -> UserNotificationService | None:
    svc = (
        db.query(UserNotificationService)
        .filter(UserNotificationService.id == int(service_id))
        .filter(UserNotificationService.user_id == int(user_id))
        .first()
    )
    if not svc:
        return None

    if name is not None:
        svc.name = str(name).strip() if str(name).strip() else None
    if enabled is not None:
        svc.enabled = bool(enabled)
    if config is not None:
        svc.config_json = _json_dumps(config)

    db.add(svc)
    db.commit()
    db.refresh(svc)
    return svc


def delete_user_notification_service(db: Session, *, user_id: int, service_id: int) -> bool:
    svc = (
        db.query(UserNotificationService)
        .filter(UserNotificationService.id == int(service_id))
        .filter(UserNotificationService.user_id == int(user_id))
        .first()
    )
    if not svc:
        return False

    # Delete the routing tag as well (it is service-generated).
    tag_id = int(svc.tag_id)

    db.delete(svc)
    try:
        db.flush()
    except Exception:
        db.rollback()
        return False

    # Tag deletion cascades through task_tags.
    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if tag:
        db.delete(tag)

    db.commit()
    return True


# ---- Legacy tag subscription + per-type channel config ----------------------------
#
# These remain for backward compatibility and for migration helpers. New deployments
# should prefer UserNotificationService entries.


def get_user_notification_tag_ids(db: Session, *, user_id: int) -> set[int]:
    rows = db.query(UserNotificationTag.tag_id).filter(UserNotificationTag.user_id == int(user_id)).all()
    return {int(r[0]) for r in rows}


def set_user_notification_tag_ids(db: Session, *, user_id: int, tag_ids: set[int]) -> None:
    # Replace subscriptions.
    db.query(UserNotificationTag).filter(UserNotificationTag.user_id == int(user_id)).delete()
    for tid in sorted({int(t) for t in (tag_ids or set())}):
        db.add(UserNotificationTag(user_id=int(user_id), tag_id=int(tid)))
    db.commit()


def get_user_channels(db: Session, *, user_id: int) -> dict[str, UserNotificationChannel]:
    out: dict[str, UserNotificationChannel] = {}
    rows = db.query(UserNotificationChannel).filter(UserNotificationChannel.user_id == int(user_id)).all()
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
    ctype = _normalize_service_type(channel_type)

    ch = (
        db.query(UserNotificationChannel)
        .filter(UserNotificationChannel.user_id == int(user_id))
        .filter(UserNotificationChannel.channel_type == ctype)
        .first()
    )
    if not ch:
        ch = UserNotificationChannel(user_id=int(user_id), channel_type=ctype)

    ch.enabled = bool(enabled)
    if config is not None:
        ch.config_json = _json_dumps(config)

    db.add(ch)
    db.commit()
    db.refresh(ch)
    return ch


# ---- HTTP helpers + integrations --------------------------------------------------


def _http_request(
    *,
    url: str,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    timeout: int = 10,
) -> tuple[int, str]:
    # Only allow network calls over HTTP(S). This prevents accidental use of
    # file:/ or other custom schemes when notification URLs are user-provided.
    parsed = parse.urlparse(str(url))
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Invalid notification URL")

    hdrs = {"User-Agent": "Timeboard"}
    if headers:
        for k, v in headers.items():
            if k and v is not None:
                hdrs[str(k)] = str(v)
    req = request.Request(url=str(url), data=data, headers=hdrs, method=str(method).upper())
    with request.urlopen(req, timeout=timeout) as resp:  # nosec B310
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


def _send_ntfy(*, config: dict, title: str, message: str, click_url: str | None = None) -> None:
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
    if click_url:
        headers["Click"] = str(click_url)

    _http_request(url=url, headers=headers, data=(message or "").encode("utf-8"))


def _send_discord(*, config: dict, message: str) -> None:
    # Accept a few legacy/common keys.
    webhook_url = str(config.get("webhook_url") or config.get("url") or config.get("webhook") or "").strip()
    if not webhook_url:
        raise ValueError("Discord requires webhook_url")
    # Discord webhook content supports Markdown but not HTML.
    content = str(message or "")
    if len(content) > 2000:
        content = content[:1997] + "..."
    payload = {
        "content": content,
        # Prevent accidental @mentions from task names/tags.
        "allowed_mentions": {"parse": []},
    }
    data = json.dumps(payload).encode("utf-8")
    _http_request(url=webhook_url, headers={"Content-Type": "application/json"}, data=data)


def _build_discord_markdown(*, title: str, payload: dict) -> str:
    """Build a Discord-friendly Markdown message.

    Discord supports a Markdown-like syntax in message content, but not HTML.
    """

    action = str(payload.get("change_action") or "").strip() or str(title or "Notification")
    task = payload.get("task") if isinstance(payload.get("task"), dict) else {}
    name = str(task.get("name") or "").strip()
    task_type = str(task.get("task_type") or "").strip()
    due_disp = str(payload.get("due_date_display") or "").strip()
    url = str(payload.get("url") or payload.get("task_internal_url") or "").strip()

    tags_val = payload.get("tags")
    tags: list[str] = []
    if isinstance(tags_val, list):
        tags = [str(t).strip() for t in tags_val if str(t).strip()]
    tags_str = ", ".join(tags)

    header = f"**{action}**"
    if task_type:
        header += f" [{task_type}]"
    if name:
        header += f" {name}"

    lines: list[str] = [header.strip()]
    if url:
        lines.append(url)
    if due_disp:
        lines.append(f"Due: {due_disp}")
    if tags_str:
        lines.append(f"Tags: {tags_str}")

    return "\n".join([ln for ln in lines if ln]).strip()


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


def _xml_escape(s: str) -> str:
    return (
        (s or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _send_wns_toast(*, channel_uri: str, access_token: str, title: str, message: str) -> None:
    uri = str(channel_uri or "").strip()
    if not uri:
        raise ValueError("WNS requires channel_uri")

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


# ---- Event persistence ------------------------------------------------------------


def create_notification_event(
    db: Session,
    *,
    user_id: int,
    task_id: int | None,
    event_type: str,
    title: str,
    message: str,
    event_key: str | None = None,
    service_id: int | None = None,
    service_type: str | None = None,
) -> NotificationEvent | None:
    et = str(event_type or "").strip().lower()
    if et not in EVENT_TYPES:
        raise ValueError("Invalid event_type")

    ev = NotificationEvent(
        user_id=int(user_id),
        task_id=(int(task_id) if task_id is not None else None),
        service_id=(int(service_id) if service_id is not None else None),
        service_type=(str(service_type).strip().lower() if service_type else None),
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


# ---- Sending ----------------------------------------------------------------------


def _send_notification_via_service(
    db: Session,
    *,
    svc: UserNotificationService,
    user: User,
    title: str,
    message_text: str,
    message_html: str | None,
    payload: dict,
) -> str:
    """Send a notification to a single configured service entry."""
    st = str(svc.service_type or "").strip().lower()
    cfg = _json_loads(svc.config_json)

    try:
        if st == CHANNEL_BROWSER:
            # Browser notifications are delivered via SSE from NotificationEvent rows.
            return "ok"

        if st == CHANNEL_EMAIL:
            to_address = str(cfg.get("to_address") or "").strip() or str(getattr(user, "email", "") or "").strip()
            if not to_address:
                raise ValueError("No recipient email address")
            subject = f"Timeboard: {title}"
            send_email(to_address=to_address, subject=subject, body_text=message_text, body_html=message_html, db=db)
            return "ok"

        if st == CHANNEL_GOTIFY:
            _send_gotify(config=cfg, title=title, message=message_text)
            return "ok"

        if st == CHANNEL_NTFY:
            _send_ntfy(config=cfg, title=title, message=message_text, click_url=str(payload.get("url") or "").strip() or None)
            return "ok"

        if st == CHANNEL_DISCORD:
            md = _build_discord_markdown(title=title, payload=payload)
            _send_discord(config=cfg, message=md or message_text)
            return "ok"

        if st == CHANNEL_WEBHOOK:
            _send_webhook(config=cfg, payload=payload)
            return "ok"

        if st == CHANNEL_GENERIC_API:
            _send_generic_api(config=cfg, payload=payload)
            return "ok"

        if st == CHANNEL_WNS:
            wns_cfg = get_wns_settings(db)
            if not wns_cfg.enabled:
                raise ValueError("WNS is disabled by admin")
            if not wns_cfg.package_sid or not wns_cfg.client_secret:
                raise ValueError("WNS is not configured (missing package_sid/client_secret)")

            channel_uri = str(cfg.get("channel_uri") or "").strip()
            if not channel_uri:
                raise ValueError("WNS channel_uri not set")

            token = _wns_get_access_token(package_sid=wns_cfg.package_sid, client_secret=wns_cfg.client_secret)
            _send_wns_toast(channel_uri=channel_uri, access_token=token, title=title, message=message_text)
            return "ok"

        return "error:unknown-service"
    except Exception as e:
        logger.warning("Notification send failed (%s svc_id=%s): %s", st, getattr(svc, "id", None), e)
        return f"error:{e}"


def notify_task_event(
    db: Session,
    *,
    task: Task,
    event_type: str,
    relevant_tag_ids: set[int] | None = None,
    event_key: str | None = None,
) -> None:
    """Send a task lifecycle notification.

    New model:
      - Each notification service entry has a generated routing tag.
      - If the task contains that tag, a notification is sent to that service.

    Legacy fallback:
      - If no services match, fall back to tag subscriptions + enabled channels.
    """
    et = str(event_type or "").strip().lower()
    if et not in EVENT_TYPES:
        raise ValueError("Invalid event_type")

    # Ensure tags are loaded.
    if not hasattr(task, "tags"):
        task = db.query(Task).options(joinedload(Task.tags)).filter(Task.id == int(task.id)).first() or task

    tag_ids = relevant_tag_ids
    if tag_ids is None:
        try:
            tag_ids = {int(t.id) for t in (task.tags or [])}
        except Exception:
            tag_ids = set()

    user = db.query(User).filter(User.id == int(task.user_id)).first()
    if not user:
        return

    # Find enabled services whose routing tag is present on this task.
    services: list[UserNotificationService] = []
    if tag_ids:
        services = (
            db.query(UserNotificationService)
            .filter(UserNotificationService.user_id == int(user.id))
            .filter(UserNotificationService.enabled.is_(True))
            .filter(UserNotificationService.tag_id.in_(sorted(tag_ids)))
            .order_by(UserNotificationService.id.asc())
            .all()
        )

    if services:
        title, msg_text, msg_html, payload = _build_task_notification(task=task, event_type=et)

        # Enrich payload with full tag list (names) and the internal task URL for convenience.
        payload.setdefault("task_internal_url", _task_internal_url(int(task.id)))

        for svc in services:
            svc_key = f"{event_key}:svc{int(svc.id)}" if event_key else None
            # Persist event for browser delivery and for dedupe of scheduled events.
            ev = create_notification_event(
                db,
                user_id=int(user.id),
                task_id=int(task.id) if getattr(task, "id", None) is not None else None,
                event_type=et,
                title=title,
                message=msg_text,
                event_key=svc_key,
                service_id=int(svc.id),
                service_type=str(svc.service_type),
            )
            if ev is None:
                # deduped
                continue

            # Enrich payload per service (useful for webhooks/APIs).
            payload2 = dict(payload)
            payload2["service"] = {
                "id": int(svc.id),
                "service_type": str(svc.service_type),
                "name": svc.name,
                "tag": (svc.tag.name if getattr(svc, "tag", None) is not None else None),
            }

            _send_notification_via_service(
                db,
                svc=svc,
                user=user,
                title=title,
                message_text=msg_text,
                message_html=msg_html,
                payload=payload2,
            )
        return

    # ---- Legacy fallback ---------------------------------------------------------

    if not tag_ids:
        return
    subscribed = get_user_notification_tag_ids(db, user_id=int(user.id))
    if not subscribed.intersection(tag_ids):
        return

    title, msg_text, msg_html, payload = _build_task_notification(task=task, event_type=et)

    # Deliver via enabled legacy channels.
    channels = (
        db.query(UserNotificationChannel)
        .filter(UserNotificationChannel.user_id == int(user.id))
        .filter(UserNotificationChannel.enabled.is_(True))
        .all()
    )

    if not channels:
        return

    for ch in channels:
        # Persist one NotificationEvent per channel so browser delivery can
        # filter on service_type, while also allowing per-channel dedupe for
        # scheduled events (e.g. past_due).
        ch_key = f"{event_key}:ch{str(ch.channel_type)}" if event_key else None
        ev = create_notification_event(
            db,
            user_id=int(user.id),
            task_id=int(task.id) if getattr(task, "id", None) is not None else None,
            event_type=et,
            title=title,
            message=msg_text,
            event_key=ch_key,
            service_id=None,
            service_type=str(ch.channel_type),
        )
        if ev is None:
            continue

        # Channel model is legacy 1-per-type; reuse the service sender by
        # adapting it into a fake service entry.
        tmp_svc = UserNotificationService(
            user_id=int(user.id),
            service_type=str(ch.channel_type),
            name=None,
            enabled=bool(ch.enabled),
            config_json=ch.config_json,
            tag_id=0,
        )
        _send_notification_via_service(
            db,
            svc=tmp_svc,
            user=user,
            title=title,
            message_text=msg_text,
            message_html=msg_html,
            payload=payload,
        )
