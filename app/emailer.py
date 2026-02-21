from __future__ import annotations

import logging
import socket
import smtplib
import json
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from typing import Iterable, Optional
from urllib import request
from urllib.error import HTTPError, URLError

from sqlalchemy.orm import Session

from .db import SessionLocal
from .meta_settings import EmailConfig, get_email_settings


logger = logging.getLogger("timeboard.email")


SMTP_CONNECT_TIMEOUT_SECONDS = 20

SENDGRID_SEND_ENDPOINT = "https://api.sendgrid.com/v3/mail/send"
SENDGRID_TIMEOUT_SECONDS = 20


EMAIL_PROVIDER_SMTP = "smtp"
EMAIL_PROVIDER_SENDGRID = "sendgrid"


def _safe_smtp_host_for_logs(host: str) -> str:
    """Return a log-safe SMTP host string.

    Users occasionally paste URLs or include credentials. We strip common
    prefixes/suffixes and any embedded credentials to avoid leaking secrets.
    """

    raw = str(host or "").strip()
    if not raw:
        return "<empty>"

    # Strip scheme.
    if "://" in raw:
        raw = raw.split("://", 1)[1]

    # Strip credentials.
    if "@" in raw:
        raw = raw.split("@", 1)[1]

    # Strip any path/query.
    raw = raw.split("/", 1)[0]
    raw = raw.split("?", 1)[0]

    # Strip brackets around IPv6 literals.
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]

    # Strip an accidentally-included ":port" suffix (common UI mistake).
    if raw.count(":") == 1:
        left, right = raw.rsplit(":", 1)
        if right.isdigit():
            raw = left

    return raw or "<empty>"


def _load_email_config(db: Session | None = None) -> EmailConfig:
    if db is not None:
        return get_email_settings(db)
    s = SessionLocal()
    try:
        return get_email_settings(s)
    finally:
        s.close()


def email_enabled(db: Session | None = None) -> bool:
    cfg = _load_email_config(db)
    if not bool(cfg.enabled):
        return False
    provider = str(getattr(cfg, "provider", "") or "").strip().lower() or EMAIL_PROVIDER_SMTP
    if provider == EMAIL_PROVIDER_SENDGRID:
        return bool(str(getattr(cfg, "sendgrid_api_key", "") or "").strip())
    if not str(cfg.smtp_host or "").strip():
        return False
    return True


def _safe_http_snippet(body: bytes | str | None, *, limit: int = 400) -> str:
    if body is None:
        return ""
    if isinstance(body, bytes):
        txt = body.decode("utf-8", errors="replace")
    else:
        txt = str(body)
    txt = " ".join(txt.split())
    if len(txt) > int(limit):
        return txt[: int(limit)] + "…"
    return txt


def _parse_sendgrid_addresses(raw: str) -> list[dict]:
    pairs = getaddresses([raw or ""])
    out: list[dict] = []
    for name, email in pairs:
        em = str(email or "").strip()
        if not em:
            continue
        d: dict = {"email": em}
        nm = str(name or "").strip()
        if nm:
            d["name"] = nm
        out.append(d)
    return out


def _send_via_sendgrid(
    *,
    cfg: EmailConfig,
    to_address: str,
    subject: str,
    body_text: str,
    body_html: Optional[str] = None,
) -> None:
    api_key = str(getattr(cfg, "sendgrid_api_key", "") or "").strip()
    if not api_key:
        raise RuntimeError("SendGrid is not configured (missing API key)")

    tos = _parse_sendgrid_addresses(to_address)
    if not tos:
        raise ValueError("No recipient email address")

    from_name, from_email = parseaddr(str(cfg.smtp_from or "").strip())
    from_email = str(from_email or "").strip() or str(cfg.smtp_from or "").strip() or "timeboard@localhost"
    from_obj: dict = {"email": from_email}
    if str(from_name or "").strip():
        from_obj["name"] = str(from_name).strip()

    content: list[dict] = [{"type": "text/plain", "value": str(body_text or "")}]
    if body_html:
        content.append({"type": "text/html", "value": str(body_html)})

    payload = {
        "personalizations": [{"to": tos}],
        "from": from_obj,
        "subject": str(subject or ""),
        "content": content,
    }

    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    req = request.Request(SENDGRID_SEND_ENDPOINT, data=data, method="POST")
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "timeboard")

    timeout = int(SENDGRID_TIMEOUT_SECONDS)
    try:
        # URL is a constant SendGrid HTTPS endpoint (not user-controlled).
        with request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            code = getattr(resp, "status", None) or resp.getcode()
            if code is None:
                return
            if int(code) >= 400:
                snippet = _safe_http_snippet(getattr(resp, "read", lambda: b"")())
                raise RuntimeError(f"SendGrid API error {int(code)}: {snippet}")
            # SendGrid success is 202 Accepted.
            return
    except HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        snippet = _safe_http_snippet(body)
        raise RuntimeError(f"SendGrid API error {int(getattr(e, 'code', 0) or 0)}: {snippet}") from e
    except (socket.timeout, TimeoutError) as e:
        raise RuntimeError(f"SendGrid request timed out after {timeout}s") from e
    except URLError as e:
        reason = getattr(e, "reason", None)
        raise RuntimeError(f"SendGrid request failed: {reason}") from e


def _smtp_connect(cfg: EmailConfig):
    host = _safe_smtp_host_for_logs(str(cfg.smtp_host))
    port = int(cfg.smtp_port)
    timeout = int(SMTP_CONNECT_TIMEOUT_SECONDS)

    try:
        server = smtplib.SMTP(host, port, timeout=timeout)
    except (socket.timeout, TimeoutError) as e:
        hint = ""
        if host in {"localhost", "127.0.0.1", "::1"}:
            hint = " (Docker note: 'localhost' inside the container refers to the container itself)"
        raise RuntimeError(
            f"SMTP connect to {host}:{port} timed out after {timeout}s{hint}"
        ) from e
    except socket.gaierror as e:
        raise RuntimeError(f"SMTP hostname lookup failed for {host}: {e}") from e
    except OSError as e:
        raise RuntimeError(f"SMTP connect to {host}:{port} failed: {e.__class__.__name__}: {e}") from e
    try:
        server.ehlo()
        if bool(cfg.use_tls):
            try:
                server.starttls()
            except smtplib.SMTPNotSupportedError as e:
                raise RuntimeError(
                    f"SMTP STARTTLS is not supported by {host}:{port} (disable 'Use STARTTLS' or use a STARTTLS-enabled port)"
                ) from e
            server.ehlo()
        if cfg.smtp_username:
            try:
                server.login(cfg.smtp_username, cfg.smtp_password)
            except smtplib.SMTPAuthenticationError as e:
                raise RuntimeError(
                    f"SMTP authentication failed for {host}:{port} (check smtp_username/smtp_password)"
                ) from e
        return server
    except Exception:
        try:
            server.quit()
        except Exception as e:
            logger.debug("SMTP quit failed: %s", e)
        raise


def send_email(
    *,
    to_address: str,
    subject: str,
    body_text: str,
    body_html: Optional[str] = None,
    db: Session | None = None,
) -> None:
    """Send an email using the configured email provider.

    Raises on failure. Callers should catch exceptions and log.
    """
    cfg = _load_email_config(db)
    if not email_enabled(db):
        provider = str(getattr(cfg, "provider", "") or "").strip().lower() or EMAIL_PROVIDER_SMTP
        if provider == EMAIL_PROVIDER_SENDGRID:
            raise RuntimeError("Email is not configured (email.enabled=false or sendgrid_api_key missing)")
        raise RuntimeError("Email is not configured (email.enabled=false or smtp_host missing)")

    provider = str(getattr(cfg, "provider", "") or "").strip().lower() or EMAIL_PROVIDER_SMTP
    if provider == EMAIL_PROVIDER_SENDGRID:
        _send_via_sendgrid(
            cfg=cfg,
            to_address=to_address,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
        )
        return

    msg = EmailMessage()
    msg["From"] = cfg.smtp_from
    msg["To"] = to_address
    msg["Subject"] = subject
    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    server = _smtp_connect(cfg)
    try:
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except Exception as e:
            logger.debug("SMTP quit failed: %s", e)


def build_overdue_reminder_email(*, username: str, tasks: Iterable[dict], dashboard_url: str) -> tuple[str, str]:
    """Return (subject, body_text) for an overdue reminder."""
    subject = "Timeboard overdue tasks reminder"
    lines = [f"Hello {username},", "", "The following tasks are overdue:", ""]

    count = 0
    for t in tasks:
        count += 1
        name = t.get("name") or "(unnamed)"
        due = t.get("due") or ""
        task_type = t.get("task_type") or ""
        lines.append(f"- {name} [{task_type}] (due {due})")

    if count == 0:
        lines = [f"Hello {username},", "", "You have no overdue tasks."]
    else:
        lines.extend(["", f"Open dashboard: {dashboard_url}", ""])

    return subject, "\n".join(lines)


def build_password_reset_email(*, username: str, reset_url: str) -> tuple[str, str]:
    subject = "Timeboard password reset"
    body = (
        f"Hello {username},\n\n"
        "A password reset was requested for your Timeboard account. "
        "If you did not request this, you can ignore this email.\n\n"
        f"Reset your password using this link (expires soon):\n{reset_url}\n"
    )
    return subject, body
