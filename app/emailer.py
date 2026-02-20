from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from typing import Iterable, Optional

from sqlalchemy.orm import Session

from .db import SessionLocal
from .meta_settings import EmailConfig, get_email_settings


logger = logging.getLogger("timeboard.email")


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
    if not str(cfg.smtp_host or "").strip():
        return False
    return True


def _smtp_connect(cfg: EmailConfig):
    server = smtplib.SMTP(str(cfg.smtp_host), int(cfg.smtp_port), timeout=20)
    try:
        server.ehlo()
        if bool(cfg.use_tls):
            server.starttls()
            server.ehlo()
        if cfg.smtp_username:
            server.login(cfg.smtp_username, cfg.smtp_password)
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
    """Send an email using SMTP settings.

    Raises on failure. Callers should catch exceptions and log.
    """
    cfg = _load_email_config(db)
    if not email_enabled(db):
        raise RuntimeError("Email is not configured (email.enabled=false or smtp_host missing)")

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
