from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from typing import Iterable, Optional

from .config import get_settings


logger = logging.getLogger("timeboard.email")


def email_enabled() -> bool:
    s = get_settings()
    if not s.email.enabled:
        return False
    if not s.email.smtp_host:
        return False
    return True


def _smtp_connect():
    s = get_settings()
    server = smtplib.SMTP(s.email.smtp_host, int(s.email.smtp_port), timeout=20)
    try:
        server.ehlo()
        if s.email.use_tls:
            server.starttls()
            server.ehlo()
        if s.email.smtp_username:
            server.login(s.email.smtp_username, s.email.smtp_password)
        return server
    except Exception:
        try:
            server.quit()
        except Exception as e:
            logger.debug("SMTP quit failed: %s", e)
        raise


def send_email(*, to_address: str, subject: str, body_text: str, body_html: Optional[str] = None) -> None:
    """Send an email using SMTP settings.

    Raises on failure. Callers should catch exceptions and log.
    """
    s = get_settings()
    if not email_enabled():
        raise RuntimeError("Email is not configured (email.enabled=false or smtp_host missing)")

    msg = EmailMessage()
    msg["From"] = s.email.smtp_from
    msg["To"] = to_address
    msg["Subject"] = subject
    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    server = _smtp_connect()
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
