from __future__ import annotations

"""Database-backed application settings.

Timeboard historically loaded some settings from settings.yml. For settings that
must be editable from the UI (email, logging retention, notification
integration credentials), we store values in the `app_meta` table.

This module provides typed helpers over that key/value store.
"""

import json
from dataclasses import dataclass
from typing import Any, Dict

from sqlalchemy.orm import Session

from .models import AppMeta


# ----------------------------
# Low-level helpers
# ----------------------------


def _get_meta_value(db: Session, key: str) -> str | None:
    row = db.query(AppMeta).filter(AppMeta.key == key).first()
    if not row:
        return None
    v = row.value
    return None if v is None else str(v)


def _set_meta_value(db: Session, key: str, value: str) -> None:
    k = str(key)
    v = str(value)
    row = db.query(AppMeta).filter(AppMeta.key == k).first()
    if row:
        row.value = v
        db.add(row)
        return
    db.add(AppMeta(key=k, value=v))


def _get_bool(db: Session, key: str, default: bool) -> bool:
    raw = _get_meta_value(db, key)
    if raw is None:
        return bool(default)
    s = str(raw).strip().lower()
    if s in {"1", "true", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "no", "n", "off"}:
        return False
    return bool(default)


def _get_int(
    db: Session,
    key: str,
    default: int,
    *,
    min_value: int | None = None,
    max_value: int | None = None,
) -> int:
    raw = _get_meta_value(db, key)
    if raw is None:
        v = int(default)
    else:
        try:
            v = int(str(raw).strip())
        except Exception:
            v = int(default)
    if min_value is not None and v < min_value:
        v = int(min_value)
    if max_value is not None and v > max_value:
        v = int(max_value)
    return v


def _get_str(db: Session, key: str, default: str) -> str:
    raw = _get_meta_value(db, key)
    if raw is None:
        return str(default)
    return str(raw)


def _get_json(db: Session, key: str, default: dict) -> dict:
    raw = _get_meta_value(db, key)
    if raw is None:
        return dict(default)
    try:
        val = json.loads(str(raw))
        if isinstance(val, dict):
            return val
    except Exception:
        pass
    return dict(default)


def _set_json(db: Session, key: str, value: dict) -> None:
    _set_meta_value(db, key, json.dumps(value, separators=(",", ":"), sort_keys=True))


# ----------------------------
# Email settings
# ----------------------------


EMAIL_ENABLED_KEY = "email.enabled"
EMAIL_SMTP_HOST_KEY = "email.smtp_host"
EMAIL_SMTP_PORT_KEY = "email.smtp_port"
EMAIL_SMTP_USERNAME_KEY = "email.smtp_username"
EMAIL_SMTP_PASSWORD_KEY = "email.smtp_password"
EMAIL_SMTP_FROM_KEY = "email.smtp_from"
EMAIL_USE_TLS_KEY = "email.use_tls"
EMAIL_REMINDER_INTERVAL_MINUTES_KEY = "email.reminder_interval_minutes"
EMAIL_RESET_TOKEN_MINUTES_KEY = "email.reset_token_minutes"


@dataclass
class EmailConfig:
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = "timeboard@localhost"
    use_tls: bool = True
    reminder_interval_minutes: int = 60
    reset_token_minutes: int = 60


def get_email_settings(db: Session) -> EmailConfig:
    """Read email settings from app_meta."""
    return EmailConfig(
        enabled=_get_bool(db, EMAIL_ENABLED_KEY, False),
        smtp_host=_get_str(db, EMAIL_SMTP_HOST_KEY, "").strip(),
        smtp_port=_get_int(db, EMAIL_SMTP_PORT_KEY, 587, min_value=1, max_value=65535),
        smtp_username=_get_str(db, EMAIL_SMTP_USERNAME_KEY, ""),
        smtp_password=_get_str(db, EMAIL_SMTP_PASSWORD_KEY, ""),
        smtp_from=_get_str(db, EMAIL_SMTP_FROM_KEY, "timeboard@localhost"),
        use_tls=_get_bool(db, EMAIL_USE_TLS_KEY, True),
        reminder_interval_minutes=_get_int(
            db,
            EMAIL_REMINDER_INTERVAL_MINUTES_KEY,
            60,
            min_value=0,
            max_value=60 * 24 * 7,
        ),
        reset_token_minutes=_get_int(
            db,
            EMAIL_RESET_TOKEN_MINUTES_KEY,
            60,
            min_value=5,
            max_value=60 * 24 * 7,
        ),
    )


def set_email_settings(
    db: Session,
    *,
    enabled: bool,
    smtp_host: str,
    smtp_port: int,
    smtp_username: str,
    smtp_password: str | None,
    smtp_from: str,
    use_tls: bool,
    reminder_interval_minutes: int,
    reset_token_minutes: int,
    keep_existing_password: bool = False,
) -> EmailConfig:
    """Persist email settings to app_meta.

    If keep_existing_password is True and smtp_password is empty/None, the
    existing value is preserved.
    """

    host = (smtp_host or "").strip()
    from_addr = (smtp_from or "").strip() or "timeboard@localhost"

    try:
        port = int(smtp_port)
    except Exception as e:
        raise ValueError("smtp_port must be an integer") from e
    if port < 1 or port > 65535:
        raise ValueError("smtp_port must be between 1 and 65535")

    try:
        rem = int(reminder_interval_minutes)
    except Exception as e:
        raise ValueError("reminder_interval_minutes must be an integer") from e
    if rem < 0 or rem > 60 * 24 * 7:
        raise ValueError("reminder_interval_minutes must be between 0 and 10080")

    try:
        ttl = int(reset_token_minutes)
    except Exception as e:
        raise ValueError("reset_token_minutes must be an integer") from e
    if ttl < 5 or ttl > 60 * 24 * 7:
        raise ValueError("reset_token_minutes must be between 5 and 10080")

    _set_meta_value(db, EMAIL_ENABLED_KEY, "true" if bool(enabled) else "false")
    _set_meta_value(db, EMAIL_SMTP_HOST_KEY, host)
    _set_meta_value(db, EMAIL_SMTP_PORT_KEY, str(port))
    _set_meta_value(db, EMAIL_SMTP_USERNAME_KEY, str(smtp_username or ""))

    pw = "" if smtp_password is None else str(smtp_password)
    if keep_existing_password and not pw:
        # preserve
        pass
    else:
        _set_meta_value(db, EMAIL_SMTP_PASSWORD_KEY, pw)

    _set_meta_value(db, EMAIL_SMTP_FROM_KEY, from_addr)
    _set_meta_value(db, EMAIL_USE_TLS_KEY, "true" if bool(use_tls) else "false")
    _set_meta_value(db, EMAIL_REMINDER_INTERVAL_MINUTES_KEY, str(rem))
    _set_meta_value(db, EMAIL_RESET_TOKEN_MINUTES_KEY, str(ttl))
    db.commit()

    return get_email_settings(db)


def seed_email_settings_from_legacy_yaml(db: Session, legacy_email: Any) -> None:
    """Seed app_meta email settings from legacy settings.yml.

    This only fills missing keys; it will not overwrite values that are already
    present in the database.
    """

    if legacy_email is None:
        return

    keys = [
        EMAIL_ENABLED_KEY,
        EMAIL_SMTP_HOST_KEY,
        EMAIL_SMTP_PORT_KEY,
        EMAIL_SMTP_USERNAME_KEY,
        EMAIL_SMTP_PASSWORD_KEY,
        EMAIL_SMTP_FROM_KEY,
        EMAIL_USE_TLS_KEY,
        EMAIL_REMINDER_INTERVAL_MINUTES_KEY,
        EMAIL_RESET_TOKEN_MINUTES_KEY,
    ]

    missing = [k for k in keys if _get_meta_value(db, k) is None]
    if not missing:
        return

    enabled = bool(getattr(legacy_email, "enabled", False))
    smtp_host = str(getattr(legacy_email, "smtp_host", "") or "")
    smtp_port = int(getattr(legacy_email, "smtp_port", 587) or 587)
    smtp_username = str(getattr(legacy_email, "smtp_username", "") or "")
    smtp_password = str(getattr(legacy_email, "smtp_password", "") or "")
    smtp_from = str(getattr(legacy_email, "smtp_from", "timeboard@localhost") or "timeboard@localhost")
    use_tls = bool(getattr(legacy_email, "use_tls", True))
    reminder_interval_minutes = int(getattr(legacy_email, "reminder_interval_minutes", 60) or 60)
    reset_token_minutes = int(getattr(legacy_email, "reset_token_minutes", 60) or 60)

    defaults: Dict[str, str] = {
        EMAIL_ENABLED_KEY: "true" if enabled else "false",
        EMAIL_SMTP_HOST_KEY: smtp_host,
        EMAIL_SMTP_PORT_KEY: str(smtp_port),
        EMAIL_SMTP_USERNAME_KEY: smtp_username,
        EMAIL_SMTP_PASSWORD_KEY: smtp_password,
        EMAIL_SMTP_FROM_KEY: smtp_from,
        EMAIL_USE_TLS_KEY: "true" if use_tls else "false",
        EMAIL_REMINDER_INTERVAL_MINUTES_KEY: str(reminder_interval_minutes),
        EMAIL_RESET_TOKEN_MINUTES_KEY: str(reset_token_minutes),
    }

    for k in missing:
        _set_meta_value(db, k, defaults.get(k, ""))
    db.commit()


# ----------------------------
# Logging settings
# ----------------------------


LOGGING_LEVEL_KEY = "logging.level"
LOGGING_RETENTION_DAYS_KEY = "logging.retention_days"

LOG_LEVELS = {"DEBUG", "INFO", "WARN", "WARNING", "ERROR", "CRITICAL"}


@dataclass
class LoggingConfig:
    level: str = "INFO"
    retention_days: int = 30


def get_logging_settings(db: Session) -> LoggingConfig:
    level = _get_str(db, LOGGING_LEVEL_KEY, "INFO").strip().upper()
    if level == "WARNING":
        level = "WARN"
    if level not in LOG_LEVELS:
        level = "INFO"
    retention = _get_int(db, LOGGING_RETENTION_DAYS_KEY, 30, min_value=0, max_value=3650)
    return LoggingConfig(level=level, retention_days=retention)


def set_logging_settings(db: Session, *, level: str, retention_days: int) -> LoggingConfig:
    lvl = (level or "").strip().upper()
    if lvl == "WARNING":
        lvl = "WARN"
    if lvl not in LOG_LEVELS:
        raise ValueError("Invalid log level")
    try:
        rd = int(retention_days)
    except Exception as e:
        raise ValueError("retention_days must be an integer") from e
    if rd < 0 or rd > 3650:
        raise ValueError("retention_days must be between 0 and 3650")

    _set_meta_value(db, LOGGING_LEVEL_KEY, lvl)
    _set_meta_value(db, LOGGING_RETENTION_DAYS_KEY, str(rd))
    db.commit()
    return get_logging_settings(db)


def seed_logging_settings_from_legacy_yaml(db: Session, legacy_logging: Any) -> None:
    if legacy_logging is None:
        return

    missing = []
    for k in (LOGGING_LEVEL_KEY, LOGGING_RETENTION_DAYS_KEY):
        if _get_meta_value(db, k) is None:
            missing.append(k)
    if not missing:
        return

    lvl = str(getattr(legacy_logging, "level", "INFO") or "INFO").strip().upper()
    if lvl not in LOG_LEVELS:
        lvl = "INFO"

    defaults: Dict[str, str] = {
        LOGGING_LEVEL_KEY: lvl,
        LOGGING_RETENTION_DAYS_KEY: "30",
    }
    for k in missing:
        _set_meta_value(db, k, defaults.get(k, ""))
    db.commit()


# ----------------------------
# WNS (Windows Push Notification Services) settings
# ----------------------------


WNS_ENABLED_KEY = "wns.enabled"
WNS_PACKAGE_SID_KEY = "wns.package_sid"
WNS_CLIENT_SECRET_KEY = "wns.client_secret"


@dataclass
class WNSConfig:
    enabled: bool = False
    package_sid: str = ""
    client_secret: str = ""


def get_wns_settings(db: Session) -> WNSConfig:
    return WNSConfig(
        enabled=_get_bool(db, WNS_ENABLED_KEY, False),
        package_sid=_get_str(db, WNS_PACKAGE_SID_KEY, "").strip(),
        client_secret=_get_str(db, WNS_CLIENT_SECRET_KEY, ""),
    )


def set_wns_settings(
    db: Session,
    *,
    enabled: bool,
    package_sid: str,
    client_secret: str | None,
    keep_existing_secret: bool = False,
) -> WNSConfig:
    _set_meta_value(db, WNS_ENABLED_KEY, "true" if bool(enabled) else "false")
    _set_meta_value(db, WNS_PACKAGE_SID_KEY, str(package_sid or "").strip())
    secret = "" if client_secret is None else str(client_secret)
    if keep_existing_secret and not secret:
        pass
    else:
        _set_meta_value(db, WNS_CLIENT_SECRET_KEY, secret)
    db.commit()
    return get_wns_settings(db)
