from __future__ import annotations

import os
import shutil
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict

import yaml
from pydantic import BaseModel, Field


DEFAULT_SETTINGS_PATH = os.environ.get("TIMEBOARD_SETTINGS", "/data/settings.yml")


class AppSettings(BaseModel):
    name: str = "Timeboard"
    timezone: str = "UTC"
    host: str = "0.0.0.0"  # nosec B104
    port: int = 8888
    base_url: str = ""


class SecuritySettings(BaseModel):
    session_secret: str = "CHANGE_ME_SESSION_SECRET"
    jwt_secret: str = "CHANGE_ME_JWT_SECRET"


class DatabaseSettings(BaseModel):
    path: str = "/data/timeboard.db"


class PurgeSettings(BaseModel):
    default_days: int = 15
    interval_minutes: int = 60


class EmailSettings(BaseModel):
    # When disabled, password reset and reminders are not sent.
    enabled: bool = False

    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""

    smtp_from: str = "timeboard@localhost"

    # If True, use STARTTLS.
    use_tls: bool = True

    # Overdue reminder cadence.
    reminder_interval_minutes: int = 60

    # Password reset token TTL.
    reset_token_minutes: int = 60


class LoggingSettings(BaseModel):
    level: str = "INFO"


class Settings(BaseModel):
    app: AppSettings = Field(default_factory=AppSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    purge: PurgeSettings = Field(default_factory=PurgeSettings)
    email: EmailSettings = Field(default_factory=EmailSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)


def _ensure_settings_file(path: str) -> None:
    p = Path(path)
    if p.exists():
        return

    p.parent.mkdir(parents=True, exist_ok=True)

    # Copy sample settings into place to make first-run behavior predictable.
    sample = Path(__file__).resolve().parent.parent / "settings.sample.yml"
    if sample.exists():
        shutil.copy(sample, p)
    else:
        # Minimal fallback
        p.write_text(
            "app:\n  name: 'Timeboard'\n  timezone: 'UTC'\n  host: '0.0.0.0'\n  port: 8888\n"
            "security:\n  session_secret: 'CHANGE_ME_SESSION_SECRET'\n  jwt_secret: 'CHANGE_ME_JWT_SECRET'\n"
            "database:\n  path: '/data/timeboard.db'\n"
            "purge:\n  default_days: 15\n  interval_minutes: 60\n"
            "email:\n  enabled: false\n  smtp_host: ''\n  smtp_port: 587\n  smtp_username: ''\n  smtp_password: ''\n  smtp_from: 'timeboard@localhost'\n  use_tls: true\n  reminder_interval_minutes: 60\n  reset_token_minutes: 60\n"
        )


def _load_yaml(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError("settings.yml must contain a YAML mapping at the root")
    return data


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings_path = os.environ.get("TIMEBOARD_SETTINGS", DEFAULT_SETTINGS_PATH)
    _ensure_settings_file(settings_path)
    raw = _load_yaml(settings_path)
    s = Settings.model_validate(raw)

    # Allow env overrides for secrets.
    session_secret = os.environ.get("TIMEBOARD_SESSION_SECRET")
    jwt_secret = os.environ.get("TIMEBOARD_JWT_SECRET")
    if session_secret:
        s.security.session_secret = session_secret
    if jwt_secret:
        s.security.jwt_secret = jwt_secret

    # Public base URL override (useful for external notifications).
    base_url_env = os.environ.get("TIMEBOARD_BASE_URL")
    if base_url_env:
        s.app.base_url = str(base_url_env).strip()

    # Port override is occasionally useful in container orchestration.
    port_env = os.environ.get("PORT") or os.environ.get("TIMEBOARD_PORT")
    if port_env:
        try:
            s.app.port = int(port_env)
        except ValueError:
            pass

    return s
