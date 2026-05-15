from __future__ import annotations

import importlib


def test_run_module_can_import_get_settings() -> None:
    """Regression: Docker entrypoint imports get_settings from app.config."""

    config = importlib.import_module("app.config")
    assert callable(getattr(config, "get_settings", None))

    run = importlib.import_module("app.run")
    assert callable(run.main)


def test_first_run_settings_file_is_created_with_runtime_secrets(tmp_path, monkeypatch) -> None:
    from app.config import get_settings

    settings_path = tmp_path / "nested" / "settings.yml"
    monkeypatch.setenv("TIMEBOARDAPP_SETTINGS", str(settings_path))
    get_settings.cache_clear()

    settings = get_settings()
    text = settings_path.read_text(encoding="utf-8")

    assert settings_path.exists()
    assert settings.security.session_secret != "CHANGE_ME_SESSION_SECRET"
    assert settings.security.jwt_secret != "CHANGE_ME_JWT_SECRET"
    assert "CHANGE_ME_SESSION_SECRET" not in text
    assert "CHANGE_ME_JWT_SECRET" not in text

    get_settings.cache_clear()

def test_existing_placeholder_settings_file_is_repaired_with_runtime_secrets(tmp_path, monkeypatch) -> None:
    from app.config import get_settings

    settings_path = tmp_path / "settings.yml"
    settings_path.write_text(
        f"""
app:
  name: "TimeboardApp"
  timezone: "UTC"
  port: 8888
security:
  session_secret: "CHANGE_ME_SESSION_SECRET"
  jwt_secret: "CHANGE_ME_JWT_SECRET"
database:
  path: "{tmp_path / 'repaired.db'}"
purge:
  default_days: 15
  interval_minutes: 5
logging:
  level: "INFO"
email:
  enabled: false
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("TIMEBOARDAPP_SETTINGS", str(settings_path))
    get_settings.cache_clear()

    settings = get_settings()
    repaired_text = settings_path.read_text(encoding="utf-8")

    assert len(settings.security.session_secret) >= 32
    assert len(settings.security.jwt_secret) >= 32
    assert settings.security.session_secret != settings.security.jwt_secret
    assert "CHANGE_ME_SESSION_SECRET" not in repaired_text
    assert "CHANGE_ME_JWT_SECRET" not in repaired_text


def test_weak_secret_env_overrides_are_ignored(tmp_path, monkeypatch) -> None:
    from app.config import get_settings

    settings_path = tmp_path / "settings.yml"
    settings_path.write_text(
        f"""
app:
  name: "TimeboardApp"
  timezone: "UTC"
security:
  session_secret: "strong-file-session-secret-123456789012345"
  jwt_secret: "strong-file-jwt-secret-123456789012345678"
database:
  path: "{tmp_path / 'env.db'}"
purge:
  default_days: 15
  interval_minutes: 5
logging:
  level: "INFO"
email:
  enabled: false
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("TIMEBOARDAPP_SETTINGS", str(settings_path))
    monkeypatch.setenv("TIMEBOARDAPP_SESSION_SECRET", "CHANGE_ME_SESSION_SECRET")
    monkeypatch.setenv("TIMEBOARDAPP_JWT_SECRET", "test-jwt-secret")
    get_settings.cache_clear()

    settings = get_settings()

    assert settings.security.session_secret == "strong-file-session-secret-123456789012345"
    assert settings.security.jwt_secret == "strong-file-jwt-secret-123456789012345678"
