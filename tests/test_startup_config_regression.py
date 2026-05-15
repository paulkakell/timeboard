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
