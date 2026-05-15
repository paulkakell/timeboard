from __future__ import annotations

import os
from pathlib import Path

from app.config import get_settings
from app.permissions import secure_sqlite_database_permissions, sqlite_database_path


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_secure_sqlite_database_permissions_repairs_existing_database_and_sidecars(tmp_path):
    db_path = tmp_path / "timeboard.db"
    sidecars = [
        tmp_path / "timeboard.db-wal",
        tmp_path / "timeboard.db-shm",
        tmp_path / "timeboard.db-journal",
    ]
    for path in [db_path, *sidecars]:
        path.write_text("secret material", encoding="utf-8")
        os.chmod(path, 0o644)

    results = secure_sqlite_database_permissions(str(db_path))

    repaired = {r.path for r in results if r.changed}
    assert db_path in repaired
    assert set(sidecars).issubset(repaired)
    for path in [db_path, *sidecars]:
        assert _mode(path) == 0o600


def test_secure_sqlite_database_permissions_sets_private_umask_for_first_create(tmp_path):
    db_path = tmp_path / "first-run.db"
    previous_umask = os.umask(0o022)
    os.umask(previous_umask)
    try:
        secure_sqlite_database_permissions(str(db_path))
        db_path.write_text("created after permission helper", encoding="utf-8")
        assert _mode(db_path) == 0o600
    finally:
        os.umask(previous_umask)


def test_sqlite_database_path_accepts_sqlalchemy_sqlite_url(tmp_path):
    db_path = tmp_path / "url.db"
    assert sqlite_database_path(f"sqlite+pysqlite:///{db_path}") == db_path


def test_generated_settings_file_is_owner_only(tmp_path, monkeypatch):
    settings_path = tmp_path / "settings.yml"
    monkeypatch.setenv("TIMEBOARDAPP_SETTINGS", str(settings_path))
    get_settings.cache_clear()
    try:
        get_settings()
        assert _mode(settings_path) == 0o600
    finally:
        get_settings.cache_clear()
