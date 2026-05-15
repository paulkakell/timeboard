from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

import pytest

from app.config import get_settings
from app.db import Base
from app.migrations import ensure_db_schema
from app.models import User
from app.validation import redact_validation_text, run_admin_validation


@pytest.fixture
def settings_tmp(tmp_path, monkeypatch):
    path = tmp_path / "settings.yml"
    db_file = tmp_path / "validation.db"
    path.write_text(
        f"""
app:
  name: "TimeboardApp"
  timezone: "UTC"
  port: 8888
  base_url: ""
security:
  session_secret: "validation-session-secret-123456789012"
  jwt_secret: "validation-jwt-secret-1234567890123456"
database:
  path: "{db_file}"
purge:
  default_days: 15
  interval_minutes: 5
logging:
  level: "INFO"
email:
  enabled: false
  smtp_host: ""
  smtp_port: 587
  smtp_user: ""
  smtp_password: ""
  from_address: ""
  reminder_interval_minutes: 60
  reset_token_minutes: 60
""".lstrip()
    )
    monkeypatch.setenv("TIMEBOARDAPP_SETTINGS", str(path))
    get_settings.cache_clear()
    return path


def make_engine(db_path: str):
    engine = create_engine(
        f"sqlite+pysqlite:///{db_path}",
        connect_args={"check_same_thread": False},
        future=True,
    )

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


def make_session(engine):
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    return Session()


def init_full_schema(engine):
    Base.metadata.create_all(bind=engine)
    ensure_db_schema(engine)


def test_validation_log_redacts_known_secret(settings_tmp):
    settings = get_settings()
    raw = f"session_secret={settings.security.session_secret}\napi_key=abc123\n"
    redacted = redact_validation_text(raw)
    assert settings.security.session_secret not in redacted
    assert "api_key=<redacted>" in redacted


def test_admin_validation_runs_and_cleans_isolated_records(settings_tmp, tmp_path):
    db_path = tmp_path / "validation_run.db"
    engine = make_engine(str(db_path))
    init_full_schema(engine)

    db = make_session(engine)
    try:
        report = run_admin_validation(db, actor="pytest", base_url=None, write_log=False)
        names = [u.username for u in db.query(User).all()]
        assert not any(name.startswith("tbval") for name in names)
        assert any(f.name == "Past-due tag bar data source" and f.status == "PASS" for f in report.findings)
        assert any(f.name == "Isolated validation fixture cleanup" and f.status == "PASS" for f in report.findings)
        assert "TimeboardApp validation report" in report.to_text()
    finally:
        db.close()

def test_dependency_inventory_normalizes_distribution_names() -> None:
    from app.validation import _normalize_package_name

    assert _normalize_package_name("pip_audit") == "pip-audit"
    assert _normalize_package_name("python.multipart") == "python-multipart"
    assert _normalize_package_name("SQLAlchemy") == "sqlalchemy"

