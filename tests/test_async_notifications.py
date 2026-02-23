from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.crud import create_task, create_user
from app.db import Base
from app.migrations import ensure_db_schema
from app.models import NotificationEvent
from app.notifications import CHANNEL_WEBHOOK, create_user_notification_service


@pytest.fixture
def settings_tmp(tmp_path, monkeypatch):
    path = tmp_path / "settings.yml"
    db_file = tmp_path / "test.db"
    path.write_text(
        f"""
app:
  name: "TimeboardApp"
  timezone: "UTC"
  base_url: "https://timeboardapp.example"
security:
  session_secret: "test-session-secret"
  jwt_secret: "test-jwt-secret"
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


def test_async_notification_failure_updates_event_log(settings_tmp, tmp_path):
    from app import notifications

    db_path = tmp_path / "async.db"
    engine = make_engine(str(db_path))
    init_full_schema(engine)
    db = make_session(engine)
    try:
        u = create_user(db, username="u1", password="password123", email="u1@example.com")

        # Create a webhook service with a deliberately disallowed URL scheme to
        # force a deterministic failure without network access.
        svc = create_user_notification_service(
            db,
            user_id=int(u.id),
            service_type=CHANNEL_WEBHOOK,
            name="Webhook",
            config={"url": "file:///etc/passwd"},
        )

        create_task(
            db,
            owner=u,
            name="Task",
            task_type="Type",
            due_date=datetime.utcnow().replace(tzinfo=timezone.utc) + timedelta(hours=1),
            tags=[svc.tag.name],
        )

        assert notifications.wait_for_notification_dispatcher_idle(timeout=5.0)

        ev = db.query(NotificationEvent).order_by(NotificationEvent.id.asc()).first()
        assert ev is not None
        assert ev.service_type == "webhook"
        assert ev.delivery_status == notifications.DELIVERY_FAILED
        assert ev.delivery_attempts == 1
        assert ev.last_attempt_at_utc is not None
        assert ev.delivered_at_utc is None
        assert ev.delivery_error is not None
        assert "Invalid notification URL" in str(ev.delivery_error)
    finally:
        db.close()
