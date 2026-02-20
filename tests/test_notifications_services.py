import pytest
from datetime import datetime, timezone, timedelta

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.crud import create_task, create_user
from app.migrations import ensure_db_schema
from app.models import NotificationEvent
from app.notifications import CHANNEL_BROWSER, create_user_notification_service
from app.db import Base


@pytest.fixture
def settings_tmp(tmp_path, monkeypatch):
    path = tmp_path / "settings.yml"
    db_file = tmp_path / "test.db"
    path.write_text(
        f"""
app:
  name: "Timeboard"
  timezone: "UTC"
  base_url: ""
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
    monkeypatch.setenv("TIMEBOARD_SETTINGS", str(path))
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


def test_create_browser_service_generates_tag_and_sends_created_event(settings_tmp, tmp_path):
    db_path = tmp_path / "n1.db"
    engine = make_engine(str(db_path))
    init_full_schema(engine)

    db = make_session(engine)
    try:
        u = create_user(db, username="u1", password="password123", email="u1@example.com")

        svc = create_user_notification_service(
            db,
            user_id=int(u.id),
            service_type=CHANNEL_BROWSER,
            name="My browser",
        )
        assert svc.tag is not None
        assert svc.tag.name.startswith("notify:")
        assert ":browser:" in svc.tag.name

        create_task(
            db,
            owner=u,
            name="Test Task",
            task_type="Type",
            due_date=datetime.utcnow().replace(tzinfo=timezone.utc) + timedelta(hours=1),
            tags=[svc.tag.name, "other"],
        )

        events = db.query(NotificationEvent).filter(NotificationEvent.user_id == int(u.id)).all()
        assert len(events) == 1
        ev = events[0]
        assert ev.service_id == int(svc.id)
        assert ev.service_type == "browser"
        assert ev.event_type == "created"
        assert (ev.message or "").startswith("CREATED:")

    finally:
        db.close()


def test_disabled_service_does_not_send(settings_tmp, tmp_path):
    db_path = tmp_path / "n2.db"
    engine = make_engine(str(db_path))
    init_full_schema(engine)

    db = make_session(engine)
    try:
        u = create_user(db, username="u2", password="password123", email="u2@example.com")
        svc = create_user_notification_service(
            db,
            user_id=int(u.id),
            service_type=CHANNEL_BROWSER,
            enabled=False,
        )

        create_task(
            db,
            owner=u,
            name="No notify",
            task_type="Type",
            due_date=datetime.utcnow().replace(tzinfo=timezone.utc) + timedelta(hours=1),
            tags=[svc.tag.name],
        )

        events = db.query(NotificationEvent).filter(NotificationEvent.user_id == int(u.id)).all()
        assert events == []
    finally:
        db.close()


def test_multiple_service_tags_create_multiple_events(settings_tmp, tmp_path):
    db_path = tmp_path / "n3.db"
    engine = make_engine(str(db_path))
    init_full_schema(engine)

    db = make_session(engine)
    try:
        u = create_user(db, username="u3", password="password123", email="u3@example.com")

        svc1 = create_user_notification_service(db, user_id=int(u.id), service_type=CHANNEL_BROWSER, name="A")
        svc2 = create_user_notification_service(db, user_id=int(u.id), service_type=CHANNEL_BROWSER, name="B")

        create_task(
            db,
            owner=u,
            name="Multi notify",
            task_type="Type",
            due_date=datetime.utcnow().replace(tzinfo=timezone.utc) + timedelta(hours=1),
            tags=[svc1.tag.name, svc2.tag.name],
        )

        events = (
            db.query(NotificationEvent)
            .filter(NotificationEvent.user_id == int(u.id))
            .order_by(NotificationEvent.id.asc())
            .all()
        )
        assert len(events) == 2
        service_ids = {ev.service_id for ev in events}
        assert service_ids == {int(svc1.id), int(svc2.id)}
        assert {ev.service_type for ev in events} == {"browser"}
    finally:
        db.close()
