from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.crud import create_password_reset_token, create_task, create_user
from app.db import Base
from app.db_admin import purge_all_data
from app.demo_data import seed_demo_data
from app.demo_dunder_mifflin import reset_to_dunder_mifflin_demo
from app.migrations import ensure_db_schema
from app.models import (
    NotificationEvent,
    Tag,
    Task,
    User,
    UserNotificationChannel,
    UserNotificationService,
    UserNotificationTag,
)
from app.notifications import CHANNEL_BROWSER, create_user_notification_service


@pytest.fixture
def settings_tmp(tmp_path, monkeypatch):
    path = tmp_path / "settings.yml"
    db_file = tmp_path / "test.db"
    path.write_text(
        f"""
app:
  name: "TimeboardApp"
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

demo:
  enabled: false
  reset_interval_minutes: 0
  disable_external_apis: true
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


def test_seed_demo_data_creates_tasks_without_notifications(settings_tmp, tmp_path):
    db_path = tmp_path / "demo.db"
    engine = make_engine(str(db_path))
    init_full_schema(engine)

    db = make_session(engine)
    try:
        admin = create_user(db, username="admin", password="password123", is_admin=True)
        res = seed_demo_data(db, owner=admin)
        assert res.get("seeded") == 1
        assert int(res.get("tasks_created") or 0) > 0

        tasks = db.query(Task).all()
        assert len(tasks) == int(res.get("tasks_created"))
        # No notification events should be created for seed data.
        assert db.query(NotificationEvent).count() == 0

        # Idempotent: calling again should not create duplicates.
        res2 = seed_demo_data(db, owner=admin)
        assert res2.get("seeded") == 0
        assert db.query(Task).count() == len(tasks)
    finally:
        db.close()


def test_purge_all_data_deletes_tasks_tags_notifications_but_keeps_users(settings_tmp, tmp_path):
    db_path = tmp_path / "purge.db"
    engine = make_engine(str(db_path))
    init_full_schema(engine)

    db = make_session(engine)
    try:
        admin = create_user(db, username="admin", password="password123", is_admin=True)

        # Notification service + routed task (creates a NotificationEvent)
        svc = create_user_notification_service(db, user_id=int(admin.id), service_type=CHANNEL_BROWSER, name="Browser")
        create_task(
            db,
            owner=admin,
            name="Task",
            task_type="Type",
            due_date=datetime.utcnow().replace(tzinfo=timezone.utc) + timedelta(hours=1),
            tags=[svc.tag.name, "demo"],
        )

        # Password reset token
        create_password_reset_token(
            db,
            user=admin,
            token="tok123",
            expires_at_utc=datetime.utcnow().replace(tzinfo=timezone.utc) + timedelta(hours=1),
        )

        assert db.query(Task).count() == 1
        assert db.query(Tag).count() >= 1
        assert db.query(UserNotificationService).count() == 1
        assert db.query(NotificationEvent).count() == 1
        assert db.query(User).count() == 1

        counts = purge_all_data(db, preserve_users=True, preserve_app_meta=True)
        assert int(counts.get("tasks") or 0) >= 1
        assert int(counts.get("tags") or 0) >= 1

        # Data cleared
        assert db.query(Task).count() == 0
        assert db.query(Tag).count() == 0
        assert db.query(UserNotificationService).count() == 0
        assert db.query(UserNotificationChannel).count() == 0
        assert db.query(UserNotificationTag).count() == 0
        assert db.query(NotificationEvent).count() == 0

        # Users preserved
        assert db.query(User).count() == 1
    finally:
        db.close()


def test_dunder_demo_reset_seeds_org_chart_tasks_and_notifications(settings_tmp, tmp_path):
    db_path = tmp_path / "dunder.db"
    engine = make_engine(str(db_path))
    init_full_schema(engine)

    db = make_session(engine)
    try:
        res = reset_to_dunder_mifflin_demo(db)
        assert res.get("seeded") == 1
        assert int(res.get("users_created") or 0) >= 10
        assert int(res.get("tasks_created") or 0) >= 5
        assert int(res.get("notifications_created") or 0) >= 1

        # Manager/subordinate relationship should exist.
        michael = db.query(User).filter(User.username == "michael").first()
        jim = db.query(User).filter(User.username == "jim").first()
        assert michael is not None
        assert jim is not None
        assert int(jim.manager_id or 0) == int(michael.id)

        # Nested subtasks should exist.
        parent = db.query(Task).filter(Task.name == "Quarterly financial close").first()
        assert parent is not None
        children = db.query(Task).filter(Task.parent_task_id == int(parent.id)).all()
        assert len(children) >= 1
    finally:
        db.close()


def test_demo_mode_forces_external_services_disabled(settings_tmp, tmp_path, monkeypatch):
    # Enable demo mode.
    path = settings_tmp
    raw = path.read_text(encoding="utf-8")
    raw = raw.replace("demo:\n  enabled: false", "demo:\n  enabled: true")
    path.write_text(raw, encoding="utf-8")
    monkeypatch.setenv("TIMEBOARDAPP_SETTINGS", str(path))
    get_settings.cache_clear()

    db_path = tmp_path / "demo_block.db"
    engine = make_engine(str(db_path))
    init_full_schema(engine)

    db = make_session(engine)
    try:
        u = create_user(db, username="admin", password="demo", is_admin=True)
        svc = create_user_notification_service(db, user_id=int(u.id), service_type="webhook", enabled=True, config={"url": "https://example.invalid"})
        assert svc.enabled is False
    finally:
        db.close()
