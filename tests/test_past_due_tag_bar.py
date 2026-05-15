import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.crud import create_task, create_user, list_past_due_tags_for_user, soft_delete_task
from app.db import Base
from app.migrations import ensure_db_schema
from app.routers.ui import _past_due_tag_bar_enabled, _save_past_due_tag_bar_pref


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
  session_secret: "test-session-secret-for-tag-bar-123456"
  jwt_secret: "test-jwt-secret-for-tag-bar-123456789"
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


def test_past_due_tag_query_returns_only_active_overdue_tags(settings_tmp, tmp_path):
    db_path = tmp_path / "past_due_tags.db"
    engine = make_engine(str(db_path))
    init_full_schema(engine)

    db = make_session(engine)
    try:
        user = create_user(db, username="tagbar", password="password123", email="tagbar@example.com")
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        create_task(
            db,
            owner=user,
            name="Past due",
            task_type="Validation",
            due_date=now - timedelta(hours=2),
            tags=["urgent", "shared"],
        )
        create_task(
            db,
            owner=user,
            name="Future",
            task_type="Validation",
            due_date=now + timedelta(hours=2),
            tags=["future", "shared"],
        )
        deleted = create_task(
            db,
            owner=user,
            name="Deleted past due",
            task_type="Validation",
            due_date=now - timedelta(days=1),
            tags=["deleted-only"],
        )
        soft_delete_task(db, task=deleted, current_user=user, when_utc=datetime.utcnow().replace(tzinfo=None))

        rows = list_past_due_tags_for_user(db, user=user)
        by_name = {row["name"]: row["task_count"] for row in rows}

        assert by_name == {"shared": 1, "urgent": 1}
    finally:
        db.close()


def test_past_due_tag_bar_preference_preserves_existing_ui_prefs(settings_tmp, tmp_path):
    db_path = tmp_path / "past_due_prefs.db"
    engine = make_engine(str(db_path))
    init_full_schema(engine)

    db = make_session(engine)
    try:
        user = create_user(db, username="pref", password="password123", email="pref@example.com")
        user.ui_prefs_json = '{"calendar":{"filters":{"completed":false},"view":"dayGridMonth"}}'
        db.add(user)
        db.commit()

        assert _past_due_tag_bar_enabled(user) is False
        _save_past_due_tag_bar_pref(db, user=user, enabled=True)
        db.refresh(user)

        data = json.loads(user.ui_prefs_json)
        assert data["calendar"]["view"] == "dayGridMonth"
        assert data["past_due_tag_bar"]["enabled"] is True
        assert _past_due_tag_bar_enabled(user) is True

        _save_past_due_tag_bar_pref(db, user=user, enabled=False)
        db.refresh(user)
        assert json.loads(user.ui_prefs_json)["past_due_tag_bar"]["enabled"] is False
    finally:
        db.close()
