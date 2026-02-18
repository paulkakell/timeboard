import os
import secrets
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker

from app.auth import authenticate_user
from app.config import get_settings
from app.crud import (
    complete_task,
    consume_password_reset_token,
    create_password_reset_token,
    create_task,
    create_user,
    list_tasks,
    restore_task,
    soft_delete_task,
)
from app.db import Base
from app.db_admin import export_db_json, import_db_json
from app.migrations import ensure_db_schema
from app.models import AppMeta, TaskStatus, User
from app.version import APP_VERSION


@pytest.fixture
def settings_tmp(tmp_path, monkeypatch):
    """Isolate settings per test run."""
    path = tmp_path / "settings.yml"
    path.write_text(
        """
app:
  name: "Timeboard"
  timezone: "UTC"
  base_url: ""
security:
  session_secret: "test-session-secret"
  jwt_secret: "test-jwt-secret"
database:
  path: "{db}"
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
""".format(db=str(tmp_path / "test.db")).lstrip()
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


def test_create_task_without_due_date_uses_creation_time(settings_tmp, tmp_path):
    db_path = tmp_path / "db1.db"
    engine = make_engine(str(db_path))
    init_full_schema(engine)

    db = make_session(engine)
    try:
        u = create_user(db, username="u1", password="password123", email="u1@example.com")
        before = datetime.utcnow().replace(tzinfo=None)
        t = create_task(db, owner=u, name="T", task_type="TypeA", due_date=None)
        after = datetime.utcnow().replace(tzinfo=None)
        assert before - timedelta(seconds=2) <= t.due_date_utc <= after + timedelta(seconds=2)
    finally:
        db.close()


def test_archived_restore_flow(settings_tmp, tmp_path):
    db_path = tmp_path / "db2.db"
    engine = make_engine(str(db_path))
    init_full_schema(engine)

    db = make_session(engine)
    try:
        u = create_user(db, username="u2", password="password123")
        t = create_task(
            db,
            owner=u,
            name="Task",
            task_type="Type",
            due_date=datetime.utcnow().replace(tzinfo=timezone.utc) - timedelta(days=1),
        )

        when = datetime.utcnow().replace(tzinfo=None)
        soft_delete_task(db, task=t, current_user=u, when_utc=when)
        assert t.status == TaskStatus.deleted
        assert t.deleted_at_utc is not None

        restore_task(db, task=t, current_user=u)
        assert t.status == TaskStatus.active
        assert t.deleted_at_utc is None
        assert t.completed_at_utc is None

        completed, spawned = complete_task(db, task=t, current_user=u, when_utc=datetime.utcnow().replace(tzinfo=None))
        assert completed.status == TaskStatus.completed
        assert completed.completed_at_utc is not None

        restore_task(db, task=completed, current_user=u)
        assert completed.status == TaskStatus.active
    finally:
        db.close()


def test_authenticate_by_email(settings_tmp, tmp_path):
    db_path = tmp_path / "db3.db"
    engine = make_engine(str(db_path))
    init_full_schema(engine)

    db = make_session(engine)
    try:
        create_user(db, username="u3", password="password123", email="u3@example.com")
        assert authenticate_user(db, "u3", "password123") is not None
        assert authenticate_user(db, "u3@example.com", "password123") is not None
        assert authenticate_user(db, "u3@example.com", "wrong") is None
    finally:
        db.close()


def test_password_reset_token_flow(settings_tmp, tmp_path):
    db_path = tmp_path / "db4.db"
    engine = make_engine(str(db_path))
    init_full_schema(engine)

    db = make_session(engine)
    try:
        u = create_user(db, username="u4", password="password123", email="u4@example.com")

        token = secrets.token_urlsafe(32)
        expires = datetime.utcnow().replace(tzinfo=None) + timedelta(minutes=30)
        create_password_reset_token(db, user=u, token=token, expires_at_utc=expires)

        assert consume_password_reset_token(db, token=token, new_password="newpassword123", now_utc=datetime.utcnow())
        assert authenticate_user(db, "u4", "newpassword123") is not None

        # Token cannot be reused
        assert consume_password_reset_token(db, token=token, new_password="x" * 10, now_utc=datetime.utcnow()) is False
    finally:
        db.close()


def test_list_tasks_sort_by_task_type(settings_tmp, tmp_path):
    db_path = tmp_path / "db5.db"
    engine = make_engine(str(db_path))
    init_full_schema(engine)

    db = make_session(engine)
    try:
        u = create_user(db, username="u5", password="password123")
        due = datetime(2026, 1, 1, tzinfo=timezone.utc)
        create_task(db, owner=u, name="B", task_type="B", due_date=due)
        create_task(db, owner=u, name="A", task_type="A", due_date=due)
        create_task(db, owner=u, name="C", task_type="C", due_date=due)

        tasks = list_tasks(db, current_user=u, sort="task_type")
        assert [t.task_type for t in tasks] == ["A", "B", "C"]
    finally:
        db.close()


def test_db_export_import_roundtrip(settings_tmp, tmp_path):
    db_path = tmp_path / "db6.db"
    engine = make_engine(str(db_path))
    init_full_schema(engine)

    db = make_session(engine)
    try:
        u1 = create_user(db, username="u6", password="password123", email="u6@example.com")
        create_task(db, owner=u1, name="T1", task_type="Type", due_date=None, tags=["tag1", "tag2"])
        create_task(db, owner=u1, name="T2", task_type="Type", due_date=None, tags=["tag2"])

        exported = export_db_json(db)
        assert "users" in exported and "tasks" in exported and "tags" in exported and "task_tags" in exported

    finally:
        db.close()

    # Import into a fresh database
    db_path2 = tmp_path / "db6b.db"
    engine2 = make_engine(str(db_path2))
    init_full_schema(engine2)
    db2 = make_session(engine2)
    try:
        import_db_json(db2, exported, replace=True)

        assert db2.query(User).count() == 1
        assert db2.execute(text("SELECT COUNT(*) FROM tasks")).scalar_one() == 2
        assert db2.execute(text("SELECT COUNT(*) FROM tags")).scalar_one() == 2
        assert db2.execute(text("SELECT COUNT(*) FROM task_tags")).scalar_one() >= 3
    finally:
        db2.close()


def test_migration_from_unversioned_db_adds_email_and_meta(settings_tmp, tmp_path):
    db_path = tmp_path / "db7.db"
    engine = make_engine(str(db_path))

    # Create an "old" users table without the email column.
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY,
                    username VARCHAR(64) NOT NULL UNIQUE,
                    hashed_password VARCHAR(255) NOT NULL,
                    is_admin BOOLEAN NOT NULL DEFAULT 0,
                    theme VARCHAR(16) NOT NULL DEFAULT 'system',
                    purge_days INTEGER NOT NULL DEFAULT 15,
                    created_at DATETIME NOT NULL,
                    updated_at DATETIME NOT NULL
                );
                """
            )
        )

    # Now apply migrations and create the rest of the schema.
    report = ensure_db_schema(engine)
    Base.metadata.create_all(bind=engine)

    # Validate email column exists.
    with engine.begin() as conn:
        cols = [r[1] for r in conn.execute(text("PRAGMA table_info(users)"))]
        assert "email" in cols

    # Validate db_version is stored.
    db = make_session(engine)
    try:
        v = db.query(AppMeta).filter(AppMeta.key == "db_version").first()
        assert v is not None
        assert v.value == APP_VERSION
    finally:
        db.close()
