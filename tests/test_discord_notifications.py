import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.crud import create_task, create_user
from app.db import Base
from app.migrations import ensure_db_schema
from app.notifications import CHANNEL_DISCORD, create_user_notification_service


@pytest.fixture
def settings_tmp(tmp_path, monkeypatch):
    path = tmp_path / "settings.yml"
    db_file = tmp_path / "test.db"
    path.write_text(
        f"""
app:
  name: "Timeboard"
  timezone: "UTC"
  base_url: "https://timeboard.example"
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


def test_discord_send_payload_uses_markdown_and_blocks_mentions(monkeypatch):
    from app import notifications

    captured = {}

    def fake_http_request(*, url, headers, data, method="POST", timeout=10):
        captured["url"] = url
        captured["headers"] = headers
        captured["data"] = data
        return 204, ""

    monkeypatch.setattr(notifications, "_http_request", fake_http_request)

    msg = "**CREATED** Test"
    notifications._send_discord(config={"url": "https://discord.example/webhook"}, message=msg)

    payload = json.loads(captured["data"].decode("utf-8"))
    assert payload["content"] == msg
    assert payload["allowed_mentions"] == {"parse": []}


def test_discord_send_truncates_overlong_messages(monkeypatch):
    from app import notifications

    captured = {}

    def fake_http_request(*, url, headers, data, method="POST", timeout=10):
        captured["data"] = data
        return 204, ""

    monkeypatch.setattr(notifications, "_http_request", fake_http_request)

    long_msg = "x" * 2100
    notifications._send_discord(config={"webhook_url": "https://discord.example/webhook"}, message=long_msg)
    payload = json.loads(captured["data"].decode("utf-8"))
    assert len(payload["content"]) <= 2000


def test_discord_service_sends_embed_with_hyperlinked_task_name(settings_tmp, tmp_path, monkeypatch):
    from app import notifications

    db_path = tmp_path / "discord.db"
    engine = make_engine(str(db_path))
    init_full_schema(engine)
    db = make_session(engine)
    try:
        u = create_user(db, username="u1", password="password123", email="u1@example.com")

        svc = create_user_notification_service(
            db,
            user_id=int(u.id),
            service_type=CHANNEL_DISCORD,
            name="Discord",
            config={"webhook_url": "https://discord.example/webhook"},
        )

        sent: list[dict] = []

        def fake_send_discord(*, config, message=None, embeds=None):
            sent.append({"message": message, "embeds": embeds, "config": config})

        monkeypatch.setattr(notifications, "_send_discord", fake_send_discord)

        create_task(
            db,
            owner=u,
            name="Task",
            task_type="Type",
            due_date=datetime.utcnow().replace(tzinfo=timezone.utc) + timedelta(hours=1),
            tags=[svc.tag.name],
        )

        assert notifications.wait_for_notification_dispatcher_idle(timeout=5.0)
        assert sent, "Expected a Discord notification to be sent"
        item = sent[0]
        embeds = item.get("embeds") or []
        assert embeds, "Expected an embed to be used when an absolute task URL is available"

        embed0 = embeds[0]
        assert embed0.get("title") == "Task"
        assert str(embed0.get("url") or "").startswith("https://timeboard.example/tasks/")
        # The embed description carries action + task_type.
        assert "CREATED" in str(embed0.get("description") or "")
        assert "Type" in str(embed0.get("description") or "")
        fields = embed0.get("fields") or []
        names = {str(f.get("name") or "") for f in fields if isinstance(f, dict)}
        assert "Due" in names
        assert "Tags" in names
        # Ensure routing tag is present in the Tags field.
        tags_field = next((f for f in fields if isinstance(f, dict) and f.get("name") == "Tags"), {})
        assert svc.tag.name in str(tags_field.get("value") or "")
    finally:
        db.close()
