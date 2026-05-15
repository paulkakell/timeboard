from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.auth import create_access_token
from app.crud import complete_task, create_in_app_notification, create_task, create_user
from app.db import Base, get_db
from app.migrations import ensure_db_schema
from app.models import User
from app.routers import api_homepage, api_metrics
from app.validation import documented_api_routes


@pytest.fixture
def settings_tmp(tmp_path, monkeypatch):
    path = tmp_path / "settings.yml"
    path.write_text(
        """
app:
  name: "TimeboardApp"
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
""".format(db=str(tmp_path / "metrics.db")).lstrip()
    )
    monkeypatch.setenv("TIMEBOARDAPP_SETTINGS", str(path))
    from app.config import get_settings

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


def make_client(Session):
    app = FastAPI()
    app.state.started_at_utc = datetime.utcnow().replace(tzinfo=None) - timedelta(seconds=10)
    app.include_router(api_metrics.router, prefix="/api/metrics")
    app.include_router(api_homepage.router, prefix="/api/homepage")

    def override_get_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def seed_metrics_data(Session):
    db = Session()
    try:
        admin = create_user(db, username="admin-metrics", password="password123", email="admin@example.com", is_admin=True)
        user = create_user(db, username="user-metrics", password="password123", email="user@example.com", is_admin=False)
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        create_task(db, owner=user, name="overdue", task_type="ops", due_date=now - timedelta(hours=2))
        create_task(db, owner=user, name="upcoming", task_type="ops", due_date=now + timedelta(hours=1))
        done = create_task(db, owner=user, name="done", task_type="ops", due_date=now + timedelta(hours=3))
        complete_task(db, task=done, current_user=user, when_utc=(now + timedelta(hours=1)).replace(tzinfo=None))
        create_in_app_notification(db, user_id=int(user.id), event_type="test", title="test", message="message")
        db.commit()
        return int(admin.id), int(user.id)
    finally:
        db.close()


def test_user_metrics_and_homepage_summary(settings_tmp, tmp_path):
    engine = make_engine(str(tmp_path / "metrics-user.db"))
    Base.metadata.create_all(bind=engine)
    ensure_db_schema(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    _admin_id, user_id = seed_metrics_data(Session)
    client = make_client(Session)

    token = create_access_token(subject="user-metrics", is_admin=False)

    response = client.get("/api/metrics/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    metrics = response.json()
    assert metrics["scope"] == "user"
    assert metrics["user"]["id"] == user_id
    assert metrics["tasks"]["active"] == 2
    assert metrics["tasks"]["completed"] == 1
    assert metrics["tasks"]["past_due"] == 1
    assert metrics["tasks"]["completed_7d"] == 1
    assert metrics["notifications"]["in_app_unread"] >= 1

    forbidden = client.get("/api/metrics/deployment", headers={"Authorization": f"Bearer {token}"})
    assert forbidden.status_code == 403

    homepage = client.get("/api/homepage/summary", headers={"Authorization": f"Bearer {token}"})
    assert homepage.status_code == 200
    summary = homepage.json()
    assert summary["status"] == "ok"
    assert summary["scope"] == "user"
    assert summary["active"] == 2
    assert summary["past_due"] == 1


def test_admin_metrics_exports_and_homepage_deployment(settings_tmp, tmp_path):
    engine = make_engine(str(tmp_path / "metrics-admin.db"))
    Base.metadata.create_all(bind=engine)
    ensure_db_schema(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    seed_metrics_data(Session)
    client = make_client(Session)

    token = create_access_token(subject="admin-metrics", is_admin=True)

    deployment = client.get("/api/metrics/deployment", headers={"Authorization": f"Bearer {token}"})
    assert deployment.status_code == 200
    assert deployment.json()["users"]["total"] == 2

    users = client.get("/api/metrics/users", headers={"Authorization": f"Bearer {token}"})
    assert users.status_code == 200
    assert len(users.json()["users"]) == 2

    prom = client.get("/api/metrics/prometheus", headers={"Authorization": f"Bearer {token}"})
    assert prom.status_code == 200
    assert "timeboardapp_info" in prom.text
    assert "timeboardapp_tasks_active" in prom.text

    influx = client.get("/api/metrics/influx", headers={"Authorization": f"Bearer {token}"})
    assert influx.status_code == 200
    assert "timeboardapp_deployment" in influx.text
    assert "timeboardapp_user" in influx.text

    homepage = client.get("/api/homepage/deployment", headers={"Authorization": f"Bearer {token}"})
    assert homepage.status_code == 200
    assert homepage.json()["scope"] == "deployment"

    homepage_users = client.get("/api/homepage/users", headers={"Authorization": f"Bearer {token}"})
    assert homepage_users.status_code == 200
    assert len(homepage_users.json()["users"]) == 2


def test_documented_api_routes_include_metrics_homepage_and_me_order():
    routes = {(row["method"], row["path"]) for row in documented_api_routes()}
    assert ("GET", "/api/metrics/prometheus") in routes
    assert ("GET", "/api/metrics/influx") in routes
    assert ("GET", "/api/homepage/summary") in routes
    assert ("GET", "/api/users/me") in routes
