import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.auth import create_access_token
from app.crud import create_user
from app.db import Base, get_db
from app.migrations import ensure_db_schema
from app.routers import api_users


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
""".format(db=str(tmp_path / "users-me.db")).lstrip()
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


def test_api_users_me_route_is_not_captured_by_user_id_route(settings_tmp, tmp_path):
    engine = make_engine(str(tmp_path / "users-me-route.db"))
    Base.metadata.create_all(bind=engine)
    ensure_db_schema(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    db = Session()
    try:
        user = create_user(db, username="me-user", password="password123", email="me@example.com")
        user_id = int(user.id)
    finally:
        db.close()

    app = FastAPI()
    app.include_router(api_users.router, prefix="/api/users")

    def override_get_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    token = create_access_token(subject="me-user", is_admin=False)
    client = TestClient(app)
    response = client.get("/api/users/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json()["id"] == user_id
    assert response.json()["username"] == "me-user"
