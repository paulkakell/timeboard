from __future__ import annotations

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


def _sqlite_url(db_path: str) -> str:
    # Ensure absolute path for sqlite file.
    if db_path.startswith("sqlite:"):
        return db_path
    return f"sqlite:///{db_path}"


settings = get_settings()
engine = create_engine(
    _sqlite_url(settings.database.path),
    connect_args={"check_same_thread": False},
)


@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    # Enforce foreign key constraints for ON DELETE CASCADE.
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
