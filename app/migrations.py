from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.engine import Engine

from .version import APP_VERSION


@dataclass
class MigrationReport:
    previous_db_version: Optional[str]
    current_db_version: str
    applied_steps: List[str]


def _parse_version(v: str) -> Tuple[int, int, int]:
    """Parse a semantic version string like '0.1.0'."""
    try:
        parts = (v or "").strip().split(".")
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        return major, minor, patch
    except Exception:
        return 0, 0, 0


def _table_exists(conn, table_name: str) -> bool:
    # SQLite-specific check.
    q = text("SELECT name FROM sqlite_master WHERE type='table' AND name=:t")
    row = conn.execute(q, {"t": table_name}).fetchone()
    return bool(row and row[0] == table_name)


def _column_exists(conn, table_name: str, column_name: str) -> bool:
    # SQLite PRAGMA table_info
    rows = conn.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
    for r in rows:
        # (cid, name, type, notnull, dflt_value, pk)
        if len(r) >= 2 and str(r[1]).lower() == column_name.lower():
            return True
    return False


def _get_meta(conn, key: str) -> Optional[str]:
    if not _table_exists(conn, "app_meta"):
        return None
    row = conn.execute(text("SELECT value FROM app_meta WHERE key=:k"), {"k": key}).fetchone()
    return str(row[0]) if row and row[0] is not None else None


def _set_meta(conn, key: str, value: str) -> None:
    # SQLite upsert
    conn.execute(
        text(
            "INSERT INTO app_meta(key, value, updated_at) VALUES (:k, :v, :u) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at"
        ),
        {"k": key, "v": value, "u": datetime.utcnow().replace(tzinfo=None)},
    )


def ensure_db_schema(engine: Engine) -> MigrationReport:
    """Ensure the database schema is compatible with the current app version.

    Timeboard ships without Alembic migrations. For small deployments, we keep
    schema upgrades lightweight and SQLite-friendly by applying additive
    migrations (new tables, new nullable columns, and indexes).

    Returns a report with any applied steps.
    """
    applied: List[str] = []

    with engine.begin() as conn:
        # Ensure the schema version table exists (for pre-versioned DBs).
        if not _table_exists(conn, "app_meta"):
            conn.execute(
                text(
                    "CREATE TABLE IF NOT EXISTS app_meta ("
                    "  key VARCHAR(64) PRIMARY KEY,"
                    "  value VARCHAR(255) NOT NULL,"
                    "  updated_at DATETIME NOT NULL"
                    ")"
                )
            )
            applied.append("create_table:app_meta")

        prev = _get_meta(conn, "db_version")

        # Add users.email (nullable).
        if _table_exists(conn, "users") and not _column_exists(conn, "users", "email"):
            conn.execute(text("ALTER TABLE users ADD COLUMN email VARCHAR(255)"))
            applied.append("alter_table:users:add_column:email")

        # Ensure unique index for users.email (helps older DBs where constraint didn't exist).
        # NOTE: SQLite allows multiple NULLs in UNIQUE indexes, which is what we want.
        if _table_exists(conn, "users"):
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email_unique ON users(email)"))

        # Ensure password reset token table exists (created via create_all in new DBs).
        if not _table_exists(conn, "password_reset_tokens"):
            conn.execute(
                text(
                    "CREATE TABLE IF NOT EXISTS password_reset_tokens ("
                    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    "  user_id INTEGER NOT NULL,"
                    "  token_hash VARCHAR(64) NOT NULL UNIQUE,"
                    "  expires_at_utc DATETIME NOT NULL,"
                    "  used_at_utc DATETIME NULL,"
                    "  created_at DATETIME NOT NULL,"
                    "  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE"
                    ")"
                )
            )
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_prt_user_id ON password_reset_tokens(user_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_prt_expires ON password_reset_tokens(expires_at_utc)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_prt_used ON password_reset_tokens(used_at_utc)"))
            applied.append("create_table:password_reset_tokens")

        # Set DB version to current app version (schema and app version are aligned for now).
        _set_meta(conn, "db_version", APP_VERSION)

        # Also store the app version that last booted against this DB.
        _set_meta(conn, "app_version", APP_VERSION)

    # If DB already had a version and it's newer than our app version, keep prev for reporting.
    # We still write app_version/db_version above to keep deployments consistent.
    return MigrationReport(previous_db_version=prev, current_db_version=APP_VERSION, applied_steps=applied)


def db_needs_upgrade(previous_db_version: Optional[str]) -> bool:
    if previous_db_version is None:
        return True
    return _parse_version(previous_db_version) < _parse_version(APP_VERSION)
