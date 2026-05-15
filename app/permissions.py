from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:  # SQLAlchemy is a required runtime dependency, but keep this helper defensive.
    from sqlalchemy.engine import make_url
except Exception:  # pragma: no cover - dependency import fallback
    make_url = None  # type: ignore[assignment]


PRIVATE_RUNTIME_UMASK = 0o077
SECURE_SECRET_FILE_MODE = 0o600
SECURE_DATA_DIR_MODE = 0o750


@dataclass(frozen=True)
class FilePermissionRepair:
    """Result from a best-effort file permission repair."""

    path: Path
    existed: bool
    changed: bool = False
    mode_before: int | None = None
    mode_after: int | None = None
    error: str | None = None


def apply_private_runtime_umask() -> int | None:
    """Force private default permissions for runtime-created files.

    SQLite creates database files through the process umask. Docker's default
    umask commonly yields 0644 files, which exposes database contents to any
    local account that can read the mounted volume. A 0077 umask makes newly
    created files owner-only by default and is safe whether the process runs as
    root, as a numeric Docker PUID, or as an explicitly supplied user.
    """

    try:
        return os.umask(PRIVATE_RUNTIME_UMASK)
    except Exception:
        return None


def sqlite_database_path(database_path: str | os.PathLike[str] | None) -> Path | None:
    """Return the SQLite database file path from a settings value or URL."""

    raw = str(database_path or "").strip()
    if not raw or raw == ":memory:":
        return None

    if raw.startswith("sqlite:") or raw.startswith("sqlite+"):
        if make_url is not None:
            try:
                parsed = make_url(raw)
                if not str(parsed.drivername or "").startswith("sqlite"):
                    return None
                parsed_database = str(parsed.database or "").strip()
                if not parsed_database or parsed_database == ":memory:":
                    return None
                return Path(parsed_database).expanduser()
            except Exception:
                pass

        # Defensive fallback for common sqlite:/// paths.
        marker = "///"
        if marker in raw:
            parsed_database = raw.split(marker, 1)[1]
            if parsed_database and parsed_database != ":memory:":
                return Path(parsed_database).expanduser()
        return None

    return Path(raw).expanduser()


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def _repair_file(path: Path, *, target_mode: int = SECURE_SECRET_FILE_MODE) -> FilePermissionRepair:
    try:
        if not path.exists():
            return FilePermissionRepair(path=path, existed=False)
        before = _mode(path)
        changed = False
        if before != target_mode:
            os.chmod(path, target_mode)
            changed = True
        after = _mode(path)
        return FilePermissionRepair(path=path, existed=True, changed=changed, mode_before=before, mode_after=after)
    except Exception as exc:
        return FilePermissionRepair(path=path, existed=path.exists(), error=f"{type(exc).__name__}: {exc}")


def _ensure_parent_directory(path: Path) -> FilePermissionRepair:
    parent = path.parent
    try:
        before: int | None = None
        existed = parent.exists()
        if existed:
            before = _mode(parent)
        parent.mkdir(parents=True, exist_ok=True, mode=SECURE_DATA_DIR_MODE)
        after = _mode(parent)
        return FilePermissionRepair(path=parent, existed=existed, changed=(before is not None and before != after), mode_before=before, mode_after=after)
    except Exception as exc:
        return FilePermissionRepair(path=parent, existed=parent.exists(), error=f"{type(exc).__name__}: {exc}")


def sqlite_related_paths(database_file: Path) -> list[Path]:
    """Return SQLite database and sidecar files that can contain DB content."""

    name = database_file.name
    parent = database_file.parent
    return [
        database_file,
        parent / f"{name}-wal",
        parent / f"{name}-shm",
        parent / f"{name}-journal",
    ]


def secure_sqlite_database_permissions(
    database_path: str | os.PathLike[str] | None,
    *,
    ensure_parent: bool = True,
) -> list[FilePermissionRepair]:
    """Apply private permissions to a SQLite database and related files.

    The function is intentionally best-effort. Startup should continue if a
    read-only bind mount prevents chmod, but validation will still report the
    permission problem so operators can fix the host path.
    """

    apply_private_runtime_umask()
    database_file = sqlite_database_path(database_path)
    if database_file is None:
        return []

    results: list[FilePermissionRepair] = []
    if ensure_parent:
        results.append(_ensure_parent_directory(database_file))
    for path in sqlite_related_paths(database_file):
        results.append(_repair_file(path))
    return results


def secure_settings_file_permissions(settings_path: str | os.PathLike[str] | None) -> FilePermissionRepair | None:
    """Apply private permissions to settings.yml when it exists."""

    if not settings_path:
        return None
    apply_private_runtime_umask()
    return _repair_file(Path(settings_path).expanduser())
