#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from pathlib import Path

PRIVATE_RUNTIME_UMASK = 0o077
DATA_DIR_MODE = 0o750


def _parse_int_env(name: str, default: int) -> int:
    value = str(os.environ.get(name, "")).strip()
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _truthy_env(name: str, default: bool = True) -> bool:
    value = str(os.environ.get(name, "")).strip().lower()
    if not value:
        return default
    return value not in {"0", "false", "no", "off"}


def _settings_parent() -> Path:
    raw = os.environ.get("TIMEBOARDAPP_SETTINGS") or os.environ.get("TIMEBOARD_SETTINGS") or "/data/settings.yml"
    return Path(raw).expanduser().parent


def _managed_data_dirs() -> list[Path]:
    dirs = [Path("/data"), _settings_parent()]
    unique: list[Path] = []
    for path in dirs:
        if not str(path) or str(path) == "/":
            continue
        resolved = path.resolve() if path.exists() else path
        if resolved not in unique:
            unique.append(resolved)
    return unique


def _ensure_dirs(paths: list[Path]) -> None:
    for path in paths:
        try:
            path.mkdir(parents=True, exist_ok=True, mode=DATA_DIR_MODE)
            current = path.stat().st_mode & 0o777
            if current & 0o007:
                os.chmod(path, current & ~0o007)
        except Exception:
            # The app will report path/permission problems during startup or
            # Admin Validation. Do not prevent startup for read-only mounts.
            continue


def _chown_tree(paths: list[Path], *, uid: int, gid: int) -> None:
    for root in paths:
        if not root.exists():
            continue
        for current_root, dirs, files in os.walk(root):
            for name in [*dirs, *files]:
                target = Path(current_root) / name
                try:
                    os.lchown(target, uid, gid)
                except Exception:
                    continue
        try:
            os.lchown(root, uid, gid)
        except Exception:
            continue


def _drop_privileges(*, uid: int, gid: int) -> None:
    if os.geteuid() != 0 or uid == 0:
        return
    try:
        os.setgroups([])
    except Exception:
        pass
    os.setgid(gid)
    os.setuid(uid)
    os.environ.setdefault("HOME", "/data")


def main() -> None:
    os.umask(PRIVATE_RUNTIME_UMASK)
    command = sys.argv[1:] or ["python", "-m", "app.run"]
    managed_dirs = _managed_data_dirs()

    _ensure_dirs(managed_dirs)

    if os.geteuid() == 0:
        target_uid = _parse_int_env("PUID", 1000)
        target_gid = _parse_int_env("PGID", target_uid)
        if target_uid != 0 and _truthy_env("TIMEBOARDAPP_CHOWN_DATA", True):
            _chown_tree(managed_dirs, uid=target_uid, gid=target_gid)
        _drop_privileges(uid=target_uid, gid=target_gid)

    os.execvp(command[0], command)


if __name__ == "__main__":
    main()
