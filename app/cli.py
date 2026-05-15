from __future__ import annotations

import argparse
import secrets
import sys
from pathlib import Path

from sqlalchemy.orm import Session

from .auth import hash_password
from .config import get_settings
from .crud import create_user, get_user_by_username
from .db import SessionLocal
from .validation import run_admin_validation


def _reset_admin_password(db: Session, *, username: str, new_password: str) -> None:
    user = get_user_by_username(db, username)
    if user:
        user.hashed_password = hash_password(new_password)
        # Safety: ensure the recovered account is actually an admin.
        user.is_admin = True
        db.add(user)
        db.commit()
        return

    create_user(db, username=username, password=new_password, is_admin=True)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="timeboardapp")
    sub = parser.add_subparsers(dest="command", required=True)

    p_reset = sub.add_parser(
        "reset-admin",
        help="Reset the admin password without knowing the current password.",
    )
    p_reset.add_argument(
        "--username",
        default="admin",
        help="Admin username to reset (default: admin)",
    )
    p_reset.add_argument(
        "--password",
        default=None,
        help="New password. If omitted, a random password is generated.",
    )
    p_reset.add_argument(
        "--print",
        action="store_true",
        help="Print the new password even when --password is provided.",
    )

    p_validate = sub.add_parser(
        "validate",
        help="Run full feature and security validation and print a pasteable log.",
    )
    p_validate.add_argument(
        "--base-url",
        default=None,
        help="Loopback base URL for live HTTP checks, for example http://127.0.0.1:8888.",
    )
    p_validate.add_argument(
        "--output",
        default=None,
        help="Optional path for the output log file. The default writes under the validation log directory.",
    )
    p_validate.add_argument(
        "--no-write-log",
        action="store_true",
        help="Print the report without writing the default validation log file.",
    )

    args = parser.parse_args(argv)

    if args.command == "reset-admin":
        new_password: str = args.password or secrets.token_urlsafe(12)
        with SessionLocal() as db:
            _reset_admin_password(db, username=args.username, new_password=new_password)

        if args.password is None or args.print:
            # Intentionally prints to stdout so operators can copy/paste.
            print(new_password)
        else:
            print("ok")
        return

    if args.command == "validate":
        settings = get_settings()
        base_url = args.base_url or f"http://127.0.0.1:{int(settings.app.port)}"
        output_path = Path(args.output).expanduser() if args.output else None
        output_is_file = bool(output_path and output_path.suffix)
        log_dir = None if output_is_file else output_path

        with SessionLocal() as db:
            report = run_admin_validation(
                db,
                actor="cli",
                base_url=base_url,
                log_dir=log_dir,
                write_log=(not bool(args.no_write_log) and not output_is_file),
            )

        if output_path and output_is_file:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            report.log_path = str(output_path)
            text = report.to_text()
            output_path.write_text(text, encoding="utf-8")
        else:
            text = report.to_text()
        print(text, end="")
        sys.exit(1 if report.has_failures else 0)

    parser.print_help()
    sys.exit(2)


if __name__ == "__main__":
    main()
