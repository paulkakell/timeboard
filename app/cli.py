from __future__ import annotations

import argparse
import secrets
import sys

from sqlalchemy.orm import Session

from .auth import hash_password
from .crud import create_user, get_user_by_username
from .db import SessionLocal


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

    parser.print_help()
    sys.exit(2)


if __name__ == "__main__":
    main()
