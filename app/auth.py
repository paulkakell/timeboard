from __future__ import annotations

import logging
import secrets

from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import Theme, User


# Use PBKDF2-SHA256 instead of bcrypt.
#
# Rationale:
# - The upstream `bcrypt` Python package enforces a hard 72-byte password limit.
# - `passlib`'s bcrypt handler is also known to break with newer bcrypt releases
#   (e.g., removal of bcrypt.__about__). This caused container startup failures.
# - PBKDF2-SHA256 is implemented fully in passlib and has no external binary
#   dependency, making docker builds more stable.
pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto",
    # Tune rounds for a reasonable security/performance balance on small servers.
    pbkdf2_sha256__rounds=200_000,
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


logger = logging.getLogger("timeboardapp.auth")


def ensure_admin_user(db: Session) -> None:
    """Ensure at least one admin account exists.

    This is intentionally called during login attempts so deployments that lose
    their admin user (e.g., via a failed import) can self-heal.

    If no admin user exists:
    - If a user with username 'admin' exists, promote it to admin and reset its password.
    - Otherwise, create a new 'admin' user.

    The randomized password is written to the container logs.
    """
    try:
        existing_admin = db.query(User).filter(User.is_admin.is_(True)).first()
        if existing_admin:
            return

        admin_password = secrets.token_urlsafe(12)

        existing_admin_username = db.query(User).filter(User.username == "admin").first()
        if existing_admin_username:
            existing_admin_username.is_admin = True
            existing_admin_username.hashed_password = hash_password(admin_password)
            db.add(existing_admin_username)
            db.commit()

            logger.warning("============================================================")
            logger.warning("TimeboardApp admin recovery: existing 'admin' user promoted")
            logger.warning("Username: admin")
            logger.warning("Password: %s", admin_password)
            logger.warning("Please log in and change this password.")
            logger.warning("============================================================")
            return

        settings = get_settings()
        u = User(
            username="admin",
            email=None,
            hashed_password=hash_password(admin_password),
            is_admin=True,
            purge_days=int(settings.purge.default_days),
            theme=Theme.system.value,
        )
        db.add(u)
        db.commit()

        logger.warning("============================================================")
        logger.warning("TimeboardApp admin recovery: new admin user created")
        logger.warning("Username: admin")
        logger.warning("Password: %s", admin_password)
        logger.warning("Please log in and change this password.")
        logger.warning("============================================================")

    except Exception:
        # Never block login flows on recovery failures.
        try:
            db.rollback()
        except Exception:
            pass
        logger.exception("Failed to auto-create admin user on login attempt")


def authenticate_user(db: Session, username_or_email: str, password: str) -> Optional[User]:
    ensure_admin_user(db)
    ident = (username_or_email or "").strip()
    if not ident:
        return None

    # Allow login with either username or email.
    q = db.query(User).filter(
        or_(
            User.username == ident,
            func.lower(User.email) == ident.lower(),
        )
    )
    user = q.first()
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def create_access_token(*, subject: str, is_admin: bool, expires_minutes: int = 60 * 24) -> str:
    settings = get_settings()
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode = {
        "sub": subject,
        "exp": expire,
        "admin": bool(is_admin),
    }
    return jwt.encode(to_encode, settings.security.jwt_secret, algorithm="HS256")


def _decode_token(token: str) -> dict:
    settings = get_settings()
    return jwt.decode(token, settings.security.jwt_secret, algorithms=["HS256"])


def get_current_user_api(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = _decode_token(token)
        username: str | None = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user


def require_admin_api(current_user: User = Depends(get_current_user_api)) -> User:
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user


def get_current_user_session(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def require_admin_session(current_user: User = Depends(get_current_user_session)) -> User:
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user
