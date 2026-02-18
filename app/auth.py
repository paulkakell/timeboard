from __future__ import annotations

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
from .models import User


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


def authenticate_user(db: Session, username_or_email: str, password: str) -> Optional[User]:
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
