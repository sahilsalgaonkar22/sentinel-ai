"""
SENTINEL AI — Identity Auth Utilities

PRODUCTION SECURITY:
- create_access_token always includes a jti (JWT ID) for revocation support.
- Uses datetime.now(timezone.utc) instead of deprecated utcnow().
- Constant-time password verification via passlib.
- No debug token paths, no bypass functions.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional
import uuid

from jose import jwt
from passlib.context import CryptContext
from backend.common.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password with constant-time comparison (bcrypt)."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a signed JWT.

    Always includes:
      - exp: expiry timestamp
      - iat: issued-at (for freshness checks)
      - jti: unique token ID (for revocation support)
    """
    to_encode = data.copy()
    now = datetime.now(timezone.utc)

    expire = now + (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    to_encode.update({
        "exp": expire,
        "iat": now,
        "jti": str(uuid.uuid4()),   # Unique ID — used by revocation blacklist
    })

    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
