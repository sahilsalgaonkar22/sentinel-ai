"""
SENTINEL AI — Auth Routes
Login, Register, Refresh, and user info endpoints.

SECURITY: No dev fallback, no debug token bypass.
All auth requires successful DB verification.

GAP-6 FIX: /auth/refresh endpoint — rotates access token without re-login.
  - Validates the current token (must not be expired)
  - Revokes the old JTI immediately (no token reuse)
  - Issues a new token with fresh exp + jti
"""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from backend.common.database import get_db_session
from backend.services.identity.models import User, Organization
from backend.services.identity.auth import get_password_hash, verify_password, create_access_token
from backend.schemas.auth import UserCreate, UserResponse, Token
from backend.gateway.middleware.auth import get_current_user, revoke_token
from fastapi.security import OAuth2PasswordRequestForm
from slowapi import Limiter
from slowapi.util import get_remote_address
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["authentication"])
from backend.gateway.limiter import limiter
# ✅ FINAL FIX: Precomputed dummy hash (no bcrypt at startup)
# This avoids:
# - bcrypt 72-byte limit crash
# - passlib/bcrypt compatibility issues
# - container restart loops
_DUMMY_HASH: str = "$2b$12$C6UzMDM.H6dfI/f/IKcEeOeWkQ1e6e9z7F3Vv9Yx8RJWb1x1oG6Ga"


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_in: UserCreate, db: AsyncSession = Depends(get_db_session)):
    result = await db.execute(select(User).where(User.email == user_in.email))
    user = result.scalar_one_or_none()
    if user:
        raise HTTPException(status_code=400, detail="User already registered")

    org_id = user_in.org_id

    # If no org_id but org_name is provided, auto-create/find the org
    if not org_id and hasattr(user_in, 'org_name') and user_in.org_name:
        import re, uuid
        slug = re.sub(r'[^a-z0-9]+', '-', user_in.org_name.lower()).strip('-')
        result = await db.execute(select(Organization).where(Organization.slug == slug))
        org = result.scalar_one_or_none()
        if not org:
            org = Organization(
                id=str(uuid.uuid4()),
                name=user_in.org_name,
                slug=slug,
                plan="free",
                is_active=True,
                max_scans_per_day=10,
                max_assets=50,
            )
            db.add(org)
            await db.flush()
        org_id = org.id
    elif not org_id:
        # Default org fallback
        result = await db.execute(select(Organization).limit(1))
        org = result.scalar_one_or_none()
        if org:
            org_id = org.id
        else:
            import uuid
            org = Organization(
                id=str(uuid.uuid4()),
                name="Default Org",
                slug="default-org",
                plan="free",
                is_active=True,
                max_scans_per_day=10,
                max_assets=50,
            )
            db.add(org)
            await db.flush()
            org_id = org.id

    if org_id:
        result = await db.execute(select(Organization).where(Organization.id == org_id))
        org = result.scalar_one_or_none()
        if not org:
            raise HTTPException(
                status_code=400,
                detail=f"Organization '{org_id}' not found."
            )
        if not org.is_active:
            raise HTTPException(status_code=403, detail="Organization is disabled")

    new_user = User(
        email=user_in.email,
        username=user_in.username or user_in.email.split('@')[0],
        hashed_password=get_password_hash(user_in.password),
        full_name=user_in.full_name,
        role=user_in.role or "viewer",
        org_id=org_id,
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    return new_user


@router.post("/login", response_model=Token)
@limiter.limit("5/minute")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db_session),
):
    try:
        result = await db.execute(select(User).where(User.email == form_data.username))
        user = result.scalar_one_or_none()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable",
        )

    password_ok = verify_password(
        form_data.password,
        user.hashed_password if user else _DUMMY_HASH
    )

    if not user or not password_ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect credentials",
        )

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")

    access_token = create_access_token(data={
        "sub": user.id,
        "email": user.email,
        "role": user.role,
        "org_id": user.org_id,
    })

    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me")
async def get_me(user: dict = Depends(get_current_user)):
    return {
        "id": user["user_id"],
        "email": user.get("email"),
        "role": user["role"],
        "org_id": user["org_id"],
    }


@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(request: Request, user: dict = Depends(get_current_user)):
    """
    Revoke the current JWT. The JTI is blacklisted in Redis for the remainder
    of the token's natural TTL — works across all gateway replicas instantly.
    """
    jti: str = user.get("jti", "")
    exp: int = user.get("exp", 0)

    if jti:
        now_ts = datetime.now(timezone.utc).timestamp()
        remaining_ttl = max(int(exp - now_ts), 1)
        await revoke_token(jti, remaining_ttl, request)

    return {"detail": "Logged out successfully. Token has been revoked."}


@router.post("/refresh", response_model=Token)
async def refresh_token(
    request: Request,
    user: dict = Depends(get_current_user),
):
    """
    GAP-6 FIX: Token refresh — rotate access token without re-login.

    The current token must be valid (not expired, not revoked).
    On success:
      1. The existing JTI is immediately blacklisted in Redis.
      2. A new token with a fresh jti + exp is returned.
    This prevents token reuse and supports sliding-window sessions.
    """
    old_jti: str = user.get("jti", "")
    old_exp: int = user.get("exp", 0)

    # Revoke the current token so it cannot be replayed
    if old_jti:
        from datetime import datetime, timezone
        now_ts = datetime.now(timezone.utc).timestamp()
        remaining_ttl = max(int(old_exp - now_ts), 1)
        await revoke_token(old_jti, remaining_ttl, request)
        logger.info("auth.refresh old_jti=%s user_id=%s", old_jti, user["user_id"])

    # Issue fresh token with same identity claims
    new_token = create_access_token(data={
        "sub":    user["user_id"],
        "email":  user.get("email", ""),
        "role":   user["role"],
        "org_id": user["org_id"],
    })

    logger.info("auth.token_refreshed user_id=%s org_id=%s", user["user_id"], user["org_id"])
    return {"access_token": new_token, "token_type": "bearer"}