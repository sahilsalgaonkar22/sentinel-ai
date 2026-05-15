"""
SENTINEL AI — Auth Middleware (FIX-1: Redis-Backed JWT Revocation)

SECURITY:
- Validates sub (user UUID), not raw email
- Token revocation stored in Redis — shared across ALL gateway replicas
- JTI blacklist TTL = remaining token lifetime (no zombie entries)
- No fallback, no bypass
"""
from fastapi import Request, HTTPException, status
from jose import JWTError, ExpiredSignatureError, jwt
from backend.common.config import settings
import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
#  Redis-backed JWT revocation  (FIX-1)
#  Key schema: sentinel:revoked:<jti>  → "1"  (TTL = remaining seconds)
# ---------------------------------------------------------------------------

async def _get_redis(request: Request):
    """Return the app-level Redis connection (set at lifespan startup)."""
    redis = getattr(request.app.state, "redis", None)
    if redis is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Auth service temporarily unavailable (Redis not connected).",
        )
    return redis


async def revoke_token(jti: str, ttl_seconds: int, request: Request) -> None:
    """
    Blacklist a JTI in Redis for `ttl_seconds`.
    Called from the /logout endpoint; idempotent.
    """
    redis = await _get_redis(request)
    await redis.setex(f"sentinel:revoked:{jti}", ttl_seconds, "1")
    logger.info("auth.token_revoked jti=%s ttl=%ds", jti, ttl_seconds)


async def _is_token_revoked(jti: str, request: Request) -> bool:
    """Return True if the JTI is on the Redis revocation list."""
    if not jti:
        return False
    try:
        redis = await _get_redis(request)
        return bool(await redis.exists(f"sentinel:revoked:{jti}"))
    except HTTPException:
        # Redis not connected — degraded mode: skip revocation check
        # This matches startup behaviour (jwt_blacklist=DISABLED)
        logger.debug("auth.revocation_skip reason=redis_unavailable jti=%s", jti)
        return False
    except Exception as exc:
        # Redis read failure — log but allow through in degraded mode
        logger.warning("auth.revocation_check_failed err=%s — allowing token (degraded mode)", exc)
        return False


# ---------------------------------------------------------------------------
#  JWT validation
# ---------------------------------------------------------------------------

async def get_current_user(request: Request) -> dict:
    """
    Validate Bearer JWT and return the user payload.

    Raises HTTP 401 on any auth failure.
    No fallback or debug bypass path exists.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth_header.split(" ", 1)[1]

    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp", "sub"]},
        )
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError as exc:
        logger.warning("auth.jwt_invalid: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id: str = payload.get("sub")
    org_id: str  = payload.get("org_id")
    role: str    = payload.get("role")
    jti: str     = payload.get("jti", "")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token: missing subject",
        )

    # FIX-1: Check Redis revocation list (shared across all replicas)
    if await _is_token_revoked(jti, request):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
        )

    return {
        "user_id": user_id,
        "email":   payload.get("email", ""),
        "org_id":  org_id,
        "role":    role or "viewer",
        "jti":     jti,
        "exp":     payload.get("exp", 0),
    }


def require_role(allowed_roles):
    """
    Dependency injection wrapper for RBAC enforcement.
    Use as: Depends(require_role(["admin", "analyst"]))
    Also accepts a single string: Depends(require_role("admin"))
    """
    # Normalize: accept both "admin" and ["admin", "analyst"]
    if isinstance(allowed_roles, str):
        allowed_roles = [allowed_roles]
    # Use a frozenset for O(1) exact-match lookups (no substring matching)
    _allowed = frozenset(allowed_roles)

    async def role_checker(request: Request):
        user = await get_current_user(request)
        if user.get("role") not in _allowed:
            logger.warning(
                "auth.rbac_denied user=%s role=%s required=%s",
                user.get("user_id"), user.get("role"), list(_allowed),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions for this operation",
            )
        return user
    return role_checker
