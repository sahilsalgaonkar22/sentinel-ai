"""
SENTINEL AI — Settings API Routes
Manage per-organization alert configuration, API key settings, and platform preferences.
All settings are org-scoped and stored in Redis (non-sensitive) + env (secrets).
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import json
import logging

from backend.gateway.middleware.auth import get_current_user, require_role
from backend.common.database import get_db_session
from backend.services.identity.models import Organization, User

logger = logging.getLogger(__name__)
router = APIRouter()

# Redis key prefix for org settings
_SETTINGS_KEY = "sentinel:settings:{org_id}"


async def _get_redis(request: Request):
    """Return Redis connection or None if unavailable."""
    redis = getattr(request.app.state, "redis", None)
    return redis


async def _get_redis_required(request: Request):
    """Return Redis connection, raising 503 if unavailable (for write ops)."""
    redis = getattr(request.app.state, "redis", None)
    if redis is None:
        raise HTTPException(
            status_code=503,
            detail="Settings storage unavailable (Redis not connected). Read-only mode active."
        )
    return redis


def _build_settings_response(org_id: str, settings_data: dict) -> dict:
    """Build the standard settings response from raw data."""
    return {
        "org_id": org_id,
        "alerts": {
            "email_enabled": settings_data.get("email_enabled", False),
            "smtp_host": settings_data.get("smtp_host", ""),
            "smtp_port": settings_data.get("smtp_port", 587),
            "smtp_user": settings_data.get("smtp_user", ""),
            "smtp_password": "••••••••" if settings_data.get("smtp_password") else "",
            "alert_recipients": settings_data.get("alert_recipients", []),
            "slack_enabled": settings_data.get("slack_enabled", False),
            "slack_webhook": "••••••••" if settings_data.get("slack_webhook") else "",
            "alert_on_critical": settings_data.get("alert_on_critical", True),
            "alert_on_high": settings_data.get("alert_on_high", True),
            "alert_on_score_below": settings_data.get("alert_on_score_below", 80),
        },
        "scanning": {
            "default_scan_mode": settings_data.get("default_scan_mode", "local"),
            "max_concurrent_scans": settings_data.get("max_concurrent_scans", 10),
            "scan_timeout_seconds": settings_data.get("scan_timeout_seconds", 300),
            "allow_advanced_scans": settings_data.get("allow_advanced_scans", False),
            "auto_schedule_enabled": settings_data.get("auto_schedule_enabled", False),
        },
        "ai": {
            "llm_enabled": bool(settings_data.get("llm_api_key")),
            "llm_endpoint": settings_data.get("llm_endpoint", "https://api.openai.com/v1"),
            "llm_model": settings_data.get("llm_model", "gpt-4"),
            "llm_api_key": "••••••••" if settings_data.get("llm_api_key") else "",
            "false_positive_threshold": settings_data.get("false_positive_threshold", 0.5),
            "auto_deduplicate": settings_data.get("auto_deduplicate", True),
        },
        "integrations": {
            "elasticsearch_url": settings_data.get("elasticsearch_url", ""),
            "s3_endpoint": settings_data.get("s3_endpoint", ""),
        },
    }


@router.get("/")
async def get_settings(
    request: Request,
    user: dict = Depends(get_current_user),
):
    """
    Return current org settings. Falls back to defaults if Redis is unavailable.
    Secrets (passwords, webhook URLs) are masked in the response.
    """
    org_id = user["org_id"]
    settings_data = {}

    redis = await _get_redis(request)
    if redis is not None:
        try:
            key = _SETTINGS_KEY.format(org_id=org_id)
            raw = await redis.get(key)
            if raw:
                settings_data = json.loads(raw)
        except Exception as exc:
            logger.warning("settings.redis_read_failed org_id=%s err=%s", org_id, exc)

    return _build_settings_response(org_id, settings_data)


@router.patch("/alerts")
async def update_alert_settings(
    request: Request,
    payload: dict,
    user: dict = Depends(require_role(["admin"])),
    db: AsyncSession = Depends(get_db_session),
):
    """Update alert/notification settings (admin only)."""
    redis = await _get_redis_required(request)
    org_id = user["org_id"]
    key = _SETTINGS_KEY.format(org_id=org_id)

    raw = await redis.get(key)
    settings_data = json.loads(raw) if raw else {}

    # Allowed alert fields
    allowed = {
        "email_enabled", "smtp_host", "smtp_port", "smtp_user", "smtp_password",
        "alert_recipients", "slack_enabled", "slack_webhook",
        "alert_on_critical", "alert_on_high", "alert_on_score_below",
    }
    for field, value in payload.items():
        if field in allowed:
            # Don't overwrite with masked values
            if isinstance(value, str) and value == "••••••••":
                continue
            settings_data[field] = value

    await redis.setex(key, 86_400 * 30, json.dumps(settings_data))  # 30 day TTL
    logger.info("settings.alerts_updated org_id=%s by=%s", org_id, user["user_id"])
    return {"status": "updated", "section": "alerts"}


@router.patch("/scanning")
async def update_scan_settings(
    request: Request,
    payload: dict,
    user: dict = Depends(require_role(["admin"])),
):
    """Update scanning preferences (admin only)."""
    redis = await _get_redis_required(request)
    org_id = user["org_id"]
    key = _SETTINGS_KEY.format(org_id=org_id)

    raw = await redis.get(key)
    settings_data = json.loads(raw) if raw else {}

    allowed = {
        "default_scan_mode", "max_concurrent_scans",
        "scan_timeout_seconds", "allow_advanced_scans", "auto_schedule_enabled",
    }
    for field, value in payload.items():
        if field in allowed:
            settings_data[field] = value

    await redis.setex(key, 86_400 * 30, json.dumps(settings_data))
    logger.info("settings.scan_updated org_id=%s by=%s", org_id, user["user_id"])
    return {"status": "updated", "section": "scanning"}


@router.patch("/ai")
async def update_ai_settings(
    request: Request,
    payload: dict,
    user: dict = Depends(require_role(["admin"])),
):
    """Update AI/LLM settings (admin only)."""
    redis = await _get_redis_required(request)
    org_id = user["org_id"]
    key = _SETTINGS_KEY.format(org_id=org_id)

    raw = await redis.get(key)
    settings_data = json.loads(raw) if raw else {}

    allowed = {
        "llm_api_key", "llm_endpoint", "llm_model",
        "false_positive_threshold", "auto_deduplicate",
    }
    for field, value in payload.items():
        if field in allowed:
            if isinstance(value, str) and value == "••••••••":
                continue
            settings_data[field] = value

    await redis.setex(key, 86_400 * 30, json.dumps(settings_data))
    logger.info("settings.ai_updated org_id=%s by=%s", org_id, user["user_id"])
    return {"status": "updated", "section": "ai"}


@router.get("/profile")
async def get_org_profile(
    user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
):
    """Return the current organization profile."""
    org_id = user["org_id"]
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return {
        "id": org.id,
        "name": org.name,
        "slug": org.slug,
        "plan": org.plan,
        "is_active": org.is_active,
        "max_scans_per_day": org.max_scans_per_day,
        "max_assets": org.max_assets,
        "created_at": org.created_at.isoformat() if org.created_at else None,
    }


@router.get("/users")
async def list_org_users(
    user: dict = Depends(require_role(["admin"])),
    db: AsyncSession = Depends(get_db_session),
):
    """List all users in the current organization (admin only)."""
    org_id = user["org_id"]
    result = await db.execute(
        select(User).where(User.org_id == org_id).order_by(User.created_at.desc())
    )
    users = result.scalars().all()
    return {
        "items": [
            {
                "id": u.id,
                "email": u.email,
                "username": u.username,
                "full_name": u.full_name,
                "role": u.role,
                "is_active": u.is_active,
                "last_login": u.last_login.isoformat() if u.last_login else None,
            }
            for u in users
        ],
        "total": len(users),
    }


@router.patch("/users/{user_id}/role")
async def update_user_role(
    user_id: str,
    payload: dict,
    user: dict = Depends(require_role(["admin"])),
    db: AsyncSession = Depends(get_db_session),
):
    """Update a user's role (admin only). Allowed: admin, analyst, viewer."""
    org_id = user["org_id"]
    new_role = payload.get("role", "")
    if new_role not in ("admin", "analyst", "viewer"):
        raise HTTPException(status_code=400, detail="Role must be: admin, analyst, or viewer")

    result = await db.execute(
        select(User).where(User.id == user_id, User.org_id == org_id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found in your organization")

    target.role = new_role
    await db.commit()
    logger.info("settings.role_updated target_user=%s new_role=%s by=%s", user_id, new_role, user["user_id"])
    return {"status": "updated", "user_id": user_id, "role": new_role}
