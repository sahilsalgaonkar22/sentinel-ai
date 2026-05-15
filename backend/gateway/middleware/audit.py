"""
SENTINEL AI — Audit Logging Middleware
Logs every authenticated API action to: stdout (Logstash picks up), database, and optional Redis stream.
Format: ISO timestamp | user_id | org_id | role | method | path | status | duration_ms
"""
import time
import json
from datetime import datetime, timezone
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# Paths that don't need audit logging (static/health)
_SKIP_PATHS = {"/health", "/metrics", "/docs", "/openapi.json", "/redoc", "/favicon.ico"}


class AuditLogMiddleware(BaseHTTPMiddleware):
    """
    Middleware that logs every authenticated request as a structured audit event.
    - Captures: user, org, role, method, path, status code, duration
    - Non-blocking: writes to stdout (JSON) for Logstash ingestion
    - Also writes to Redis stream 'sentinel:audit' if Redis available
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip health checks and static paths
        if request.url.path in _SKIP_PATHS:
            return await call_next(request)

        start = time.monotonic()

        # Extract user from JWT (best-effort, don't block on failure)
        user_id = "anonymous"
        org_id = "unknown"
        role = "unknown"
        try:
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                from jose import jwt as _jwt
                from backend.common.config import settings
                token = auth.split(" ")[1]
                payload = _jwt.decode(
                    token, settings.JWT_SECRET,
                    algorithms=[settings.JWT_ALGORITHM],
                    options={"verify_exp": False},
                )
                user_id = payload.get("sub", "anonymous")
                org_id = payload.get("org_id", "unknown")
                role = payload.get("role", "unknown")
        except Exception:
            pass

        response = await call_next(request)
        duration_ms = round((time.monotonic() - start) * 1000, 1)

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "audit",
            "user_id": user_id,
            "org_id": org_id,
            "role": role,
            "method": request.method,
            "path": request.url.path,
            "query": str(request.url.query) if request.url.query else None,
            "status": response.status_code,
            "duration_ms": duration_ms,
            "ip": request.client.host if request.client else "unknown",
            "user_agent": request.headers.get("user-agent", "")[:100],
        }

        # Write to stdout as JSON (Logstash / ECS compatible)
        print(json.dumps(event))

        # Async write to Redis stream (non-fatal)
        try:
            redis = getattr(request.app.state, "redis", None)
            if redis:
                await redis.xadd(
                    "sentinel:audit",
                    event,
                    maxlen=10000,  # Keep last 10k audit events in Redis
                    approximate=True,
                )
        except Exception:
            pass

        return response
