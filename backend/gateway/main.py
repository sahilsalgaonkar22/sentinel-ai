"""
SENTINEL AI — API Gateway
FastAPI application with JWT auth, RBAC, WebSocket, and all service routes.

STARTUP GUARD: env_validator runs before ANY application module is imported.
If environment variables are invalid/missing the process exits immediately.
"""
# ── STARTUP GUARD (must be first) ─────────────────────────────────────────────
# Import and run env validation BEFORE any application module loads.
# This prevents partially-configured services from silently starting.
from backend.common.env_validator import enforce_environment as _enforce_env
_enforce_env()
# ── End startup guard ──────────────────────────────────────────────────────────

import asyncio
import os
import sys
import uuid
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

logger = logging.getLogger(__name__)

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from prometheus_fastapi_instrumentator import Instrumentator

from backend.common.config import settings
from backend.common.database import init_db
from backend.gateway.routes import auth, scans, ai, vulnerabilities, assets, dashboard, reporting, live_scan, settings as settings_route
from backend.gateway.routes.websocket_manager import manager
from backend.gateway.middleware.auth import get_current_user
from backend.gateway.middleware.audit import AuditLogMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: create DB tables, init Redis, start result processor + watchdog. Shutdown: cleanup."""
    from backend.common.logging_config import configure_logging
    configure_logging(service_name="gateway")

    import redis.asyncio as aioredis
    logger.info("startup.begin service=%s version=%s", settings.APP_NAME, settings.APP_VERSION)
    await init_db()
    logger.info("startup.db_ready")

    # Initialize Redis connection (Fail-Open Allowed)
    redis_ok = False
    try:
        allow_fail_open = getattr(settings, "ALLOW_REDIS_FAIL_OPEN", True)
        app.state.redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True, socket_connect_timeout=5, socket_timeout=5)
        await app.state.redis.ping()
        logger.info("startup.redis_connected url=%s", settings.REDIS_URL)
        
        # Initialize Redis-backed WebSocket pub/sub manager
        await manager.initialize(app.state.redis)
        logger.info("startup.ws_pubsub_initialized")
        redis_ok = True
    except Exception as e:
        if not getattr(settings, "ALLOW_REDIS_FAIL_OPEN", True):
            raise RuntimeError(f"Redis unavailable and ALLOW_REDIS_FAIL_OPEN=false. Aborting. err={e}")
        logger.critical(
            "REDIS_DEGRADED_MODE=True redis_err=%s "
            "| jwt_blacklist=DISABLED | caching=DISABLED | settings_cache=DISABLED", e
        )
        app.state.redis = None

    # Explicit feature capability map — downstream code checks this, never probes Redis directly
    app.state.features = {
        "jwt_blacklist": redis_ok,
        "rate_limit": "redis" if redis_ok else "memory",
        "settings_cache": redis_ok,
        "ws_pubsub": redis_ok,
    }
    logger.info("startup.features %s", app.state.features)

    # Initialize MinIO/S3 bucket (non-fatal)
    try:
        from backend.common.storage import ensure_bucket_exists
        await ensure_bucket_exists()
        logger.info("startup.minio_ready bucket=%s", settings.S3_BUCKET)
    except Exception as e:
        logger.warning("startup.minio_unavailable err=%s report_storage=disabled", e)

    logger.info("startup.mode execution_mode=%s kafka=%s",
                settings.EXECUTION_MODE, settings.KAFKA_BOOTSTRAP_SERVERS)

    # Start Kafka Result Processor (distributed mode only)
    result_processor_task = None
    if settings.EXECUTION_MODE == "distributed":
        from backend.services.kafka.result_processor import run_result_processor
        result_processor_task = asyncio.create_task(run_result_processor())
        logger.info("startup.kafka_result_processor_started")
    else:
        logger.info("startup.local_mode kafka_result_processor=disabled")

    # FIX-2: Start distributed scan timeout watchdog
    from backend.services.scan_control.timeout_watcher import scan_timeout_watcher
    watchdog_task = asyncio.create_task(scan_timeout_watcher())
    logger.info("startup.watchdog_started timeout=%ds", settings.SCAN_TIMEOUT_SECONDS)

    # Start Scheduler
    from backend.services.scan_control.scheduler import scheduler_manager
    scheduler_manager.start()

    # Initialize Elasticsearch (non-fatal — degrades gracefully if not configured)
    from backend.common.elasticsearch_client import es_client
    await es_client.connect(settings.ELASTICSEARCH_URL)
    if es_client.enabled:
        logger.info("startup.elasticsearch_connected")
    else:
        logger.warning("startup.elasticsearch_disabled search_indexing=off")

    # Start MLOps retrain scheduler (checks for sufficient feedback, retrains weekly)
    from backend.services.ai_intelligence.retrain_scheduler import start_retrain_scheduler
    retrain_task = asyncio.create_task(start_retrain_scheduler())
    logger.info("startup.retrain_scheduler_started")

    # Start Kafka DLQ replay worker (replays failed Kafka events back to broker)
    from backend.services.kafka.dlq_worker import replay_kafka_dlq
    dlq_task = asyncio.create_task(replay_kafka_dlq())
    logger.info("startup.kafka_dlq_worker_started interval=%ds", settings.DLQ_RETRY_INTERVAL_SECONDS)

    logger.info("startup.complete routes=%d", len(app.routes))
    yield

    # Shutdown cleanup
    logger.info("shutdown.begin")
    # FIX-3: Shutdown Redis pub/sub manager cleanly
    await manager.shutdown()
    watchdog_task.cancel()
    retrain_task.cancel()
    dlq_task.cancel()
    try:
        await watchdog_task
    except asyncio.CancelledError:
        pass
    try:
        await retrain_task
    except asyncio.CancelledError:
        pass
    try:
        await dlq_task
    except asyncio.CancelledError:
        pass
    if result_processor_task:
        result_processor_task.cancel()
        try:
            await result_processor_task
        except asyncio.CancelledError:
            pass
    await es_client.close()
    if app.state.redis:
        await app.state.redis.aclose()
    logger.info("shutdown.complete")


from backend.gateway.limiter import limiter

app = FastAPI(
    title=f"{settings.APP_NAME} Gateway",
    version=settings.APP_VERSION,
    debug=settings.DEBUG,
    lifespan=lifespan
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

Instrumentator().instrument(app).expose(app)

# ── Observability: Sentry + OpenTelemetry (OTLP/Jaeger) ─────────────────────
try:
    import sentry_sdk
    sentry_dsn = os.getenv("SENTRY_DSN", getattr(settings, "SENTRY_DSN", None))
    if sentry_dsn:
        sentry_sdk.init(
            dsn=sentry_dsn,
            traces_sample_rate=1.0,
            profiles_sample_rate=1.0,
            environment=os.getenv("SENTINEL_ENV", "production"),
            release=settings.APP_VERSION,
        )
        logger.info("startup.sentry_initialized")
    else:
        logger.warning("Sentry not configured — fallback to local logging")
except ImportError:
    logger.warning("sentry-sdk not installed — fallback to local logging")

# Sentry context-enrichment middleware: tags every request with org_id + trace_id
try:
    import sentry_sdk
    from starlette.middleware.base import BaseHTTPMiddleware as _BaseHTTPMiddleware

    class SentryContextMiddleware(_BaseHTTPMiddleware):
        """Attach org/scan context to every Sentry event automatically."""
        async def dispatch(self, request, call_next):
            with sentry_sdk.configure_scope() as scope:
                scope.set_tag("service", settings.OTEL_SERVICE_NAME)
                user = getattr(request.state, "user", None)
                if user:
                    scope.set_tag("org_id", user.get("org_id", "unknown"))
                    scope.set_user({"id": user.get("user_id"), "username": user.get("email")})
                request_id = request.headers.get("X-Request-ID", "")
                if request_id:
                    scope.set_tag("request_id", request_id)
            return await call_next(request)
except ImportError:
    SentryContextMiddleware = None

try:
    from opentelemetry import trace
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    # Use OTLP exporter (port 4318) — NOT legacy Jaeger Thrift (14268)
    otlp_endpoint = (
        os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
        or getattr(settings, "OTEL_EXPORTER_OTLP_ENDPOINT", None)
    )
    if otlp_endpoint:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        provider = TracerProvider()
        processor = BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{otlp_endpoint}/v1/traces"))
        provider.add_span_processor(processor)
        trace.set_tracer_provider(provider)
        FastAPIInstrumentor.instrument_app(app)
        logger.info("startup.otel_tracing_initialized endpoint=%s", otlp_endpoint)
except ImportError:
    pass
# ───────────────────────────────────────────────────────────────────────────────
# FIX-10: CORS — reads from settings.CORS_ALLOWED_ORIGINS (validated at startup).
# settings validator already rejects empty / wildcard values.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in settings.CORS_ALLOWED_ORIGINS.split(",")
        if origin.strip()
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)
# Audit logging — captures every authenticated request
app.add_middleware(AuditLogMiddleware)


# ── GAP-11: X-Request-ID middleware ──────────────────────────────────────────
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse

class RequestIDMiddleware(BaseHTTPMiddleware):
    """Generate a unique X-Request-ID for every request if not already present."""
    async def dispatch(self, request: StarletteRequest, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        response: StarletteResponse = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject security response headers into every API response.

    Addresses OWASP security header recommendations:
    - CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
      Permissions-Policy, Cross-Origin-Opener-Policy, X-XSS-Protection.
    """
    async def dispatch(self, request: StarletteRequest, call_next):
        response: StarletteResponse = await call_next(request)
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; "
            "font-src 'self' data: https://fonts.gstatic.com; connect-src 'self' ws: wss: http://localhost:* https://localhost:* http://127.0.0.1:* https://127.0.0.1:*; frame-ancestors 'self';"
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("X-XSS-Protection", "1; mode=block")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        return response


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIDMiddleware)

# Sentry context enrichment — attaches org_id/request_id to every error event
if SentryContextMiddleware is not None:
    app.add_middleware(SentryContextMiddleware)

# Routes
from backend.gateway.routes import alerts as alerts_route
from backend.gateway.routes import compliance as compliance_route
app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(ai.router)
app.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["vulnerabilities"])
app.include_router(assets.router, prefix="/assets", tags=["assets"])
app.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
app.include_router(reporting.router, prefix="/reporting", tags=["reporting"])
app.include_router(live_scan.router, prefix="/live-scan", tags=["live-scan"])
app.include_router(settings_route.router, prefix="/settings", tags=["settings"])
app.include_router(alerts_route.router)
app.include_router(compliance_route.router, prefix="/compliance", tags=["compliance"])



# Real-time WebSocket Endpoint
@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str, token: str = None):
    """
    Real-time scan event stream — JWT required, always.
    org_id from the token gates all scan subscriptions (FIX-3).
    """
    if not token:
        await websocket.close(code=1008)   # Policy Violation — no token
        return

    org_id  = None
    user_id = None
    try:
        from jose import jwt as jose_jwt, JWTError
        payload  = jose_jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        user_id  = payload.get("sub")
        org_id   = payload.get("org_id")
        if not user_id or not org_id:
            raise JWTError("Missing sub or org_id in token")
    except Exception:
        await websocket.close(code=1008)
        return

    await manager.connect(websocket, client_id, org_id=org_id)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                if message.get("type") == "subscribe_scan":
                    scan_id = message.get("scan_id")
                    if scan_id:
                        # FIX-3: validate scan ownership before granting subscription
                        from backend.common.database import AsyncSessionLocal
                        async with AsyncSessionLocal() as db:
                            granted = await manager.subscribe_to_scan(
                                client_id=client_id,
                                scan_id=scan_id,
                                org_id=org_id,
                                db=db,
                            )
                        if not granted:
                            await manager.send_personal(client_id, {
                                "type": "error",
                                "message": "Scan not found or unauthorized",
                            })
            except json.JSONDecodeError:
                pass

            await manager.send_personal(client_id, {
                "type": "heartbeat",
                "timestamp": datetime.now(timezone.utc).isoformat(),  # T4 FIX: real timestamp
            })

    except WebSocketDisconnect:
        manager.disconnect(client_id)
    except Exception as exc:
        logger.warning("ws.error client_id=%s err=%s", client_id, exc)
        manager.disconnect(client_id)


@app.get("/health")
async def health_check():
    """
    Active dependency probe with full degraded-state reporting.

    HTTP codes:
      200 — all critical services ok OR redis/kafka degraded (fail-open)
      503 — PostgreSQL unreachable (fail-closed, system cannot function)

    Response shape:
      status: "healthy" | "degraded" | "critical"
      Each dependency has a status field: "ok" | "degraded" | "down"
    """
    from datetime import datetime, timezone

    deps: dict = {}
    critical_down = False
    any_degraded = False

    # ── PostgreSQL (FAIL-CLOSED) ───────────────────────────────────────────────
    try:
        from backend.common.database import AsyncSessionLocal
        from sqlalchemy import text
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        deps["postgresql"] = {"status": "ok"}
    except Exception as e:
        deps["postgresql"] = {"status": "down", "error": str(e)[:120]}
        critical_down = True

    # ── Redis (FAIL-OPEN) ─────────────────────────────────────────────────────
    try:
        import redis.asyncio as _aioredis
        r = _aioredis.from_url(settings.REDIS_URL, decode_responses=True,
                               socket_connect_timeout=2)
        await r.ping()
        await r.aclose()
        deps["redis"] = {"status": "ok"}
    except Exception as e:
        deps["redis"] = {
            "status": "degraded",
            "error": str(e)[:120],
            "impact": "jwt_blacklist=disabled, caching=disabled, rate_limit=memory",
        }
        any_degraded = True

    # ── Elasticsearch (FAIL-OPEN) ─────────────────────────────────────────────
    try:
        from backend.common.elasticsearch_client import es_client
        deps["elasticsearch"] = {
            "status": "ok" if es_client.enabled else "degraded",
            "impact": None if es_client.enabled else "full-text search degraded to PostgreSQL LIKE",
        }
        if not es_client.enabled:
            any_degraded = True
    except Exception as e:
        deps["elasticsearch"] = {"status": "degraded", "error": str(e)[:80]}
        any_degraded = True

    # ── Kafka (advisory, FAIL-OPEN) ───────────────────────────────────────────
    try:
        if not settings.KAFKA_BOOTSTRAP_SERVERS:
            deps["kafka"] = {
                "status": "disabled",
                "impact": "local mode (Kafka disabled)"
            }
        else:
            from confluent_kafka.admin import AdminClient
            from backend.services.kafka.manager import kafka_manager

            admin = AdminClient({
                "bootstrap.servers": settings.KAFKA_BOOTSTRAP_SERVERS,
                "socket.timeout.ms": 3000,
                **kafka_manager._sasl_conf(),
            })
            metadata = admin.list_topics(timeout=3)
            deps["kafka"] = {"status": "ok", "brokers": len(metadata.brokers)}
    except Exception as e:
        deps["kafka"] = {
            "status": "degraded",
            "error": str(e)[:120],
            "impact": "scans routed to PostgreSQL DLQ for replay",
        }
        any_degraded = True

    # ── MinIO/S3 (advisory) ───────────────────────────────────────────────────
    try:
        from backend.common.storage import ensure_bucket_exists
        await ensure_bucket_exists()
        deps["minio"] = {"status": "ok"}
    except Exception as e:
        deps["minio"] = {
            "status": "degraded",
            "error": str(e)[:80],
            "impact": "PDF report uploads disabled"
        }
        any_degraded = True

    # ── Overall status ────────────────────────────────────────────────────────
    if critical_down:
        overall = "critical"
    elif any_degraded:
        overall = "degraded"
    else:
        overall = "healthy"

    # Pull live feature capability map set at startup
    features = {}
    try:
        features = getattr(app.state, "features", {})
    except Exception:
        pass

    response_body = {
        "status": overall,
        "service": settings.OTEL_SERVICE_NAME,
        "version": settings.APP_VERSION,
        "execution_mode": settings.EXECUTION_MODE,
        "dependencies": deps,
        "features": features,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }

    if critical_down:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=503, content=response_body)

    return response_body


@app.get("/health/tools")
async def tool_health():
    """Returns real-time tool availability: REAL vs FALLBACK per binary."""
    try:
        from backend.common.tool_validator import get_tool_report
        return get_tool_report()
    except Exception as e:
        return {"error": str(e), "tools": {}, "production_ready": False}


@app.get("/")
async def root():
    return {"message": f"Welcome to {settings.APP_NAME} API Gateway v{settings.APP_VERSION}"}
