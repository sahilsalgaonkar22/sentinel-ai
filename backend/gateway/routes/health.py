from fastapi import APIRouter
from backend.common.config import settings

router = APIRouter()


@router.get("/health")
async def health_check():
    from datetime import datetime, timezone

    deps = {}
    critical_down = False
    any_degraded = False

    # ── PostgreSQL (FAIL-CLOSED)
    try:
        from backend.common.database import AsyncSessionLocal
        from sqlalchemy import text
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        deps["postgresql"] = {"status": "ok"}
    except Exception as e:
        deps["postgresql"] = {"status": "down", "error": str(e)[:120]}
        critical_down = True

    # ── Redis (FAIL-OPEN)
    try:
        import redis.asyncio as _aioredis
        r = _aioredis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5
        )
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

    # ── Elasticsearch (FAIL-OPEN)
    try:
        from backend.common.elasticsearch_client import es_client
        deps["elasticsearch"] = {
            "status": "ok" if es_client.enabled else "degraded",
            "impact": None if es_client.enabled else "search degraded",
        }
        if not es_client.enabled:
            any_degraded = True
    except Exception as e:
        deps["elasticsearch"] = {
            "status": "degraded",
            "error": str(e)[:80]
        }
        any_degraded = True

    # ── Kafka (SAFE for local mode)
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
            deps["kafka"] = {
                "status": "ok",
                "brokers": len(metadata.brokers)
            }
    except Exception as e:
        deps["kafka"] = {
            "status": "degraded",
            "error": str(e)[:120],
            "impact": "scans routed to DLQ",
        }
        any_degraded = True

    # ── MinIO (SAFE)
    try:
        from backend.common.storage import ensure_bucket_exists
        await ensure_bucket_exists()
        deps["minio"] = {"status": "ok"}
    except Exception as e:
        deps["minio"] = {
            "status": "degraded",
            "error": str(e)[:80],
            "impact": "report uploads disabled"
        }
        any_degraded = True

    # ── Overall status
    if critical_down:
        overall = "critical"
    elif any_degraded:
        overall = "degraded"
    else:
        overall = "healthy"

    response_body = {
        "status": overall,
        "service": settings.OTEL_SERVICE_NAME,
        "version": settings.APP_VERSION,
        "execution_mode": settings.EXECUTION_MODE,
        "dependencies": deps,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }

    if critical_down:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=503, content=response_body)

    return response_body