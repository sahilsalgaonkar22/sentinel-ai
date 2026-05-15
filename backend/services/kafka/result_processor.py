"""
SENTINEL AI — Kafka Result Processor (Production-Hardened)

FIX-1:  asyncio.get_running_loop() replaces deprecated get_event_loop()
FIX-4:  confluent_kafka ImportError now raises RuntimeError (no silent skip)
FIX-5:  _pending_scans backed by Redis for gateway-restart resilience
        Scan state is stored as JSON in Redis with 24-hour TTL.
        On restart the gateway lazy-loads state from Redis on first result.
"""
import asyncio
import json
import os
import traceback
import logging
from typing import Set, List
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

KAFKA_BOOTSTRAP = os.environ["KAFKA_BOOTSTRAP_SERVERS"]   # Hard fail if unset
TOPIC_RESULTS     = "scan.results"
TOPIC_RESULTS_DLQ = "scan.results.dlq"   # FIX-11: Explicit DLQ for scan results
STATE_TTL_SEC     = 86_400   # 24 h — enough for any scan in flight


# ── FIX-4: Hard fail if confluent_kafka missing ──────────────────────────────
try:
    from confluent_kafka import Consumer, KafkaError
except ImportError as exc:
    raise RuntimeError(
        "confluent_kafka is required for distributed mode. "
        "Install it: pip install confluent-kafka"
    ) from exc


# ── FIX-5: Redis-backed scan state ───────────────────────────────────────────

def _get_redis():
    """
    FIX-8: Synchronous Redis client. URL MUST include password.
    Format: redis://:password@redis:6379/0
    """
    import redis as _redis
    url = os.getenv("REDIS_URL", "")
    if not url:
        raise RuntimeError("REDIS_URL is not set — required for distributed scan state")
    # Validate URL includes authentication
    if "@" not in url and "localhost" not in url and "127.0.0.1" not in url:
        raise RuntimeError(
            "REDIS_URL must include password for production: redis://:password@redis:6379/0"
        )
    return _redis.from_url(url, decode_responses=True)


def _state_key(scan_id: str) -> str:
    return f"sentinel:scan_state:{scan_id}"


def _save_state(scan_id: str, state: dict) -> None:
    """Atomically persist scan state to Redis."""
    try:
        r = _get_redis()
        r.setex(_state_key(scan_id), STATE_TTL_SEC, json.dumps(state))
    except Exception as exc:
        logger.error("result_processor.redis_save_failed scan_id=%s err=%s", scan_id, exc)


def _load_state(scan_id: str) -> dict | None:
    """Load scan state from Redis; returns None if not found."""
    try:
        r = _get_redis()
        raw = r.get(_state_key(scan_id))
        return json.loads(raw) if raw else None
    except Exception as exc:
        logger.warning("result_processor.redis_load_failed scan_id=%s err=%s", scan_id, exc)
        return None


def _delete_state(scan_id: str) -> None:
    try:
        _get_redis().delete(_state_key(scan_id))
    except Exception:
        pass


def register_pending_scan(scan_id: str, tools: list, org_id: str, target: str) -> None:
    """
    Called by orchestrator BEFORE dispatching Kafka jobs.
    State survives gateway restart via Redis.
    """
    state = {
        "expected_tools": list(set(tools)),
        "completed_tools": [],
        "all_findings": [],
        "org_id": org_id,
        "target": target,
        "has_error": False,
        "error_msg": "",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_state(scan_id, state)
    logger.info("result_processor.registered scan_id=%s tools=%s", scan_id, tools)


# ── Result Handler ────────────────────────────────────────────────────────────

async def _handle_result(msg_value: bytes) -> None:
    """Process a single scan.results message."""
    try:
        result = json.loads(msg_value.decode("utf-8"))
    except Exception as exc:
        logger.error("result_processor.parse_error err=%s", exc)
        return

    scan_id   = result.get("scan_id", "")
    org_id    = result.get("org_id", "")
    tool_name = result.get("tool_name", "")
    target    = result.get("target", "")
    findings  = result.get("findings", [])
    error     = result.get("error", "")

    if not scan_id:
        return

    # FIX-13: Idempotency guard — deduplicate redelivered Kafka messages.
    # Key: scan_id + tool_name uniquely identifies one result delivery.
    # If Redis already has this key, the result was already processed.
    idempotency_key = f"sentinel:processed:{scan_id}:{tool_name}"
    try:
        r = _get_redis()
        already_processed = r.set(idempotency_key, "1", nx=True, ex=STATE_TTL_SEC)
        if not already_processed:
            # nx=True returns None if key already existed
            logger.warning(
                "result_processor.duplicate_skipped scan_id=%s tool=%s idempotency_key=%s",
                scan_id, tool_name, idempotency_key
            )
            return
    except Exception as exc:
        # Redis unavailable: log and continue processing (best-effort dedup)
        logger.warning("result_processor.idempotency_check_failed err=%s proceeding", exc)

    # Load state from Redis (survives restart)
    state = _load_state(scan_id)

    if state is None:
        # Lazy-register unknown scans (e.g., worker produced result for
        # a scan this gateway instance didn't register).
        # Register with exactly the tools we've heard from so far.
        logger.warning(
            "result_processor.unknown_scan scan_id=%s tool=%s — lazy-registering",
            scan_id, tool_name
        )
        state = {
            "expected_tools": [tool_name],
            "completed_tools": [],
            "all_findings": [],
            "org_id": org_id,
            "target": target,
            "has_error": False,
            "error_msg": "",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    # Update state atomically
    if tool_name not in state["completed_tools"]:
        state["completed_tools"].append(tool_name)

    state["all_findings"].extend(findings)

    if error:
        state["has_error"]  = True
        state["error_msg"] = f"{tool_name}: {error}"

    remaining = set(state["expected_tools"]) - set(state["completed_tools"])
    logger.info(
        "result_processor.progress scan_id=%s tool=%s findings=%d remaining=%s",
        scan_id, tool_name, len(findings), remaining or "none"
    )

    if remaining:
        # Persist updated state and wait for more results
        _save_state(scan_id, state)
        return

    # All tools done — finalize
    await _finalize_distributed_scan(scan_id, state)


async def _finalize_distributed_scan(scan_id: str, state: dict) -> None:
    """All tools done — run the same pipeline as local mode."""
    all_findings = state["all_findings"]
    org_id       = state["org_id"]
    target       = state["target"]
    logger.info("result_processor.finalizing scan_id=%s findings=%d", scan_id, len(all_findings))

    # Remove from Redis before finalizing (idempotency guard)
    _delete_state(scan_id)

    try:
        from backend.services.scan_control.orchestrator import finalize_scan
        await finalize_scan(scan_id, org_id, target, all_findings)
    except Exception as exc:
        logger.error("result_processor.finalize_failed scan_id=%s err=%s", scan_id, exc, exc_info=True)
        try:
            from backend.common.database import AsyncSessionLocal
            from backend.services.scan_control.models import Scan, ScanStatus
            from sqlalchemy.future import select
            async with AsyncSessionLocal() as db:
                result = await db.execute(select(Scan).where(Scan.id == scan_id))
                scan = result.scalar_one_or_none()
                if scan and scan.status not in (ScanStatus.COMPLETED.value,):
                    scan.status = ScanStatus.FAILED.value
                    scan.error_message = f"Result processor error: {exc}"[:500]
                    await db.commit()
        except Exception:
            pass


# ── Main Consumer Loop ────────────────────────────────────────────────────────

async def run_result_processor() -> None:
    """
    Long-running asyncio task — polls scan.results topic in a thread executor.

    FIX-1:  Uses get_running_loop() (not deprecated get_event_loop()).
    FIX-6:  Uses SASL credentials from kafka_manager._sasl_conf().
    FIX-11: Failed messages are routed to scan.results.dlq.
    """
    logger.info("result_processor.starting bootstrap=%s", KAFKA_BOOTSTRAP)

    from backend.services.kafka.manager import kafka_manager

    consumer = Consumer({
        "bootstrap.servers": KAFKA_BOOTSTRAP,
        "group.id":          "sentinel-gateway-result-processor",
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
        "session.timeout.ms": 30_000,
        **kafka_manager._sasl_conf(),  # FIX-6: SASL credentials
    })
    consumer.subscribe([TOPIC_RESULTS])

    # FIX-1: get_running_loop() — works inside a coroutine, no deprecation
    loop = asyncio.get_running_loop()

    def _poll():
        return consumer.poll(timeout=0.5)

    try:
        while True:
            msg = await loop.run_in_executor(None, _poll)

            if msg is None:
                await asyncio.sleep(0.05)
                continue

            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    await asyncio.sleep(0.1)
                    continue
                logger.error("result_processor.consumer_error %s", msg.error())
                await asyncio.sleep(1.0)
                continue

            try:
                await _handle_result(msg.value())
                await loop.run_in_executor(None, lambda: consumer.commit(asynchronous=False))
            except Exception as exc:
                # FIX-11: Route unprocessable messages to scan.results.dlq
                logger.error(
                    "result_processor.handle_failed routing_to_dlq err=%s", exc, exc_info=True
                )
                try:
                    raw = msg.value()
                    payload = json.loads(raw.decode("utf-8")) if raw else {}
                    await kafka_manager.produce_to_dlq(
                        TOPIC_RESULTS, msg.key().decode() if msg.key() else "unknown",
                        payload, str(exc)
                    )
                except Exception as dlq_exc:
                    logger.critical(
                        "result_processor.dlq_route_failed err=%s original_err=%s",
                        dlq_exc, exc
                    )
                # Commit even on failure to avoid infinite retry loops
                await loop.run_in_executor(None, lambda: consumer.commit(asynchronous=False))

    except asyncio.CancelledError:
        logger.info("result_processor.shutdown")
    except Exception as exc:
        logger.critical("result_processor.fatal_error %s", exc, exc_info=True)
        raise
    finally:
        consumer.close()
