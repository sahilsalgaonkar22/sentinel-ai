"""
SENTINEL AI — Dead Letter Queue (DLQ) Consumer Service

Reads from all *.dlq topics, logs failures, sends structured alerts,
and optionally retries eligible jobs up to MAX_RETRIES times.

Usage:
    python -m backend.services.kafka.dlq_consumer

Deploy as a dedicated pod (see k8s/dlq-consumer.yaml).
"""
import asyncio
import json
import logging
import os
import signal
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

DLQ_TOPICS = [
    "scan.jobs.network.dlq",
    "scan.jobs.web.dlq",
    "scan.jobs.code.dlq",
    "scan.jobs.container.dlq",
    "scan.jobs.advanced.dlq",
    "scan.results.dlq",
]

KAFKA_BOOTSTRAP = os.environ["KAFKA_BOOTSTRAP_SERVERS"]
GROUP_ID = "sentinel-dlq-consumer"
MAX_RETRIES = int(os.getenv("DLQ_MAX_RETRIES", "3"))
RETRY_DELAY_SECONDS = int(os.getenv("DLQ_RETRY_DELAY_SECONDS", "30"))

_shutdown = False


def _handle_signal(signum, frame):
    global _shutdown
    logger.info("dlq_consumer.shutdown_signal signal=%d", signum)
    _shutdown = True


signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT, _handle_signal)


def _build_consumer():
    from confluent_kafka import Consumer
    return Consumer({
        "bootstrap.servers": KAFKA_BOOTSTRAP,
        "group.id": GROUP_ID,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
        "session.timeout.ms": 30000,
    })


def _send_alert(message: dict, error: str, original_topic: str) -> None:
    """
    Send a structured failure alert.
    Uses structured logging as the alert sink —
    connect a log aggregator (Datadog, Grafana Loki, etc.) to these events.
    """
    logger.critical(
        "dlq.alert "
        "scan_id=%s org_id=%s tool=%s target=%s "
        "original_topic=%s error=%s retries=%d ts=%s",
        message.get("scan_id", "unknown"),
        message.get("org_id", ""),
        message.get("tool_name", ""),
        message.get("target", ""),
        original_topic,
        error,
        message.get("_dlq_retry_count", 0),
        datetime.now(timezone.utc).isoformat(),
    )

    # Slack webhook alert (if configured)
    slack_webhook = os.getenv("SENTINEL_SLACK_WEBHOOK", "")
    if slack_webhook:
        try:
            import httpx
            payload = {
                "text": (
                    f"🚨 *DLQ Alert — Sentinel AI*\n"
                    f"*Scan ID:* {message.get('scan_id', 'unknown')}\n"
                    f"*Tool:* {message.get('tool_name', '')}\n"
                    f"*Target:* {message.get('target', '')}\n"
                    f"*Error:* `{error[:300]}`\n"
                    f"*Original Topic:* `{original_topic}`\n"
                    f"*Timestamp:* {datetime.now(timezone.utc).isoformat()}"
                )
            }
            # Fire-and-forget via synchronous httpx (DLQ is not latency-sensitive)
            with httpx.Client(timeout=5) as client:
                client.post(slack_webhook, json=payload)
        except Exception as exc:
            logger.warning("dlq.slack_alert_failed %s", exc)


async def _retry_job(message: dict, original_topic: str) -> bool:
    """
    Attempt to republish the job to its original topic.

    Returns True if republished, False if max retries exceeded.
    """
    retry_count = message.get("_dlq_retry_count", 0) + 1
    if retry_count > MAX_RETRIES:
        logger.error(
            "dlq.retry_exhausted scan_id=%s topic=%s retries=%d",
            message.get("scan_id"), original_topic, retry_count
        )
        return False

    await asyncio.sleep(RETRY_DELAY_SECONDS)

    message["_dlq_retry_count"] = retry_count
    message.pop("_dlq_original_topic", None)
    message.pop("_dlq_error", None)

    from backend.services.kafka.manager import kafka_manager
    try:
        await kafka_manager.produce(
            topic=original_topic,
            key=message.get("scan_id", "unknown"),
            value=message,
        )
        logger.info(
            "dlq.retry_published scan_id=%s topic=%s attempt=%d",
            message.get("scan_id"), original_topic, retry_count
        )
        return True
    except Exception as exc:
        logger.error(
            "dlq.retry_failed scan_id=%s topic=%s error=%s",
            message.get("scan_id"), original_topic, exc
        )
        return False


async def _process_dlq_message(raw_value: bytes, dlq_topic: str) -> None:
    """Process a single DLQ message."""
    try:
        msg_dict = json.loads(raw_value.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.error("dlq.parse_error topic=%s error=%s raw=%s", dlq_topic, exc, raw_value[:200])
        return

    original_topic = msg_dict.get("_dlq_original_topic", dlq_topic.removesuffix(".dlq"))
    error = msg_dict.get("_dlq_error", "unknown error")

    logger.warning(
        "dlq.received scan_id=%s original_topic=%s error=%s",
        msg_dict.get("scan_id", "?"), original_topic, error
    )

    # Send alert for every DLQ entry
    _send_alert(msg_dict, error, original_topic)

    # Retry if eligible
    retry_eligible = msg_dict.get("_dlq_retry_count", 0) < MAX_RETRIES
    if retry_eligible:
        await _retry_job(msg_dict, original_topic)
    else:
        logger.error(
            "dlq.terminal scan_id=%s original_topic=%s — no more retries",
            msg_dict.get("scan_id", "?"), original_topic
        )


async def run_dlq_consumer() -> None:
    """
    Long-running asyncio task that polls all DLQ topics.
    consumer.poll() runs in thread executor to avoid blocking the event loop.
    """
    logger.info("dlq_consumer.starting topics=%s bootstrap=%s", DLQ_TOPICS, KAFKA_BOOTSTRAP)

    consumer = _build_consumer()
    consumer.subscribe(DLQ_TOPICS)

    loop = asyncio.get_running_loop()

    def _poll():
        return consumer.poll(timeout=1.0)

    try:
        while not _shutdown:
            msg = await loop.run_in_executor(None, _poll)

            if msg is None:
                await asyncio.sleep(0.1)
                continue

            if msg.error():
                from confluent_kafka import KafkaError as KE
                if msg.error().code() == KE._PARTITION_EOF:
                    await asyncio.sleep(0.1)
                    continue
                logger.error("dlq_consumer.kafka_error %s", msg.error())
                await asyncio.sleep(2.0)
                continue

            await _process_dlq_message(msg.value(), msg.topic())

            # Commit only after successful processing
            await loop.run_in_executor(None, lambda: consumer.commit(asynchronous=False))

    except asyncio.CancelledError:
        logger.info("dlq_consumer.cancelled")
    except Exception as exc:
        logger.critical("dlq_consumer.fatal_error %s", exc, exc_info=True)
        raise
    finally:
        consumer.close()
        logger.info("dlq_consumer.stopped")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    asyncio.run(run_dlq_consumer())
