"""
SENTINEL AI — Kafka Manager

PRODUCTION HARDENING:
- Hard-fails at import if confluent_kafka is not installed (no silent skip).
- Producer failures are logged and raised — no silent message drops.
- Consumer created with manual commit and no auto-commit.
- Dedicated DLQ topic (scan.jobs.*.dlq) for failed jobs.
"""
from typing import List
import json
import asyncio
import logging
import os

logger = logging.getLogger(__name__)

try:
    from confluent_kafka import Producer, Consumer, KafkaError, KafkaException
except ImportError:
    raise RuntimeError(
        "confluent_kafka is not installed. "
        "Install it: pip install confluent-kafka"
    )


class KafkaManager:
    """SENTINEL AI Kafka Integration Layer."""

    def __init__(self, bootstrap_servers: str = None):
        self.bootstrap_servers = (
            bootstrap_servers
            or os.environ["KAFKA_BOOTSTRAP_SERVERS"]  # Raises KeyError if missing — intentional
        )
        self.producer: Producer = None
        self._init_producer()

    def _sasl_conf(self) -> dict:
        """
        FIX-6: Build SASL configuration from environment.
        Returns empty dict if no SASL credentials configured (local/dev mode).
        In production (SASL_PLAINTEXT or SASL_SSL), credentials MUST be set.
        """
        username = os.environ.get("KAFKA_SASL_USERNAME", "")
        password = os.environ.get("KAFKA_SASL_PASSWORD", "")
        security_protocol = os.environ.get("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")

        if not username or not password:
            # No SASL configured — assume PLAINTEXT (dev-only)
            logger.warning(
                "kafka.sasl_not_configured security_protocol will be PLAINTEXT. "
                "Set KAFKA_SASL_USERNAME and KAFKA_SASL_PASSWORD for production."
            )
            return {}

        conf = {
            "security.protocol": security_protocol,
            "sasl.mechanism": "PLAIN",
            "sasl.username": username,
            "sasl.password": password,
        }
        logger.info("kafka.sasl_configured protocol=%s username=%s", security_protocol, username)
        return conf

    def _init_producer(self):
        conf = {
            "bootstrap.servers": self.bootstrap_servers,
            "client.id": "sentinel-gateway-producer",
            "retry.backoff.ms": 500,
            "message.send.max.retries": 5,
            "delivery.report.only.error": False,
            "socket.timeout.ms": 10000,
            **self._sasl_conf(),  # FIX-6: Inject SASL credentials
        }
        self.producer = Producer(conf)
        logger.info("kafka.producer_ready bootstrap=%s", self.bootstrap_servers)

    def _delivery_report(self, err, msg):
        if err is not None:
            logger.error(
                "kafka.delivery_failed topic=%s key=%s err=%s",
                msg.topic(), msg.key(), err
            )
        else:
            logger.debug(
                "kafka.delivery_ok topic=%s partition=%d offset=%d",
                msg.topic(), msg.partition(), msg.offset()
            )

    async def produce(self, topic: str, key: str, value: dict) -> None:
        """
        Produce a message to Kafka. Raises on producer queue failure.
        Non-blocking: uses run_in_executor to avoid blocking the event loop on flush.
        """
        if not self.producer:
            raise RuntimeError("Kafka producer is not initialized")

        payload = json.dumps(value).encode("utf-8")

        try:
            self.producer.produce(
                topic,
                key=key.encode("utf-8"),
                value=payload,
                callback=self._delivery_report,
            )
            self.producer.poll(0)

            try:
                from backend.common.metrics import kafka_messages_total
                kafka_messages_total.labels(topic=topic).inc()
            except Exception:
                pass

        except BufferError:
            logger.warning("kafka.queue_full topic=%s waiting for flush", topic)
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self.producer.flush)
        except KafkaException as exc:
            logger.error("kafka.produce_error topic=%s error=%s. Moving to DB DLQ.", topic, exc)
            try:
                from backend.common.database import AsyncSessionLocal
                from backend.services.scan_control.models import KafkaFallbackDLQ
                async with AsyncSessionLocal() as db:
                    dlq_item = KafkaFallbackDLQ(topic=topic, message_key=key, payload=value, error=str(exc))
                    db.add(dlq_item)
                    await db.commit()
            except Exception as db_exc:
                logger.critical("kafka.db_dlq_failed error=%s payload=%s", db_exc, value)

        except Exception as exc:
            logger.error("kafka.produce_unexpected_error topic=%s error=%s", topic, exc)
            try:
                from backend.common.database import AsyncSessionLocal
                from backend.services.scan_control.models import KafkaFallbackDLQ
                async with AsyncSessionLocal() as db:
                    dlq_item = KafkaFallbackDLQ(topic=topic, message_key=key, payload=value, error=str(exc))
                    db.add(dlq_item)
                    await db.commit()
            except Exception as db_exc:
                pass
        """Route a failed message to its DLQ topic."""
        dlq_topic = f"{original_topic}.dlq"
        dlq_payload = {
            **value,
            "_dlq_original_topic": original_topic,
            "_dlq_error": error,
        }
        await self.produce(dlq_topic, key, dlq_payload)
        logger.warning("kafka.dlq_routed original_topic=%s key=%s error=%s", original_topic, key, error)

    def flush(self, timeout: float = 10.0):
        if self.producer:
            remaining = self.producer.flush(timeout=timeout)
            if remaining > 0:
                logger.warning("kafka.flush_incomplete remaining=%d", remaining)

    def get_consumer(self, group_id: str, topics: List[str]) -> Consumer:
        """Create a Kafka consumer with manual commit and SASL auth (FIX-6)."""
        conf = {
            "bootstrap.servers": self.bootstrap_servers,
            "group.id": group_id,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,    # Manual commit only
            "session.timeout.ms": 30000,
            "max.poll.interval.ms": 600000,
            **self._sasl_conf(),  # FIX-6: Inject SASL credentials
        }
        consumer = Consumer(conf)
        consumer.subscribe(topics)
        return consumer


# Topics Registry
TOPIC_SCAN_REQUESTED   = "scan.requested"
TOPIC_SCAN_STARTED     = "scan.started"
TOPIC_SCAN_PROGRESS    = "scan.progress"
TOPIC_SCAN_COMPLETED   = "scan.completed"
TOPIC_FINDING_RAW      = "finding.raw"
TOPIC_FINDING_PROCESSED = "finding.processed"
TOPIC_ALERT_CRITICAL   = "alert.critical"

TOPIC_SCAN_JOBS_NETWORK   = "scan.jobs.network"
TOPIC_SCAN_JOBS_WEB       = "scan.jobs.web"
TOPIC_SCAN_JOBS_CODE      = "scan.jobs.code"
TOPIC_SCAN_JOBS_CONTAINER = "scan.jobs.container"
TOPIC_SCAN_JOBS_ADVANCED  = "scan.jobs.advanced"
TOPIC_SCAN_RESULTS        = "scan.results"
TOPIC_SCAN_LOGS           = "scan.logs"

# DLQ Topics
TOPIC_DLQ_NETWORK   = "scan.jobs.network.dlq"
TOPIC_DLQ_WEB       = "scan.jobs.web.dlq"
TOPIC_DLQ_CODE      = "scan.jobs.code.dlq"
TOPIC_DLQ_CONTAINER = "scan.jobs.container.dlq"
TOPIC_DLQ_ADVANCED  = "scan.jobs.advanced.dlq"

kafka_manager = KafkaManager()
