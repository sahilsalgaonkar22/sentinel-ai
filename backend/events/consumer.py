"""
SENTINEL AI — Kafka Consumer (Legacy compat wrapper)

BLOCKER-4 FIX: Removed import of tombstoned events/producer.py.
GAP-7 FIX: Replaced blocking synchronous poll() loop with asyncio-compatible
           run_in_executor pattern — matches WorkerBase and result_processor.py.

DLQ now uses kafka_manager.produce_to_dlq() (async) — consistent with the
rest of the production pipeline.
"""
import asyncio
import json
import logging

from confluent_kafka import Consumer, KafkaError
from backend.common.config import settings

logger = logging.getLogger(__name__)


class KafkaConsumer:
    """Async-compatible Kafka consumer with DLQ support."""

    def __init__(self, group_id: str):
        from backend.services.kafka.manager import kafka_manager
        self._kafka_manager = kafka_manager

        self.consumer = Consumer({
            "bootstrap.servers": settings.KAFKA_BOOTSTRAP_SERVERS,
            "group.id": group_id,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
            "session.timeout.ms": 30_000,
            **kafka_manager._sasl_conf(),   # GAP-10: inject SASL credentials
        })

    async def consume(self, topics: list, message_handler, max_retries: int = 3):
        """
        Async consumer loop — uses run_in_executor so poll() never blocks the
        FastAPI event loop.  DLQ routing via kafka_manager on exhausted retries.
        """
        self.consumer.subscribe(topics)
        loop = asyncio.get_running_loop()

        def _poll():
            return self.consumer.poll(timeout=0.5)

        logger.info("consumer.started topics=%s group=%s", topics, self.consumer.memberid())

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
                    logger.error("consumer.poll_error err=%s", msg.error())
                    await asyncio.sleep(1.0)
                    continue

                retries = 0
                last_exc = None
                while retries < max_retries:
                    try:
                        message_data = json.loads(msg.value().decode("utf-8"))
                        await asyncio.coroutine(message_handler)(message_data) \
                            if asyncio.iscoroutinefunction(message_handler) \
                            else message_handler(message_data)
                        await loop.run_in_executor(
                            None, lambda: self.consumer.commit(asynchronous=False)
                        )
                        break
                    except Exception as exc:
                        last_exc = exc
                        logger.warning(
                            "consumer.retry attempt=%d/%d err=%s",
                            retries + 1, max_retries, exc
                        )
                        retries += 1
                        await asyncio.sleep(0.5 * retries)
                else:
                    # Exhausted retries — route to DLQ
                    logger.error(
                        "consumer.dlq_route topic=%s err=%s", msg.topic(), last_exc
                    )
                    try:
                        payload = json.loads(msg.value().decode("utf-8")) if msg.value() else {}
                        await self._kafka_manager.produce_to_dlq(
                            msg.topic(),
                            msg.key().decode() if msg.key() else "unknown",
                            payload,
                            str(last_exc),
                        )
                    except Exception as dlq_err:
                        logger.critical(
                            "consumer.dlq_failed topic=%s dlq_err=%s original=%s",
                            msg.topic(), dlq_err, last_exc
                        )
                    await loop.run_in_executor(
                        None, lambda: self.consumer.commit(asynchronous=False)
                    )

        except asyncio.CancelledError:
            logger.info("consumer.shutdown topics=%s", topics)
        finally:
            self.consumer.close()

    def close(self):
        self.consumer.close()
