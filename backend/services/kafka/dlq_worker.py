"""
Sentinel AI — Kafka DLQ Replay Worker

Continuously polls the `kafka_dlq` table for pending events and replays
them back into Kafka. On success, marks the row as 'replayed'. On failure,
increments the retry_count. After DLQ_MAX_RETRIES failures, marks as 'dead'.

This worker runs as a background asyncio task started in main.py lifespan.
"""
import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy.future import select
from sqlalchemy import update

from backend.common.config import settings

logger = logging.getLogger(__name__)


async def replay_kafka_dlq() -> None:
    """
    Background loop that processes pending DLQ events.
    Interval and max retries are controlled by env vars:
      DLQ_RETRY_INTERVAL_SECONDS (default: 60)
      DLQ_MAX_RETRIES (default: 10)
    """
    interval = settings.DLQ_RETRY_INTERVAL_SECONDS
    max_retries = settings.DLQ_MAX_RETRIES

    logger.info("dlq_worker.start interval=%ds max_retries=%d", interval, max_retries)

    while True:
        try:
            await _process_batch(max_retries)
        except Exception as e:
            logger.error("dlq_worker.batch_error err=%s", e)
        await asyncio.sleep(interval)


async def _process_batch(max_retries: int) -> None:
    """Fetch and replay one batch of pending DLQ events."""
    from backend.common.database import AsyncSessionLocal
    from backend.services.scan_control.models import KafkaFallbackDLQ
    from backend.services.kafka.manager import kafka_manager

    async with AsyncSessionLocal() as session:
        # Fetch pending events that haven't exceeded max retries
        result = await session.execute(
            select(KafkaFallbackDLQ)
            .where(
                KafkaFallbackDLQ.status == "pending",
                KafkaFallbackDLQ.retry_count < max_retries
            )
            .limit(50)  # Process at most 50 per cycle to avoid overwhelming Kafka
        )
        pending = result.scalars().all()

        if not pending:
            return

        logger.info("dlq_worker.processing count=%d", len(pending))

        for event in pending:
            try:
                # Attempt replay into Kafka
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda e=event: kafka_manager.produce(
                        topic=e.topic,
                        key=e.message_key or e.id,
                        value=e.payload,
                    )
                )
                # Success — mark as replayed
                await session.execute(
                    update(KafkaFallbackDLQ)
                    .where(KafkaFallbackDLQ.id == event.id)
                    .values(
                        status="replayed",
                        updated_at=datetime.now(timezone.utc),
                    )
                )
                logger.info(
                    "dlq_worker.replayed id=%s topic=%s retry=%d",
                    event.id, event.topic, event.retry_count
                )

            except Exception as replay_err:
                new_count = event.retry_count + 1
                new_status = "dead" if new_count >= max_retries else "pending"

                await session.execute(
                    update(KafkaFallbackDLQ)
                    .where(KafkaFallbackDLQ.id == event.id)
                    .values(
                        retry_count=new_count,
                        status=new_status,
                        error=str(replay_err),
                        updated_at=datetime.now(timezone.utc),
                    )
                )
                logger.warning(
                    "dlq_worker.replay_failed id=%s topic=%s retry=%d/%d status=%s err=%s",
                    event.id, event.topic, new_count, max_retries, new_status, replay_err
                )

        await session.commit()
