"""
SENTINEL AI — Distributed Scan Timeout Watchdog (FIX-2)

Runs as a background asyncio task inside the gateway lifespan.
Every 30 seconds, queries for RUNNING scans older than SCAN_TIMEOUT_SECONDS
and marks them FAILED with a meaningful error message.

This handles the case where a worker consumes a Kafka job and crashes
after committing the offset but before producing a result — causing the
scan to hang in RUNNING state indefinitely.
"""
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.future import select

from backend.common.config import settings
from backend.common.database import AsyncSessionLocal
from backend.services.scan_control.models import Scan, ScanStatus

logger = logging.getLogger(__name__)

# Check every 30 seconds
WATCHER_INTERVAL_SECONDS = 30


async def scan_timeout_watcher() -> None:
    """
    Long-running background coroutine.
    Marks any RUNNING scan older than SCAN_TIMEOUT_SECONDS as FAILED.
    """
    logger.info(
        "scan_timeout_watcher.started interval=%ds timeout=%ds",
        WATCHER_INTERVAL_SECONDS, settings.SCAN_TIMEOUT_SECONDS,
    )

    while True:
        try:
            await asyncio.sleep(WATCHER_INTERVAL_SECONDS)
            await _expire_stale_scans()
        except asyncio.CancelledError:
            logger.info("scan_timeout_watcher.stopped")
            break
        except Exception as exc:
            # Never crash the watchdog — log and continue
            logger.error("scan_timeout_watcher.error err=%s", exc, exc_info=True)


async def _expire_stale_scans() -> None:
    """Find RUNNING scans past their deadline and mark them FAILED."""
    deadline = datetime.now(timezone.utc) - timedelta(seconds=settings.SCAN_TIMEOUT_SECONDS)

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Scan).where(
                Scan.status == ScanStatus.RUNNING.value,
                Scan.started_at < deadline,
            )
        )
        stale_scans = result.scalars().all()

        if not stale_scans:
            return

        for scan in stale_scans:
            elapsed = (datetime.now(timezone.utc) - scan.started_at.replace(tzinfo=timezone.utc)).seconds
            logger.warning(
                "scan_timeout_watcher.expiring scan_id=%s org_id=%s "
                "target=%s elapsed=%ds timeout=%ds",
                scan.id, scan.org_id, scan.target_raw,
                elapsed, settings.SCAN_TIMEOUT_SECONDS,
            )
            scan.status = ScanStatus.FAILED.value
            scan.error_message = (
                f"Scan timed out after {elapsed}s "
                f"(limit: {settings.SCAN_TIMEOUT_SECONDS}s). "
                "The worker may have crashed. Check worker logs and DLQ."
            )
            scan.completed_at = datetime.now(timezone.utc)

        await db.commit()

        logger.error(
            "scan_timeout_watcher.expired_count count=%d",
            len(stale_scans),
        )
