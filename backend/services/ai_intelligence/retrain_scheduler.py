"""
SENTINEL AI — MLOps Retrain Scheduler
Runs as a background asyncio task. Every 24 hours it checks if there
are ≥100 un-trained AIFeedback records; if so, it triggers train.py.
The trained models are hot-swapped into the running service.
"""
from __future__ import annotations
import asyncio
import logging
import os
import importlib

logger = logging.getLogger(__name__)

# Minimum unprocessed feedback records before triggering a retrain
_RETRAIN_THRESHOLD = 100
# How often to check (seconds) — 24 hours
_CHECK_INTERVAL = 86_400


async def _count_unprocessed_feedback() -> int:
    """Count AIFeedback rows where retrained=False."""
    try:
        from sqlalchemy import select, func
        from backend.common.database import AsyncSessionLocal
        from backend.services.scan_control.models import AIFeedback

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(func.count()).select_from(AIFeedback).where(
                    AIFeedback.retrained == False  # noqa: E712
                )
            )
            return result.scalar() or 0
    except Exception as exc:
        logger.warning("[RETRAIN] Could not count feedback: %s", exc)
        return 0


async def _mark_feedback_retrained():
    """Mark all pending feedback records as retrained=True."""
    try:
        from sqlalchemy import update
        from backend.common.database import AsyncSessionLocal
        from backend.services.scan_control.models import AIFeedback

        async with AsyncSessionLocal() as db:
            await db.execute(
                update(AIFeedback)
                .where(AIFeedback.retrained == False)  # noqa: E712
                .values(retrained=True)
            )
            await db.commit()
    except Exception as exc:
        logger.warning("[RETRAIN] Could not mark feedback retrained: %s", exc)


def _run_training() -> bool:
    """
    Execute the XGBoost training pipeline synchronously.
    Returns True if new models were saved successfully.
    """
    try:
        from backend.services.ai_intelligence.train import train_and_evaluate
        train_and_evaluate()
        return True
    except Exception as exc:
        logger.error("[RETRAIN] Training failed: %s", exc, exc_info=True)
        return False


def _hot_swap_models():
    """
    Force-reload the false_positive and risk_scoring modules so they
    pick up the newly written .joblib files without a service restart.
    """
    for module_name in (
        "backend.services.ai_intelligence.false_positive",
        "backend.services.ai_intelligence.risk_scoring",
    ):
        try:
            mod = importlib.import_module(module_name)
            importlib.reload(mod)
            logger.info("[RETRAIN] Hot-swapped module: %s", module_name)
        except Exception as exc:
            logger.warning("[RETRAIN] Hot-swap failed for %s: %s", module_name, exc)


async def start_retrain_scheduler():
    """
    Long-running background task. Checks feedback count every CHECK_INTERVAL seconds.
    Triggers training when threshold reached.
    """
    logger.info(
        "[RETRAIN] Scheduler started. threshold=%d interval=%ds",
        _RETRAIN_THRESHOLD, _CHECK_INTERVAL,
    )
    while True:
        try:
            await asyncio.sleep(_CHECK_INTERVAL)

            pending = await _count_unprocessed_feedback()
            logger.info("[RETRAIN] Pending feedback records: %d", pending)

            if pending >= _RETRAIN_THRESHOLD:
                logger.info(
                    "[RETRAIN] Threshold reached (%d >= %d). Starting training...",
                    pending, _RETRAIN_THRESHOLD,
                )

                # Run training in a thread pool (CPU-bound)
                loop = asyncio.get_event_loop()
                success = await loop.run_in_executor(None, _run_training)

                if success:
                    await _mark_feedback_retrained()
                    _hot_swap_models()
                    logger.info("[RETRAIN] Training complete. Models hot-swapped.")
                else:
                    logger.error("[RETRAIN] Training failed. Models unchanged.")
            else:
                logger.info(
                    "[RETRAIN] Not enough feedback yet (%d/%d). Next check in %dh.",
                    pending, _RETRAIN_THRESHOLD, _CHECK_INTERVAL // 3600,
                )

        except asyncio.CancelledError:
            logger.info("[RETRAIN] Scheduler cancelled.")
            break
        except Exception as exc:
            logger.error("[RETRAIN] Unexpected error: %s", exc, exc_info=True)
            # Don't crash — wait and retry
            await asyncio.sleep(60)
