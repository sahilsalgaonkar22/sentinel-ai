"""
Sentinel AI — Alert DLQ & Diagnostic Routes

Exposes:
  GET  /alerts/dlq              — List all alert DLQ events (admin only)
  GET  /alerts/dlq/stats        — Summary counts by status
  POST /alerts/dlq/{id}/retry   — Manually trigger a single DLQ event retry
  GET  /alerts/kafka-dlq        — List Kafka DLQ events (admin only)
"""
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func, update

from backend.common.database import get_db_session
from backend.gateway.middleware.auth import get_current_user, require_role
from backend.services.scan_control.models import AlertDLQ, KafkaFallbackDLQ

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("/dlq")
async def list_alert_dlq(
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db_session),
    user: dict = Depends(require_role("admin")),
):
    """
    List Alert DLQ events for the org.
    Admins can see failed/pending alerts and understand delivery failures.
    """
    org_id = user["org_id"]
    query = (
        select(AlertDLQ)
        .where(AlertDLQ.org_id == org_id)
        .order_by(AlertDLQ.created_at.desc())
        .limit(min(limit, 200))
        .offset(offset)
    )
    if status:
        query = query.where(AlertDLQ.status == status)

    result = await db.execute(query)
    events = result.scalars().all()

    total_q = select(func.count()).select_from(AlertDLQ).where(AlertDLQ.org_id == org_id)
    if status:
        total_q = total_q.where(AlertDLQ.status == status)
    total = (await db.execute(total_q)).scalar() or 0

    return {
        "items": [
            {
                "id": e.id,
                "scan_id": e.scan_id,
                "alert_type": e.alert_type,
                "status": e.status,
                "retry_count": e.retry_count,
                "error_message": e.error_message,
                "last_attempt_at": e.last_attempt_at.isoformat() if e.last_attempt_at else None,
                "created_at": e.created_at.isoformat() if e.created_at else None,
                "payload_summary": {
                    k: v for k, v in (e.payload or {}).items()
                    if k in ("subject", "title", "alert_type", "severity")
                },
            }
            for e in events
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/dlq/stats")
async def alert_dlq_stats(
    db: AsyncSession = Depends(get_db_session),
    user: dict = Depends(require_role("admin")),
):
    """Summary of Alert DLQ event counts by status."""
    org_id = user["org_id"]
    rows = await db.execute(
        select(AlertDLQ.status, func.count().label("count"))
        .where(AlertDLQ.org_id == org_id)
        .group_by(AlertDLQ.status)
    )
    counts = {row.status: row.count for row in rows}
    return {
        "pending": counts.get("pending", 0),
        "failed": counts.get("failed", 0),
        "resolved": counts.get("resolved", 0),
        "total": sum(counts.values()),
    }


@router.post("/dlq/{dlq_id}/retry")
async def retry_alert_dlq_event(
    dlq_id: str,
    db: AsyncSession = Depends(get_db_session),
    user: dict = Depends(require_role("admin")),
):
    """
    Manually trigger a retry for a single DLQ event.
    Resets status to 'pending' so the next alerting cycle picks it up.
    """
    org_id = user["org_id"]
    result = await db.execute(
        select(AlertDLQ).where(AlertDLQ.id == dlq_id, AlertDLQ.org_id == org_id)
    )
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="DLQ event not found")

    await db.execute(
        update(AlertDLQ)
        .where(AlertDLQ.id == dlq_id)
        .values(status="pending", retry_count=0, error_message=None)
    )
    await db.commit()

    logger.info("alert_dlq.manual_retry id=%s org_id=%s user=%s", dlq_id, org_id, user.get("user_id"))
    return {"message": "DLQ event re-queued for retry", "id": dlq_id}


@router.get("/kafka-dlq")
async def list_kafka_dlq(
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db_session),
    user: dict = Depends(require_role("admin")),
):
    """List Kafka DLQ events — shows events the replay worker is processing."""
    org_id = user["org_id"]
    query = (
        select(KafkaFallbackDLQ)
        .where(KafkaFallbackDLQ.org_id == org_id)
        .order_by(KafkaFallbackDLQ.created_at.desc())
        .limit(min(limit, 200))
        .offset(offset)
    )
    if status:
        query = query.where(KafkaFallbackDLQ.status == status)

    result = await db.execute(query)
    events = result.scalars().all()

    total_q = select(func.count()).select_from(KafkaFallbackDLQ).where(KafkaFallbackDLQ.org_id == org_id)
    if status:
        total_q = total_q.where(KafkaFallbackDLQ.status == status)
    total = (await db.execute(total_q)).scalar() or 0

    return {
        "items": [
            {
                "id": e.id,
                "topic": e.topic,
                "message_key": e.message_key,
                "status": e.status,
                "retry_count": e.retry_count,
                "error": e.error,
                "updated_at": e.updated_at.isoformat() if e.updated_at else None,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in events
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }
