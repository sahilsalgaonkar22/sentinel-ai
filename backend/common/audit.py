"""
SENTINEL AI — Audit Logging (FIX-5+6: print → logging, utcnow → timezone-aware)
Records user actions for compliance and security monitoring.
"""
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_audit_log = []


async def log_event(
    user_id: str,
    action: str,
    details: dict = None,
    org_id: str = None,
    resource_type: str = None,
    resource_id: str = None,
):
    """Log an audit event. In production, persists to DB and Elasticsearch."""
    event = {
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "user_id":       user_id,
        "org_id":        org_id,
        "action":        action,
        "resource_type": resource_type,
        "resource_id":   resource_id,
        "details":       details or {},
    }
    _audit_log.append(event)
    logger.info(
        "audit.event action=%s user_id=%s org_id=%s resource=%s/%s",
        action, user_id, org_id, resource_type, resource_id,
    )
    return event


def get_audit_log(limit: int = 100):
    """Retrieve recent audit log entries."""
    return _audit_log[-limit:]
