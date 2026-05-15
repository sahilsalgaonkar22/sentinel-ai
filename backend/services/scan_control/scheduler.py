"""
SENTINEL AI -- Scan Scheduler (GAP-1 FIX)

Changes vs original:
  - GAP-1: self.jobs now backed by PostgreSQL (survives gateway restart).
    On startup, loads all Scan rows with is_recurring=True from DB.
  - T1:  cron expressions parsed with `croniter` instead of `int(cron.split()[0])`.
    Falls back to 24-hour interval if croniter unavailable or expression invalid.
  - Preserves all original logic: drift detection, alerting.
"""
import asyncio
import json
import uuid
import logging
from datetime import datetime, timezone
from sqlalchemy.future import select

from backend.common.database import AsyncSessionLocal
from backend.services.scan_control.models import Scan, Finding
from backend.services.scan_control.orchestrator import start_scan_task
from backend.services.scan_control.scan_comparator import compare_scans
from backend.services.alerting import alert_on_scan_complete, alert_on_drift

logger = logging.getLogger(__name__)


def _next_run_due(cron_expr: str, last_run: datetime | None) -> bool:
    """
    Return True if the cron schedule is due to fire.
    Uses croniter when available; falls back to an interval-hours parser.
    """
    now = datetime.now(timezone.utc)

    # Try croniter first (T1 FIX)
    try:
        from croniter import croniter
        if not croniter.is_valid(cron_expr):
            raise ValueError("invalid cron")
        cron = croniter(cron_expr, last_run or now)
        prev = cron.get_prev(datetime)
        return now >= prev
    except Exception:
        pass

    # Fallback: treat first token as hours interval
    try:
        hours = int(cron_expr.split()[0])
    except Exception:
        hours = 24

    if last_run is None:
        return True
    return (now - last_run).total_seconds() >= hours * 3600


class SchedulerManager:
    """Asyncio-based Scheduler for recurring scans + drift detection.

    GAP-1 FIX: State is loaded from PostgreSQL on startup, not kept in-memory only.
    """

    def __init__(self):
        # scan_id -> {"cron": str, "last_run": datetime|None}
        self.jobs: dict = {}
        self._task = None

    def start(self):
        """Start the background polling loop."""
        if not self._task:
            self._task = asyncio.create_task(self._startup_and_loop())
            logger.info("scheduler.started")

    def sync_schedule(self, scan_id: str, cron_expr: str):
        """Add or update a schedule in memory (also called by the scans route)."""
        self.jobs[scan_id] = {"cron": cron_expr, "last_run": None}
        logger.info("scheduler.synced scan_id=%s cron=%s", scan_id, cron_expr)

    def remove_schedule(self, scan_id: str):
        self.jobs.pop(scan_id, None)

    async def _load_from_db(self):
        """GAP-1 FIX: Load all recurring scans from DB on startup."""
        try:
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(Scan).where(Scan.is_recurring == True)  # noqa: E712
                )
                recurring = result.scalars().all()
                for scan in recurring:
                    if scan.id not in self.jobs:
                        self.jobs[scan.id] = {
                            "cron": scan.cron_schedule or "24 * * * *",
                            "last_run": scan.completed_at,
                        }
            logger.info("scheduler.loaded_from_db count=%d", len(self.jobs))
        except Exception as exc:
            logger.error("scheduler.db_load_error err=%s", exc)

    async def _startup_and_loop(self):
        """Load DB state then start polling loop."""
        await self._load_from_db()
        await self._scheduler_loop()

    async def _scheduler_loop(self):
        """Poll every 60 seconds and fire due jobs."""
        while True:
            try:
                await asyncio.sleep(60)
                for scan_id, data in list(self.jobs.items()):
                    try:
                        if _next_run_due(data["cron"], data["last_run"]):
                            logger.info("scheduler.triggering scan_id=%s", scan_id)
                            self.jobs[scan_id]["last_run"] = datetime.now(timezone.utc)
                            asyncio.create_task(self._execute_scheduled_scan(scan_id))
                    except Exception as exc:
                        logger.error("scheduler.job_error scan_id=%s err=%s", scan_id, exc)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("scheduler.loop_error err=%s", exc)

    async def _execute_scheduled_scan(self, original_scan_id: str):
        """Execute scan, wait for completion, check for drift, fire alerts."""
        async with AsyncSessionLocal() as db:
            orig_scan = await db.get(Scan, original_scan_id)
            if not orig_scan:
                self.remove_schedule(original_scan_id)
                return

            org_id    = orig_scan.org_id
            target    = orig_scan.target_raw
            scan_name = orig_scan.name

            new_scan_id = str(uuid.uuid4())
            new_scan = Scan(
                id=new_scan_id,
                name=f"{scan_name} (Scheduled)",
                target_raw=target,
                scan_type=orig_scan.scan_type,
                org_id=org_id,
                initiated_by="scheduler",
                is_recurring=True,
                cron_schedule=orig_scan.cron_schedule,
            )
            db.add(new_scan)
            await db.commit()

        logger.info("scheduler.scan_started scan_id=%s target=%s", new_scan_id, target)
        await start_scan_task(new_scan_id, org_id, target)

        # ── Drift Detection ──────────────────────────────────────────────────
        logger.info("scheduler.drift_check scan_id=%s target=%s", new_scan_id, target)
        try:
            async with AsyncSessionLocal() as db:
                r1 = await db.execute(select(Finding).where(Finding.scan_id == original_scan_id))
                r2 = await db.execute(select(Finding).where(Finding.scan_id == new_scan_id))

                def _to_dict(f):
                    return {
                        "id": f.id, "title": f.title, "severity": f.severity,
                        "cvss_score": f.cvss_score, "cve_id": f.cve_id,
                        "affected_component": f.affected_component or "",
                        "tool_name": f.tool_name,
                    }

                old_fs = [_to_dict(f) for f in r1.scalars().all()]
                new_fs = [_to_dict(f) for f in r2.scalars().all()]

                scan_after  = await db.get(Scan, new_scan_id)
                scan_before = await db.get(Scan, original_scan_id)

                before_score = scan_before.security_score or 0.0
                after_score  = scan_after.security_score  or 0.0

                drift = compare_scans(old_fs, new_fs, before_score, after_score)

                new_issues  = drift.get("new_findings", [])
                resolved    = drift.get("resolved_findings", [])
                score_delta = drift.get("score_delta", 0)

                scan_after.drift_summary = {
                    "vs_scan_id":     original_scan_id,
                    "new_count":      len(new_issues),
                    "resolved_count": len(resolved),
                    "score_delta":    score_delta,
                    "new_criticals":  len([f for f in new_issues if f.get("severity") == "critical"]),
                    "new_highs":      len([f for f in new_issues if f.get("severity") == "high"]),
                    "checked_at":     datetime.now(timezone.utc).isoformat(),
                }
                await db.commit()

                new_criticals = len([f for f in new_issues if f.get("severity") == "critical"])
                new_highs     = len([f for f in new_issues if f.get("severity") == "high"])

                if new_issues:
                    logger.warning(
                        "scheduler.drift_detected scan_id=%s target=%s "
                        "new_criticals=%d new_highs=%d",
                        new_scan_id, target, new_criticals, new_highs
                    )
                    await alert_on_drift(
                        scan_name=scan_name, target=target,
                        new_criticals=new_criticals, new_highs=new_highs,
                        resolved=len(resolved), score_delta=score_delta,
                        org_id=org_id, scan_id=new_scan_id
                    )
                    await alert_on_scan_complete(
                        scan_name=f"{scan_name} (Scheduled)", target=target,
                        score=after_score, grade=scan_after.risk_grade or "?",
                        critical_count=scan_after.critical_count or 0,
                        high_count=scan_after.high_count or 0,
                        total_findings=scan_after.total_findings or 0,
                        drift_detected=True,
                        org_id=org_id, scan_id=new_scan_id
                    )
                else:
                    logger.info(
                        "scheduler.no_drift scan_id=%s target=%s score=%.1f delta=%+.1f",
                        new_scan_id, target, after_score, score_delta
                    )

        except Exception as exc:
            logger.error("scheduler.drift_error scan_id=%s err=%s", new_scan_id, exc)


scheduler_manager = SchedulerManager()
