"""
SENTINEL AI — Scan Routes
Create, list, manage, and retrieve findings for vulnerability scans.
All data comes from real DB — no hardcoded fallback for core flows.

FIX-2: empty target_raw is rejected (HTTP 400) instead of defaulting to 127.0.0.1
"""
import logging
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc, func
from typing import List
from datetime import datetime, timezone

from backend.common.database import get_db
from backend.services.scan_control.models import Scan, ScanStatus, Finding
from backend.schemas.scan import ScanCreate, ScanResponse
from backend.gateway.middleware.auth import get_current_user

logger = logging.getLogger(__name__)

# Max concurrent scans an org can have in RUNNING/PENDING state simultaneously
MAX_CONCURRENT_SCANS_PER_ORG: int = 10

router = APIRouter(prefix="/scans", tags=["scans"])


async def _get_db(user: dict = Depends(get_current_user)):
    """Inject org-scoped DB session."""
    async for session in get_db(user):
        yield session


from backend.gateway.limiter import limiter
from fastapi import Request

@router.post("/", response_model=ScanResponse, status_code=201)
@limiter.limit("10/minute")
async def create_scan(
    request: Request,
    scan_in: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(_get_db),
    user: dict = Depends(get_current_user)
):
    """Create a new scan and immediately dispatch it for execution."""
    org_id = user["org_id"]

    # FIX-2: reject empty target — never inject loopback as default
    if not scan_in.target_raw or not scan_in.target_raw.strip():
        raise HTTPException(
            status_code=400,
            detail="target_raw is required. Provide an IP, domain, URL, git URL, or docker image."
        )

    # Org-level concurrency guard — prevent runaway parallel scans
    running_count_result = await db.execute(
        select(func.count(Scan.id)).where(
            Scan.org_id == org_id,
            Scan.status.in_([ScanStatus.PENDING.value, ScanStatus.RUNNING.value]),
        )
    )
    running_count = running_count_result.scalar() or 0
    if running_count >= MAX_CONCURRENT_SCANS_PER_ORG:
        raise HTTPException(
            status_code=429,
            detail=f"Concurrent scan limit reached ({MAX_CONCURRENT_SCANS_PER_ORG} active scans). "
                   "Wait for existing scans to complete."
        )

    new_scan = Scan(
        name=scan_in.name,
        target_raw=scan_in.target_raw.strip(),
        target_id=scan_in.target_id,
        scan_type=scan_in.scan_type,
        status=ScanStatus.PENDING.value,
        org_id=org_id,
        initiated_by=user["user_id"]
    )
    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan)

    logger.info(
        "scan.created scan_id=%s target=%s org_id=%s user_id=%s",
        new_scan.id, new_scan.target_raw, org_id, user["user_id"]
    )

    # Dispatch scan execution in background
    from backend.services.scan_control.orchestrator import start_scan_task
    background_tasks.add_task(start_scan_task, new_scan.id, org_id, new_scan.target_raw)

    return new_scan


@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    db: AsyncSession = Depends(_get_db),
    user: dict = Depends(get_current_user),
    offset: int = 0,    # T3 FIX: pagination
    limit: int = 50,    # max 200 per page
):
    """List all scans for the authenticated org with pagination."""
    limit = min(limit, 200)   # cap to prevent abuse
    org_id = user["org_id"]
    result = await db.execute(
        select(Scan).where(Scan.org_id == org_id)
        .order_by(desc(Scan.created_at))
        .offset(offset)
        .limit(limit)
    )
    scans = result.scalars().all()
    return scans



@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(_get_db),
    user: dict = Depends(get_current_user)
):
    """Get a specific scan by ID."""
    org_id = user["org_id"]
    scan = await db.get(Scan, scan_id)
    if not scan or scan.org_id != org_id:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/findings")
async def get_scan_findings(
    scan_id: str,
    db: AsyncSession = Depends(_get_db),
    user: dict = Depends(get_current_user)
):
    """Get all findings for a completed scan."""
    org_id = user["org_id"]

    # Verify scan belongs to org
    scan = await db.get(Scan, scan_id)
    if not scan or scan.org_id != org_id:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = await db.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id, Finding.org_id == org_id)
        .order_by(desc(Finding.cvss_score))
    )
    findings = result.scalars().all()

    return {
        "scan_id": scan_id,
        "scan_name": scan.name,
        "scan_status": scan.status,
        "total": len(findings),
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "cve_id": f.cve_id,
                "cwe_id": f.cwe_id,
                "tool_name": f.tool_name,
                "remediation": f.remediation,
                "exploit_available": f.exploit_available,
                "created_at": f.created_at.isoformat() if f.created_at else None,
            }
            for f in findings
        ]
    }


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    db: AsyncSession = Depends(_get_db),
    user: dict = Depends(get_current_user)
):
    """Cancel a running scan."""
    org_id = user["org_id"]
    scan = await db.get(Scan, scan_id)
    if not scan or scan.org_id != org_id:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status in [ScanStatus.COMPLETED.value, ScanStatus.FAILED.value]:
        raise HTTPException(status_code=400, detail=f"Cannot cancel scan in status: {scan.status}")

    scan.status = ScanStatus.CANCELLED.value
    scan.completed_at = datetime.now(timezone.utc)  # FIX: timezone-aware
    await db.commit()

    logger.info("scan.cancelled scan_id=%s user_id=%s", scan_id, user["user_id"])
    return {"status": "cancelled", "scan_id": scan_id}


@router.get("/{scan_id}/attack-paths")
async def get_attack_paths(
    scan_id: str,
    db: AsyncSession = Depends(_get_db),
    user: dict = Depends(get_current_user)
):
    """Get attack paths generated for a completed scan."""
    org_id = user["org_id"]
    scan = await db.get(Scan, scan_id)
    if not scan or scan.org_id != org_id:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id, Finding.org_id == org_id)
    )
    findings = result.scalars().all()

    findings_data = [
        {
            "title": f.title,
            "severity": f.severity,
            "cvss_score": f.cvss_score,
            "cve_id": f.cve_id,
            "affected_component": f.affected_component or "",
            "tool_name": f.tool_name,
            "exploit_available": f.exploit_available,
        }
        for f in findings
    ]

    from backend.services.ai_intelligence.attack_graph import generate_attack_paths
    paths = generate_attack_paths(findings_data)
    return {"scan_id": scan_id, "attack_paths": paths, "total": len(paths)}


@router.post("/compare")
async def compare_scans(
    payload: dict,
    db: AsyncSession = Depends(_get_db),
    user: dict = Depends(get_current_user),
):
    """Compare two scans (Before vs After) and return diff."""
    org_id = user["org_id"]
    scan_id_before = payload.get("scan_id_before")
    scan_id_after = payload.get("scan_id_after")

    if not scan_id_before or not scan_id_after:
        raise HTTPException(status_code=400, detail="Both scan_id_before and scan_id_after are required")

    # Load both scans
    scan_before = await db.get(Scan, scan_id_before)
    scan_after = await db.get(Scan, scan_id_after)

    if not scan_before or scan_before.org_id != org_id:
        raise HTTPException(status_code=404, detail="Before-scan not found")
    if not scan_after or scan_after.org_id != org_id:
        raise HTTPException(status_code=404, detail="After-scan not found")

    # FIX-7: Always filter findings by org_id even when scan ownership is verified
    r1 = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id_before, Finding.org_id == org_id)
    )
    r2 = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id_after, Finding.org_id == org_id)
    )

    def _to_dict(f):
        return {
            "id": f.id, "title": f.title, "severity": f.severity,
            "cvss_score": f.cvss_score, "cve_id": f.cve_id,
            "affected_component": f.affected_component or "",
            "tool_name": f.tool_name, "remediation": f.remediation,
        }

    before_findings = [_to_dict(f) for f in r1.scalars().all()]
    after_findings = [_to_dict(f) for f in r2.scalars().all()]

    from backend.services.scan_control.scan_comparator import compare_scans as do_compare
    comparison = do_compare(
        before_findings, after_findings,
        scan_before.security_score or 0,
        scan_after.security_score or 0,
    )
    comparison["scan_before"] = {"id": scan_id_before, "name": scan_before.name, "target": scan_before.target_raw}
    comparison["scan_after"] = {"id": scan_id_after, "name": scan_after.name, "target": scan_after.target_raw}
    return comparison


@router.post("/{scan_id}/schedule")
async def schedule_scan(
    scan_id: str,
    payload: dict,
    db: AsyncSession = Depends(_get_db),
    user: dict = Depends(get_current_user),
):
    """Set a cron schedule for a scan."""
    org_id = user["org_id"]
    cron_expr = payload.get("cron")
    if not cron_expr:
        raise HTTPException(status_code=400, detail="cron expression required")

    scan = await db.get(Scan, scan_id)
    if not scan or scan.org_id != org_id:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    scan.schedule_cron = cron_expr
    scan.is_recurring = True
    await db.commit()
    
    from backend.services.scan_control.scheduler import scheduler_manager
    scheduler_manager.sync_schedule(scan_id, cron_expr)
    
    return {"status": "scheduled", "scan_id": scan_id, "cron": cron_expr}


@router.delete("/{scan_id}/schedule")
async def unschedule_scan(
    scan_id: str,
    db: AsyncSession = Depends(_get_db),
    user: dict = Depends(get_current_user),
):
    """Remove a cron schedule."""
    org_id = user["org_id"]
    scan = await db.get(Scan, scan_id)
    if not scan or scan.org_id != org_id:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    scan.schedule_cron = None
    scan.is_recurring = False
    await db.commit()
    
    from backend.services.scan_control.scheduler import scheduler_manager
    scheduler_manager.remove_schedule(scan_id)
    
    return {"status": "unscheduled", "scan_id": scan_id}


@router.get("/scheduled/list")
async def list_scheduled_scans(
    db: AsyncSession = Depends(_get_db),
    user: dict = Depends(get_current_user)
):
    """List all scheduled scans for the authenticated org."""
    org_id = user["org_id"]
    result = await db.execute(
        select(Scan).where(Scan.org_id == org_id, Scan.is_recurring == True)
    )
    return result.scalars().all()


@router.get("/{scan_id}/drift")
async def get_scan_drift(
    scan_id: str,
    db: AsyncSession = Depends(_get_db),
    user: dict = Depends(get_current_user)
):
    """Get drift summary for a recurring scan."""
    org_id = user["org_id"]
    scan = await db.get(Scan, scan_id)
    if not scan or scan.org_id != org_id:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    return {
        "scan_id": scan_id,
        "drift_summary": scan.drift_summary or {}
    }


@router.get("/{scan_id}/report-url")
async def get_scan_report_url(
    scan_id: str,
    db: AsyncSession = Depends(_get_db),
    user: dict = Depends(get_current_user)
):
    """Get presigned S3 URL for downloading PDF report."""
    org_id = user["org_id"]
    scan = await db.get(Scan, scan_id)
    if not scan or scan.org_id != org_id:
        raise HTTPException(status_code=404, detail="Scan not found")

    from backend.common.storage import get_report_url
    url = await get_report_url(scan_id)
    if not url:
        raise HTTPException(status_code=404, detail="Report not ready or storage disabled")

    return {"scan_id": scan_id, "url": url}

