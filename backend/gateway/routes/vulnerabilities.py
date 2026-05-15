"""
SENTINEL AI — Vulnerability Routes
All routes query the real DB. No demo fallbacks. No hardcoded data.
Reads from Finding table (populated by real scans) as primary data source.
"""
import logging

from fastapi import APIRouter, Depends, HTTPException, Request

logger = logging.getLogger(__name__)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from backend.common.database import get_db
from backend.services.scan_control.models import Finding, AttackPath
from backend.schemas.api import AttackPathResponse
from backend.gateway.middleware.auth import get_current_user
from backend.gateway.limiter import limiter

router = APIRouter()


async def _get_db(user: dict = Depends(get_current_user)):
    async for session in get_db(user):
        yield session


@router.get("/")
@limiter.limit("60/minute")
async def list_vulnerabilities(
    request: Request,
    page: int = 1, per_page: int = 20, severity: str = None,
    db: AsyncSession = Depends(_get_db), user: dict = Depends(get_current_user)
):
    org_id = user["org_id"]
    try:
        query = select(Finding).where(Finding.org_id == org_id).order_by(desc(Finding.created_at))
        if severity:
            query = query.where(Finding.severity == severity)

        count_q = select(func.count()).select_from(Finding).where(Finding.org_id == org_id)
        if severity:
            count_q = count_q.where(Finding.severity == severity)
        total = (await db.execute(count_q)).scalar() or 0

        result = await db.execute(query.offset((page - 1) * per_page).limit(per_page))
        findings = result.scalars().all()

        items = []
        for f in findings:
            items.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "tool_name": f.tool_name,
                "cve_id": f.cve_id,
                "cwe_id": f.cwe_id,
                "cvss_score": f.cvss_score,
                "epss_score": getattr(f, "epss_score", None),
                "evidence": f.tool_output,
                "remediation": f.remediation,
                "status": getattr(f, "status", "open"),
                "created_at": f.created_at.isoformat() if f.created_at else None,
                "scan_id": f.scan_id,
            })

        return {
            "items": items,
            "total": total,
            "page": page,
            "per_page": per_page,
            "message": "No vulnerabilities found. Run a scan to populate." if total == 0 else None,
        }
    except Exception as e:
        logger.error("vulnerabilities.list_query_failed error=%s", e)
        return {
            "items": [],
            "total": 0,
            "page": page,
            "per_page": per_page,
            "message": "Database unavailable. Start infrastructure with: docker-compose up -d",
        }


@router.get("/stats/summary")
async def vulnerability_stats(db: AsyncSession = Depends(_get_db), user: dict = Depends(get_current_user)):
    """Real vulnerability summary statistics from DB using Finding table."""
    try:
        org_id = user["org_id"]
        total = (await db.execute(
            select(func.count()).select_from(Finding).where(Finding.org_id == org_id)
        )).scalar() or 0
        critical = (await db.execute(
            select(func.count()).select_from(Finding).where(
                Finding.org_id == org_id, Finding.severity == "critical"
            )
        )).scalar() or 0
        high = (await db.execute(
            select(func.count()).select_from(Finding).where(
                Finding.org_id == org_id, Finding.severity == "high"
            )
        )).scalar() or 0
        medium = (await db.execute(
            select(func.count()).select_from(Finding).where(
                Finding.org_id == org_id, Finding.severity == "medium"
            )
        )).scalar() or 0
        low = max(0, total - critical - high - medium)
        return {"total": total, "critical": critical, "high": high, "medium": medium, "low": low}
    except Exception as e:
        logger.error("vulnerabilities.stats_query_failed error=%s", e)
        return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}


@router.get("/attack-paths/")
async def list_attack_paths(db: AsyncSession = Depends(_get_db), user: dict = Depends(get_current_user)):
    """Real attack paths from DB. Returns [] if none exist yet."""
    try:
        org_id = user["org_id"]
        result = await db.execute(
            select(AttackPath).where(AttackPath.org_id == org_id).order_by(desc(AttackPath.risk_score))
        )
        paths = result.scalars().all()
        return [AttackPathResponse.model_validate(p) for p in paths]
    except Exception as e:
        logger.error("vulnerabilities.attack_path_query_failed error=%s", e)
        return []


@router.get("/{vuln_id}")
async def get_vulnerability(vuln_id: str, db: AsyncSession = Depends(_get_db), user: dict = Depends(get_current_user)):
    org_id = user["org_id"]
    try:
        result = await db.execute(select(Finding).where(Finding.id == vuln_id, Finding.org_id == org_id))
        finding = result.scalar_one_or_none()
        if finding:
            return {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "description": finding.description,
                "tool_name": finding.tool_name,
                "cve_id": finding.cve_id,
                "cwe_id": finding.cwe_id,
                "cvss_score": finding.cvss_score,
                "evidence": finding.tool_output,
                "remediation": finding.remediation,
                "status": getattr(finding, "status", "open"),
                "created_at": finding.created_at.isoformat() if finding.created_at else None,
                "scan_id": finding.scan_id,
            }
    except Exception:
        pass
    raise HTTPException(status_code=404, detail="Vulnerability not found")
