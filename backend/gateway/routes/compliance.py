"""
SENTINEL AI — Compliance Routes
Map scan findings to compliance frameworks (OWASP, PCI-DSS, ISO 27001, NIST CSF).
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from backend.gateway.middleware.auth import get_current_user
from backend.common.database import get_db_session
from backend.services.scan_control.models import Scan, Finding
from backend.services.compliance.mapper import map_findings_to_compliance

router = APIRouter()


@router.get("/{scan_id}")
async def get_compliance_report(
    scan_id: str,
    db: AsyncSession = Depends(get_db_session),
    user: dict = Depends(get_current_user),
):
    """Generate compliance mapping for a scan's findings."""
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
            "description": f.description or "",
            "severity": f.severity,
            "cvss_score": f.cvss_score,
            "cve_id": f.cve_id,
            "cwe_id": f.cwe_id,
            "affected_component": f.affected_component or "",
            "tool_name": f.tool_name,
        }
        for f in findings
    ]

    compliance = map_findings_to_compliance(findings_data)
    compliance["scan_id"] = scan_id
    compliance["scan_name"] = scan.name
    compliance["target"] = scan.target_raw

    return compliance


@router.get("/frameworks/list")
async def list_frameworks(user: dict = Depends(get_current_user)):
    """List all supported compliance frameworks."""
    return {
        "frameworks": [
            {"id": "owasp_top_10", "name": "OWASP Top 10 (2021)", "controls": 10},
            {"id": "pci_dss", "name": "PCI-DSS v4.0", "controls": 11},
            {"id": "iso_27001", "name": "ISO 27001:2022", "controls": 11},
            {"id": "nist_csf", "name": "NIST CSF 2.0", "controls": 8},
        ]
    }
