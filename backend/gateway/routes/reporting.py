"""
SENTINEL AI — Reporting Routes
Generate, list, and download real PDF security reports.
"""
import os
import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from backend.gateway.middleware.auth import get_current_user
from backend.common.database import get_db_session
from backend.services.scan_control.models import Scan, Finding
from backend.services.ai_intelligence.security_scorer import compute_security_score
from backend.services.reporting.pdf_generator import generate_report, REPORTS_DIR


router = APIRouter()


@router.get("/")
async def list_reports(
    user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
):
    """List all generated PDF reports — local filesystem + S3-tracked in DB."""
    reports = []
    seen_ids = set()

    # Local filesystem reports
    if os.path.exists(REPORTS_DIR):
        for fname in sorted(os.listdir(REPORTS_DIR), reverse=True):
            if fname.endswith(".pdf"):
                fpath = os.path.join(REPORTS_DIR, fname)
                stat = os.stat(fpath)
                report_id = fname.replace("sentinel_report_", "").replace(".pdf", "")
                seen_ids.add(report_id)
                reports.append({
                    "id": report_id,
                    "name": fname,
                    "type": "pdf",
                    "status": "completed",
                    "size": f"{stat.st_size / 1024:.1f} KB",
                    "created_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                })

    # Also check DB for S3-backed reports not on local disk
    try:
        result = await db.execute(
            select(Scan).where(Scan.report_s3_key.isnot(None))
        )
        for scan in result.scalars().all():
            # Extract report_id from s3_key like "reports/{scan_id}.pdf"
            s3_key = scan.report_s3_key or ""
            report_id = s3_key.replace("reports/", "").replace(".pdf", "")
            if report_id and report_id not in seen_ids:
                reports.append({
                    "id": report_id,
                    "name": f"sentinel_report_{report_id[:8]}.pdf",
                    "type": "pdf",
                    "status": "completed",
                    "size": "—",
                    "scan_id": scan.id,
                    "target": scan.target_raw,
                    "created_at": scan.completed_at.isoformat() if scan.completed_at else scan.created_at.isoformat(),
                })
    except Exception as e:
        logger.warning("Failed to list S3 reports from DB: %s", e)

    return {"items": reports}


@router.post("/generate")
async def generate_report_endpoint(
    report_config: dict,
    user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
):
    """Generate a real PDF report from a scan's findings.

    Optional: pass `compare_scan_id` to include a Before vs After section.
    """
    scan_id = report_config.get("scan_id")
    if not scan_id:
        raise HTTPException(status_code=400, detail="scan_id is required")

    # Load scan
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Load findings
    result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings_orm = result.scalars().all()

    findings_data = []
    for f in findings_orm:
        findings_data.append({
            "title": f.title,
            "description": f.description or "",
            "severity": f.severity,
            "cvss_score": f.cvss_score,
            "cve_id": f.cve_id,
            "cwe_id": f.cwe_id,
            "affected_component": f.affected_component or "",
            "remediation": f.remediation or "Apply vendor patch.",
            "exploit_available": f.exploit_available,
            "tool_name": f.tool_name,
            "tool_output": f.tool_output or {},
        })

    # Compute score
    score_data = compute_security_score(findings_data)

    # Build scan data
    tools = scan.tools_used
    if isinstance(tools, str):
        try:
            tools = json.loads(tools)
        except (json.JSONDecodeError, TypeError):
            tools = []

    scan_data = {
        "id": scan.id,
        "name": scan.name,
        "scan_type": scan.scan_type,
        "target_raw": scan.target_raw,
        "input_type": getattr(scan, "input_type", None),
        "tools_used": tools or [],
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "total_findings": len(findings_data),
    }

    # ── Before vs After comparison (optional) ──────────────────────────────
    comparison_data = None
    compare_scan_id = report_config.get("compare_scan_id")
    if compare_scan_id:
        prev_result = await db.execute(select(Scan).where(Scan.id == compare_scan_id))
        prev_scan = prev_result.scalar_one_or_none()
        if prev_scan:
            prev_findings_result = await db.execute(
                select(Finding).where(Finding.scan_id == compare_scan_id)
            )
            prev_findings_orm = prev_findings_result.scalars().all()
            prev_findings_data = [
                {"title": f.title, "severity": f.severity, "cve_id": f.cve_id or "",
                 "affected_component": f.affected_component or "", "tool_name": f.tool_name}
                for f in prev_findings_orm
            ]
            prev_score = compute_security_score(prev_findings_data)

            # Determine new / resolved / persistent findings
            curr_keys = {f.get("title", "") + f.get("affected_component", "") for f in findings_data}
            prev_keys = {f.get("title", "") + f.get("affected_component", "") for f in prev_findings_data}
            new_keys = curr_keys - prev_keys
            resolved_keys = prev_keys - curr_keys
            persistent_keys = curr_keys & prev_keys

            score_before = prev_score["score"]
            score_after = score_data["score"]
            delta = score_after - score_before

            comparison_data = {
                "score_before": score_before,
                "score_after": score_after,
                "score_delta": delta,
                "grade_before": prev_score["grade"],
                "grade_after": score_data["grade"],
                "new_count": len(new_keys),
                "resolved_count": len(resolved_keys),
                "persistent_count": len(persistent_keys),
                "compare_scan_id": compare_scan_id,
                "summary": (
                    f"Security score changed from {score_before} ({prev_score['grade']}) "
                    f"to {score_after} ({score_data['grade']}). "
                    f"{len(new_keys)} new findings, {len(resolved_keys)} resolved."
                ),
            }

    # Generate PDF (with optional comparison section)
    filepath = generate_report(scan_data, findings_data, score_data, comparison_data=comparison_data)
    filename = os.path.basename(filepath)
    report_id = filename.replace("sentinel_report_", "").replace(".pdf", "")

    from backend.common.storage import upload_report
    with open(filepath, "rb") as f:
        s3_key = await upload_report(scan_id, f.read())

    if s3_key:
        scan.report_s3_key = s3_key
        await db.commit()

    return {
        "id": report_id,
        "name": filename,
        "type": "pdf",
        "status": "completed",
        "size": f"{os.path.getsize(filepath) / 1024:.1f} KB",
        "scan_id": scan_id,
        "compare_scan_id": compare_scan_id,
        "security_score": score_data["score"],
        "risk_grade": score_data["grade"],
        "has_comparison": comparison_data is not None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "s3_key": s3_key,
    }



@router.get("/{report_id}/download")
async def download_report(
    report_id: str,
    user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
):
    """Download a generated PDF report. Falls back to S3 if local file is missing."""
    # Try local filesystem first
    if os.path.exists(REPORTS_DIR):
        for fname in os.listdir(REPORTS_DIR):
            if report_id in fname and fname.endswith(".pdf"):
                filepath = os.path.join(REPORTS_DIR, fname)
                return FileResponse(
                    filepath,
                    media_type="application/pdf",
                    filename=fname,
                )

    # Fallback: try to fetch from S3 via scan's report_s3_key
    try:
        from backend.common.storage import download_report as s3_download
        # Try to find a scan whose report_s3_key contains this report_id
        result = await db.execute(
            select(Scan).where(Scan.report_s3_key.isnot(None))
        )
        scans_with_reports = result.scalars().all()
        for scan in scans_with_reports:
            if report_id in (scan.report_s3_key or ""):
                pdf_bytes = await s3_download(scan.report_s3_key)
                if pdf_bytes:
                    # Save locally for future requests
                    os.makedirs(REPORTS_DIR, exist_ok=True)
                    local_path = os.path.join(REPORTS_DIR, f"sentinel_report_{report_id}.pdf")
                    with open(local_path, "wb") as f:
                        f.write(pdf_bytes)
                    return FileResponse(
                        local_path,
                        media_type="application/pdf",
                        filename=f"sentinel_report_{report_id}.pdf",
                    )
    except Exception as e:
        logger.warning("S3 report download fallback failed: %s", e)

    raise HTTPException(status_code=404, detail="Report not found")


@router.delete("/{report_id}")
async def delete_report(report_id: str, user: dict = Depends(get_current_user)):
    """Delete a generated report."""
    for fname in os.listdir(REPORTS_DIR):
        if report_id in fname and fname.endswith(".pdf"):
            os.remove(os.path.join(REPORTS_DIR, fname))
            return {"status": "deleted"}
    raise HTTPException(status_code=404, detail="Report not found")
