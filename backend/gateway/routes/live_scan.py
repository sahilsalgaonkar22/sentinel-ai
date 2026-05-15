"""
SENTINEL AI — Live Scan Monitoring Routes
Real-time status derived from actual DB scan state.
No random data — all status computed from real scan records.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.future import select
from sqlalchemy import desc
from datetime import datetime, timedelta

from backend.gateway.middleware.auth import get_current_user
from backend.common.database import AsyncSessionLocal
from backend.services.scan_control.models import Scan, ScanStatus, Finding

router = APIRouter()

# Tool registry — defines capabilities, not status (status comes from DB)
TOOL_REGISTRY = [
    {"id": "nmap",    "name": "Nmap",       "category": "Network",    "description": "TCP/UDP port scanning and service detection"},
    {"id": "zap",     "name": "OWASP ZAP",  "category": "Web",        "description": "Dynamic application security testing"},
    {"id": "nikto",   "name": "Nikto",      "category": "Web",        "description": "Web server vulnerability scanner"},
    {"id": "semgrep", "name": "Semgrep",    "category": "Code",       "description": "Static analysis for security patterns"},
    {"id": "bandit",  "name": "Bandit",     "category": "Code",       "description": "Python security linter"},
    {"id": "trivy",   "name": "Trivy",      "category": "Container",  "description": "Container image vulnerability scanner"},
    {"id": "masscan", "name": "Masscan",    "category": "Network",    "description": "Ultra-fast port scanner"},
    {"id": "pentagi", "name": "Pentagi",    "category": "Advanced",   "description": "AI-driven autonomous penetration testing"},
]


@router.get("/tools")
async def get_tool_statuses(user: dict = Depends(get_current_user)):
    """
    Get tool statuses derived from real running scans in DB.
    If a scan is running, compute which tools are active based on progress %.
    """
    async with AsyncSessionLocal() as db:
        # Get the most recent running or recently completed scan
        result = await db.execute(
            select(Scan)
            .where(Scan.org_id == user["org_id"])
            .order_by(desc(Scan.created_at))
            .limit(5)
        )
        recent_scans = result.scalars().all()

        running_scans = [s for s in recent_scans if s.status == ScanStatus.RUNNING.value]
        completed_scans = [s for s in recent_scans if s.status == ScanStatus.COMPLETED.value]

        tool_statuses = []
        for tool in TOOL_REGISTRY:
            if running_scans:
                scan = running_scans[0]
                progress = scan.progress or 0

                # Determine per-tool progress based on total scan progress
                # Tools execute sequentially: nmap→zap→nikto→semgrep→bandit→trivy
                tool_order = ["nmap", "zap", "nikto", "semgrep", "bandit", "trivy"]
                tool_idx = tool_order.index(tool["id"]) if tool["id"] in tool_order else -1
                total_tools = len(tool_order)

                if tool_idx == -1:
                    # Not a primary tool in this scan
                    tool_status = "idle"
                    tool_progress = 0
                else:
                    tool_start_pct = (tool_idx / total_tools) * 95
                    tool_end_pct = ((tool_idx + 1) / total_tools) * 95

                    if progress < tool_start_pct:
                        tool_status = "queued"
                        tool_progress = 0
                    elif progress < tool_end_pct:
                        tool_status = "running"
                        tool_progress = int(((progress - tool_start_pct) / (tool_end_pct - tool_start_pct)) * 100)
                    else:
                        tool_status = "completed"
                        tool_progress = 100

                # Count findings from DB for this tool
                findings_result = await db.execute(
                    select(Finding)
                    .where(
                        Finding.scan_id == scan.id,
                        Finding.tool_name == tool["id"]
                    )
                )
                tool_findings = findings_result.scalars().all()

                tool_statuses.append({
                    **tool,
                    "status": tool_status,
                    "progress": tool_progress,
                    "scan_id": scan.id,
                    "findings_count": len(tool_findings),
                    "started_at": scan.started_at.isoformat() if scan.started_at else None,
                })
            elif completed_scans:
                scan = completed_scans[0]
                findings_result = await db.execute(
                    select(Finding).where(
                        Finding.scan_id == scan.id,
                        Finding.tool_name == tool["id"]
                    )
                )
                tool_findings = findings_result.scalars().all()

                tool_statuses.append({
                    **tool,
                    "status": "completed" if tool_findings else "idle",
                    "progress": 100 if tool_findings else 0,
                    "scan_id": scan.id,
                    "findings_count": len(tool_findings),
                    "started_at": scan.started_at.isoformat() if scan.started_at else None,
                })
            else:
                tool_statuses.append({
                    **tool,
                    "status": "idle",
                    "progress": 0,
                    "scan_id": None,
                    "findings_count": 0,
                    "started_at": None,
                })

        return tool_statuses


@router.get("/active")
async def get_active_scans(user: dict = Depends(get_current_user)):
    """Get currently running scans from DB."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Scan)
            .where(Scan.org_id == user["org_id"], Scan.status == ScanStatus.RUNNING.value)
            .order_by(desc(Scan.created_at))
        )
        running = result.scalars().all()

        # Also get queued
        result2 = await db.execute(
            select(Scan)
            .where(Scan.org_id == user["org_id"], Scan.status == ScanStatus.PENDING.value)
        )
        queued = result2.scalars().all()

        return {
            "active_scans": [
                {
                    "scan_id": s.id,
                    "name": s.name,
                    "target": s.target_raw,
                    "status": s.status,
                    "progress": s.progress,
                    "started_at": s.started_at.isoformat() if s.started_at else None,
                    "findings_so_far": s.total_findings,
                }
                for s in running
            ],
            "queue_depth": len(queued),
            "workers_online": len(TOOL_REGISTRY),
            "workers_busy": len(running),
        }


@router.get("/logs/{scan_id}")
async def get_scan_logs(
    scan_id: str,
    tool: str = None,
    user: dict = Depends(get_current_user)
):
    """
    Get structured log output for a scan.
    Returns findings as structured log entries (real data from DB).
    """
    async with AsyncSessionLocal() as db:
        # Verify scan access
        scan = await db.get(Scan, scan_id)
        if not scan or scan.org_id != user["org_id"]:
            return {"scan_id": scan_id, "logs": [], "total": 0}

        # Get findings as log lines (real scan output)
        query = select(Finding).where(Finding.scan_id == scan_id)
        if tool:
            query = query.where(Finding.tool_name == tool)
        query = query.order_by(Finding.created_at)

        result = await db.execute(query)
        findings = result.scalars().all()

        logs = []
        # Scan lifecycle events
        if scan.started_at:
            logs.append({
                "timestamp": scan.started_at.strftime("%H:%M:%S.000"),
                "level": "INFO",
                "tool": "orchestrator",
                "message": f"Scan '{scan.name}' started — target: {scan.target_raw}"
            })

        # Finding events as log lines
        for f in findings:
            ts = f.created_at.strftime("%H:%M:%S.000") if f.created_at else "00:00:00.000"
            level = "CRITICAL" if f.severity == "critical" else "HIGH" if f.severity == "high" else "WARN" if f.severity == "medium" else "INFO"
            logs.append({
                "timestamp": ts,
                "level": level,
                "tool": f.tool_name,
                "message": f"[{f.severity.upper()}] {f.title}"
                           + (f" [{f.cve_id}]" if f.cve_id else "")
                           + f" (CVSS: {f.cvss_score})"
            })

        if scan.completed_at:
            logs.append({
                "timestamp": scan.completed_at.strftime("%H:%M:%S.000"),
                "level": "INFO",
                "tool": "orchestrator",
                "message": f"Scan completed — {scan.total_findings} findings total"
            })

        return {
            "scan_id": scan_id,
            "scan_name": scan.name,
            "scan_status": scan.status,
            "logs": logs,
            "total": len(logs)
        }


@router.get("/logs/tool/{tool_id}")
async def get_tool_logs_latest(
    tool_id: str,
    user: dict = Depends(get_current_user)
):
    """Get the latest logs for a specific tool across all recent scans."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Finding)
            .where(Finding.org_id == user["org_id"], Finding.tool_name == tool_id)
            .order_by(desc(Finding.created_at))
            .limit(50)
        )
        findings = result.scalars().all()

        logs = []
        for f in findings:
            ts = f.created_at.strftime("%H:%M:%S.000") if f.created_at else "00:00:00.000"
            level = "CRITICAL" if f.severity == "critical" else "HIGH" if f.severity == "high" else "WARN"
            logs.append({
                "timestamp": ts,
                "level": level,
                "message": f"[{f.severity.upper()}] {f.title}"
                           + (f" [{f.cve_id}]" if f.cve_id else "")
                           + f" | CVSS:{f.cvss_score} | {f.cwe_id or ''}"
            })

        return {"tool_id": tool_id, "logs": logs, "total": len(logs)}
