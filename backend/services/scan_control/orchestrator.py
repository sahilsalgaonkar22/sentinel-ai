"""
SENTINEL AI -- Scan Orchestrator (Hybrid Mode)
Supports:
1. Local: subprocess execution
2. Distributed: Kafka job dispatch
"""
import asyncio
import json
import logging
import uuid
import traceback
from datetime import datetime, timezone
from typing import List, Dict

logger = logging.getLogger(__name__)

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from backend.common.config import settings
from backend.common.database import AsyncSessionLocal, get_session_factory
from backend.services.scan_control.models import Scan, ScanStatus, Finding
from backend.services.scan_control.input_detector import (
    detect_input_type, get_tools_for_target, get_scan_type_for_input, InputType
)
from backend.services.scan_control.tool_executor import execute_tools_parallel
from backend.services.ai_intelligence.security_scorer import compute_security_score
from backend.services.ai_intelligence.deduplication import deduplicate_findings
from backend.services.correlation.engine import correlate_findings, enrich_findings_with_context
from backend.services.ai_intelligence.attack_graph import generate_attack_paths
from backend.services.alerting import alert_on_scan_complete
from backend.gateway.routes.websocket_manager import manager as ws_manager

# New Features
from backend.services.scan_control.scope_validator import validate_scope
from backend.services.scan_control.git_cloner import clone_repo, cleanup_repo
from backend.services.kafka.manager import kafka_manager, TOPIC_SCAN_LOGS

# Observability
from backend.common.metrics import (
    scans_total, findings_total, active_scans, scan_duration_seconds
)


# ---------------------------------------------------------------------------
#  Finding Persistence
# ---------------------------------------------------------------------------

async def _persist_findings(
    db: AsyncSession,
    scan_id: str,
    org_id: str,
    findings_data: List[dict],
) -> List[Finding]:
    """Persist a batch of tool findings to the database."""
    now = datetime.now(timezone.utc)
    findings = []
    for f in findings_data:
        sev = f.get("severity", "info").lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "info"

        finding = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            org_id=org_id,
            title=f["title"],
            description=f.get("description", ""),
            severity=sev,
            cvss_score=f.get("cvss_score"),
            cve_id=f.get("cve_id"),
            cwe_id=f.get("cwe_id"),
            tool_name=f.get("tool_name", "unknown"),
            tool_output=f.get("tool_output", {}),
            affected_component=f.get("affected_component", ""),
            remediation=f.get("remediation", "Apply vendor patch."),
            references=[],
            is_false_positive=False,
            is_duplicate=False,
            exploit_available=f.get("exploit_available", False),
            created_at=now,
            updated_at=now,
        )
        db.add(finding)
        findings.append(finding)
    await db.commit()
    return findings


# ---------------------------------------------------------------------------
#  Finalization
# ---------------------------------------------------------------------------

async def finalize_scan(scan_id: str, org_id: str, target_raw: str, all_findings: List[dict]):
    """Deduplication, Correlation, Scoring, and Persisting."""
    _finalize_start = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            return

        await ws_manager.push_log_line(scan_id, "orchestrator", f"Deduplicating {len(all_findings)} findings...")
        
        # Step 3: Deduplicate findings
        unique_findings, dups = deduplicate_findings(all_findings)
        
        # Step 4: Enrich with exposure context
        unique_findings = enrich_findings_with_context(unique_findings, target_raw)

        # Step 5: Correlate across tools
        correlated = correlate_findings(unique_findings)
        await ws_manager.push_log_line(scan_id, "orchestrator", f"Correlated {len(correlated)} unique findings")
        
        scan.progress = 90
        await db.commit()
        await ws_manager.broadcast_scan_update(scan_id, {"progress": scan.progress, "status": scan.status})

        # Step 6: Persist findings
        persisted = await _persist_findings(db, scan_id, org_id, correlated)

        # Emit per-finding Prometheus counters
        for f in correlated:
            try:
                findings_total.labels(
                    severity=f.get("severity", "info"),
                    tool_name=f.get("tool_name", "unknown"),
                ).inc()
            except Exception:
                pass

        # Step 7: Compute security score
        scan.progress = 95
        await db.commit()
        await ws_manager.broadcast_scan_update(scan_id, {"progress": scan.progress, "status": scan.status})

        score_data = compute_security_score(correlated)
        security_score = score_data["score"]
        risk_grade = score_data["grade"]

        # Step 8: Generate attack paths
        attack_paths = generate_attack_paths(correlated)

        # Step 9: Count by severity
        crit = sum(1 for f in persisted if f.severity == "critical")
        high = sum(1 for f in persisted if f.severity == "high")
        med = sum(1 for f in persisted if f.severity == "medium")
        low = sum(1 for f in persisted if f.severity in ("low", "info"))

        # Step 10: Finalize scan
        scan.status = ScanStatus.COMPLETED.value
        scan.progress = 100
        scan.completed_at = datetime.now(timezone.utc)
        scan.total_findings = len(persisted)
        scan.critical_count = crit
        scan.high_count = high
        scan.medium_count = med
        scan.low_count = low
        scan.security_score = security_score
        scan.risk_grade = risk_grade
        await db.commit()

        # Prometheus scan completion metrics
        try:
            scans_total.labels(status="completed").inc()
            active_scans.dec()
            elapsed = (datetime.now(timezone.utc) - _finalize_start).total_seconds()
            scan_duration_seconds.observe(elapsed)
        except Exception:
            pass

        # S3 upload — persist findings summary as scan log
        try:
            from backend.common.storage import upload_scan_log
            log_content = (
                f"Scan: {scan.name}\nTarget: {target_raw}\nStatus: COMPLETED\n"
                f"Score: {security_score}/100 Grade: {risk_grade}\n"
                f"Findings: {len(persisted)} (C:{crit} H:{high} M:{med} L:{low})\n"
                f"Tools: {scan.tools_used}\n"
                f"Completed: {scan.completed_at.isoformat()}\n"
            )
            await upload_scan_log(scan_id, log_content)
        except Exception as s3_err:
            logger.warning("scan.s3_upload_error scan_id=%s err=%s", scan_id, s3_err)

        await ws_manager.push_log_line(scan_id, "orchestrator", f"COMPLETE. Score: {security_score}/100 Grade: {risk_grade}")
        await ws_manager.broadcast_scan_update(scan_id, {
            "progress": scan.progress, 
            "status": scan.status,
            "security_score": security_score,
            "risk_grade": risk_grade
        })

        # Step 11: Alerts — pass org_id so alerting reads Redis settings
        try:
            await alert_on_scan_complete(
                scan_name=scan.name,
                target=target_raw,
                score=security_score,
                grade=risk_grade,
                critical_count=crit,
                high_count=high,
                total_findings=len(persisted),
                org_id=org_id,
                scan_id=scan_id
            )
        except Exception as alert_err:
            logger.warning("scan.alert_error scan_id=%s err=%s", scan_id, alert_err)

        # Step 12: Elasticsearch indexing (non-blocking, non-fatal)
        try:
            from backend.common.elasticsearch_client import es_client
            if es_client.enabled:
                es_findings = [
                    {
                        "id": f.id,
                        "scan_id": f.scan_id,
                        "org_id": org_id,
                        "title": f.title,
                        "description": f.description or "",
                        "severity": f.severity,
                        "cvss_score": f.cvss_score,
                        "cve_id": f.cve_id,
                        "cwe_id": f.cwe_id,
                        "tool_name": f.tool_name,
                        "affected_component": f.affected_component or "",
                        "remediation": f.remediation or "",
                        "exploit_available": f.exploit_available,
                        "is_false_positive": f.is_false_positive,
                        "ai_risk_score": f.ai_risk_score,
                    }
                    for f in persisted
                ]
                await es_client.index_findings_bulk(es_findings)
                await es_client.index_scan({
                    "id": scan.id,
                    "org_id": org_id,
                    "name": scan.name,
                    "target": target_raw,
                    "scan_type": scan.scan_type,
                    "status": scan.status,
                    "security_score": security_score,
                    "risk_grade": risk_grade,
                    "started_at": scan.started_at.isoformat() if scan.started_at else None,
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                })
                logger.info("scan.es_indexed scan_id=%s findings=%d", scan_id, len(es_findings))
        except Exception as es_err:
            logger.warning("scan.es_index_error scan_id=%s err=%s", scan_id, es_err)



# ---------------------------------------------------------------------------
#  Execution Modes
# ---------------------------------------------------------------------------

from backend.services.scan_control.tool_executor import execute_tools_parallel

async def _run_local_scan(scan: Scan, tools: List[str], target: str) -> List[dict]:
    """
    Parallel execution of all tools with live progress updates.
    """

    await ws_manager.push_log_line(scan.id, "orchestrator", f"Running {len(tools)} tools in parallel...")

    # Initial progress
    scan.progress = 5
    async with AsyncSessionLocal() as db:
        db.add(scan)
        await db.commit()

    await ws_manager.broadcast_scan_update(scan.id, {
        "progress": scan.progress,
        "status": scan.status
    })

    config = {
        "allow_pentagi": settings.PENTAGI_ENABLED,
        "pentagi_image": settings.PENTAGI_IMAGE
    }

    try:
        # 🚀 PARALLEL EXECUTION
        results = await execute_tools_parallel(tools, target, config)

        await ws_manager.push_log_line(
            scan.id,
            "orchestrator",
            f"All tools completed. Total findings: {len(results)}"
        )

        # Move progress forward
        scan.progress = 85
        async with AsyncSessionLocal() as db:
            db.add(scan)
            await db.commit()

        await ws_manager.broadcast_scan_update(scan.id, {
            "progress": scan.progress,
            "status": scan.status
        })

        return results

    except Exception as e:
        logger.error("parallel_scan_failed scan_id=%s err=%s", scan.id, e, exc_info=True)
        await ws_manager.push_log_line(scan.id, "orchestrator", f"ERROR: {e}", level="ERROR")
        return []

async def _dispatch_distributed_jobs(scan: Scan, tools: List[str], target: str):
    """Publish jobs to Kafka topics for workers to execute.
    The result_processor (running in gateway lifespan) will consume scan.results
    and call finalize_scan() when all tools complete.
    """
    # Register scan with result processor BEFORE dispatching
    # so it knows how many tool results to aggregate
    from backend.services.kafka.result_processor import register_pending_scan
    register_pending_scan(scan.id, tools, scan.org_id, target)

    for tool_name in tools:
        # Determine topic
        if tool_name in ("nmap", "masscan"):
            topic = "scan.jobs.network"
        elif tool_name in ("nikto", "zap", "http_security", "nuclei", "httpx"):
            topic = "scan.jobs.web"
        elif tool_name in ("bandit", "semgrep", "gitleaks"):
            topic = "scan.jobs.code"
        elif tool_name in ("trivy",):
            topic = "scan.jobs.container"
        elif tool_name in ("pentagi",):
            topic = "scan.jobs.advanced"
        elif tool_name in ("subfinder",):
            topic = "scan.jobs.network"
        else:
            topic = "scan.jobs.network"

        job = {
            "scan_id": scan.id,
            "org_id": scan.org_id,
            "tool_name": tool_name,
            "target": target,
            "config": {
                "allow_pentagi": settings.PENTAGI_ENABLED,
                "pentagi_image": settings.PENTAGI_IMAGE
            }
        }
        await kafka_manager.produce(topic, key=scan.id, value=job)
        await ws_manager.push_log_line(scan.id, "orchestrator", f"Dispatched {tool_name} to Kafka topic: {topic}")

    await ws_manager.push_log_line(
        scan.id, "orchestrator",
        f"All {len(tools)} jobs dispatched. Result processor waiting for workers..."
    )


# ---------------------------------------------------------------------------
#  Core Scan Entry
# ---------------------------------------------------------------------------

async def _run_real_scan(scan_id: str, org_id: str, target_raw: str):
    git_tmp_dir = None
    target_to_scan = target_raw

    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if not scan:
                return

            # Mark running
            scan.status = ScanStatus.RUNNING.value
            scan.started_at = datetime.now(timezone.utc)
            scan.progress = 2
            await db.commit()

        # Prometheus: scan started
        try:
            scans_total.labels(status="started").inc()
            active_scans.inc()
        except Exception:
            pass

        await ws_manager.broadcast_scan_update(scan_id, {"progress": 2, "status": scan.status})
        await ws_manager.push_log_line(scan_id, "orchestrator", f"Starting setup for {target_raw}")

        # Scope Validation
        is_allowed, reason = validate_scope(target_raw, org_id)
        if not is_allowed:
            raise ValueError(f"Scope Validation Failed: {reason}")
        await ws_manager.push_log_line(scan_id, "orchestrator", "Scope validation passed.")

        # Detect Input
        input_type, tools = get_tools_for_target(target_raw)

        # Git Auto-Clone
        if input_type == InputType.GIT_REPO:
            await ws_manager.push_log_line(scan_id, "orchestrator", "Cloning Git repository...")
            git_tmp_dir = await clone_repo(target_raw)
            target_to_scan = git_tmp_dir
            await ws_manager.push_log_line(scan_id, "orchestrator", f"Cloned to temp directory.")

        async with AsyncSessionLocal() as db:
            db.add(scan)
            scan.input_type = input_type.value
            scan.tools_used = json.dumps(tools)
            await db.commit()

        # Hybrid Execution Mode Switch
        mode = settings.EXECUTION_MODE
        await ws_manager.push_log_line(scan_id, "orchestrator", f"Execution Mode: {mode.upper()}")

        if mode == "distributed":
            await _dispatch_distributed_jobs(scan, tools, target_to_scan)
            # A separate 'result_processor' consumer handles the rest
            return
        
        # Local Mode
        all_findings = await _run_local_scan(scan, tools, target_to_scan)
        
        # Finalize
        await finalize_scan(scan_id, org_id, target_to_scan, all_findings)

    except Exception as exc:
        err_msg = str(exc)
        logger.error("scan.fatal_error scan_id=%s err=%s", scan_id, err_msg, exc_info=True)
        try:
            scans_total.labels(status="failed").inc()
            active_scans.dec()
        except Exception:
            pass
        try:
            await ws_manager.push_log_line(scan_id, "orchestrator", f"FATAL ERROR: {err_msg}", level="ERROR")
            async with AsyncSessionLocal() as db:
                result = await db.execute(select(Scan).where(Scan.id == scan_id))
                scan = result.scalar_one_or_none()
                if scan:
                    scan.status = ScanStatus.FAILED.value
                    scan.error_message = err_msg[:500]
                    await db.commit()
                    await ws_manager.broadcast_scan_update(scan_id, {"progress": scan.progress, "status": scan.status})
        except Exception:
            pass
    finally:
        # Cleanup Git clone
        if git_tmp_dir:
            cleanup_repo(git_tmp_dir)


async def start_scan_task(scan_id: str, org_id: str, target_raw: str):
    """Background entry point."""
    await _run_real_scan(scan_id, org_id, target_raw)
