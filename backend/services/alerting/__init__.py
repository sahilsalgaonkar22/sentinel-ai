"""
SENTINEL AI — Alerting Service (Production Hardened)

CRITICAL FIX: Config is now read at CALL-TIME from Redis org settings
(stored by the Settings UI), with env-var fallback for when Redis is
unavailable or org settings are unconfigured.

Email (SMTP) + Slack webhook notifications.
Covers: scan completion, exploit chains (Pentagi), drift detection, critical findings.
Redis-backed rate limiting prevents alert spam (1 alert per scan per hour max).
"""
import os
import json
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

try:
    import httpx
    _httpx = True
except ImportError:
    _httpx = False


# ── Env-var fallbacks (used when Redis settings not available) ────────────────
_ENV_SMTP_HOST         = os.getenv("SENTINEL_SMTP_HOST", "")
_ENV_SMTP_PORT         = int(os.getenv("SENTINEL_SMTP_PORT", "587"))
_ENV_SMTP_USER         = os.getenv("SENTINEL_SMTP_USER", "")
_ENV_SMTP_PASS         = os.getenv("SENTINEL_SMTP_PASSWORD", os.getenv("SENTINEL_SMTP_PASS", ""))
_ENV_SMTP_FROM         = os.getenv("SENTINEL_SMTP_FROM", "sentinel@sentinel.ai")
_ENV_SLACK_WEBHOOK     = os.getenv("SENTINEL_SLACK_WEBHOOK", "")
_ENV_ALERT_RECIPIENTS  = [r.strip() for r in os.getenv("SENTINEL_ALERT_EMAILS", "").split(",") if r.strip()]
ALERT_COOLDOWN_SECONDS = int(os.getenv("SENTINEL_ALERT_COOLDOWN", "3600"))  # 1 hour

# Redis key prefix — must match the Settings API
_SETTINGS_KEY = "sentinel:settings:{org_id}"


# ── Org Settings Loader ───────────────────────────────────────────────────────

def _load_org_settings(org_id: Optional[str]) -> dict:
    """
    Fetch org-specific alert settings from Redis.
    Returns an empty dict if org_id is None, Redis is unavailable, or nothing is stored.
    """
    if not org_id:
        return {}
    try:
        import redis as sync_redis
        from backend.common.config import settings as _cfg
        r = sync_redis.from_url(_cfg.REDIS_URL, decode_responses=True, socket_connect_timeout=2)
        key = _SETTINGS_KEY.format(org_id=org_id)
        raw = r.get(key)
        return json.loads(raw) if raw else {}
    except Exception as exc:
        logger.debug("alert.redis_settings_unavailable reason=%s", exc)
        return {}


def _effective(org_cfg: dict, key: str, env_default):
    """Return org Redis setting if set, otherwise fall back to env var default."""
    val = org_cfg.get(key)
    if val is not None and val != "":
        return val
    return env_default


# ── Rate Limiting (Redis-backed) ──────────────────────────────────────────────

def _is_rate_limited(alert_key: str) -> bool:
    """Return True if this alert was already sent recently (Redis dedup)."""
    try:
        import redis as sync_redis
        from backend.common.config import settings as _cfg
        r = sync_redis.from_url(_cfg.REDIS_URL, decode_responses=True, socket_connect_timeout=2)
        redis_key = f"sentinel:alert:sent:{alert_key}"
        if r.get(redis_key):
            return True
        r.setex(redis_key, ALERT_COOLDOWN_SECONDS, "1")
        return False
    except Exception:
        return False  # If Redis unavailable, don't suppress alerts


# ── Email ─────────────────────────────────────────────────────────────────────

def send_email_alert(
    subject: str,
    body_html: str,
    recipients: Optional[List[str]] = None,
    org_settings: Optional[dict] = None,
) -> bool:
    """
    Send an email alert via SMTP.
    Config priority: org_settings (from Redis) → env vars → disabled.
    """
    cfg = org_settings or {}

    email_enabled = cfg.get("email_enabled", True)
    if not email_enabled:
        logger.debug("alert.email_skipped reason=disabled_by_org_settings")
        return False

    smtp_host = _effective(cfg, "smtp_host", _ENV_SMTP_HOST)
    smtp_port = int(_effective(cfg, "smtp_port", _ENV_SMTP_PORT))
    smtp_user = _effective(cfg, "smtp_user", _ENV_SMTP_USER)
    smtp_pass = _effective(cfg, "smtp_password", _ENV_SMTP_PASS)

    if not smtp_host or not smtp_user:
        logger.debug("alert.email_skipped reason=smtp_not_configured")
        return False

    # Recipients: org settings → env var → provided list
    to_addrs = (
        recipients
        or cfg.get("alert_recipients")
        or _ENV_ALERT_RECIPIENTS
    )
    if not to_addrs:
        logger.warning("alert.email_skipped reason=no_recipients")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[SENTINEL AI] {subject}"
        msg["From"]    = _ENV_SMTP_FROM
        msg["To"]      = ", ".join(to_addrs)
        msg.attach(MIMEText(body_html, "html"))

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(_ENV_SMTP_FROM, to_addrs, msg.as_string())

        logger.info("alert.email_sent recipients=%d subject=%s", len(to_addrs), subject)
        return True
    except Exception as exc:
        raise Exception(f"Failed to send email SMTP: {exc}")

async def send_email_with_retry(subject: str, body: str, recipients: list, org_settings: dict, scan_id: str = None) -> bool:
    import asyncio
    from backend.common.config import settings as _s
    retries = _s.SENTINEL_ALERT_MAX_RETRIES
    delay = _s.SENTINEL_ALERT_BACKOFF_BASE
    for attempt in range(retries):
        try:
            loop = asyncio.get_running_loop()
            success = await loop.run_in_executor(None, lambda: send_email_alert(subject, body, recipients, org_settings))
            if success: return True
        except Exception as e:
            logger.warning("alert.email_retry attempt=%d/%d err=%s", attempt + 1, retries, e)
            if attempt < retries - 1:
                await asyncio.sleep(delay)
                delay *= _s.SENTINEL_ALERT_BACKOFF_BASE
            else:
                try:
                    from backend.common.database import AsyncSessionLocal
                    from backend.services.scan_control.models import AlertDLQ
                    async with AsyncSessionLocal() as db:
                        db.add(AlertDLQ(scan_id=scan_id, alert_type="SMTP", payload={"subject": subject, "body": body}, error_message=str(e), status="failed"))
                        await db.commit()
                    logger.error("alert.email_exhausted_to_dlq scan_id=%s", scan_id)
                except Exception as dlq_err:
                    logger.critical("alert.email_dlq_failed err=%s", dlq_err)
    return False

# ── Slack ─────────────────────────────────────────────────────────────────────

def send_slack_alert(
    title: str,
    message: str,
    severity: str = "high",
    fields: Optional[Dict[str, Any]] = None,
    org_settings: Optional[dict] = None,
) -> bool:
    """
    Send a Slack webhook alert.
    Config priority: org_settings (from Redis) → env vars → disabled.
    """
    cfg = org_settings or {}

    slack_enabled = cfg.get("slack_enabled", True)
    if not slack_enabled:
        logger.debug("alert.slack_skipped reason=disabled_by_org_settings")
        return False

    webhook_url = _effective(cfg, "slack_webhook", _ENV_SLACK_WEBHOOK)
    if not webhook_url:
        logger.debug("alert.slack_skipped reason=no_webhook")
        return False

    if not _httpx:
        logger.error("alert.slack_skipped reason=httpx_not_installed")
        return False

    color_map = {
        "critical": "#dc2626", "high": "#f97316",
        "medium": "#f59e0b",   "low":  "#3b82f6", "info": "#64748b",
    }
    attachment = {
        "color":  color_map.get(severity, "#64748b"),
        "title":  f":shield: {title}",
        "text":   message,
        "footer": f"Sentinel AI | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "fields": [{"title": k, "value": str(v), "short": True}
                   for k, v in (fields or {}).items()],
    }

    resp = httpx.post(webhook_url, json={"attachments": [attachment]}, timeout=10)
    if resp.status_code == 200:
        logger.info("alert.slack_sent title=%s", title)
        return True
    raise Exception(f"Slack API failed with code {resp.status_code}")

async def send_slack_with_retry(title: str, message: str, severity: str, fields: dict, org_settings: dict, scan_id: str = None) -> bool:
    import asyncio
    from backend.common.config import settings as _s
    retries = _s.SENTINEL_ALERT_MAX_RETRIES
    delay = _s.SENTINEL_ALERT_BACKOFF_BASE
    for attempt in range(retries):
        try:
            loop = asyncio.get_running_loop()
            success = await loop.run_in_executor(None, lambda: send_slack_alert(title, message, severity, fields, org_settings))
            if success: return True
        except Exception as e:
            logger.warning("alert.slack_retry attempt=%d/%d err=%s", attempt + 1, retries, e)
            if attempt < retries - 1:
                await asyncio.sleep(delay)
                delay *= _s.SENTINEL_ALERT_BACKOFF_BASE
            else:
                try:
                    from backend.common.database import AsyncSessionLocal
                    from backend.services.scan_control.models import AlertDLQ
                    async with AsyncSessionLocal() as db:
                        db.add(AlertDLQ(scan_id=scan_id, alert_type="SLACK", payload={"title": title, "message": message}, error_message=str(e), status="failed"))
                        await db.commit()
                    logger.error("alert.slack_exhausted_to_dlq scan_id=%s", scan_id)
                except Exception as dlq_err:
                    logger.critical("alert.slack_dlq_failed err=%s", dlq_err)
    return False

# ── Alert Functions (called by orchestrator) ──────────────────────────────────

async def alert_on_scan_complete(
    scan_name: str,
    target: str,
    score: float,
    grade: str,
    critical_count: int,
    high_count: int,
    total_findings: int,
    drift_detected: bool = False,
    org_id: Optional[str] = None,
    scan_id: Optional[str] = None,
):
    """
    Trigger alerts when a scan completes with concerning findings.
    Loads org-specific SMTP/Slack config from Redis at call-time.
    """
    if critical_count == 0 and high_count == 0 and score >= 80 and not drift_detected:
        return  # Clean scan — no alert needed

    alert_key = f"scan_complete:{scan_name}:{target}"
    if _is_rate_limited(alert_key):
        logger.info("alert.rate_limited scan_name=%s", scan_name)
        return

    # Load live org settings from Redis (may be empty — falls back to env vars)
    org_cfg = _load_org_settings(org_id)

    # Check severity thresholds set by org
    if critical_count == 0 and not org_cfg.get("alert_on_high", True) and not drift_detected:
        logger.debug("alert.suppressed reason=org_threshold scan=%s", scan_name)
        return
    if critical_count > 0 and not org_cfg.get("alert_on_critical", True) and not drift_detected:
        logger.debug("alert.suppressed reason=org_critical_threshold scan=%s", scan_name)
        return
    if score >= org_cfg.get("alert_on_score_below", 80) and not drift_detected and critical_count == 0:
        logger.debug("alert.suppressed reason=score_above_threshold scan=%s", scan_name)
        return

    severity    = "critical" if critical_count > 0 else "high"
    drift_badge = " ⚠️ DRIFT DETECTED" if drift_detected else ""
    subject     = f"{'CRITICAL' if critical_count > 0 else 'HIGH'} Risk Detected: {scan_name}{drift_badge}"

    body = f"""
    <h2>Sentinel AI Security Alert{' — Drift Detected' if drift_detected else ''}</h2>
    <table border='1' cellpadding='8' cellspacing='0' style='border-collapse:collapse;'>
        <tr><td><strong>Scan</strong></td><td>{scan_name}</td></tr>
        <tr><td><strong>Target</strong></td><td>{target}</td></tr>
        <tr><td><strong>Score</strong></td><td>{score}/100 ({grade})</td></tr>
        <tr><td><strong>Total Findings</strong></td><td>{total_findings}</td></tr>
        <tr><td><strong>Critical</strong></td><td style='color:red;'>{critical_count}</td></tr>
        <tr><td><strong>High</strong></td><td style='color:orange;'>{high_count}</td></tr>
        {'<tr><td><strong>Status</strong></td><td style="color:red;font-weight:bold;">NEW RISKS DETECTED SINCE LAST SCAN</td></tr>' if drift_detected else ''}
    </table>
    <p>Login to the Sentinel AI dashboard to review findings and remediation steps.</p>
    """

    import asyncio
    await asyncio.gather(
        send_email_with_retry(subject, body, None, org_cfg, scan_id),
        send_slack_with_retry(
            subject,
            f"Scan *{scan_name}* on `{target}` scored *{score}/100* ({grade}). "
            f"Critical: {critical_count} | High: {high_count} | Total: {total_findings}"
            + (" | *New risks detected since last scan!*" if drift_detected else ""),
            severity,
            {"Target": target, "Score": f"{score}/100", "Grade": grade,
                    "Critical": critical_count, "High": high_count, "Total": total_findings},
            org_cfg,
            scan_id
        )
    )


async def alert_on_exploit_chain(
    scan_name: str,
    target: str,
    chain: dict,
    org_id: Optional[str] = None,
    scan_id: Optional[str] = None,
):
    """
    CRITICAL alert when Pentagi confirms a successful exploit chain.
    This is the highest-priority alert in the system.
    """
    alert_key = f"exploit_chain:{scan_name}:{target}"
    if _is_rate_limited(alert_key):
        return

    org_cfg    = _load_org_settings(org_id)
    title      = f"CONFIRMED EXPLOIT: {scan_name}"
    chain_name = chain.get("name", "Unknown Chain")
    impact     = chain.get("final_impact", "System Compromise")
    entry      = chain.get("entry_point", target)

    logger.critical(
        "alert.exploit_chain scan_name=%s target=%s chain=%s impact=%s",
        scan_name, target, chain_name, impact
    )

    body = f"""
    <h1 style='color:red;'>⚠️ CONFIRMED EXPLOIT CHAIN DETECTED</h1>
    <p>An automated exploit engine has confirmed a complete attack chain against your infrastructure.</p>
    <table border='1' cellpadding='8' cellspacing='0' style='border-collapse:collapse;'>
        <tr><td><strong>Scan</strong></td><td>{scan_name}</td></tr>
        <tr><td><strong>Target</strong></td><td>{target}</td></tr>
        <tr><td><strong>Attack Chain</strong></td><td style='color:red;font-weight:bold;'>{chain_name}</td></tr>
        <tr><td><strong>Entry Point</strong></td><td>{entry}</td></tr>
        <tr><td><strong>Final Impact</strong></td><td style='color:red;'>{impact}</td></tr>
    </table>
    <h3>Attack Path:</h3>
    <ol>
    {''.join(f"<li>{step.get('action', step)}</li>" for step in chain.get("chain_steps", []))}
    </ol>
    <p><strong>IMMEDIATE ACTION REQUIRED.</strong> Log into Sentinel AI to review full exploit details.</p>
    """

    import asyncio
    await asyncio.gather(
        send_email_with_retry(title, body, None, org_cfg, scan_id),
        send_slack_with_retry(
            title,
            f":rotating_light: Exploit confirmed on `{target}` via *{chain_name}*. "
            f"Entry: `{entry}` | Impact: *{impact}*",
            "critical",
            {"Chain": chain_name, "Entry": entry, "Impact": impact},
            org_cfg,
            scan_id
        )
    )


async def alert_on_drift(
    scan_name: str,
    target: str,
    new_criticals: int,
    new_highs: int,
    resolved: int,
    score_delta: float,
    org_id: Optional[str] = None,
    scan_id: Optional[str] = None,
):
    """
    Alert when continuous monitoring detects configuration drift.
    Fires only when NEW findings appear compared to last scan.
    """
    if new_criticals == 0 and new_highs == 0:
        return  # No new risks — no alert

    alert_key = f"drift:{scan_name}:{target}"
    if _is_rate_limited(alert_key):
        return

    org_cfg   = _load_org_settings(org_id)
    severity  = "critical" if new_criticals > 0 else "high"
    direction = "↓" if score_delta < 0 else "↑"
    subject   = f"Security Drift Detected: {scan_name} ({direction}{abs(score_delta):.1f} pts)"

    logger.warning(
        "alert.drift scan_name=%s target=%s new_criticals=%d new_highs=%d score_delta=%+.1f",
        scan_name, target, new_criticals, new_highs, score_delta
    )

    body = f"""
    <h2>Sentinel AI — Security Drift Alert</h2>
    <p>Continuous monitoring detected new vulnerabilities since the last scan of {target}.</p>
    <table border='1' cellpadding='8' cellspacing='0' style='border-collapse:collapse;'>
        <tr><td><strong>Scan</strong></td><td>{scan_name}</td></tr>
        <tr><td><strong>Target</strong></td><td>{target}</td></tr>
        <tr><td><strong>Score Change</strong></td>
            <td style='color:{"red" if score_delta < 0 else "green"};'>{direction}{abs(score_delta):.1f} points</td></tr>
        <tr><td><strong>New Critical Findings</strong></td>
            <td style='color:red;font-weight:bold;'>{new_criticals}</td></tr>
        <tr><td><strong>New High Findings</strong></td>
            <td style='color:orange;'>{new_highs}</td></tr>
        <tr><td><strong>Resolved Since Last Scan</strong></td>
            <td style='color:green;'>{resolved}</td></tr>
    </table>
    """

    import asyncio
    await asyncio.gather(
        send_email_with_retry(subject, body, None, org_cfg, scan_id),
        send_slack_with_retry(
            subject,
            f"Drift on `{target}`: +{new_criticals} critical, +{new_highs} high. "
            f"Score change: {direction}{abs(score_delta):.1f} pts. "
            f"{resolved} findings resolved.",
            severity,
            {"New Critical": new_criticals, "New High": new_highs,
                    "Resolved": resolved, "Score Δ": f"{direction}{abs(score_delta):.1f}"},
            org_cfg,
            scan_id
        )
    )
