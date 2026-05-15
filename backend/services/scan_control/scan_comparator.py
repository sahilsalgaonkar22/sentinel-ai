"""
SENTINEL AI -- Scan Comparison Engine
Computes diff between two scans: new findings, resolved findings, persistent findings.
Enables Before vs After comparison for re-scans.
"""
from typing import List, Dict, Tuple, Optional


def _finding_key(finding: dict) -> str:
    """Unique key for a finding to enable comparison."""
    return "|".join([
        finding.get("title", "").lower().strip(),
        finding.get("severity", "").lower(),
        finding.get("affected_component", "").lower().strip(),
    ])


def compare_scans(
    before_findings: List[dict],
    after_findings: List[dict],
    before_score: float,
    after_score: float,
) -> dict:
    """
    Compare two sets of scan findings (before and after).

    Returns:
        {
            "new_findings": [...],       # Found in after but not before
            "resolved_findings": [...],  # Found in before but not after
            "persistent_findings": [...],# Found in both
            "score_before": float,
            "score_after": float,
            "score_delta": float,        # Positive = improved
            "severity_comparison": {...},
            "summary": str
        }
    """
    before_keys = {}
    after_keys = {}

    for f in before_findings:
        key = _finding_key(f)
        before_keys[key] = f

    for f in after_findings:
        key = _finding_key(f)
        after_keys[key] = f

    # New: in after but not before
    new_findings = [after_keys[k] for k in after_keys if k not in before_keys]
    # Resolved: in before but not after
    resolved_findings = [before_keys[k] for k in before_keys if k not in after_keys]
    # Persistent: in both
    persistent_findings = [after_keys[k] for k in after_keys if k in before_keys]

    # Severity comparison
    def count_severity(findings):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    before_sevs = count_severity(before_findings)
    after_sevs = count_severity(after_findings)

    sev_comparison = {}
    for sev in ("critical", "high", "medium", "low", "info"):
        delta = after_sevs[sev] - before_sevs[sev]
        sev_comparison[sev] = {
            "before": before_sevs[sev],
            "after": after_sevs[sev],
            "delta": delta,
            "trend": "improved" if delta < 0 else ("degraded" if delta > 0 else "unchanged"),
        }

    score_delta = after_score - before_score

    # Generate summary
    if score_delta > 10:
        summary = f"Security posture significantly improved. Score increased by {score_delta:.0f} points."
    elif score_delta > 0:
        summary = f"Security posture improved slightly. Score increased by {score_delta:.0f} points."
    elif score_delta == 0:
        summary = "Security posture unchanged between scans."
    elif score_delta > -10:
        summary = f"Security posture slightly degraded. Score decreased by {abs(score_delta):.0f} points."
    else:
        summary = f"Security posture significantly degraded. Score decreased by {abs(score_delta):.0f} points."

    if resolved_findings:
        summary += f" {len(resolved_findings)} vulnerabilities were resolved."
    if new_findings:
        summary += f" {len(new_findings)} new vulnerabilities were introduced."

    return {
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "persistent_findings": persistent_findings,
        "new_count": len(new_findings),
        "resolved_count": len(resolved_findings),
        "persistent_count": len(persistent_findings),
        "score_before": before_score,
        "score_after": after_score,
        "score_delta": score_delta,
        "score_trend": "improved" if score_delta > 0 else ("degraded" if score_delta < 0 else "unchanged"),
        "severity_comparison": sev_comparison,
        "summary": summary,
    }
