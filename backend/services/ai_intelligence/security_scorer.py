"""
SENTINEL AI — Security Scoring Engine
Computes a percentage-based security score (0-100%) with risk classification.
"""
from typing import List, Dict


def compute_security_score(findings: List[dict]) -> dict:
    """
    Compute a security score from scan findings.

    Algorithm:
      base = 100
      For each finding (excluding info, false positives, duplicates):
        critical: -25
        high:     -10
        medium:   -5
        low:      -1
      Bonus deductions:
        exploit_available: extra -5
      Floor at 0.

    Returns:
      {
        "score": int 0-100,
        "grade": str,
        "color": str,
        "total_deductions": int,
        "breakdown": {
          "critical": {"count": N, "deduction": N},
          ...
        },
        "findings_summary": {
          "total": N, "critical": N, "high": N, "medium": N, "low": N, "info": N
        }
      }
    """
    DEDUCTIONS = {"critical": 25, "high": 10, "medium": 5, "low": 1}

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    severity_deduction = 0
    exploit_deduction = 0

    for f in findings:
        # Skip non-actionable
        if f.get("is_false_positive"):
            continue
        if f.get("is_duplicate"):
            continue

        sev = f.get("severity", "info").lower()
        if sev not in counts:
            sev = "info"
        counts[sev] = counts.get(sev, 0) + 1

        # Severity deduction
        ded = DEDUCTIONS.get(sev, 0)
        severity_deduction += ded

        # Exploit bonus deduction
        if f.get("exploit_available"):
            exploit_deduction += 5

    total_deduction = severity_deduction + exploit_deduction
    score = max(0, 100 - total_deduction)

    # Grade
    if score >= 81:
        grade = "Secure"
        color = "green"
    elif score >= 61:
        grade = "Medium Risk"
        color = "yellow"
    elif score >= 41:
        grade = "High Risk"
        color = "orange"
    else:
        grade = "Critical Risk"
        color = "red"

    return {
        "score": score,
        "grade": grade,
        "color": color,
        "total_deductions": total_deduction,
        "breakdown": {
            sev: {"count": counts[sev], "deduction": counts[sev] * DEDUCTIONS.get(sev, 0)}
            for sev in ("critical", "high", "medium", "low")
        },
        "findings_summary": {
            "total": sum(counts.values()),
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "info": counts["info"],
        },
    }
