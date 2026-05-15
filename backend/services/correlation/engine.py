"""
SENTINEL AI -- Finding Correlation Engine
Merges findings across multiple tools into unified vulnerability entities.
Example: Nmap open port + Nikto finding + CVE match = single correlated vulnerability.
"""
from typing import List, Dict, Optional
from collections import defaultdict


def correlate_findings(findings: List[dict]) -> List[dict]:
    """
    Correlate findings from different tools that describe the same vulnerability.

    Merges by:
      1. CVE match (same CVE from different tools)
      2. Component match (same port/service/file from different tools)
      3. Semantic match (same vulnerability type on same target)

    Returns correlated findings with enriched data.
    """
    if not findings:
        return []

    # Group by CVE
    by_cve: Dict[str, List[dict]] = defaultdict(list)
    # Group by component
    by_component: Dict[str, List[dict]] = defaultdict(list)
    # Ungrouped
    ungrouped: List[dict] = []

    for f in findings:
        cve = f.get("cve_id", "")
        comp = f.get("affected_component", "")

        grouped = False
        if cve:
            by_cve[cve].append(f)
            grouped = True
        if comp:
            # Normalize component: "192.168.1.1:80" -> "192.168.1.1:80"
            by_component[comp.strip().lower()].append(f)
            grouped = True
        if not grouped:
            ungrouped.append(f)

    correlated = []

    # Merge CVE groups
    for cve, group in by_cve.items():
        if len(group) > 1:
            merged = _merge_group(group)
            merged["correlation_type"] = "cve_match"
            merged["correlation_confidence"] = 0.95
            merged["correlated_tools"] = list(set(f.get("tool_name", "") for f in group))
            correlated.append(merged)
        else:
            correlated.append(group[0])

    # Merge component groups (only for findings not already merged by CVE)
    cve_titles = {f.get("title") for f in correlated}
    for comp, group in by_component.items():
        # Filter out already-correlated findings
        remaining = [f for f in group if f.get("title") not in cve_titles]
        if len(remaining) > 1:
            # Check if same tool — don't merge same-tool findings
            tools = set(f.get("tool_name", "") for f in remaining)
            if len(tools) > 1:
                merged = _merge_group(remaining)
                merged["correlation_type"] = "component_match"
                merged["correlation_confidence"] = 0.80
                merged["correlated_tools"] = list(tools)
                correlated.append(merged)
            else:
                for f in remaining:
                    if f.get("title") not in cve_titles:
                        correlated.append(f)
                        cve_titles.add(f.get("title"))
        elif len(remaining) == 1 and remaining[0].get("title") not in cve_titles:
            correlated.append(remaining[0])
            cve_titles.add(remaining[0].get("title"))

    # Add ungrouped
    for f in ungrouped:
        if f.get("title") not in cve_titles:
            correlated.append(f)

    return correlated


def _merge_group(group: List[dict]) -> dict:
    """Merge a group of related findings into a single enriched finding."""
    # Take the most severe finding as the base
    sev_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    sorted_group = sorted(group, key=lambda f: sev_order.get(f.get("severity", "info"), 0), reverse=True)
    base = dict(sorted_group[0])

    # Enrich with data from others
    all_tools = set()
    all_descriptions = []
    all_remediations = []
    max_cvss = base.get("cvss_score", 0) or 0
    has_exploit = base.get("exploit_available", False)

    for f in group:
        tool = f.get("tool_name", "")
        if tool:
            all_tools.add(tool)

        desc = f.get("description", "")
        if desc and desc not in all_descriptions:
            all_descriptions.append(desc)

        rem = f.get("remediation", "")
        if rem and rem not in all_remediations:
            all_remediations.append(rem)

        cvss = f.get("cvss_score", 0) or 0
        if cvss > max_cvss:
            max_cvss = cvss

        if f.get("exploit_available"):
            has_exploit = True

        # Take CVE if base doesn't have one
        if not base.get("cve_id") and f.get("cve_id"):
            base["cve_id"] = f["cve_id"]
        if not base.get("cwe_id") and f.get("cwe_id"):
            base["cwe_id"] = f["cwe_id"]

    base["cvss_score"] = max_cvss
    base["exploit_available"] = has_exploit
    base["description"] = " | ".join(all_descriptions[:3])
    base["remediation"] = " ".join(all_remediations[:3])
    base["confirming_tools"] = list(all_tools)
    base["confirmed_by_count"] = len(all_tools)

    return base


def enrich_findings_with_context(findings: List[dict], target: str) -> List[dict]:
    """Add exposure and asset context to findings."""
    import ipaddress

    is_public = False
    try:
        ip = ipaddress.ip_address(target)
        is_public = not ip.is_private and not ip.is_loopback
    except ValueError:
        # Domain — assume public
        if "." in target and not target.startswith((".", "/", "\\")):
            is_public = True

    for f in findings:
        f["exposure_level"] = "external" if is_public else "internal"
        f["target"] = target

        # Enrich severity if exploit is available and target is public
        if is_public and f.get("exploit_available") and f.get("severity") in ("medium", "high"):
            original = f["severity"]
            f["severity"] = "critical" if original == "high" else "high"
            f["severity_upgraded"] = True
            f["severity_upgrade_reason"] = f"Upgraded from {original}: exploit available on public-facing asset"

    return findings
