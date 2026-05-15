"""
SENTINEL AI — Compliance Mapping Engine
Maps findings to industry compliance frameworks:
- OWASP Top 10
- PCI-DSS v4.0
- ISO 27001:2022
- NIST CSF 2.0
- HIPAA
- SOC 2
"""
from typing import List, Dict


# ── OWASP Top 10 (2021) ─────────────────────────────────────────────────────

OWASP_TOP_10 = {
    "A01:2021": {
        "name": "Broken Access Control",
        "cwes": ["CWE-200", "CWE-201", "CWE-352", "CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863"],
        "keywords": ["access control", "authorization", "privilege", "idor", "path traversal"],
    },
    "A02:2021": {
        "name": "Cryptographic Failures",
        "cwes": ["CWE-259", "CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-295", "CWE-319", "CWE-798"],
        "keywords": ["ssl", "tls", "crypto", "hash", "password", "encryption", "cleartext", "hsts", "certificate"],
    },
    "A03:2021": {
        "name": "Injection",
        "cwes": ["CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-96", "CWE-502", "CWE-611", "CWE-917"],
        "keywords": ["injection", "sqli", "xss", "rce", "command injection", "deserialization", "xxe"],
    },
    "A04:2021": {
        "name": "Insecure Design",
        "cwes": ["CWE-209", "CWE-256", "CWE-501", "CWE-522", "CWE-602"],
        "keywords": ["design flaw", "threat model", "insecure design"],
    },
    "A05:2021": {
        "name": "Security Misconfiguration",
        "cwes": ["CWE-16", "CWE-611", "CWE-693", "CWE-732", "CWE-1021"],
        "keywords": ["misconfiguration", "default", "header", "csp", "x-frame", "cors", "server version", "directory listing"],
    },
    "A06:2021": {
        "name": "Vulnerable and Outdated Components",
        "cwes": ["CWE-1104"],
        "keywords": ["outdated", "vulnerable component", "dependency", "library", "cve-", "upgrade", "update"],
    },
    "A07:2021": {
        "name": "Identification and Authentication Failures",
        "cwes": ["CWE-287", "CWE-384", "CWE-521", "CWE-613", "CWE-620", "CWE-640"],
        "keywords": ["authentication", "session", "credential", "brute force", "weak password"],
    },
    "A08:2021": {
        "name": "Software and Data Integrity Failures",
        "cwes": ["CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502", "CWE-565", "CWE-829"],
        "keywords": ["integrity", "deserialization", "tampering", "supply chain"],
    },
    "A09:2021": {
        "name": "Security Logging and Monitoring Failures",
        "cwes": ["CWE-117", "CWE-223", "CWE-532", "CWE-778"],
        "keywords": ["logging", "monitoring", "audit", "detection"],
    },
    "A10:2021": {
        "name": "Server-Side Request Forgery (SSRF)",
        "cwes": ["CWE-918"],
        "keywords": ["ssrf", "server-side request"],
    },
}


# ── PCI-DSS v4.0 Requirements ───────────────────────────────────────────────

PCI_DSS = {
    "1.0": {"name": "Install and maintain network security controls", "keywords": ["firewall", "port", "network", "segmentation"]},
    "2.0": {"name": "Apply secure configurations", "keywords": ["default", "configuration", "hardening", "server version"]},
    "3.0": {"name": "Protect stored account data", "keywords": ["encryption", "storage", "data protection", "pii"]},
    "4.0": {"name": "Protect with strong cryptography during transmission", "keywords": ["tls", "ssl", "hsts", "cleartext", "certificate"]},
    "5.0": {"name": "Protect from malicious software", "keywords": ["malware", "antivirus", "trojan"]},
    "6.0": {"name": "Develop and maintain secure systems", "keywords": ["vulnerability", "patch", "cve", "update", "code review", "injection", "xss"]},
    "7.0": {"name": "Restrict access by business need", "keywords": ["access control", "authorization", "privilege"]},
    "8.0": {"name": "Identify users and authenticate access", "keywords": ["authentication", "password", "mfa", "credential"]},
    "10.0": {"name": "Log and monitor access", "keywords": ["logging", "monitoring", "audit"]},
    "11.0": {"name": "Test security regularly", "keywords": ["scan", "penetration test", "assessment"]},
    "12.0": {"name": "Support with organizational policies", "keywords": ["policy", "governance", "awareness"]},
}


# ── ISO 27001:2022 Controls ──────────────────────────────────────────────────

ISO_27001 = {
    "A.5": {"name": "Organizational controls", "keywords": ["policy", "governance", "risk"]},
    "A.6": {"name": "People controls", "keywords": ["awareness", "training", "personnel"]},
    "A.7": {"name": "Physical controls", "keywords": ["physical", "access", "facility"]},
    "A.8.5": {"name": "Secure authentication", "keywords": ["authentication", "password", "mfa"]},
    "A.8.9": {"name": "Configuration management", "keywords": ["configuration", "hardening", "default"]},
    "A.8.10": {"name": "Information deletion", "keywords": ["data retention", "deletion"]},
    "A.8.12": {"name": "Data leakage prevention", "keywords": ["leak", "secret", "api key", "credential", "exposure"]},
    "A.8.20": {"name": "Networks security", "keywords": ["network", "firewall", "port", "segmentation"]},
    "A.8.24": {"name": "Use of cryptography", "keywords": ["encryption", "tls", "ssl", "crypto", "hash"]},
    "A.8.25": {"name": "Secure development lifecycle", "keywords": ["code", "review", "sast", "vulnerability"]},
    "A.8.28": {"name": "Secure coding", "keywords": ["injection", "xss", "sqli", "code quality"]},
}


# ── NIST CSF 2.0 ─────────────────────────────────────────────────────────────

NIST_CSF = {
    "ID.AM": {"name": "Asset Management", "keywords": ["asset", "inventory", "discovery", "subdomain"]},
    "ID.RA": {"name": "Risk Assessment", "keywords": ["risk", "vulnerability", "threat", "cvss", "epss"]},
    "PR.AC": {"name": "Access Control", "keywords": ["access control", "authentication", "authorization"]},
    "PR.DS": {"name": "Data Security", "keywords": ["encryption", "data protection", "secret", "leak"]},
    "PR.IP": {"name": "Information Protection", "keywords": ["configuration", "hardening", "patch"]},
    "PR.PT": {"name": "Protective Technology", "keywords": ["firewall", "header", "csp", "hsts"]},
    "DE.CM": {"name": "Security Continuous Monitoring", "keywords": ["monitoring", "scan", "detection"]},
    "RS.MI": {"name": "Mitigation", "keywords": ["remediation", "fix", "patch", "update"]},
}


def _matches_framework(finding: dict, rules: dict) -> List[str]:
    """Check if a finding matches any rules in a framework."""
    matches = []
    cwe = finding.get("cwe_id", "")
    title = (finding.get("title", "") or "").lower()
    desc = (finding.get("description", "") or "").lower()
    combined = f"{title} {desc}"

    for code, rule in rules.items():
        # Check CWE match
        cwes = rule.get("cwes", [])
        if cwe and cwe in cwes:
            matches.append(code)
            continue

        # Check keyword match
        keywords = rule.get("keywords", [])
        if any(kw in combined for kw in keywords):
            matches.append(code)

    return matches


def map_findings_to_compliance(findings: List[dict]) -> dict:
    """
    Map all findings to compliance frameworks.

    Returns:
        {
            "owasp_top_10": {
                "A01:2021": {"name": "Broken Access Control", "findings": [...], "status": "fail"},
                ...
            },
            "pci_dss": {...},
            "iso_27001": {...},
            "nist_csf": {...},
            "summary": {
                "owasp_coverage": 3,
                "pci_violations": 5,
                "iso_gaps": 2,
                "compliance_score": 72.5,
            }
        }
    """
    result = {
        "owasp_top_10": {},
        "pci_dss": {},
        "iso_27001": {},
        "nist_csf": {},
    }

    # Initialize all framework entries
    for code, info in OWASP_TOP_10.items():
        result["owasp_top_10"][code] = {
            "name": info["name"],
            "findings": [],
            "count": 0,
            "max_severity": "pass",
            "status": "pass",
        }

    for code, info in PCI_DSS.items():
        result["pci_dss"][code] = {
            "name": info["name"],
            "findings": [],
            "count": 0,
            "max_severity": "pass",
            "status": "pass",
        }

    for code, info in ISO_27001.items():
        result["iso_27001"][code] = {
            "name": info["name"],
            "findings": [],
            "count": 0,
            "max_severity": "pass",
            "status": "pass",
        }

    for code, info in NIST_CSF.items():
        result["nist_csf"][code] = {
            "name": info["name"],
            "findings": [],
            "count": 0,
            "max_severity": "pass",
            "status": "pass",
        }

    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "pass": -1}

    for finding in findings:
        sev = finding.get("severity", "info").lower()
        finding_summary = {
            "title": finding.get("title", ""),
            "severity": sev,
            "tool_name": finding.get("tool_name", ""),
            "cve_id": finding.get("cve_id"),
            "cwe_id": finding.get("cwe_id"),
        }

        # OWASP
        for code in _matches_framework(finding, OWASP_TOP_10):
            entry = result["owasp_top_10"][code]
            entry["findings"].append(finding_summary)
            entry["count"] += 1
            if severity_rank.get(sev, 0) > severity_rank.get(entry["max_severity"], -1):
                entry["max_severity"] = sev
            entry["status"] = "fail"

        # PCI-DSS
        for code in _matches_framework(finding, PCI_DSS):
            entry = result["pci_dss"][code]
            entry["findings"].append(finding_summary)
            entry["count"] += 1
            if severity_rank.get(sev, 0) > severity_rank.get(entry["max_severity"], -1):
                entry["max_severity"] = sev
            entry["status"] = "fail"

        # ISO 27001
        for code in _matches_framework(finding, ISO_27001):
            entry = result["iso_27001"][code]
            entry["findings"].append(finding_summary)
            entry["count"] += 1
            if severity_rank.get(sev, 0) > severity_rank.get(entry["max_severity"], -1):
                entry["max_severity"] = sev
            entry["status"] = "fail"

        # NIST CSF
        for code in _matches_framework(finding, NIST_CSF):
            entry = result["nist_csf"][code]
            entry["findings"].append(finding_summary)
            entry["count"] += 1
            if severity_rank.get(sev, 0) > severity_rank.get(entry["max_severity"], -1):
                entry["max_severity"] = sev
            entry["status"] = "fail"

    # Compute summary
    owasp_fails = sum(1 for v in result["owasp_top_10"].values() if v["status"] == "fail")
    pci_fails = sum(1 for v in result["pci_dss"].values() if v["status"] == "fail")
    iso_fails = sum(1 for v in result["iso_27001"].values() if v["status"] == "fail")
    nist_fails = sum(1 for v in result["nist_csf"].values() if v["status"] == "fail")

    total_controls = len(OWASP_TOP_10) + len(PCI_DSS) + len(ISO_27001) + len(NIST_CSF)
    total_fails = owasp_fails + pci_fails + iso_fails + nist_fails
    compliance_score = round(((total_controls - total_fails) / total_controls) * 100, 1) if total_controls else 100

    result["summary"] = {
        "owasp_violations": owasp_fails,
        "owasp_total": len(OWASP_TOP_10),
        "pci_violations": pci_fails,
        "pci_total": len(PCI_DSS),
        "iso_gaps": iso_fails,
        "iso_total": len(ISO_27001),
        "nist_gaps": nist_fails,
        "nist_total": len(NIST_CSF),
        "total_controls": total_controls,
        "total_violations": total_fails,
        "compliance_score": compliance_score,
        "overall_status": "compliant" if total_fails == 0 else ("partial" if compliance_score >= 70 else "non-compliant"),
    }

    return result
