import asyncio
from backend.services.reporting.pdf_generator import generate_report

scan_data = {
    "target_raw": "https://kartik-rathi.site",
    "scan_type": "web",
    "completed_at": "2026-05-15T12:00:00Z",
    "tools_used": ["nmap", "nikto", "zap"]
}
findings = [
    {"title": "Open Port 22", "severity": "medium", "description": "SSH is open.", "remediation": "Firewall."},
    {"title": "XSS", "severity": "high", "description": "Cross-site scripting.", "remediation": "Sanitize."}
]
score_data = {"score": 85, "grade": "Secure", "findings_summary": {"critical": 0, "high": 1, "medium": 1, "low": 0, "total": 2}}

path = generate_report(scan_data, findings, score_data)
print(f"Generated at: {path}")
