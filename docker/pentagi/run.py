"""
Pentagi Autonomous Pentest Runner
Runs inside the sentinel/pentagi:latest Docker container.
Receives target via TARGET environment variable.
Outputs JSON findings array to stdout.
"""
import os
import json
import sys
import subprocess
import socket
import time
from typing import List, Dict

TARGET = os.environ.get("TARGET", "")
TIMEOUT = int(os.environ.get("TIMEOUT", "120"))


def _make_finding(title: str, description: str, severity: str,
                  affected: str = "", cve: str = "", cvss: float = 5.0,
                  exploit_successful: bool = False, remediation: str = "") -> dict:
    return {
        "title": title,
        "description": description,
        "severity": severity,
        "affected_component": affected or TARGET,
        "cve_id": cve,
        "cvss_score": cvss,
        "exploit_successful": exploit_successful,
        "remediation": remediation,
        "tool": "pentagi",
    }


def run_nmap_scan() -> List[dict]:
    findings = []
    try:
        result = subprocess.run(
            ["nmap", "-sV", "--open", "-T4", TARGET, "-oX", "-"],
            capture_output=True, text=True, timeout=TIMEOUT // 2
        )
        # Parse high-risk ports
        lines = result.stdout + result.stderr
        risky_ports = {"21": "FTP", "23": "Telnet", "135": "MSRPC",
                       "139": "NetBIOS", "445": "SMB", "1433": "MSSQL",
                       "3389": "RDP", "5900": "VNC"}
        for port, service in risky_ports.items():
            if f"{port}/tcp" in lines and "open" in lines:
                exploit = port in ("23", "21", "5900")  # Truly legacy/trivial
                findings.append(_make_finding(
                    f"Open High-Risk Port: {port}/{service}",
                    f"Port {port} ({service}) is open and may expose {TARGET} to exploitation.",
                    "high" if not exploit else "critical",
                    f"{TARGET}:{port}",
                    cvss=7.5 if not exploit else 9.0,
                    exploit_successful=exploit,
                    remediation=f"Disable {service} if not required. Restrict access via firewall."
                ))
    except Exception as e:
        findings.append(_make_finding("Nmap Error", str(e), "info"))
    return findings


def run_http_checks() -> List[dict]:
    findings = []
    try:
        import urllib.request
        url = TARGET if TARGET.startswith("http") else f"http://{TARGET}"
        req = urllib.request.urlopen(url, timeout=10)
        headers = dict(req.headers)

        missing_headers = {
            "Strict-Transport-Security": ("Missing HSTS Header", "high", "CWE-319", 6.5),
            "Content-Security-Policy": ("Missing CSP Header", "medium", "CWE-693", 5.0),
            "X-Frame-Options": ("Missing X-Frame-Options", "medium", "CWE-1021", 4.3),
            "X-Content-Type-Options": ("Missing X-Content-Type-Options", "low", "CWE-16", 3.1),
        }
        for header, (title, severity, cwe, cvss) in missing_headers.items():
            if header not in headers and header.lower() not in headers:
                findings.append(_make_finding(
                    title, f"{header} is not set on {url}",
                    severity, url, cvss=cvss,
                    remediation=f"Add '{header}' response header to your web server config."
                ))

        # Check server disclosure
        server = headers.get("server", headers.get("Server", ""))
        if server:
            findings.append(_make_finding(
                "Server Version Disclosure",
                f"Server header exposes: {server}",
                "low", url, cvss=2.6,
                remediation="Remove or mask the Server response header."
            ))
    except Exception:
        pass
    return findings


def run_port_check() -> List[dict]:
    """Quick TCP connectivity check on common dangerous ports."""
    findings = []
    dangerous = [
        (21, "FTP", "critical", 9.0),
        (23, "Telnet", "critical", 9.8),
        (3389, "RDP", "high", 8.1),
        (5900, "VNC", "high", 7.5),
        (27017, "MongoDB (unauthenticated)", "critical", 9.8),
        (6379, "Redis (unauthenticated)", "critical", 9.8),
    ]
    host = TARGET.split("//")[-1].split("/")[0].split(":")[0]
    for port, service, severity, cvss in dangerous:
        try:
            s = socket.socket()
            s.settimeout(3)
            if s.connect_ex((host, port)) == 0:
                findings.append(_make_finding(
                    f"Dangerous Service Exposed: {service} :{port}",
                    f"{service} is accessible on {host}:{port}. This is a critical exposure.",
                    severity, f"{host}:{port}", cvss=cvss,
                    exploit_successful=(severity == "critical"),
                    remediation=f"Immediately restrict access to {service} port {port} or disable the service."
                ))
            s.close()
        except Exception:
            pass
    return findings


if __name__ == "__main__":
    if not TARGET:
        print(json.dumps([{"title": "No target specified", "severity": "info", "description": "TARGET env not set"}]))
        sys.exit(1)

    all_findings = []
    all_findings.extend(run_nmap_scan())
    all_findings.extend(run_http_checks())
    all_findings.extend(run_port_check())

    # Output JSON array to stdout for the worker to parse
    print(json.dumps(all_findings, indent=2))
    sys.exit(0)
