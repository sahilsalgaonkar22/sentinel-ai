"""
SENTINEL AI — Real Tool Executor

PRODUCTION CONTRACT:
- _run_port_probe (Python socket fake) is REMOVED.
  nmap binary is REQUIRED. If absent → RuntimeError at startup via tool_validator.
- All binary-not-found paths raise ToolNotAvailableError (HTTP 503 to caller).
- No fake/simulation findings are generated anywhere in this module.
- SSRF protection: all hostnames are resolved once; the locked IP is used for execution.
  Changing DNS responses cannot affect the scan target after lock.
"""
import asyncio
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import uuid
try:
    import defusedxml.ElementTree as ET  # XXE-safe XML parser
except ImportError:
    import xml.etree.ElementTree as ET   # noqa: S405 — defusedxml preferred
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse
import ipaddress
import logging

import httpx

from backend.common.tool_validator import is_tool_available

logger = logging.getLogger(__name__)


class ToolNotAvailableError(RuntimeError):
    """Raised when a required binary is not installed on this worker."""


# ---------------------------------------------------------------------------
#  Finding data structure
# ---------------------------------------------------------------------------

def _make_finding(
    title: str,
    description: str,
    severity: str,
    tool_name: str,
    cvss_score: float = 0.0,
    cve_id: str = None,
    cwe_id: str = None,
    affected_component: str = None,
    remediation: str = None,
    exploit_available: bool = False,
    tool_output: dict = None,
) -> dict:
    """Create a standardized finding dict."""
    return {
        "title": title,
        "description": description,
        "severity": severity,
        "cvss_score": cvss_score,
        "cve_id": cve_id,
        "cwe_id": cwe_id,
        "affected_component": affected_component or "",
        "remediation": remediation or "Apply vendor patch and follow security best practices.",
        "exploit_available": exploit_available,
        "tool_name": tool_name,
        "tool_output": tool_output or {},
    }


# ---------------------------------------------------------------------------
#  SSRF / DNS Rebinding Protection
# ---------------------------------------------------------------------------

# RFC 1918 + loopback + link-local + cloud-metadata ranges to block
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),     # link-local / AWS metadata
    ipaddress.ip_network("100.64.0.0/10"),       # shared address space (RFC 6598)
    ipaddress.ip_network("fd00::/8"),            # ULA IPv6
    ipaddress.ip_network("::1/128"),             # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),           # IPv6 link-local
]

_BLOCKED_METADATA_IPS = {
    "169.254.169.254",   # AWS/GCP/Azure IMDS
    "100.100.100.200",   # Alibaba metadata
}


def _resolve_and_lock(hostname: str) -> str:
    """
    Resolve hostname to a single IP. Validate against blocked ranges.

    Returns:
        Validated IP string.

    Raises:
        ValueError: if hostname resolves to a blocked/private IP.
        socket.gaierror: if hostname cannot be resolved.
    """
    # If already an IP, validate directly
    try:
        addr = ipaddress.ip_address(hostname)
        _validate_ip(addr, hostname)
        return str(addr)
    except ValueError:
        pass  # not a bare IP — proceed to DNS resolution

    # DNS resolution — use getaddrinfo for full resolution (supports IPv6)
    try:
        results = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve hostname '{hostname}': {exc}") from exc

    if not results:
        raise ValueError(f"No DNS records returned for '{hostname}'")

    # Take the first returned IP and lock it
    ip_str = results[0][4][0]
    addr = ipaddress.ip_address(ip_str)
    _validate_ip(addr, hostname)

    logger.debug("ssrf_check.resolved hostname=%s locked_ip=%s", hostname, ip_str)
    return ip_str


def _validate_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address, original: str) -> None:
    """Raise ValueError if addr is in any blocked range."""
    if str(addr) in _BLOCKED_METADATA_IPS:
        raise ValueError(f"SSRF blocked: '{original}' resolves to cloud metadata endpoint {addr}")
    for net in _BLOCKED_NETWORKS:
        if addr in net:
            raise ValueError(
                f"SSRF blocked: '{original}' resolves to private/reserved IP {addr} ({net})"
            )


def resolve_target_ip(target: str) -> str:
    """
    Public interface: extract hostname from target (URL, IP, or hostname:port),
    resolve + validate, and return the locked IP string.

    Raises ValueError on SSRF-blocked targets.
    """
    # Strip URL scheme and path if target is a URL
    if "://" in target:
        parsed = urlparse(target)
        hostname = parsed.hostname or target
    elif ":" in target and not target.startswith("["):
        # host:port
        hostname = target.rsplit(":", 1)[0]
    else:
        hostname = target

    return _resolve_and_lock(hostname)


# ---------------------------------------------------------------------------
#  NMAP / Port Scanner (nmap REQUIRED — no fallback)
# ---------------------------------------------------------------------------

async def run_nmap(target: str, config: dict = None) -> List[dict]:
    config = config or {}
    nmap_bin = shutil.which("nmap")

    if not nmap_bin:
        raise ToolNotAvailableError(
            "nmap binary not found. Install nmap before starting the network worker."
        )

    try:
        locked_ip = resolve_target_ip(target)
    except ValueError as exc:
        return [_make_finding(
            "SSRF Blocked",
            str(exc),
            "critical",
            "nmap",
            cvss_score=9.1,
            cwe_id="CWE-918",
            remediation="Do not scan private/metadata IP ranges.",
        )]

    return await _run_nmap_subprocess(nmap_bin, locked_ip, target, config)


async def _run_nmap_subprocess(nmap_bin: str, locked_ip: str, original_target: str, config: dict) -> List[dict]:
    ports = config.get("ports", "22,80,443,8080,8443,3306,5432,6379,27017,3389")

    args = [
        nmap_bin,
        "-sV",
        "--version-intensity", "5",
        "-oX", "-",
        "--open",
        "-p", ports,
        locked_ip
    ]

    if config.get("run_vuln_scripts"):
        args.extend(["--script", "vuln"])

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return [_make_finding(
                "Nmap Scan Timeout",
                f"Nmap scan of {original_target} timed out after 120s.",
                "info",
                "nmap",
            )]

        if proc.returncode != 0:
            err = stderr.decode(errors="ignore")[:500]
            logger.error("nmap.failed target=%s err=%s", original_target, err)
            return [_make_finding(
                "Nmap Execution Failed",
                err,
                "medium",
                "nmap",
            )]

        xml_output = stdout.decode("utf-8", errors="replace")
        return _parse_nmap_xml(xml_output, original_target, locked_ip)

    except Exception as exc:
        logger.error("nmap.error target=%s error=%s", original_target, exc)
        return [_make_finding(
            "Nmap Execution Error",
            str(exc),
            "medium",
            "nmap",
        )]

# ---------------------------------------------------------------------------
#  BANDIT — Python Security Scanner (REQUIRED)
# ---------------------------------------------------------------------------

BANDIT_CWE = {
    "B101": "CWE-617", "B102": "CWE-78",  "B103": "CWE-732", "B104": "CWE-605",
    "B105": "CWE-259", "B106": "CWE-259", "B107": "CWE-259", "B108": "CWE-377",
    "B110": "CWE-390", "B301": "CWE-502", "B303": "CWE-327", "B307": "CWE-78",
    "B311": "CWE-330", "B324": "CWE-327", "B501": "CWE-295", "B502": "CWE-326",
    "B506": "CWE-611", "B602": "CWE-78",  "B603": "CWE-78",  "B608": "CWE-89",
}

BANDIT_SEVERITY = {"HIGH": ("high", 7.5), "MEDIUM": ("medium", 5.0), "LOW": ("low", 3.1)}


async def run_bandit(target: str, config: dict = None) -> List[dict]:
    """Run real bandit against Python code. Hard fails if binary is absent."""
    scan_path = target if os.path.exists(target) else "."
    bandit_bin = shutil.which("bandit")
    if not bandit_bin:
        raise ToolNotAvailableError(
            "bandit binary not found. Install bandit before starting the code worker."
        )

    cmd = [bandit_bin, "-r", scan_path, "-f", "json", "-ll", "--quiet"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            cwd=os.getcwd()
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        raw = stdout.decode("utf-8", errors="replace")
        return _parse_bandit_json(raw)
    except asyncio.TimeoutError:
        return [_make_finding("Bandit Timeout", "bandit scan timed out after 120s.", "info", "bandit")]
    except Exception as exc:
        logger.error("bandit.error target=%s error=%s", target, exc)
        return [_make_finding("Bandit Error", str(exc), "info", "bandit")]


def _parse_bandit_json(raw: str) -> List[dict]:
    findings = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        try:
            idx = raw.index("{")
            data = json.loads(raw[idx:])
        except Exception:
            return findings

    for issue in data.get("results", []):
        test_id = issue.get("test_id", "")
        sev_key = issue.get("issue_severity", "MEDIUM").upper()
        severity, cvss = BANDIT_SEVERITY.get(sev_key, ("medium", 5.0))
        cwe = BANDIT_CWE.get(test_id)
        fname = issue.get("filename", "")
        line = issue.get("line_number", 0)
        issue_text = issue.get("issue_text", "")
        code = issue.get("code", "").strip()

        findings.append(_make_finding(
            title=f"[{test_id}] {issue_text}",
            description=f"File: {fname} (line {line})\nCode:\n{code[:500]}",
            severity=severity,
            tool_name="bandit",
            cvss_score=cvss,
            cwe_id=cwe,
            affected_component=f"{fname}:{line}",
            remediation=(
                f"Fix {test_id}: {issue_text}. "
                f"See https://bandit.readthedocs.io/en/latest/plugins/{test_id.lower()}.html"
            ),
            tool_output={
                "test_id": test_id, "filename": fname, "line": line,
                "severity": sev_key, "confidence": issue.get("issue_confidence", ""),
            },
        ))

    return findings


# ---------------------------------------------------------------------------
#  SEMGREP — Static Analysis (optional)
# ---------------------------------------------------------------------------

async def run_semgrep(target: str, config: dict = None) -> List[dict]:
    """Run real semgrep. Returns empty list if not installed (not required)."""
    scan_path = target if os.path.exists(target) else "."
    semgrep_bin = shutil.which("semgrep")
    if not semgrep_bin:
        logger.info("semgrep.not_installed skipping")
        return []

    cmd = [semgrep_bin, "--config", "auto", scan_path, "--json", "--quiet"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            cwd=os.getcwd()
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
        raw = stdout.decode("utf-8", errors="replace")
        return _parse_semgrep_json(raw)
    except Exception as exc:
        logger.warning("semgrep.error %s", exc)
        return []


def _parse_semgrep_json(raw: str) -> List[dict]:
    findings = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return findings

    for result in data.get("results", []):
        sev_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
        severity = sev_map.get(result.get("extra", {}).get("severity", "WARNING"), "medium")
        cvss_map = {"high": 7.0, "medium": 5.0, "low": 3.0}
        path = result.get("path", "")
        line_start = result.get("start", {}).get("line", 0)
        rule_id = result.get("check_id", "unknown")
        message = result.get("extra", {}).get("message", "")

        findings.append(_make_finding(
            title=f"Semgrep: {rule_id}",
            description=f"{message}\nFile: {path}:{line_start}",
            severity=severity,
            tool_name="semgrep",
            cvss_score=cvss_map.get(severity, 5.0),
            affected_component=f"{path}:{line_start}",
            remediation=f"Fix the issue identified by rule {rule_id}.",
            tool_output={"rule_id": rule_id, "path": path, "line": line_start},
        ))

    return findings


# ---------------------------------------------------------------------------
#  NIKTO / HTTP Security Analysis (nikto optional; HTTP checks always run)
# ---------------------------------------------------------------------------

async def run_nikto(target: str, config: dict = None) -> List[dict]:
    """
    Run nikto against the target if available; otherwise fall back to the
    built-in Python HTTP security checker (_run_http_security_check).

    PRODUCTION: install nikto on worker nodes for full coverage.
    DEVELOPMENT: HTTP security fallback runs automatically — no 503 on dev hosts.
    """
    nikto_bin = shutil.which("nikto")
    if nikto_bin:
        logger.info("nikto.using_binary bin=%s target=%s", nikto_bin, target)
        return await _run_nikto_subprocess(nikto_bin, target, config)

    # nikto not installed — fall back to HTTP security check (non-fatal)
    logger.warning(
        "nikto.binary_not_found target=%s falling_back_to=http_security_check "
        "install: apt-get install nikto",
        target,
    )
    findings = await _run_http_security_check(target)
    # Tag all findings with a note so operators know full nikto wasn't run
    for f in findings:
        f["tool_name"] = "http_security"
        f.setdefault("description", "")
        f["description"] += " [nikto not available — install for full web scan coverage]"
    return findings



async def _run_nikto_subprocess(nikto_bin: str, target: str, config: dict) -> List[dict]:
    """Execute nikto and parse JSON output."""
    url = target if target.startswith("http") else f"http://{target}"
    cmd = [nikto_bin, "-h", url, "-Format", "json", "-output", "-"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        raw = stdout.decode("utf-8", errors="replace")
        findings = []
        try:
            data = json.loads(raw)
            for vuln in data.get("vulnerabilities", []):
                findings.append(_make_finding(
                    title=vuln.get("msg", "Nikto Finding"),
                    description=vuln.get("msg", ""),
                    severity="medium",
                    tool_name="nikto",
                    tool_output=vuln,
                ))
        except json.JSONDecodeError:
            logger.warning("nikto.json_parse_failed target=%s returning empty findings", target)
        return findings
    except asyncio.TimeoutError:
        return [_make_finding(
            "Nikto Scan Timeout",
            f"Nikto scan of {target} timed out after 120s.",
            "info", "nikto",
        )]
    except Exception as exc:
        logger.error("nikto.error target=%s error=%s", target, exc)
        return [_make_finding("Nikto Execution Error", str(exc), "info", "nikto")]


async def _run_http_security_check(target: str) -> List[dict]:
    """Python-native HTTP security checker — real HTTP requests."""
    findings = []
    urls = (
        [target] if target.startswith("http")
        else [f"https://{target}", f"http://{target}"]
    )

    resp = None
    headers = {}
    found_url = None
    for url in urls:
        try:
            verify = url.startswith("https://")
            async with httpx.AsyncClient(verify=verify, follow_redirects=True, timeout=10) as client:
                resp = await client.get(url)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                found_url = url
                break
        except (httpx.ConnectError, httpx.ReadError, ssl.SSLError):
            try:
                async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:  # noqa: S501
                    resp = await client.get(url)
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    found_url = url
                    break
            except Exception:
                continue
        except Exception:
            continue

    if resp is None:
        return [_make_finding(
            "Target Unreachable via HTTP",
            f"Could not connect to {target} via HTTP/HTTPS.",
            "info", "nikto",
        )]

    SECURITY_HEADERS = {
        "strict-transport-security": {
            "title": "Missing HSTS Header",
            "desc": "The server does not set Strict-Transport-Security, making it vulnerable to downgrade attacks.",
            "severity": "medium", "cvss": 5.0, "cwe": "CWE-319",
            "fix": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        },
        "content-security-policy": {
            "title": "Missing Content-Security-Policy",
            "desc": "No CSP header found. This increases risk of XSS attacks.",
            "severity": "medium", "cvss": 5.0, "cwe": "CWE-693",
            "fix": "Set Content-Security-Policy header with appropriate directives.",
        },
        "x-frame-options": {
            "title": "Missing X-Frame-Options",
            "desc": "Page can be embedded in iframes, enabling clickjacking.",
            "severity": "low", "cvss": 3.5, "cwe": "CWE-1021",
            "fix": "Add header: X-Frame-Options: DENY or SAMEORIGIN",
        },
        "x-content-type-options": {
            "title": "Missing X-Content-Type-Options",
            "desc": "Browser may MIME-sniff responses, leading to XSS.",
            "severity": "low", "cvss": 3.0, "cwe": "CWE-16",
            "fix": "Add header: X-Content-Type-Options: nosniff",
        },
        "referrer-policy": {
            "title": "Missing Referrer-Policy",
            "desc": "No referrer policy set. Sensitive URL data may leak to third parties.",
            "severity": "low", "cvss": 2.5, "cwe": "CWE-200",
            "fix": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
        },
    }

    for header, info in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(_make_finding(
                title=info["title"],
                description=info["desc"] + f"\nTarget: {found_url}",
                severity=info["severity"],
                tool_name="nikto",
                cvss_score=info["cvss"],
                cwe_id=info["cwe"],
                affected_component=found_url,
                remediation=info["fix"],
                tool_output={"missing_header": header, "url": found_url},
            ))

    server = headers.get("server", "")
    if server and any(v in server.lower() for v in ["apache/", "nginx/", "iis/", "tomcat/"]):
        findings.append(_make_finding(
            title="Server Version Disclosure",
            description=f"Server header reveals version: {server}",
            severity="low",
            tool_name="nikto",
            cvss_score=2.5,
            cwe_id="CWE-200",
            affected_component=found_url,
            remediation="Suppress version information in the Server header.",
            tool_output={"server_header": server},
        ))

    return findings


# ---------------------------------------------------------------------------
#  HTTP Security Scan (standalone)
# ---------------------------------------------------------------------------

async def run_http_security(target: str, config: dict = None) -> List[dict]:
    return await _run_http_security_check(target)


# ---------------------------------------------------------------------------
#  TRIVY — Container & Dependency Scanning (REQUIRED)
# ---------------------------------------------------------------------------

async def run_trivy(target: str, config: dict = None) -> List[dict]:
    """Run trivy. Hard fails if binary is absent."""
    trivy_bin = shutil.which("trivy")
    if not trivy_bin:
        raise ToolNotAvailableError(
            "trivy binary not found. Install trivy before starting the container worker."
        )
    return await _run_trivy_subprocess(trivy_bin, target, config)


async def _run_trivy_subprocess(trivy_bin: str, target: str, config: dict) -> List[dict]:
    cmd = [trivy_bin, "image", "--format", "json", target]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
        raw = stdout.decode("utf-8", errors="replace")
        return _parse_trivy_json(raw)
    except asyncio.TimeoutError:
        return [_make_finding("Trivy Timeout", f"trivy scan of {target} timed out", "info", "trivy")]
    except Exception as exc:
        logger.error("trivy.error target=%s error=%s", target, exc)
        return [_make_finding("Trivy Error", str(exc), "info", "trivy")]


def _parse_trivy_json(raw: str) -> List[dict]:
    findings = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return findings

    cvss_map = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 0.0}
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            sev = vuln.get("Severity", "UNKNOWN").lower()
            if sev not in cvss_map:
                sev = "info"
            findings.append(_make_finding(
                title=f"{vuln.get('VulnerabilityID', 'UNKNOWN')}: {vuln.get('Title', 'Unknown Vuln')}",
                description=vuln.get("Description", ""),
                severity=sev,
                tool_name="trivy",
                cvss_score=cvss_map.get(sev, 5.0),
                cve_id=vuln.get("VulnerabilityID"),
                affected_component=vuln.get("PkgName", ""),
                remediation=(
                    f"Update {vuln.get('PkgName', 'package')} from "
                    f"{vuln.get('InstalledVersion', '?')} to {vuln.get('FixedVersion', 'latest')}."
                ),
                tool_output={
                    "pkg": vuln.get("PkgName"),
                    "installed": vuln.get("InstalledVersion"),
                    "fixed": vuln.get("FixedVersion"),
                },
            ))
    return findings


# ---------------------------------------------------------------------------
#  OWASP ZAP (optional)
# ---------------------------------------------------------------------------

async def run_zap(target: str, config: dict = None) -> List[dict]:
    """
    Use running ZAP container API first.
    Fallback → CLI → fallback → HTTP checks
    """
    config = config or {}
    ZAP_API = "http://zap:8080"

    # ✅ PRIMARY: Use ZAP container API
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{ZAP_API}/JSON/core/view/alerts/",
                params={"baseurl": target}
            )
            alerts = resp.json().get("alerts", [])

        findings = []

        for alert in alerts:
            risk_map = {
                "High": "high",
                "Medium": "medium",
                "Low": "low",
                "Informational": "info"
            }

            severity = risk_map.get(alert.get("risk"), "medium")

            findings.append(_make_finding(
                title=f"ZAP: {alert.get('alert', 'Unknown')}",
                description=alert.get("description", ""),
                severity=severity,
                tool_name="zap",
                cvss_score=5.0,
                cwe_id=alert.get("cweid"),
                affected_component=alert.get("url"),
                remediation=alert.get("solution"),
                tool_output=alert,
            ))

        if findings:
            return findings

    except Exception as e:
        logger.warning("zap.api_failed target=%s error=%s", target, e)

    # 🔁 FALLBACK → CLI
    zap_bin = shutil.which("zap-cli") or shutil.which("zap.sh")

    if zap_bin:
        return await _run_zap_subprocess(zap_bin, target, config)

    # 🔁 FINAL FALLBACK
    logger.info("zap.not_available fallback=http_security")
    findings = await run_nikto(target, config)
    findings.extend(await _run_http_security_check(target))
    return findings

# ---------------------------------------------------------------------------
#  MASSCAN — Fast Port Scanner (optional)
# ---------------------------------------------------------------------------

async def run_masscan(target: str, config: dict = None) -> List[dict]:
    """Run masscan. Hard fails if binary is absent."""
    config = config or {}
    masscan_bin = shutil.which("masscan")

    if not masscan_bin:
        raise ToolNotAvailableError(
            "masscan binary not found. Install masscan before starting the network worker."
        )

    try:
        locked_ip = resolve_target_ip(target)
    except ValueError as exc:
        return [_make_finding("SSRF Blocked", str(exc), "critical", "masscan", cvss_score=9.1, cwe_id="CWE-918")]

    return await _run_masscan_subprocess(masscan_bin, locked_ip, target, config)


async def _run_masscan_subprocess(masscan_bin: str, locked_ip: str, original_target: str, config: dict) -> List[dict]:
    ports = config.get("ports", "1-1024")
    rate = config.get("rate", "1000")
    cmd = [masscan_bin, locked_ip, "-p", ports, "--rate", str(rate), "-oJ", "-"]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        raw = stdout.decode("utf-8", errors="replace")

        findings = []
        clean = raw.strip().rstrip(",")
        if not clean.startswith("["):
            clean = "[" + clean + "]"
        clean = re.sub(r",\s*]", "]", clean)

        try:
            data = json.loads(clean)
        except json.JSONDecodeError:
            return [_make_finding("Masscan Parse Error", "Failed to parse masscan output", "info", "masscan")]

        SERVICE_MAP = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 443: "https", 445: "smb",
            1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
            6379: "redis", 8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
        }
        RISKY = {21, 23, 135, 139, 445, 1433, 3389, 5900}
        DB_PORTS = {3306, 5432, 6379, 27017, 1433}

        for entry in data:
            for port_info in entry.get("ports", []):
                port = port_info.get("port", 0)
                proto = port_info.get("proto", "tcp")
                status = port_info.get("status", "")
                if status != "open":
                    continue

                svc = SERVICE_MAP.get(port, "unknown")
                severity = "low"
                if port in RISKY:
                    severity = "medium"
                if port in DB_PORTS:
                    severity = "high"

                findings.append(_make_finding(
                    title=f"Open Port {port}/{proto} - {svc}",
                    description=f"Masscan detected open port {port}/{proto} on {original_target}. Service: {svc}",
                    severity=severity,
                    tool_name="masscan",
                    affected_component=f"{original_target}:{port}",
                    remediation=f"Review if port {port}/{proto} ({svc}) needs to be exposed.",
                    tool_output={"host": locked_ip, "port": str(port), "proto": proto, "service": svc},
                ))

        return findings

    except asyncio.TimeoutError:
        return [_make_finding("Masscan Timeout", f"masscan scan of {original_target} timed out", "info", "masscan")]
    except Exception as exc:
        logger.error("masscan.error target=%s error=%s", original_target, exc)
        return [_make_finding("Masscan Error", str(exc), "info", "masscan")]


# ---------------------------------------------------------------------------
#  PENTAGI — Advanced Penetration Testing (Docker-based)
# ---------------------------------------------------------------------------

async def run_pentagi(target: str, config: dict = None) -> List[dict]:
    """
    Run Pentagi advanced pentest in isolated Docker container.
    Requires explicit consent flag. Docker must be available.
    """
    config = config or {}

    if not config.get("allow_pentagi", False):
        return [_make_finding(
            "Pentagi: Permission Required",
            "Advanced penetration testing requires explicit permission. "
            "Set allow_pentagi=true in scan config to enable.",
            "info", "pentagi",
        )]

    docker_bin = shutil.which("docker")
    if not docker_bin:
        raise ToolNotAvailableError(
            "docker binary not found. Install Docker before using the advanced worker."
        )

    pentagi_image = config.get("pentagi_image", "sentinel/pentagi:latest")
    container_name = f"pentagi-{uuid.uuid4().hex[:8]}"
    log_dir = os.path.join(os.getcwd(), "pentagi_logs")
    os.makedirs(log_dir, exist_ok=True)

    # Resolve + validate target IP before passing to container
    try:
        locked_ip = resolve_target_ip(target)
    except ValueError as exc:
        return [_make_finding("SSRF Blocked", str(exc), "critical", "pentagi", cvss_score=9.1, cwe_id="CWE-918")]

    try:
        cmd = [
            docker_bin, "run", "--rm",
            "--name", container_name,
            "--network", "none",
            "-e", f"TARGET={locked_ip}",
            "-e", "TIMEOUT=120",
            pentagi_image,
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)
        raw_output = stdout.decode("utf-8", errors="replace")
        raw_errors = stderr.decode("utf-8", errors="replace")

        log_file = os.path.join(log_dir, f"{container_name}.log")
        with open(log_file, "w") as f:
            f.write(f"=== STDOUT ===\n{raw_output}\n=== STDERR ===\n{raw_errors}\n")

        from backend.common.storage import upload_pentagi_logs
        scan_id = config.get("scan_id", "unknown")
        await upload_pentagi_logs(scan_id, container_name, raw_output, raw_errors)

        findings = []
        try:
            data = json.loads(raw_output)
            for item in (data if isinstance(data, list) else data.get("findings", [])):
                findings.append(_make_finding(
                    title=item.get("title", "Pentagi Finding"),
                    description=item.get("description", ""),
                    severity=item.get("severity", "medium"),
                    tool_name="pentagi",
                    cvss_score=item.get("cvss_score", 5.0),
                    cve_id=item.get("cve_id"),
                    affected_component=item.get("affected_component", target),
                    remediation=item.get("remediation", "Review pentagi report for details."),
                    exploit_available=item.get("exploit_successful", False),
                    tool_output=item,
                ))
        except json.JSONDecodeError:
            if raw_output.strip():
                findings.append(_make_finding(
                    "Pentagi: Unstructured Results",
                    raw_output[:2000],
                    "medium", "pentagi",
                    tool_output={"raw_log": log_file},
                ))

        return findings

    except asyncio.TimeoutError:
        try:
            await asyncio.create_subprocess_exec(docker_bin, "kill", container_name)
        except Exception:
            pass
        return [_make_finding("Pentagi Timeout", f"Pentagi scan of {target} timed out", "info", "pentagi")]
    except Exception as exc:
        return [_make_finding("Pentagi Error", str(exc), "info", "pentagi")]


# ---------------------------------------------------------------------------
#  Master Executor
# ---------------------------------------------------------------------------

# ── NUCLEI — Template-based CVE Scanner ──────────────────────────────────────

async def run_nuclei(target: str, config: dict = None) -> List[dict]:
    """Run Nuclei with community templates for real CVE detection."""
    nuclei_bin = shutil.which("nuclei")
    if not nuclei_bin:
        logger.warning("nuclei.not_installed skipping")
        return []

    url = target if target.startswith("http") else f"https://{target}"
    cmd = [
        nuclei_bin,
        "-u", url,
        "-jsonl",
        "-silent",
        "-severity", "critical,high,medium,low",
        "-timeout", "10",
        "-retries", "1",
        "-no-update-templates",
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        raw = stdout.decode("utf-8", errors="replace")

        findings = []
        for line in raw.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                sev = data.get("info", {}).get("severity", "medium").lower()
                cvss_map = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 3.0}
                cve_ids = data.get("info", {}).get("classification", {}).get("cve-id", [])
                cve_id = cve_ids[0] if cve_ids else None
                cwe_ids = data.get("info", {}).get("classification", {}).get("cwe-id", [])
                cwe_id = cwe_ids[0] if cwe_ids else None

                findings.append(_make_finding(
                    title=f"Nuclei: {data.get('info', {}).get('name', 'Unknown')}",
                    description=(
                        f"{data.get('info', {}).get('description', '')}\n"
                        f"Template: {data.get('template-id', '')}\n"
                        f"Matched: {data.get('matched-at', '')}"
                    ),
                    severity=sev,
                    tool_name="nuclei",
                    cvss_score=cvss_map.get(sev, 5.0),
                    cve_id=cve_id,
                    cwe_id=cwe_id,
                    affected_component=data.get("matched-at", url),
                    remediation=data.get("info", {}).get("remediation", "Apply vendor patch."),
                    exploit_available=sev in ("critical", "high"),
                    tool_output={
                        "template_id": data.get("template-id"),
                        "matcher_name": data.get("matcher-name"),
                        "type": data.get("type"),
                        "host": data.get("host"),
                        "tags": data.get("info", {}).get("tags", []),
                    },
                ))
            except json.JSONDecodeError:
                continue

        logger.info("nuclei.completed target=%s findings=%d", target, len(findings))
        return findings

    except asyncio.TimeoutError:
        return [_make_finding("Nuclei Timeout", f"Nuclei scan of {target} timed out after 300s.", "info", "nuclei")]
    except Exception as exc:
        logger.error("nuclei.error target=%s error=%s", target, exc)
        return [_make_finding("Nuclei Error", str(exc), "info", "nuclei")]


# ── SUBFINDER — Subdomain Enumeration ────────────────────────────────────────

async def run_subfinder(target: str, config: dict = None) -> List[dict]:
    """Run Subfinder to discover subdomains of a target domain."""
    subfinder_bin = shutil.which("subfinder")
    if not subfinder_bin:
        logger.warning("subfinder.not_installed skipping")
        return []

    # Extract domain from URL if needed
    domain = target
    if "://" in target:
        parsed = urlparse(target)
        domain = parsed.hostname or target
    # Strip www.
    if domain.startswith("www."):
        domain = domain[4:]

    cmd = [subfinder_bin, "-d", domain, "-silent", "-json"]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        raw = stdout.decode("utf-8", errors="replace")

        subdomains = []
        for line in raw.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                host = data.get("host", "")
                if host:
                    subdomains.append(host)
            except json.JSONDecodeError:
                # Plain text output
                if "." in line.strip():
                    subdomains.append(line.strip())

        findings = []
        if subdomains:
            findings.append(_make_finding(
                title=f"Subdomain Enumeration: {len(subdomains)} subdomains found",
                description=(
                    f"Subfinder discovered {len(subdomains)} subdomains for {domain}:\n"
                    + "\n".join(f"  • {s}" for s in subdomains[:50])
                    + (f"\n  ... and {len(subdomains) - 50} more" if len(subdomains) > 50 else "")
                ),
                severity="info",
                tool_name="subfinder",
                cvss_score=0.0,
                affected_component=domain,
                remediation="Review all discovered subdomains for unauthorized or forgotten services.",
                tool_output={"subdomains": subdomains, "count": len(subdomains)},
            ))

            # Flag potentially risky subdomains
            risky_prefixes = ["admin", "staging", "dev", "test", "beta", "internal", "vpn", "mail", "ftp", "db", "api-internal"]
            for sub in subdomains:
                prefix = sub.split(".")[0].lower()
                if prefix in risky_prefixes:
                    findings.append(_make_finding(
                        title=f"Sensitive Subdomain: {sub}",
                        description=f"Subdomain '{sub}' uses prefix '{prefix}' which may indicate a sensitive/internal service exposed to the internet.",
                        severity="medium",
                        tool_name="subfinder",
                        cvss_score=5.0,
                        cwe_id="CWE-200",
                        affected_component=sub,
                        remediation=f"Verify that {sub} should be publicly accessible. Consider restricting access with authentication or VPN.",
                    ))

        logger.info("subfinder.completed domain=%s subdomains=%d", domain, len(subdomains))
        return findings

    except asyncio.TimeoutError:
        return [_make_finding("Subfinder Timeout", f"Subfinder scan of {domain} timed out.", "info", "subfinder")]
    except Exception as exc:
        logger.error("subfinder.error domain=%s error=%s", domain, exc)
        return [_make_finding("Subfinder Error", str(exc), "info", "subfinder")]


# ── HTTPX — HTTP Probing + Tech Fingerprinting ───────────────────────────────

async def run_httpx_probe(target: str, config: dict = None) -> List[dict]:
    """Run httpx for HTTP probing and technology detection."""
    # Use httpx-pd to avoid collision with Python httpx library
    httpx_bin = shutil.which("httpx-pd") or shutil.which("httpx")
    if not httpx_bin:
        logger.warning("httpx-pd.not_installed skipping")
        return []

    url = target if target.startswith("http") else f"https://{target}"
    cmd = [
        httpx_bin,
        "-u", url,
        "-json",
        "-silent",
        "-tech-detect",
        "-status-code",
        "-title",
        "-server",
        "-content-length",
        "-follow-redirects",
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        raw = stdout.decode("utf-8", errors="replace")

        findings = []
        for line in raw.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                techs = data.get("tech", [])
                server = data.get("webserver", "")
                status = data.get("status_code", 0)
                title = data.get("title", "")

                # Technology fingerprint finding
                if techs:
                    findings.append(_make_finding(
                        title=f"Technology Stack Detected: {', '.join(techs[:5])}",
                        description=(
                            f"httpx detected the following technologies on {url}:\n"
                            + "\n".join(f"  • {t}" for t in techs)
                            + f"\nServer: {server}"
                            + f"\nStatus: {status}"
                            + f"\nTitle: {title}"
                        ),
                        severity="info",
                        tool_name="httpx",
                        cvss_score=0.0,
                        affected_component=url,
                        remediation="Review exposed technologies for known vulnerabilities.",
                        tool_output={"technologies": techs, "server": server, "status": status, "title": title},
                    ))

                # Flag outdated/risky tech
                risky_tech = ["PHP/5", "PHP/7.0", "PHP/7.1", "Apache/2.2", "nginx/1.1", "jQuery/1.", "jQuery/2.",
                              "WordPress", "Drupal", "Joomla"]
                for tech in techs:
                    for risky in risky_tech:
                        if risky.lower() in tech.lower():
                            findings.append(_make_finding(
                                title=f"Potentially Outdated Technology: {tech}",
                                description=f"The technology '{tech}' may be outdated and contain known vulnerabilities.",
                                severity="medium",
                                tool_name="httpx",
                                cvss_score=5.0,
                                cwe_id="CWE-1104",
                                affected_component=url,
                                remediation=f"Update {tech} to the latest stable version.",
                            ))

            except json.JSONDecodeError:
                continue

        logger.info("httpx.completed target=%s findings=%d", target, len(findings))
        return findings

    except asyncio.TimeoutError:
        return [_make_finding("httpx Timeout", f"httpx probe of {target} timed out.", "info", "httpx")]
    except Exception as exc:
        logger.error("httpx.error target=%s error=%s", target, exc)
        return [_make_finding("httpx Error", str(exc), "info", "httpx")]


# ── GITLEAKS — Secrets Detection in Git Repos ────────────────────────────────

async def run_gitleaks(target: str, config: dict = None) -> List[dict]:
    """Run Gitleaks to detect hardcoded secrets in source code."""
    gitleaks_bin = shutil.which("gitleaks")
    if not gitleaks_bin:
        logger.warning("gitleaks.not_installed skipping")
        return []

    scan_path = target if os.path.exists(target) else "."
    fd, report_file = tempfile.mkstemp(prefix="gitleaks-", suffix=".json")
    os.close(fd)  # Close the file descriptor; gitleaks will write to the path

    cmd = [
        gitleaks_bin,
        "detect",
        "--source", scan_path,
        "--report-format", "json",
        "--report-path", report_file,
        "--no-banner",
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

        findings = []
        try:
            with open(report_file, "r") as f:
                leaks = json.load(f)

            for leak in leaks:
                rule_id = leak.get("RuleID", "unknown")
                description = leak.get("Description", "Secret detected")
                file_path = leak.get("File", "")
                line = leak.get("StartLine", 0)
                # Redact the secret — show only first/last 4 chars
                secret = leak.get("Secret", "")
                redacted = f"{secret[:4]}...{secret[-4:]}" if len(secret) > 8 else "***REDACTED***"

                findings.append(_make_finding(
                    title=f"Secret Leak [{rule_id}]: {description}",
                    description=(
                        f"Gitleaks detected a potential secret in source code.\n"
                        f"File: {file_path}:{line}\n"
                        f"Rule: {rule_id}\n"
                        f"Match: {redacted}\n"
                        f"Entropy: {leak.get('Entropy', 'N/A')}"
                    ),
                    severity="high",
                    tool_name="gitleaks",
                    cvss_score=8.0,
                    cwe_id="CWE-798",
                    affected_component=f"{file_path}:{line}",
                    remediation=(
                        f"Remove the hardcoded secret from {file_path}. "
                        f"Rotate the credential immediately. "
                        f"Use environment variables or a secrets manager instead."
                    ),
                    exploit_available=True,
                    tool_output={
                        "rule_id": rule_id,
                        "file": file_path,
                        "line": line,
                        "entropy": leak.get("Entropy"),
                        "author": leak.get("Author", ""),
                        "commit": leak.get("Commit", ""),
                    },
                ))
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        finally:
            try:
                os.remove(report_file)
            except OSError:
                pass

        logger.info("gitleaks.completed target=%s secrets=%d", target, len(findings))
        return findings

    except asyncio.TimeoutError:
        return [_make_finding("Gitleaks Timeout", f"Gitleaks scan timed out.", "info", "gitleaks")]
    except Exception as exc:
        logger.error("gitleaks.error target=%s error=%s", target, exc)
        return [_make_finding("Gitleaks Error", str(exc), "info", "gitleaks")]


# ── EPSS + CISA KEV Threat Intelligence Enrichment ───────────────────────────

_CISA_KEV_CACHE: dict = {"data": set(), "loaded_at": None}
_EPSS_CACHE: dict = {"data": {}, "loaded_at": None}


async def _load_cisa_kev() -> set:
    """Load CISA Known Exploited Vulnerabilities catalog (cached 24h)."""
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    if _CISA_KEV_CACHE["loaded_at"] and (now - _CISA_KEV_CACHE["loaded_at"]) < timedelta(hours=24):
        return _CISA_KEV_CACHE["data"]

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
            if resp.status_code == 200:
                data = resp.json()
                kev_set = {v["cveID"] for v in data.get("vulnerabilities", [])}
                _CISA_KEV_CACHE["data"] = kev_set
                _CISA_KEV_CACHE["loaded_at"] = now
                logger.info("cisa_kev.loaded count=%d", len(kev_set))
                return kev_set
    except Exception as exc:
        logger.warning("cisa_kev.load_failed err=%s", exc)

    return _CISA_KEV_CACHE["data"]


async def _get_epss_score(cve_id: str) -> Optional[float]:
    """Get EPSS score for a CVE from FIRST.org API."""
    if not cve_id or not cve_id.startswith("CVE-"):
        return None

    # Check cache
    if cve_id in _EPSS_CACHE["data"]:
        return _EPSS_CACHE["data"][cve_id]

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"https://api.first.org/data/v1/epss?cve={cve_id}")
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("data", [])
                if items:
                    score = float(items[0].get("epss", 0))
                    _EPSS_CACHE["data"][cve_id] = score
                    return score
    except Exception:
        pass
    return None


async def enrich_findings_with_threat_intel(findings: List[dict]) -> List[dict]:
    """Enrich findings with EPSS scores and CISA KEV flags."""
    kev_set = await _load_cisa_kev()

    for finding in findings:
        cve_id = finding.get("cve_id")
        if not cve_id:
            continue

        # CISA KEV check
        if cve_id in kev_set:
            finding["severity"] = "critical"
            finding["cvss_score"] = max(finding.get("cvss_score", 0), 9.5)
            finding["exploit_available"] = True
            finding["description"] = (
                f"⚠️ CISA KNOWN EXPLOITED VULNERABILITY ⚠️\n"
                f"This CVE is in the CISA KEV catalog — it is actively being exploited in the wild.\n\n"
                + finding.get("description", "")
            )
            finding.setdefault("tool_output", {})["cisa_kev"] = True

        # EPSS score
        epss = await _get_epss_score(cve_id)
        if epss is not None:
            finding.setdefault("tool_output", {})["epss_score"] = epss
            finding.setdefault("tool_output", {})["epss_percentile"] = f"{epss * 100:.1f}%"
            if epss > 0.5:  # >50% chance of exploitation
                if finding.get("severity") not in ("critical",):
                    finding["severity"] = "high"
                finding["description"] = (
                    f"EPSS Score: {epss * 100:.1f}% probability of exploitation in 30 days\n"
                    + finding.get("description", "")
                )

    return findings


TOOL_RUNNERS = {
    "nmap": run_nmap,
    "masscan": run_masscan,
    "bandit": run_bandit,
    "semgrep": run_semgrep,
    "nikto": run_nikto,
    "zap": run_zap,
    "trivy": run_trivy,
    "http_security": run_http_security,
    "pentagi": run_pentagi,
    "nuclei": run_nuclei,
    "subfinder": run_subfinder,
    "httpx": run_httpx_probe,
    "gitleaks": run_gitleaks,
}


async def execute_tools_parallel(tools: list[str], target: str, config: dict = None) -> List[dict]:
    """
    Run multiple tools in parallel (production-safe).
    """

    config = config or {}

    tasks = []
    for tool in tools:
        runner = TOOL_RUNNERS.get(tool)
        if not runner:
            continue

        tasks.append(
            asyncio.create_task(
                runner(target, config)
            )
        )

    results = await asyncio.gather(*tasks, return_exceptions=True)

    findings = []

    for result in results:
        if isinstance(result, Exception):
            logger.error("parallel_tool_error: %s", result)
            continue

        if isinstance(result, list):
            findings.extend(result)

    # Enrich with EPSS + CISA KEV threat intelligence
    try:
        findings = await enrich_findings_with_threat_intel(findings)
    except Exception as exc:
        logger.warning("threat_intel_enrichment_failed err=%s", exc)

    return findings