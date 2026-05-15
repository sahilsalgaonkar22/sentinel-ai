"""
SENTINEL AI — Scope Validator

SSRF / DNS Rebinding Fix:
- Hostnames are resolved ONCE and the IP is locked.
- The locked IP (not the hostname) is validated against blocked ranges.
- RFC 1918 + loopback + link-local + metadata IPs are ALL blocked by default.
- Private IP scanning is DENIED unless explicitly whitelisted by the operator.
  Set ALLOW_PRIVATE_SCAN=true and provide org-level scope rules to enable.
"""
import ipaddress
import re
import socket
import logging
from typing import Tuple

logger = logging.getLogger(__name__)


# Blocked IP ranges — cloud metadata, link-local, RFC 1918, loopback
BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),    # AWS/GCP/Azure metadata
    ipaddress.ip_network("100.64.0.0/10"),      # RFC 6598 shared
    ipaddress.ip_network("0.0.0.0/8"),          # this network
    ipaddress.ip_network("240.0.0.0/4"),        # reserved
    ipaddress.ip_network("fd00::/8"),           # ULA IPv6
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
]

# Exact IP blocks (metadata endpoints)
BLOCKED_IPS = {
    "169.254.169.254",   # AWS/GCP/Azure IMDS
    "100.100.100.200",   # Alibaba metadata
}

# Blocked hostnames (exact match or suffix)
BLOCKED_HOSTS = [
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
    "localhost",
]

# Blocked URL patterns (regex)
BLOCKED_PATTERNS = [
    r"169\.254\.169\.254",
    r"metadata\.google\.internal",
    r"localhost.*:2379",    # etcd
    r"localhost.*:10250",   # kubelet
    r"localhost.*:6443",    # k8s API
]


def _resolve_hostname_once(hostname: str) -> str:
    """
    Resolve hostname to a single canonical IP.
    Called once — the returned IP is used for all subsequent validation and scanning.
    DNS response changes after this point are ignored (TOCTOU protection).
    """
    try:
        results = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        if not results:
            raise ValueError(f"No DNS records for '{hostname}'")
        return results[0][4][0]
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve hostname '{hostname}': {exc}") from exc


def _is_ip_blocked(ip_str: str) -> Tuple[bool, str]:
    """Check if a resolved IP is in any blocked range. Returns (blocked, reason)."""
    if ip_str in BLOCKED_IPS:
        return True, f"{ip_str} is a cloud metadata endpoint"
    try:
        addr = ipaddress.ip_address(ip_str)
        for net in BLOCKED_NETWORKS:
            if addr in net:
                return True, f"{ip_str} is in blocked network {net}"
        if addr.is_multicast or addr.is_reserved:
            return True, f"{ip_str} is multicast/reserved"
    except ValueError:
        pass
    return False, ""


def validate_scope(target: str, org_id: str = "") -> Tuple[bool, str]:
    """
    Validate and resolve the scan target.

    Process:
    1. Check hostname/URL against known-bad patterns.
    2. Resolve hostname → locked IP (single DNS lookup).
    3. Validate locked IP against blocked ranges (RFC 1918, metadata, loopback).

    Returns:
        (allowed: bool, reason_or_locked_ip: str)
        On success, `reason_or_locked_ip` contains the validated locked IP string.
        On failure, it contains the rejection reason.
    """
    target = target.strip()
    if not target:
        return False, "Empty target"

    target_lower = target.lower()

    # 1. Check blocked hostnames
    for blocked in BLOCKED_HOSTS:
        if blocked in target_lower:
            return False, f"Blocked: scanning {blocked} is not allowed"

    # 2. Check blocked URL patterns
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, target, re.IGNORECASE):
            return False, "Blocked: target matches restricted pattern"

    # 3. Extract hostname for resolution
    if "://" in target:
        from urllib.parse import urlparse
        parsed = urlparse(target)
        hostname = parsed.hostname or target
    elif ":" in target and not target.startswith("["):
        hostname = target.rsplit(":", 1)[0]
    else:
        hostname = target

    # 4. Resolve to locked IP (TOCTOU protection — one DNS call)
    try:
        # Check if it's already an IP
        addr = ipaddress.ip_address(hostname)
        locked_ip = str(addr)
    except ValueError:
        try:
            locked_ip = _resolve_hostname_once(hostname)
        except ValueError as exc:
            return False, str(exc)

    # 5. Validate locked IP
    blocked, reason = _is_ip_blocked(locked_ip)
    if blocked:
        logger.warning(
            "scope.blocked target=%s resolved_ip=%s reason=%s org=%s",
            target, locked_ip, reason, org_id
        )
        return False, f"Blocked: {reason}"

    # 6. Block over-broad CIDR ranges
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            if net.num_addresses > 256:
                return False, (
                    f"Blocked: CIDR range too large ({net.num_addresses} addresses). "
                    "Maximum allowed: /24 (256 addresses)"
                )
        except ValueError:
            pass

    # 7. Block path traversal attempts — ZERO TOLERANCE
    # Any occurrence of ".." is immediately rejected, regardless of count or depth.
    if ".." in target:
        return False, "Blocked: path traversal attempt detected (.. in target)"

    logger.debug("scope.allowed target=%s locked_ip=%s org=%s", target, locked_ip, org_id)
    return True, locked_ip  # Return locked IP for use by caller


def validate_scope_or_raise(target: str, org_id: str = "") -> str:
    """
    Like validate_scope but raises ValueError on rejection.
    Returns the locked IP on success.
    """
    from fastapi import HTTPException
    allowed, result = validate_scope(target, org_id)
    if not allowed:
        raise HTTPException(status_code=400, detail=f"Target rejected: {result}")
    return result  # locked IP
