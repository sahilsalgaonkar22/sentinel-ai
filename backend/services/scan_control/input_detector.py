"""
SENTINEL AI — Input Detection Engine
Classifies user-provided targets and routes to appropriate security tools.
"""
import re
import os
import ipaddress
from enum import Enum
from typing import List


class InputType(str, Enum):
    NETWORK_IP = "network_ip"
    DOMAIN = "domain"
    WEB_URL = "web_url"
    GIT_REPO = "git_repo"
    LOCAL_PATH = "local_path"
    DOCKER_IMAGE = "docker_image"
    UNKNOWN = "unknown"


# Tool routing map: input type -> list of tools to run
TOOL_ROUTING = {
    InputType.NETWORK_IP:   ["masscan", "nmap", "nikto"],
    InputType.DOMAIN:       ["subfinder", "httpx", "nmap", "nikto", "nuclei"],
    InputType.WEB_URL:      ["httpx", "nuclei", "nikto", "http_security"],
    InputType.GIT_REPO:     ["gitleaks", "bandit", "semgrep"],
    InputType.LOCAL_PATH:   ["gitleaks", "bandit", "semgrep"],
    InputType.DOCKER_IMAGE: ["trivy"],
    InputType.UNKNOWN:      ["nmap"],
}



def detect_input_type(target: str) -> InputType:
    """
    Classify a target string into an InputType.

    Rules (checked in order):
      1. Valid IPv4/IPv6 address -> NETWORK_IP
      2. Local filesystem path that exists -> LOCAL_PATH
      3. GitHub/GitLab/Bitbucket URL -> GIT_REPO
      4. HTTP(S) URL -> WEB_URL
      5. Docker image pattern (name:tag or registry/name) -> DOCKER_IMAGE
      6. Domain-like string (has dots, no spaces) -> DOMAIN
      7. Fallback -> UNKNOWN
    """
    target = target.strip()
    if not target:
        return InputType.UNKNOWN

    # 1. Check for IP address
    try:
        ipaddress.ip_address(target)
        return InputType.NETWORK_IP
    except ValueError:
        pass

    # Also handle IP:port like 192.168.1.1:8080
    ip_port = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?$', target)
    if ip_port:
        try:
            ipaddress.ip_address(ip_port.group(1))
            return InputType.NETWORK_IP
        except ValueError:
            pass

    # 2. Local filesystem path
    if os.path.exists(target):
        return InputType.LOCAL_PATH

    # Also accept common path patterns even if not existing yet
    if target.startswith(("./", "../", "/", "C:\\", "D:\\")) and not target.startswith("http"):
        return InputType.LOCAL_PATH

    # 3. Git repository URL
    git_patterns = [
        r'github\.com', r'gitlab\.com', r'bitbucket\.org',
        r'\.git$', r'git@', r'git://',
    ]
    for pattern in git_patterns:
        if re.search(pattern, target, re.IGNORECASE):
            return InputType.GIT_REPO

    # 4. HTTP/HTTPS URL
    if re.match(r'^https?://', target, re.IGNORECASE):
        return InputType.WEB_URL

    # 5. Docker image pattern: name:tag or registry/name:tag
    docker_pattern = re.match(
        r'^(?:[\w.-]+/)?[\w.-]+(?::[\w.-]+)?$', target
    )
    if docker_pattern and ('/' in target or ':' in target):
        # Distinguish from plain domains by checking for docker-like patterns
        if ':' in target and not target.endswith(('.com', '.org', '.net', '.io')):
            return InputType.DOCKER_IMAGE
        if '/' in target and not '.' in target.split('/')[0]:
            return InputType.DOCKER_IMAGE

    # 6. Domain-like
    domain_pattern = re.match(
        r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', target
    )
    if domain_pattern:
        return InputType.DOMAIN

    # 7. Fallback
    return InputType.UNKNOWN


def get_tools_for_target(target: str) -> tuple:
    """Returns (input_type, tools_list) for a given target string."""
    input_type = detect_input_type(target)
    tools = TOOL_ROUTING.get(input_type, ["nmap"])
    return input_type, tools


def get_scan_type_for_input(input_type: InputType) -> str:
    """Map input type to scan_type enum value."""
    mapping = {
        InputType.NETWORK_IP: "network",
        InputType.DOMAIN: "network",
        InputType.WEB_URL: "web",
        InputType.GIT_REPO: "code",
        InputType.LOCAL_PATH: "code",
        InputType.DOCKER_IMAGE: "container",
        InputType.UNKNOWN: "full",
    }
    return mapping.get(input_type, "full")
