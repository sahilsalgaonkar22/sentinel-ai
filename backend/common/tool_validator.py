"""
SENTINEL AI — Tool Availability Validator

PRODUCTION CONTRACT:
- validate_tools_or_die() MUST be called at worker startup.
- Any required binary that is missing causes a hard RuntimeError → worker crashes immediately.
- FALLBACK mode is REMOVED. Workers that cannot find their binary do NOT start.
- Exposed via /health/tools on the gateway for observability.
"""
import shutil
import subprocess
import sys
from typing import Dict, Tuple
import logging

logger = logging.getLogger(__name__)


# Each tool specifies which worker category requires it (required=True → hard fail if absent)
TOOL_CHECKS = {
    "nmap": {
        "binary": "nmap",
        "version_args": ["--version"],
        "check_output": "Nmap",
        "category": "network",
        "required": True,
    },
    "masscan": {
        "binary": "masscan",
        "version_args": ["--version"],
        "check_output": "masscan",
        "category": "network",
        "required": False,   # Optional: nmap covers the gap
    },
    "nikto": {
        "binary": "nikto",
        "version_args": ["-Version"],
        "check_output": "Nikto",
        "category": "web",
        "required": False,   # HTTP-native fallback exists for web headers
    },
    "bandit": {
        "binary": "bandit",
        "version_args": ["--version"],
        "check_output": "bandit",
        "category": "code",
        "required": True,
    },
    "semgrep": {
        "binary": "semgrep",
        "version_args": ["--version"],
        "check_output": "",
        "category": "code",
        "required": False,
    },
    "trivy": {
        "binary": "trivy",
        "version_args": ["--version"],
        "check_output": "Version",
        "category": "container",
        "required": True,
    },
    "docker": {
        "binary": "docker",
        "version_args": ["--version"],
        "check_output": "Docker",
        "category": "advanced",
        # FIX-4: Docker socket removed from advanced worker pod (k8s/workers.yaml).
        # Advanced scanning now uses PENTAGI_REMOTE_API instead of local Docker.
        # Setting required=False prevents startup crash on advanced worker.
        "required": False,
    },
    "nuclei": {
        "binary": "nuclei",
        "version_args": ["-version"],
        "check_output": "nuclei",
        "category": "web",
        "required": False,
    },
    "subfinder": {
        "binary": "subfinder",
        "version_args": ["-version"],
        "check_output": "subfinder",
        "category": "network",
        "required": False,
    },
    "httpx-pd": {
        "binary": "httpx-pd",
        "version_args": ["-version"],
        "check_output": "",
        "category": "web",
        "required": False,
    },
    "gitleaks": {
        "binary": "gitleaks",
        "version_args": ["version"],
        "check_output": "gitleaks",
        "category": "code",
        "required": False,
    },
}


def _check_binary(binary: str) -> Tuple[bool, str]:
    """Returns (found, version_string)."""
    path = shutil.which(binary)
    if not path:
        return False, ""
    try:
        result = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        version = (result.stdout + result.stderr).strip().split("\n")[0]
        return True, version
    except Exception:
        return True, "(version check failed)"


# Cached results after startup validation
_tool_status: Dict[str, dict] = {}


def validate_tools(worker_category: str = "all") -> Dict[str, dict]:
    """
    Run tool availability checks and cache results.

    For required tools: raises RuntimeError if binary is missing.
    Called once at worker startup.
    """
    global _tool_status
    _tool_status = {}

    missing_required = []
    logger.info("tool_validator.start category=%s", worker_category)

    for tool_name, cfg in TOOL_CHECKS.items():
        if worker_category != "all" and cfg["category"] != worker_category:
            continue

        found, version = _check_binary(cfg["binary"])
        binary_path = shutil.which(cfg["binary"]) or "NOT FOUND"
        is_required = cfg.get("required", False)

        _tool_status[tool_name] = {
            "available": found,
            "version": version,
            "binary": binary_path,
            "category": cfg["category"],
            "required": is_required,
        }

        if found:
            logger.info("tool_validator.ok tool=%s path=%s version=%s", tool_name, binary_path, version[:80])
        else:
            if is_required:
                missing_required.append(tool_name)
                logger.critical("tool_validator.MISSING_REQUIRED tool=%s category=%s", tool_name, cfg["category"])
            else:
                logger.warning("tool_validator.missing_optional tool=%s", tool_name)

    if missing_required:
        raise RuntimeError(
            f"[TOOL_VALIDATOR] STARTUP FAILED — required tools are missing: {missing_required}\n"
            f"Install them before starting the worker. "
            f"See docker/Dockerfile.worker for installation instructions."
        )

    available_count = sum(1 for t in _tool_status.values() if t["available"])
    total = len(_tool_status)
    logger.info("tool_validator.complete available=%d/%d", available_count, total)
    return _tool_status


def validate_tools_or_die(worker_category: str = "all") -> None:
    """
    Convenience wrapper: validates tools and exits the process if any required tool is missing.
    Call this as the first thing in a worker's main() / __main__ block.
    """
    try:
        validate_tools(worker_category)
    except RuntimeError as exc:
        logger.critical("%s", exc)
        sys.exit(1)


def get_tool_status() -> Dict[str, dict]:
    """Return cached tool status (populated at startup)."""
    return _tool_status


def is_tool_available(tool_name: str) -> bool:
    """Check if a specific tool binary is available (from startup cache)."""
    status = _tool_status.get(tool_name)
    if status is not None:
        return status["available"]
    # Not pre-validated — check now (not cached)
    return shutil.which(tool_name) is not None


def get_tool_report() -> dict:
    """Structured report for /health/tools endpoint."""
    real = [t for t, s in _tool_status.items() if s["available"]]
    missing = [t for t, s in _tool_status.items() if not s["available"]]
    missing_required = [t for t, s in _tool_status.items() if not s["available"] and s.get("required")]

    return {
        "available_tools": real,
        "missing_tools": missing,
        "missing_required": missing_required,
        "available_count": len(real),
        "missing_count": len(missing),
        "tools": _tool_status,
        "production_ready": len(missing_required) == 0,
    }
