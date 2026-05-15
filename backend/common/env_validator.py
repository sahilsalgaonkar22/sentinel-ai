"""
SENTINEL AI — Production Environment Validator
===============================================

Validates ALL required environment variables before the application
initializes ANY other module. Enforces:

  - No missing variables
  - No placeholder values ("REPLACE_WITH*")
  - Minimum entropy on secrets (JWT ≥ 64 chars, passwords ≥ 16 chars)
  - Cross-service consistency (DB password == POSTGRES_PASSWORD,
    Redis URL password == REDIS_PASSWORD)
  - Wildcard CORS is never permitted
  - Secrets are NEVER printed in full — only masked prefixes

Fail-fast design: any violation → structured error → sys.exit(1)
"""
from __future__ import annotations

import os
import re
import sys
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional
from urllib.parse import urlparse, unquote

logger = logging.getLogger(__name__)

# ── Sentinel markers ──────────────────────────────────────────────────────────
_PLACEHOLDER_PATTERNS = [
    "REPLACE_WITH",
    "YOUR_",
    "CHANGEME",
    "CHANGE_ME",
    "TODO",
    "FIXME",
    "<YOUR",
    "example.com",   # domain placeholder in JWT/secrets
]

_WEAK_SECRETS = {
    "", "secret", "password", "changeme", "test", "dev",
    "sentinel", "admin", "1234", "local", "docker",
}


# ── Result containers ─────────────────────────────────────────────────────────

@dataclass
class ValidationError:
    var: str
    reason: str


@dataclass
class ValidationResult:
    errors: List[ValidationError] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return len(self.errors) == 0

    def add_error(self, var: str, reason: str) -> None:
        self.errors.append(ValidationError(var=var, reason=reason))

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)


# ── Masking helpers ───────────────────────────────────────────────────────────

def _mask(value: str, reveal: int = 4) -> str:
    """Show only the first `reveal` chars; mask the rest. Never exposes full secret."""
    if not value:
        return "<empty>"
    if len(value) <= reveal:
        return "*" * len(value)
    return value[:reveal] + "*" * (len(value) - reveal)


def _mask_url(url: str) -> str:
    """Mask the password component of a URL, leaving schema/host/path visible."""
    try:
        parsed = urlparse(url)
        if parsed.password:
            masked = url.replace(f":{parsed.password}@", f":{_mask(parsed.password)}@")
            return masked
    except Exception:
        pass
    return url


# ── Individual validators ─────────────────────────────────────────────────────

def _check_required(result: ValidationResult, var: str) -> Optional[str]:
    """Return value if present and non-empty, otherwise record error."""
    value = os.environ.get(var, "").strip()
    if not value:
        result.add_error(var, "Required variable is not set or empty")
        return None
    return value


def _check_placeholder(result: ValidationResult, var: str, value: str) -> bool:
    """Fail if the value looks like a placeholder."""
    upper = value.upper()
    for pattern in _PLACEHOLDER_PATTERNS:
        if pattern.upper() in upper:
            result.add_error(
                var,
                f"Value contains placeholder text '{pattern}'. "
                "Set a real value before starting the application."
            )
            return False
    return True


def _check_min_length(
    result: ValidationResult, var: str, value: str, min_len: int, label: str = "chars"
) -> bool:
    if len(value) < min_len:
        result.add_error(
            var,
            f"Too short: {len(value)} {label} (minimum {min_len}). "
            f"Current value starts with: {_mask(value)}"
        )
        return False
    return True


def _check_not_weak(result: ValidationResult, var: str, value: str) -> bool:
    if value.lower() in _WEAK_SECRETS:
        result.add_error(var, f"Value is a well-known weak secret: '{value[:8]}…'")
        return False
    return True


# ── Cross-service consistency ─────────────────────────────────────────────────

def _extract_url_password(url: str) -> Optional[str]:
    """Extract password component from a URL string."""
    try:
        parsed = urlparse(url)
        if parsed.password:
            return unquote(parsed.password)
    except Exception:
        pass
    return None


def _check_db_consistency(result: ValidationResult) -> None:
    """DATABASE_URL password must match POSTGRES_PASSWORD."""
    db_url = os.environ.get("DATABASE_URL", "")
    pg_pass = os.environ.get("POSTGRES_PASSWORD", "")
    if not db_url or not pg_pass:
        return  # handled by required-field checks

    url_pass = _extract_url_password(db_url)
    if url_pass is None:
        result.add_error(
            "DATABASE_URL",
            "URL does not contain a password component. "
            "Format: postgresql+asyncpg://user:PASSWORD@host:5432/db"
        )
        return

    if url_pass != pg_pass:
        result.add_error(
            "DATABASE_URL",
            f"Password in DATABASE_URL ({_mask(url_pass)}) does not match "
            f"POSTGRES_PASSWORD ({_mask(pg_pass)}). "
            "These must be identical."
        )


def _check_redis_consistency(result: ValidationResult) -> None:
    """REDIS_URL password must match REDIS_PASSWORD."""
    redis_url = os.environ.get("REDIS_URL", "")
    redis_pass = os.environ.get("REDIS_PASSWORD", "")
    if not redis_url or not redis_pass:
        return

    url_pass = _extract_url_password(redis_url)
    if url_pass is None:
        result.add_error(
            "REDIS_URL",
            "REDIS_URL does not contain a password component. "
            "Format: redis://:PASSWORD@redis:6379/0"
        )
        return

    if url_pass != redis_pass:
        result.add_error(
            "REDIS_URL",
            f"Password in REDIS_URL ({_mask(url_pass)}) does not match "
            f"REDIS_PASSWORD ({_mask(redis_pass)}). "
            "These must be identical."
        )


def _check_cors(result: ValidationResult) -> None:
    """CORS origins must be set and contain no wildcards."""
    value = os.environ.get("CORS_ALLOWED_ORIGINS", "")
    if not value:
        result.add_error("CORS_ALLOWED_ORIGINS", "Must be set (e.g. https://app.yourdomain.com)")
        return
    origins = [o.strip() for o in value.split(",") if o.strip()]
    for o in origins:
        if o == "*":
            result.add_error(
                "CORS_ALLOWED_ORIGINS",
                "Wildcard '*' is never allowed in production. "
                "Specify explicit origins."
            )
        elif not o.startswith("https://"):
            result.add_warning(
                f"CORS origin '{o}' does not use HTTPS. "
                "Only HTTPS origins should be allowed in production."
            )


def _check_database_url(result: ValidationResult) -> None:
    db_url = os.environ.get("DATABASE_URL", "")
    if not db_url:
        return  # caught by required-field check
    if "sqlite" in db_url.lower():
        result.add_error("DATABASE_URL", "SQLite is not allowed. Use PostgreSQL.")
    if not db_url.startswith(("postgresql+asyncpg://", "postgresql+psycopg://", "postgresql://", "postgres://")):
        result.add_error(
            "DATABASE_URL",
            f"Must be a PostgreSQL URL (postgresql+psycopg://...). Got: {db_url[:30]}…"
        )


def _check_production_hostnames(result: ValidationResult) -> None:
    """Warn if default development hostnames are used."""
    dev_hosts = {"localhost", "127.0.0.1", "0.0.0.0"}
    for var in ("REDIS_URL", "DATABASE_URL", "KAFKA_BOOTSTRAP_SERVERS"):
        value = os.environ.get(var, "")
        for h in dev_hosts:
            if h in value:
                result.add_warning(
                    f"{var} contains development hostname '{h}'. "
                    "Verify this is intentional in production."
                )


# ── Required variable spec ────────────────────────────────────────────────────

@dataclass
class VarSpec:
    name: str
    min_length: int = 0
    check_weak: bool = False
    optional: bool = False
    description: str = ""


REQUIRED_VARS: List[VarSpec] = [
    VarSpec("POSTGRES_PASSWORD",      min_length=16, check_weak=True,
            description="PostgreSQL superuser password"),
    VarSpec("JWT_SECRET",             min_length=64, check_weak=True,
            description="JWT signing key (256-bit, hex). Generate: openssl rand -hex 32"),
    VarSpec("SECRET_KEY",             min_length=64, check_weak=True,
            description="Application secret key (256-bit, hex). Generate: openssl rand -hex 32"),
    VarSpec("REDIS_PASSWORD",         min_length=16, check_weak=True,
            description="Redis authentication password"),
    VarSpec("REDIS_URL",              min_length=10,
            description="Redis connection URL with password (redis://:password@host:6379/0)"),
    VarSpec("KAFKA_SASL_USERNAME",    min_length=3, optional=True,
        description="Kafka SASL username (optional in dev)"),
VarSpec("KAFKA_SASL_PASSWORD",    min_length=16, check_weak=True, optional=True,
        description="Kafka SASL password (optional in dev)"),
    VarSpec("KAFKA_BOOTSTRAP_SERVERS", min_length=5,
            description="Kafka broker addresses (host:port)"),
    VarSpec("DATABASE_URL",           min_length=20,
            description="PostgreSQL async connection URL"),
    VarSpec("CORS_ALLOWED_ORIGINS",   min_length=8,
            description="Comma-separated HTTPS frontend origins"),
    VarSpec("S3_ACCESS_KEY",          min_length=8,
            description="MinIO/S3 access key ID"),
    VarSpec("S3_SECRET_KEY",          min_length=16, check_weak=True,
            description="MinIO/S3 secret key"),
    # LLM_API_KEY is optional — system degrades gracefully without AI features
    VarSpec("LLM_API_KEY",            optional=True,
            description="LLM API key (optional; AI features disabled if absent)"),
]


# ── Main validation entry point ───────────────────────────────────────────────

def validate_environment(strict: bool = True) -> ValidationResult:
    """
    Run all environment variable validations.

    Args:
        strict: If True (default), optional vars with placeholder values still fail.

    Returns:
        ValidationResult with .ok == True if all required vars pass.
    """
    result = ValidationResult()

    # 1. Check each required variable
    for spec in REQUIRED_VARS:
        value = os.environ.get(spec.name, "").strip()

        # Existence check
        if not value:
            if spec.optional:
                result.add_warning(f"{spec.name} is not set — {spec.description} (optional)")
                continue
            result.add_error(spec.name, f"Required but not set. {spec.description}")
            continue

        # Placeholder check (applies to required AND optional)
        if not _check_placeholder(result, spec.name, value):
            continue  # further checks meaningless if it's a placeholder

        # Min length
        if spec.min_length > 0:
            _check_min_length(result, spec.name, value, spec.min_length)

        # Weak value check
        if spec.check_weak:
            _check_not_weak(result, spec.name, value)

    # 2. Structural validators
    _check_database_url(result)
    _check_cors(result)

    # 3. Cross-service consistency
    _check_db_consistency(result)
    _check_redis_consistency(result)

    # 4. Hostname warnings (production awareness)
    _check_production_hostnames(result)

    return result


def enforce_environment() -> None:
    """
    Run validation and crash immediately on any failure.

    Call this as the VERY FIRST thing in any entrypoint before importing
    application modules. This prevents secrets-less containers from silently
    starting with broken configurations.
    """
    result = validate_environment()

    # Always emit warnings
    for w in result.warnings:
        logger.warning("env.warning: %s", w)

    if result.ok:
        logger.info(
            "env.validation_passed vars_checked=%d warnings=%d",
            len(REQUIRED_VARS), len(result.warnings)
        )
        return

    # Build structured failure output
    lines = [
        "",
        "=" * 72,
        "  ⛔  SENTINEL AI — STARTUP BLOCKED: Invalid Environment",
        "=" * 72,
        f"  {len(result.errors)} error(s) must be resolved before the app can start.",
        "",
    ]
    for i, err in enumerate(result.errors, 1):
        lines.append(f"  [{i}] {err.var}")
        lines.append(f"       → {err.reason}")
        lines.append("")

    lines += [
        "  Quick fix:",
        "    cp .env.example .env",
        "    # Fill in real secrets",
        "    python scripts/check_env.py   # verify before starting",
        "",
        "  Generate secure secrets:",
        "    JWT_SECRET:        openssl rand -hex 32",
        "    SECRET_KEY:        openssl rand -hex 32",
        "    POSTGRES_PASSWORD: openssl rand -hex 16",
        "    REDIS_PASSWORD:    openssl rand -hex 16",
        "    KAFKA_SASL_PASSWORD: openssl rand -hex 16",
        "=" * 72,
        "",
    ]

    msg = "\n".join(lines)
    # Print to stderr (never to log — avoids partial-secret leakage in log aggregators)
    print(msg, file=sys.stderr)
    sys.exit(1)
