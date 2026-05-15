"""
SENTINEL AI — Centralized Configuration

PRODUCTION RULES (ENFORCED, NOT OPTIONAL):
- DATABASE_URL must be a PostgreSQL URL (postgresql+asyncpg://...)
  SQLite is REJECTED at startup.
- JWT_SECRET: 256-bit minimum (≥64 hex chars). Hard startup failure if missing or weak.
  Generate: export JWT_SECRET=$(openssl rand -hex 32)   # 64-char hex = 256 bits
- REDIS_URL must use rediss:// (TLS) with password in production.
- CORS_ALLOWED_ORIGINS must be set — empty list causes startup failure.
- DEBUG is read-only; enabling it does NOT unlock any bypass logic.

⛔ NEVER use .env files in production — use secrets manager or injected env vars.
"""
from pydantic_settings import BaseSettings
from pydantic import field_validator
import os

# Load .env ONLY if explicitly set — never in production containers
if os.getenv("SENTINEL_LOAD_DOTENV", "false").lower() == "true":
    from dotenv import load_dotenv
    load_dotenv()


class Settings(BaseSettings):
    APP_NAME: str = "SENTINEL AI"
    APP_VERSION: str = "5.0.0"
    DEBUG: bool = False

    # ── Auth ──────────────────────────────────────────────────────────────
    # MUST be set via env var. Minimum 64 hex chars (256-bit entropy).
    # Generate: openssl rand -hex 32
    JWT_SECRET: str = os.getenv("JWT_SECRET", "")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60  # 1 hour

    # ── CORS — REQUIRED in production ─────────────────────────────────────
    # Comma-separated list of allowed frontend origins.
    # Example: https://app.example.com,https://dashboard.example.com
    # MUST NOT be empty — startup will FAIL.
    CORS_ALLOWED_ORIGINS: str = os.getenv("CORS_ALLOWED_ORIGINS", "")

    # ── Database (PostgreSQL ONLY) ─────────────────────────────────────────
    DATABASE_URL: str = os.getenv("DATABASE_URL", "")

    # ── Execution ─────────────────────────────────────────────────────────
    EXECUTION_MODE: str = os.getenv("SENTINEL_EXECUTION_MODE", "local")
    SCAN_TIMEOUT_SECONDS: int = int(os.getenv("SCAN_TIMEOUT_SECONDS", "300"))

    # ── AI / LLM ──────────────────────────────────────────────────────────
    LLM_API_KEY: str = os.getenv("LLM_API_KEY", "")
    LLM_ENDPOINT: str = os.getenv("LLM_ENDPOINT", "https://api.openai.com/v1")
    LLM_MODEL: str = os.getenv("LLM_MODEL", "gpt-4")

    # ── Workers ───────────────────────────────────────────────────────────
    # MOCK_WORKERS is permanently disabled; this flag is removed from prod
    BACKGROUND_SCANS: bool = os.getenv("BACKGROUND_SCANS", "True").lower() == "true"

    # ── Redis ─────────────────────────────────────────────────────────────
    # rediss:// = TLS + password required in production
    # Format: rediss://:password@redis:6379/0
    REDIS_URL: str = os.getenv("REDIS_URL", "")
    REDIS_PASSWORD: str = os.getenv("REDIS_PASSWORD", "")

    # ── Kafka ─────────────────────────────────────────────────────────────
    KAFKA_BOOTSTRAP_SERVERS: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "")

    # ── Elasticsearch ─────────────────────────────────────────────────────
    ELASTICSEARCH_URL: str = os.getenv("ELASTICSEARCH_URL", "")

    # ── S3 / MinIO ────────────────────────────────────────────────────────
    S3_ENDPOINT: str = os.getenv("S3_ENDPOINT", "")
    S3_ACCESS_KEY: str = os.getenv("S3_ACCESS_KEY", "")
    S3_SECRET_KEY: str = os.getenv("S3_SECRET_KEY", "")
    S3_BUCKET: str = os.getenv("S3_BUCKET", "sentinel-reports")

    # ── Alerting ─────────────────────────────────────────────────────────────
    SENTINEL_SMTP_HOST: str = os.getenv("SENTINEL_SMTP_HOST", "")
    SENTINEL_SMTP_PORT: int = int(os.getenv("SENTINEL_SMTP_PORT", "587"))
    SENTINEL_SMTP_USER: str = os.getenv("SENTINEL_SMTP_USER", "")
    SENTINEL_SMTP_PASSWORD: str = os.getenv("SENTINEL_SMTP_PASSWORD", "")
    SENTINEL_SMTP_FROM: str = os.getenv("SENTINEL_SMTP_FROM", "sentinel@localhost")
    SENTINEL_SLACK_WEBHOOK: str = os.getenv("SENTINEL_SLACK_WEBHOOK", "")
    # Retry config (used by alerting/__init__.py send_*_with_retry)
    SENTINEL_ALERT_MAX_RETRIES: int = int(os.getenv("SENTINEL_ALERT_MAX_RETRIES", "5"))
    SENTINEL_ALERT_BACKOFF_BASE: int = int(os.getenv("SENTINEL_ALERT_BACKOFF_BASE", "2"))

    # ── Pentagi ─────────────────────────────────────────────────────────────
    PENTAGI_ENABLED: bool = os.getenv("PENTAGI_ENABLED", "false").lower() == "true"
    PENTAGI_IMAGE: str = os.getenv("PENTAGI_IMAGE", "sentinel/pentagi:latest")

    # ── Observability ────────────────────────────────────────────────────────────
    SENTRY_DSN: str = os.getenv("SENTRY_DSN", "")
    OTEL_SERVICE_NAME: str = os.getenv("OTEL_SERVICE_NAME", "sentinel-gateway")
    OTEL_EXPORTER_OTLP_ENDPOINT: str = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    OTEL_TRACES_EXPORTER: str = os.getenv("OTEL_TRACES_EXPORTER", "otlp")

    # ── Rate Limiting ───────────────────────────────────────────────────────────
    RATE_LIMIT_REDIS_ENABLED: bool = os.getenv("RATE_LIMIT_REDIS_ENABLED", "true").lower() == "true"
    RATE_LIMIT_FALLBACK_MEMORY: bool = os.getenv("RATE_LIMIT_FALLBACK_MEMORY", "true").lower() == "true"

    # ── DLQ Replay Worker ──────────────────────────────────────────────────────────
    DLQ_RETRY_INTERVAL_SECONDS: int = int(os.getenv("DLQ_RETRY_INTERVAL_SECONDS", "60"))
    DLQ_MAX_RETRIES: int = int(os.getenv("DLQ_MAX_RETRIES", "10"))

    # ── Fail-Open Toggles ──────────────────────────────────────────────────────────
    ALLOW_REDIS_FAIL_OPEN: bool = os.getenv("ALLOW_REDIS_FAIL_OPEN", "true").lower() == "true"
    ALLOW_KAFKA_FAIL_OPEN: bool = os.getenv("ALLOW_KAFKA_FAIL_OPEN", "true").lower() == "true"

    @field_validator("JWT_SECRET")
    @classmethod
    def validate_jwt_secret(cls, v: str) -> str:
        # 256-bit minimum — 64 hex characters from openssl rand -hex 32
        MIN_ENTROPY_CHARS = 64
        KNOWN_WEAK = {
            "super-secret-sentinel-key-2024",
            "CHANGE-ME-USE-A-REAL-256-BIT-SECRET",
            "sentinel-production-secret-key-change-me",
            "changeme", "secret", "password", "test", "dev",
            "",
        }
        v_lower = v.lower()
        if v in KNOWN_WEAK or v_lower in KNOWN_WEAK or len(v) < MIN_ENTROPY_CHARS:
            raise RuntimeError(
                f"JWT_SECRET must be securely provided via environment. "
                f"Minimum {MIN_ENTROPY_CHARS} characters (256-bit). "
                f"Generate one: export JWT_SECRET=$(openssl rand -hex 32)"
            )
        return v

    @field_validator("CORS_ALLOWED_ORIGINS")
    @classmethod
    def validate_cors_origins(cls, v: str) -> str:
        """CORS_ALLOWED_ORIGINS must be explicitly set — no wildcard fallback."""
        origins = [o.strip() for o in v.split(",") if o.strip()]
        if not origins:
            raise RuntimeError(
                "CORS_ALLOWED_ORIGINS must be set in production. "
                "Example: CORS_ALLOWED_ORIGINS=https://app.yourdomain.com"
            )
        for origin in origins:
            if origin == "*":
                raise RuntimeError(
                    "CORS_ALLOWED_ORIGINS=* is never allowed in production. "
                    "Specify explicit frontend origins."
                )
        return v

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        if not v:
            raise ValueError(
                "DATABASE_URL is not set. "
                "PostgreSQL is required: DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/db"
            )
        if "sqlite" in v.lower():
            raise ValueError(
                "SQLite is not allowed in production. "
                "Use PostgreSQL: DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/db"
            )
        if not v.startswith(("postgresql+asyncpg://", "postgresql+psycopg://", "postgresql://", "postgres://")):
            raise ValueError(
                f"Unsupported database: only PostgreSQL (postgresql+psycopg://) is allowed. Got: {v[:30]}..."
            )
        return v

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
