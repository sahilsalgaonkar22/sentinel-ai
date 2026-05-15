"""
SENTINEL AI — Structured Logging Configuration (FIX-10)

Configures JSON-structured logging for the entire platform.
Import and call configure_logging() at the entry point of each service.

Usage:
    from backend.common.logging_config import configure_logging
    configure_logging(service_name="gateway")
"""
import logging
import logging.config
import os
import json
from datetime import datetime, timezone


class _JSONFormatter(logging.Formatter):
    """
    Emits every log record as a single JSON line for log aggregators
    (Logstash, Loki, CloudWatch, Datadog, etc.).
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "level":      record.levelname,
            "logger":     record.name,
            "message":    record.getMessage(),
            "service":    getattr(record, "service", os.getenv("SERVICE_NAME", "sentinel")),
            "module":     record.module,
            "func":       record.funcName,
            "line":       record.lineno,
        }
        # Include exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        # Include any extra fields attached to the record
        for key, val in record.__dict__.items():
            if key not in (
                "args", "asctime", "created", "exc_info", "exc_text",
                "filename", "funcName", "id", "levelname", "levelno", "lineno",
                "message", "module", "msecs", "msg", "name", "pathname",
                "process", "processName", "relativeCreated", "stack_info",
                "thread", "threadName",
            ):
                log_entry[key] = val
        return json.dumps(log_entry)


def configure_logging(service_name: str = "sentinel", level: str | None = None) -> None:
    """
    Call once at process startup to configure JSON structured logging.
    Level defaults to the LOG_LEVEL env var, falling back to INFO.
    """
    log_level = (level or os.getenv("LOG_LEVEL", "INFO")).upper()

    logging.config.dictConfig({
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "json": {
                "()": _JSONFormatter,
            },
        },
        "handlers": {
            "stdout": {
                "class":     "logging.StreamHandler",
                "stream":    "ext://sys.stdout",
                "formatter": "json",
            },
        },
        "root": {
            "level":    log_level,
            "handlers": ["stdout"],
        },
        # Suppress noisy third-party loggers
        "loggers": {
            "uvicorn":             {"level": "WARNING"},
            "uvicorn.error":       {"level": "WARNING"},
            "uvicorn.access":      {"level": "WARNING"},
            "sqlalchemy.engine":   {"level": "WARNING"},
            "confluent_kafka":     {"level": "WARNING"},
        },
    })

    logger = logging.getLogger(__name__)
    logger.info("logging.configured service=%s level=%s", service_name, log_level)
