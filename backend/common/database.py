"""
SENTINEL AI — Database Layer
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import Column, DateTime, String
from sqlalchemy.exc import OperationalError
from datetime import datetime, timezone
from backend.common.config import settings
import logging

logger = logging.getLogger(__name__)

# ✅ Base must be import-safe for Alembic
Base = declarative_base()

# ── Engine (lazy, never created at import-time) ──────────────────────────────
_engine = None


def get_engine():
    """Return (or create) the async SQLAlchemy engine. Import-safe."""
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            settings.DATABASE_URL,
            echo=False,
            future=True
        )
    return _engine


_session_factory = None


def get_session_factory():
    """Return (or create) the async session factory. Import-safe."""
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _session_factory


class _AsyncSessionProxy:
    """
    Callable proxy that behaves exactly like the old AsyncSessionLocal.

    All existing code:
        async with AsyncSessionLocal() as db: ...
    continues to work unchanged, even when imported before init_db() runs.
    """

    def __call__(self):
        return get_session_factory()()

    # Make it also usable as an async context manager directly
    def __aenter__(self):
        return self().__aenter__()

    def __aexit__(self, *args):
        # This path is never reached; __call__ creates the real context manager
        pass


# Drop-in replacement — every imported reference stays valid
AsyncSessionLocal = _AsyncSessionProxy()


class TimestampMixin:
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class TenantMixin:
    org_id = Column(String(36), index=True, nullable=True)


async def init_db():
    logger.info("Database initialization skipped (schema managed manually via docker exec).")


def _find_alembic_root() -> str:
    import os
    candidate = os.path.dirname(os.path.abspath(__file__))
    for _ in range(5):
        if os.path.exists(os.path.join(candidate, "alembic.ini")):
            return candidate
        candidate = os.path.dirname(candidate)
    return os.getcwd()


async def get_db_session():
    from fastapi import HTTPException
    try:
        async with get_session_factory()() as session:
            yield session
    except OperationalError as exc:
        logger.error("db.session_error %s", exc)
        raise HTTPException(
            status_code=503,
            detail="Database temporarily unavailable. Please retry."
        ) from exc


async def get_db(user: dict = None):
    from fastapi import HTTPException
    try:
        async with get_session_factory()() as session:
            if user and user.get("org_id"):
                session.info["org_id"] = user["org_id"]
            yield session
    except OperationalError as exc:
        logger.error("db.session_error %s", exc)
        raise HTTPException(
            status_code=503,
            detail="Database temporarily unavailable. Please retry."
        ) from exc