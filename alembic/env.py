"""
SENTINEL AI — Alembic Migration Environment

Driver selection for sync migrations:
  - Inside Docker (gateway image): uses psycopg v3 (psycopg-binary is installed, psycopg2 is NOT)
  - On Windows host (.venv): uses psycopg2 (installed in local venv)

Runtime uses asyncpg; Alembic uses a sync driver only during migrations.
"""

import sys
import os

# Ensure project root is in Python path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from dotenv import load_dotenv
# Load .env.docker first if DATABASE_URL not already set (i.e. we're inside Docker)
if not os.environ.get("DATABASE_URL"):
    _docker_env = os.path.join(BASE_DIR, ".env.docker")
    if os.path.exists(_docker_env):
        load_dotenv(_docker_env)
    else:
        load_dotenv(os.path.join(BASE_DIR, ".env"))

from logging.config import fileConfig
from sqlalchemy import pool, create_engine
from alembic import context

# Import ALL models so autogenerate detects all tables
from backend.services.identity.models import User, Organization          # noqa: F401
from backend.services.scan_control.models import Scan, Asset, Finding, AttackPath  # noqa: F401
from backend.common.database import Base

config = context.config

# ── Build a synchronous DB URL for Alembic ───────────────────────────────────
# asyncpg (postgresql+asyncpg://) cannot be used synchronously.
# We prefer psycopg (v3) which is installed in the Docker image.
# Fall back to psycopg2 if psycopg is unavailable (local host venv).
_db_url = os.environ.get("DATABASE_URL", "").strip()
if not _db_url:
    raise RuntimeError("DATABASE_URL not set — run: cp .env.example .env && fill in secrets")
if "sqlite" in _db_url.lower():
    raise RuntimeError("SQLite is not allowed. Use PostgreSQL.")

def _pick_sync_url(url: str) -> str:
    """Convert asyncpg URL to the best available sync driver."""
    if not (url.startswith("postgresql+asyncpg://") or url.startswith("postgres://")):
        return url  # already sync-compatible (psycopg or psycopg2)
    # Strip the async prefix to get the bare credentials
    bare = url.split("://", 1)[1] if "://" in url else url
    # Try psycopg v3 first (installed in Docker image)
    try:
        import psycopg  # noqa: F401
        return f"postgresql+psycopg://{bare}"
    except ImportError:
        pass
    # Fall back to psycopg2 (available in host venv)
    return f"postgresql+psycopg2://{bare}"

_sync_url = _pick_sync_url(_db_url)

config.set_main_option("sqlalchemy.url", _sync_url)

# Logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


# ── OFFLINE MODE ─────────────────────────────────────────────────────────────
def run_migrations_offline() -> None:
    context.configure(
        url=_sync_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# ── ONLINE MODE (synchronous psycopg2) ───────────────────────────────────────
def run_migrations_online() -> None:
    connectable = create_engine(
        _sync_url,
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


# ── ENTRYPOINT ────────────────────────────────────────────────────────────────
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()