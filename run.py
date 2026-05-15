"""
SENTINEL AI — Application Runner

STARTUP ORDER (enforced):
  1. Load .env via python-dotenv (dev/local only; containers inject vars directly)
  2. Validate ALL environment variables — crash immediately if any are invalid
  3. Initialize FastAPI application
  4. Start uvicorn server

Run with:
    python run.py                          # local development
    uvicorn backend.gateway.main:app ...   # production (env already injected)
"""
import os
import sys
import asyncio
from pathlib import Path

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# ── Step 1: Load .env for local development ───────────────────────────────────
# In production containers (Docker/K8s), .env is NOT loaded — env vars are
# injected by the orchestrator. SENTINEL_LOAD_DOTENV controls this gate.
_ENV_FILE = Path(__file__).parent / ".env"
if _ENV_FILE.exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(dotenv_path=str(_ENV_FILE), override=True)
        print(f"[startup] Loaded: {_ENV_FILE}", file=sys.stderr)
    except ImportError:
        print(
            "[startup] WARNING: python-dotenv not installed. "
            "Environment variables must be set manually.",
            file=sys.stderr,
        )
else:
    print(
        f"[startup] No .env file found at {_ENV_FILE}. "
        "Expecting environment variables to be injected externally (K8s/Docker).",
        file=sys.stderr,
    )

# ── Step 2: Validate environment — crash-on-failure ───────────────────────────
# enforce_environment() prints a structured error block to stderr and calls
# sys.exit(1) if ANY required variable is missing, invalid, or a placeholder.
# This MUST run before any application module is imported.
try:
    from backend.common.env_validator import enforce_environment
    enforce_environment()
except ImportError as _e:
    # Fallback: env_validator not importable (e.g. running outside project root)
    print(
        f"[startup] CRITICAL: Cannot import env_validator ({_e}). "
        "Run from the project root directory.",
        file=sys.stderr,
    )
    sys.exit(1)

# ── Step 3: Start application ─────────────────────────────────────────────────
import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "backend.gateway.main:app",
        host=os.getenv("BIND_HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("UVICORN_RELOAD", "false").lower() == "true",
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
        workers=int(os.getenv("UVICORN_WORKERS", "1")),
        loop="none",
        # Require forwarded headers to be trusted (reverse proxy aware)
        proxy_headers=True,
        forwarded_allow_ips=os.getenv("TRUSTED_PROXY_IPS", "127.0.0.1"),
    )
