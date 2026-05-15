"""
SENTINEL AI — Test-suite conftest.py (PHASE 1 FIX)

Loads .env before any application module is imported.
This prevents the integration tests from crashing with INTERNLERROR
on config validation at pytest collection time.

Must run before backend.common.config is imported.
"""
import os
import sys

# Ensure project root (sentinel-platform/) is on sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Signal the config module to load .env
os.environ.setdefault("SENTINEL_LOAD_DOTENV", "true")

# Load .env immediately — before any Settings() is instantiated
from dotenv import load_dotenv
_env_path = os.path.join(PROJECT_ROOT, ".env")
if os.path.exists(_env_path):
    load_dotenv(_env_path, override=False)
    print(f"[conftest] Loaded environment from {_env_path}")
else:
    print(f"[conftest] WARNING: .env not found at {_env_path}")

import pytest
