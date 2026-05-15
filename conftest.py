"""
Root conftest.py — Adds the project root to sys.path so that
`from backend.xyz import ...` resolves correctly in all tests.

CRITICAL: Load .env BEFORE any backend import so that env_validator
does not call sys.exit(1) during pytest collection.
"""
import sys
import os

# Add sentinel-platform root to path
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# Signal config to honour .env
os.environ.setdefault("SENTINEL_LOAD_DOTENV", "true")

# Load .env immediately, before any Settings() is constructed
try:
    from dotenv import load_dotenv as _load_dotenv
    _env_file = os.path.join(_ROOT, ".env")
    if os.path.exists(_env_file):
        _load_dotenv(_env_file, override=False)
except ImportError:
    pass  # python-dotenv not available — env must be set externally

import pytest
