#!/usr/bin/env python3
"""
SENTINEL AI — Environment Check Tool
=====================================

Run this before starting the application to validate your .env configuration.

Usage:
    python scripts/check_env.py              # Check current environment
    python scripts/check_env.py --env-file .env  # Specify env file path
    python scripts/check_env.py --generate   # Generate a new .env from .env.example

Examples:
    cp .env.example .env && python scripts/check_env.py
"""
from __future__ import annotations

import argparse
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path

# ── Bootstrap: resolve project root and add to path ──────────────────────────
SCRIPT_DIR  = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ── ANSI colours (safe on Windows) ────────────────────────────────────────────
def _supports_color() -> bool:
    # Windows Terminal supports ANSI, classic CMD does not
    if os.name == "nt":
        return os.environ.get("FORCE_COLOR") == "1" or "WT_SESSION" in os.environ
    return sys.stdout.isatty()

_GREEN  = "\033[92m" if _supports_color() else ""
_RED    = "\033[91m" if _supports_color() else ""
_YELLOW = "\033[93m" if _supports_color() else ""
_CYAN   = "\033[96m" if _supports_color() else ""
_BOLD   = "\033[1m"  if _supports_color() else ""
_RESET  = "\033[0m"  if _supports_color() else ""

# Use ASCII-safe symbols (no Unicode checkmarks that break cp1252)
PASS = f"{_GREEN}[PASS]{_RESET}"
FAIL = f"{_RED}[FAIL]{_RESET}"
WARN = f"{_YELLOW}[WARN]{_RESET}"
INFO = f"{_CYAN}[INFO]{_RESET}"


def _safe_print(*args, **kwargs) -> None:
    """Print with UTF-8 fallback for Windows terminals with restricted codecs."""
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        # Strip all non-ASCII characters and retry
        text = " ".join(str(a) for a in args)
        safe = text.encode("ascii", errors="replace").decode("ascii")
        print(safe, **{k: v for k, v in kwargs.items() if k != "file"})


def _header(text: str) -> None:
    print(f"\n{_BOLD}{_CYAN}{text}{_RESET}")
    print("─" * len(text))


def _load_env_file(env_path: Path) -> bool:
    """Load .env file using python-dotenv. Returns True on success."""
    try:
        from dotenv import load_dotenv
        loaded = load_dotenv(dotenv_path=str(env_path), override=True)
        if loaded:
            print(f"{INFO}  Loaded env file: {env_path}")
        else:
            print(f"{WARN}  No variables loaded from: {env_path} (file may be empty)")
        return True
    except ImportError:
        print(f"{WARN}  python-dotenv not installed — reading from OS environment only.")
        print(f"       Install with: pip install python-dotenv")
        return False


def _check_env_file_exists(env_path: Path) -> bool:
    if env_path.exists():
        print(f"{PASS}  .env file found: {env_path}")
        return True
    else:
        print(f"{FAIL}  .env file NOT found: {env_path}")
        print(f"       Run: cp .env.example .env  then fill in real secrets.")
        return False


def _run_full_validation() -> bool:
    """Import and run the env_validator module. Returns True if all pass."""
    try:
        from backend.common.env_validator import validate_environment, REQUIRED_VARS, _mask
        result = validate_environment()

        # Print per-var results
        _header("Variable Validation")
        all_vars_checked = {spec.name: spec for spec in REQUIRED_VARS}

        for spec in REQUIRED_VARS:
            var_errors = [e for e in result.errors if e.var == spec.name]
            value = os.environ.get(spec.name, "")

            if var_errors:
                for err in var_errors:
                    tag = f"{'(optional) ' if spec.optional else ''}"
                    print(f"  {FAIL}  {spec.name} {tag}")
                    print(f"          → {err.reason}")
            elif not value and spec.optional:
                print(f"  {WARN}  {spec.name}  (optional — not set)")
            else:
                masked = _mask(value) if value else "<not set>"
                print(f"  {PASS}  {spec.name}  [{masked}]")

        # Non-variable errors (cross-service consistency, structural)
        other_errors = [e for e in result.errors if e.var not in all_vars_checked]
        if other_errors:
            _header("Consistency Checks")
            for err in other_errors:
                print(f"  {FAIL}  {err.var}")
                print(f"          → {err.reason}")

        # Warnings
        if result.warnings:
            _header("Warnings")
            for w in result.warnings:
                print(f"  {WARN}  {w}")

        return result.ok

    except ImportError as e:
        print(f"{FAIL}  Cannot import env_validator: {e}")
        print(f"       Ensure you are running from the project root.")
        return False


def _check_secret_strength() -> None:
    """Extra entropy checks beyond what the validator does."""
    _header("Secret Strength Analysis")

    checks = [
        ("JWT_SECRET",         64, "256-bit (openssl rand -hex 32)"),
        ("SECRET_KEY",         64, "256-bit (openssl rand -hex 32)"),
        ("POSTGRES_PASSWORD",  16, "128-bit minimum"),
        ("REDIS_PASSWORD",     16, "128-bit minimum"),
        ("KAFKA_SASL_PASSWORD",16, "128-bit minimum"),
        ("S3_SECRET_KEY",      16, "128-bit minimum"),
    ]

    for var, min_len, hint in checks:
        value = os.environ.get(var, "")
        if not value:
            continue  # validator already caught this

        # Check entropy via character diversity
        has_hex = bool(re.search(r'[0-9a-f]', value.lower()))
        length_ok = len(value) >= min_len
        not_repetitive = len(set(value)) >= 8  # at least 8 unique chars

        if length_ok and not_repetitive:
            print(f"  {PASS}  {var}: {len(value)} chars, good entropy")
        elif not length_ok:
            print(f"  {FAIL}  {var}: only {len(value)} chars (need ≥{min_len}). Hint: {hint}")
        else:
            print(f"  {WARN}  {var}: {len(value)} chars but low character diversity. "
                  f"Regenerate with: openssl rand -hex 32")


def _suggest_secret_generation() -> None:
    """Print commands to generate all required secrets."""
    _header("Secret Generation Commands")
    print("  Run these commands to generate cryptographically secure secrets:\n")
    cmds = [
        ("JWT_SECRET",          "openssl rand -hex 32"),
        ("SECRET_KEY",          "openssl rand -hex 32"),
        ("POSTGRES_PASSWORD",   "openssl rand -hex 16"),
        ("REDIS_PASSWORD",      "openssl rand -hex 16"),
        ("KAFKA_SASL_PASSWORD", "openssl rand -hex 16"),
        ("S3_SECRET_KEY",       "openssl rand -hex 24"),
    ]
    for var, cmd in cmds:
        print(f"  export {var}=$({cmd})")
    print()


def _generate_env_file(env_example: Path, env_target: Path) -> None:
    """
    Copy .env.example to .env, replacing REPLACE_WITH_* placeholders
    with cryptographically secure auto-generated values.
    """
    _header("Generating .env File")

    if not env_example.exists():
        print(f"  {FAIL}  .env.example not found: {env_example}")
        return

    if env_target.exists():
        confirm = input(f"  {env_target} already exists. Overwrite? [y/N]: ").strip().lower()
        if confirm != "y":
            print("  Aborted.")
            return

    content = env_example.read_text(encoding="utf-8")
    replacements = {
        "REPLACE_WITH_SECURE_PASSWORD": lambda: secrets.token_hex(16),
        "REPLACE_WITH_64_CHAR_HEX_SECRET": lambda: secrets.token_hex(32),
        "REPLACE_WITH_MINIO_ACCESS_KEY": lambda: f"sentinel_{secrets.token_hex(6)}",
        "REPLACE_WITH_MINIO_SECRET_KEY": lambda: secrets.token_hex(24),
    }

    generated = {}
    for placeholder, gen_fn in replacements.items():
        # Each unique placeholder occurrence gets the SAME generated value
        # so that DATABASE_URL and POSTGRES_PASSWORD stay consistent
        if placeholder in content:
            if placeholder not in generated:
                generated[placeholder] = gen_fn()
            content = content.replace(placeholder, generated[placeholder])

    # Fix cross-service consistency: sync DATABASE_URL with POSTGRES_PASSWORD
    pg_pass = generated.get("REPLACE_WITH_SECURE_PASSWORD", "")
    if pg_pass and "DATABASE_URL=" in content:
        # The DATABASE_URL placeholder is already replaced by the same value
        pass  # already consistent since same placeholder → same value

    env_target.write_text(content)
    print(f"  {PASS}  Generated: {env_target}")
    print(f"  {WARN}  Review the file and set CORS_ALLOWED_ORIGINS to your real domain.")
    print(f"  {WARN}  Set LLM_API_KEY if you want AI features.")
    print(f"\n  Verify the generated file:")
    print(f"    python scripts/check_env.py --env-file {env_target}")


def _print_summary(passed: bool) -> None:
    width = 60
    print("\n" + "=" * width)
    if passed:
        print(f"  {_BOLD}{_GREEN}✔  ALL CHECKS PASSED — Ready to start SENTINEL AI{_RESET}")
        print(f"\n  Start the application:")
        print(f"    docker compose up -d")
        print(f"    # or: python run.py")
    else:
        print(f"  {_BOLD}{_RED}✘  CHECKS FAILED — Fix errors above before starting{_RESET}")
        print(f"\n  After fixing:")
        print(f"    python scripts/check_env.py   # re-verify")
    print("=" * width + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SENTINEL AI — Environment Validation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=PROJECT_ROOT / ".env",
        help="Path to the .env file (default: .env in project root)",
    )
    parser.add_argument(
        "--generate",
        action="store_true",
        help="Generate a new .env file from .env.example with random secrets",
    )
    parser.add_argument(
        "--show-generation-hints",
        action="store_true",
        help="Print commands to generate secrets manually",
    )
    args = parser.parse_args()

    print(f"\n{_BOLD}SENTINEL AI — Environment Validator{_RESET}")
    print(f"{'─' * 40}")

    # Generate mode
    if args.generate:
        example = PROJECT_ROOT / ".env.example"
        _generate_env_file(example, args.env_file)
        sys.exit(0)

    if args.show_generation_hints:
        _suggest_secret_generation()
        sys.exit(0)

    # 1. Check .env file exists
    _header("Environment File")
    env_exists = _check_env_file_exists(args.env_file)

    # 2. Load .env into os.environ
    if env_exists:
        _load_env_file(args.env_file)

    # 3. Run full validation
    passed = _run_full_validation()

    # 4. Secret strength (bonus analysis)
    _check_secret_strength()

    # 5. Summary
    _print_summary(passed)

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
