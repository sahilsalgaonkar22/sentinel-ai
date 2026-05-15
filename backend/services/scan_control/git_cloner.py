"""
SENTINEL AI — Git Repository Cloner (FIX-5: print → structured logging)
Shallow-clones git repos to temp directories for code scanning.
"""
import asyncio
import logging
import os
import re
import shutil
import tempfile

logger = logging.getLogger(__name__)


def _normalize_git_url(url: str) -> str:
    """Convert various git URL formats to cloneable HTTPS URLs."""
    url = url.strip()

    # Already HTTPS
    if url.startswith("https://") or url.startswith("http://"):
        if not url.endswith(".git"):
            url = url.rstrip("/") + ".git"
        return url

    # SSH format: git@github.com:user/repo.git
    ssh_match = re.match(r"git@([^:]+):(.+)", url)
    if ssh_match:
        host, path = ssh_match.groups()
        if not path.endswith(".git"):
            path += ".git"
        return f"https://{host}/{path}"

    # github.com/user/repo (no protocol)
    if re.match(r"^[a-zA-Z0-9.-]+\.(com|org|io|dev)/", url):
        if not url.endswith(".git"):
            url = url.rstrip("/") + ".git"
        return f"https://{url}"

    return url


async def clone_repo(url: str, timeout: int = 60) -> str:
    """
    Shallow clone a git repository.

    Args:
        url:     Git repository URL (HTTPS, SSH, or shorthand)
        timeout: Maximum seconds for clone operation

    Returns:
        Path to cloned repository directory

    Raises:
        RuntimeError: If clone fails
    """
    clone_url = _normalize_git_url(url)
    clone_dir = tempfile.mkdtemp(prefix="sentinel_repo_")

    logger.info("git.clone_start url=%s dir=%s", clone_url, clone_dir)

    git_bin = shutil.which("git")
    if not git_bin:
        shutil.rmtree(clone_dir, ignore_errors=True)
        raise RuntimeError("git binary not found. Install git to scan repositories.")

    cmd = [
        git_bin, "clone",
        "--depth", "1",        # Shallow clone
        "--single-branch",     # Only default branch
        "--quiet",
        clone_url,
        clone_dir,
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

        if proc.returncode != 0:
            err_msg = stderr.decode("utf-8", errors="replace").strip()
            shutil.rmtree(clone_dir, ignore_errors=True)
            raise RuntimeError(f"Git clone failed (exit {proc.returncode}): {err_msg}")

        # Verify directory has content
        if not os.listdir(clone_dir):
            shutil.rmtree(clone_dir, ignore_errors=True)
            raise RuntimeError("Clone succeeded but directory is empty")

        logger.info("git.clone_complete url=%s dir=%s", clone_url, clone_dir)
        return clone_dir

    except asyncio.TimeoutError:
        shutil.rmtree(clone_dir, ignore_errors=True)
        raise RuntimeError(f"Git clone timed out after {timeout}s")
    except RuntimeError:
        raise
    except Exception as e:
        shutil.rmtree(clone_dir, ignore_errors=True)
        raise RuntimeError(f"Git clone error: {e}")


def cleanup_repo(path: str) -> None:
    """Remove a cloned repository directory."""
    if path and os.path.exists(path):
        try:
            shutil.rmtree(path)
            logger.info("git.cleanup_complete path=%s", path)
        except Exception as e:
            logger.warning("git.cleanup_failed path=%s err=%s", path, e)
