"""
Sentinel AI — Centralized Rate Limiter
- Primary: Redis-backed SlowAPI (distributed, per-org)
- Fallback: In-memory SlowAPI (single-node, kicks in when Redis is down)

Downstream code imports `limiter` only — never instantiates its own.
"""
import os
from slowapi import Limiter
from slowapi.util import get_remote_address


def org_or_ip(request):
    """
    Custom key function for SlowAPI.
    Per-org rate limiting (not per-IP) when user is authenticated.
    Prevents one org from consuming another's quota.
    Falls back to remote IP for unauthenticated requests.
    """
    user = getattr(request.state, "user", None)
    if user and "org_id" in user:
        return f"org:{user['org_id']}"
    return get_remote_address(request)


def _build_limiter() -> Limiter:
    """
    Build a SmallAPI Limiter instance.

    Priority:
    1. Redis storage (RATE_LIMIT_REDIS_ENABLED=true AND Redis reachable)
    2. In-memory storage (RATE_LIMIT_FALLBACK_MEMORY=true)
    3. Disabled (drop-through — requests are never blocked, but logged)
    """
    redis_enabled = os.getenv("RATE_LIMIT_REDIS_ENABLED", "true").lower() == "true"
    memory_fallback = os.getenv("RATE_LIMIT_FALLBACK_MEMORY", "true").lower() == "true"
    redis_url = os.getenv("REDIS_URL", "")

    if "PYTEST_CURRENT_TEST" in os.environ:
        return Limiter(key_func=org_or_ip, default_limits=["10000/minute"])

    if redis_enabled and redis_url:
        try:
            import redis as sync_redis
            r = sync_redis.from_url(redis_url, socket_connect_timeout=2)
            r.ping()
            r.close()
            # Redis is reachable — use distributed storage
            return Limiter(
                key_func=org_or_ip,
                default_limits=["100/minute"],
                storage_uri=redis_url,
            )
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(
                "rate_limit.redis_unavailable err=%s | fallback=memory", e
            )

    if memory_fallback:
        import logging
        logging.getLogger(__name__).info("rate_limit.using_memory_storage")
        # In-memory: works on a single node; acceptable when Redis is degraded
        return Limiter(key_func=org_or_ip, default_limits=["100/minute"])

    # Both disabled — return a limiter that won't reject anything useful
    return Limiter(key_func=org_or_ip, default_limits=["10000/minute"])


limiter = _build_limiter()
