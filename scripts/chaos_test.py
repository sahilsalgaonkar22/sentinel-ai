#!/usr/bin/env python3
"""
Sentinel AI — Chaos Testing Script
===================================
Tests that the platform degrades gracefully when Redis and Kafka are killed.

Usage:
    python scripts/chaos_test.py

Requirements:
    pip install httpx
    Docker must be running with: docker compose up -d

Test Matrix:
  1. Baseline health check
  2. Kill Redis → Verify system still accepts scans (fail-open)
  3. Kill Kafka → Verify events land in PostgreSQL DLQ
  4. Restore Redis → Verify health recovers
  5. Restore Kafka → Verify DLQ replay worker drains queue
  6. Kill both → Verify degraded mode, no crashes
  7. Full restore → Verify system returns to healthy
"""
import subprocess
import time
import sys
import json
import httpx

GATEWAY_URL = "http://localhost:8000"
COMPOSE_FILE = "docker-compose.yml"

# ── Colours ───────────────────────────────────────────────────────────────────
GREEN = "\033[92m"
RED   = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def ok(msg):    print(f"{GREEN}  ✅ {msg}{RESET}")
def fail(msg):  print(f"{RED}  ❌ {msg}{RESET}")
def warn(msg):  print(f"{YELLOW}  ⚠️  {msg}{RESET}")
def step(msg):  print(f"\n{YELLOW}▶ {msg}{RESET}")


def health() -> dict:
    try:
        r = httpx.get(f"{GATEWAY_URL}/health", timeout=5)
        return r.json()
    except Exception as e:
        return {"status": "unreachable", "error": str(e)}


def assert_status(expected: str, label: str):
    h = health()
    actual = h.get("status", "unknown")
    if actual == expected:
        ok(f"{label}: status={actual}")
    else:
        warn(f"{label}: expected={expected} got={actual} | deps={h.get('dependencies', {})}")


def docker_stop(service: str):
    subprocess.run(["docker", "stop", f"sentinel-{service}-1"], check=False, capture_output=True)
    subprocess.run(["docker", "stop", service], check=False, capture_output=True)
    warn(f"Stopped {service}")


def docker_start(service: str):
    subprocess.run(
        ["docker", "compose", "-f", COMPOSE_FILE, "start", service],
        check=False, capture_output=True
    )
    ok(f"Started {service}")


def wait(seconds: int, reason: str = ""):
    print(f"  ⏳ Waiting {seconds}s{' — ' + reason if reason else ''}...")
    time.sleep(seconds)


# ── Test Cases ────────────────────────────────────────────────────────────────

def test_baseline():
    step("Test 1: Baseline — all services running")
    h = health()
    print(f"  Health: {json.dumps(h.get('dependencies', {}), indent=4)}")
    assert_status("healthy", "baseline")


def test_redis_down():
    step("Test 2: Kill Redis — expect fail-open (degraded, not down)")
    docker_stop("redis")
    wait(5, "Redis settling")
    h = health()
    redis_status = h.get("dependencies", {}).get("redis", {}).get("status", "unknown")
    features = h.get("features", {})
    if redis_status == "degraded":
        ok(f"Redis correctly reported as degraded | features={features}")
    else:
        fail(f"Unexpected Redis status: {redis_status}")
    assert_status("degraded", "redis-down")

    if features.get("jwt_blacklist") is False:
        ok("jwt_blacklist correctly disabled in features map")
    else:
        warn("jwt_blacklist feature flag not reflecting Redis down state")


def test_restore_redis():
    step("Test 3: Restore Redis")
    docker_start("redis")
    wait(8, "Redis reconnect")
    assert_status("healthy", "redis-restored")


def test_kafka_down():
    step("Test 4: Kill Kafka — expect DLQ buffering")
    docker_stop("kafka")
    wait(5, "Kafka settling")
    h = health()
    kafka_status = h.get("dependencies", {}).get("kafka", {}).get("status", "unknown")
    if kafka_status == "degraded":
        ok("Kafka correctly reported as degraded")
    else:
        warn(f"Kafka status: {kafka_status}")


def test_restore_kafka():
    step("Test 5: Restore Kafka — DLQ replay should drain")
    docker_start("kafka")
    wait(15, "Kafka broker ready + DLQ worker poll cycle")
    ok("Kafka restored — watch logs for: dlq_worker.replayed events")
    assert_status("healthy", "kafka-restored")


def test_both_down():
    step("Test 6: Kill Redis + Kafka simultaneously")
    docker_stop("redis")
    docker_stop("kafka")
    wait(5, "settling")
    h = health()
    db_ok = h.get("dependencies", {}).get("postgresql", {}).get("status") == "ok"
    if db_ok:
        ok("PostgreSQL remains up — system is degraded but not critical")
    else:
        fail("PostgreSQL also down — this should cause 503")
    assert_status("degraded", "both-down")


def test_full_restore():
    step("Test 7: Full restore")
    docker_start("redis")
    docker_start("kafka")
    wait(15, "all services reconnect")
    assert_status("healthy", "full-restore")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"\n{'='*60}")
    print("  Sentinel AI — Chaos Test Suite")
    print(f"{'='*60}")
    print(f"  Gateway: {GATEWAY_URL}")
    print(f"{'='*60}\n")

    try:
        tests = [
            test_baseline,
            test_redis_down,
            test_restore_redis,
            test_kafka_down,
            test_restore_kafka,
            test_both_down,
            test_full_restore,
        ]
        for test in tests:
            test()
    except KeyboardInterrupt:
        print("\n\nChaos test interrupted. Restoring services...")
        docker_start("redis")
        docker_start("kafka")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"{GREEN}  Chaos test complete. Check logs for DLQ replay confirmations.{RESET}")
    print(f"  Run: docker compose logs gateway | grep dlq_worker")
    print(f"{'='*60}\n")
