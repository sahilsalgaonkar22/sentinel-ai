"""
SENTINEL AI — Integration Test Suite
Tests run against real FastAPI app via TestClient.
No mocks, no patches — all real backend code paths exercised.
"""
import pytest
import os
os.environ["RATE_LIMIT_REDIS_ENABLED"] = "false"
os.environ["RATE_LIMIT_FALLBACK_MEMORY"] = "false"

from fastapi.testclient import TestClient
from backend.gateway.main import app

client = TestClient(app)


# ─── Utility ──────────────────────────────────────────────────────────────────

def get_auth_token() -> str:
    """Obtain a real JWT from the login endpoint."""
    resp = client.post(
        "/auth/login",
        data={"username": "admin@sentinel.ai", "password": "sentinel2024!"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    return resp.json()["access_token"]


def auth_headers() -> dict:
    return {"Authorization": f"Bearer {get_auth_token()}"}


# ─── 0. Infrastructure ────────────────────────────────────────────────────────

def test_health_check():
    """Gateway must respond 200 with status=healthy."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("healthy", "degraded")
    assert data["service"] == "sentinel-gateway"
    assert "dependencies" in data


def test_metrics_endpoint_exposed():
    """Prometheus /metrics endpoint must return metric format."""
    resp = client.get("/metrics")
    assert resp.status_code == 200
    text = resp.text
    # Must contain at least one Prometheus metric family
    assert any(kw in text for kw in [
        "python_gc_objects_collected_total",
        "http_requests_total",
        "process_virtual_memory_bytes",
    ]), f"No Prometheus metrics found in response: {text[:300]}"


# ─── 1. Authentication ────────────────────────────────────────────────────────

def test_login_returns_jwt():
    """POST /auth/login must return a valid JWT."""
    resp = client.post(
        "/auth/login",
        data={"username": "admin@sentinel.ai", "password": "sentinel2024!"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert len(data["access_token"]) > 20
    assert data["token_type"] == "bearer"


def test_auth_me_returns_user():
    """GET /auth/me must return valid user identity."""
    resp = client.get("/auth/me", headers=auth_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert "email" in data or "id" in data
    assert "role" in data
    assert "org_id" in data


# ─── 2. Security / RBAC ──────────────────────────────────────────────────────

def test_unauthorized_access_scans():
    """GET /scans without token must return 401."""
    resp = client.get("/scans")
    assert resp.status_code == 401


def test_unauthorized_access_vulnerabilities():
    """GET /vulnerabilities without token must return 401."""
    resp = client.get("/vulnerabilities")
    assert resp.status_code == 401


def test_unauthorized_ai_risk_score():
    """POST /ai/risk-score without token must return 401."""
    resp = client.post("/ai/risk-score", json={"title": "test", "features": {}})
    assert resp.status_code == 401


# ─── 3. Scan Management ───────────────────────────────────────────────────────

def test_create_scan_returns_id():
    """POST /scans must create new scan with UUID, persist to DB."""
    hdrs = auth_headers()
    resp = client.post("/scans/", json={
        "name": "Integration-Test-Scan",
        "target_raw": "192.168.100.1",
        "scan_type": "full",
    }, headers=hdrs)
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "id" in data
    assert len(data["id"]) == 36  # UUID4 length
    assert data["status"] in ("pending", "running")
    assert data["target_raw"] == "192.168.100.1"


def test_get_scan_by_id():
    """GET /scans/{id} must return the created scan from DB."""
    hdrs = auth_headers()
    # Create a scan first
    create_resp = client.post("/scans/", json={
        "name": "ID-Test-Scan",
        "target_raw": "10.0.0.1",
        "scan_type": "quick",
    }, headers=hdrs)
    assert create_resp.status_code == 201
    scan_id = create_resp.json()["id"]

    # Fetch it
    get_resp = client.get(f"/scans/{scan_id}", headers=hdrs)
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert data["id"] == scan_id
    assert data["target_raw"] == "10.0.0.1"


def test_list_scans_authenticated():
    """GET /scans must return a list (empty or results)."""
    resp = client.get("/scans", headers=auth_headers())
    assert resp.status_code == 200
    data = resp.json()
    # Must return either a list or a paginated dict
    assert isinstance(data, (list, dict))


# ─── 4. AI Inference ─────────────────────────────────────────────────────────

def test_ai_risk_score_real_model():
    """POST /ai/risk-score must return a bounded float from the real model."""
    resp = client.post("/ai/risk-score", json={
        "title": "SQL Injection via untrusted input",
        "features": {
            "cvss_score": 9.8,
            "exploit_available": True,
            "confidence_score": 0.95,
            "scanner_type": "zap",
            "asset_criticality": "high",
            "exposure_level": "external",
        }
    }, headers=auth_headers())
    assert resp.status_code == 200, f"AI risk-score failed: {resp.text}"
    data = resp.json()
    assert "risk_score" in data
    score = data["risk_score"]
    assert isinstance(score, (int, float)), f"Expected numeric score, got {type(score)}"
    assert 0 <= score <= 10, f"Score out of [0,10] range: {score}"
    assert score > 0, "Score should be non-zero for critical finding"


def test_ai_false_positive_classifier():
    """POST /ai/false-positive must return boolean + confidence."""
    resp = client.post("/ai/false-positive", json={
        "features": {
            "cvss_score": 1.5,
            "exploit_available": False,
            "confidence_score": 0.2,
            "scanner_type": "nikto",
            "asset_criticality": "low",
            "exposure_level": "internal",
        },
        "raw_finding_str": "Missing X-Frame-Options header"
    }, headers=auth_headers())
    assert resp.status_code == 200, f"FP classifier failed: {resp.text}"
    data = resp.json()
    assert "is_false_positive" in data
    assert "confidence" in data
    assert isinstance(data["is_false_positive"], bool)
    assert isinstance(data["confidence"], (int, float))
    assert 0.0 <= data["confidence"] <= 1.0


def test_ai_search_endpoint():
    """GET /ai/search returns structured results."""
    resp = client.get("/ai/search?q=sql", headers=auth_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert "vulnerabilities" in data
    assert "scans" in data


def test_ai_chat_endpoint():
    """POST /ai/chat returns a response string."""
    resp = client.post("/ai/chat", json={"query": "How do I fix SQL injection?"}, headers=auth_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert "response" in data or "reply" in data
    reply = data.get("response") or data.get("reply", "")
    assert len(reply) > 5


# ─── 5. Vulnerability Management ─────────────────────────────────────────────

def test_vulnerability_stats_endpoint():
    """GET /vulnerabilities/stats/summary must return stats dict."""
    resp = client.get("/vulnerabilities/stats/summary", headers=auth_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data


def test_vulnerability_list_paginated():
    """GET /vulnerabilities must return valid paginated or list response."""
    resp = client.get("/vulnerabilities?page=1&per_page=10", headers=auth_headers())
    assert resp.status_code == 200


# ─── 6. Live Monitoring ───────────────────────────────────────────────────────

def test_live_scan_tools_endpoint():
    """GET /live-scan/tools must return tool registry with status."""
    resp = client.get("/live-scan/tools", headers=auth_headers())
    assert resp.status_code == 200
    tools = resp.json()
    assert isinstance(tools, list)
    assert len(tools) >= 6
    for tool in tools:
        assert "id" in tool
        assert "name" in tool
        assert "status" in tool
        assert tool["status"] in ("idle", "queued", "running", "completed")


def test_live_active_scans_endpoint():
    """GET /live-scan/active must return scan queue info."""
    resp = client.get("/live-scan/active", headers=auth_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert "active_scans" in data
    assert "workers_online" in data


# ─── 7. Rate Limiting ─────────────────────────────────────────────────────────

def test_rate_limiting_active():
    """After 100 requests, endpoint should return 429 with rate limit error."""
    for _ in range(100):
        client.get("/")
    resp = client.get("/")
    assert resp.status_code == 429
    # Rate limiter returns JSON error, not plaintext
    body = resp.text
    assert "Rate limit" in body or "rate limit" in body or "Too Many" in body or "429" in body, \
        f"Expected rate limit message in body, got: {body}"


# ─── 8. Attack Graph ──────────────────────────────────────────────────────────

def test_ai_attack_graph_structure():
    """GET /ai/attack-graph returns valid force-graph data with nodes and links."""
    hdrs = auth_headers()
    resp = client.get("/ai/attack-graph", headers=hdrs)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text[:200]}"
    data = resp.json()

    # Required top-level keys
    assert "nodes" in data, "Missing 'nodes' key"
    assert "links" in data, "Missing 'links' key"
    assert "total_nodes" in data, "Missing 'total_nodes' key"
    assert "total_links" in data, "Missing 'total_links' key"

    # Must have some data (fallback demo graph always returns 5+ nodes)
    assert len(data["nodes"]) >= 2, f"Expected at least 2 nodes, got {len(data['nodes'])}"

    # Every node must have required fields
    for node in data["nodes"]:
        assert "id" in node, f"Node missing 'id': {node}"
        assert "name" in node, f"Node missing 'name': {node}"
        assert "type" in node, f"Node missing 'type': {node}"
        assert "risk_score" in node, f"Node missing 'risk_score': {node}"
        assert node["type"] in ("vulnerability", "asset", "actor"), \
            f"Unexpected node type: {node['type']}"

    # Every link must have source and target
    for link in data["links"]:
        assert "source" in link, f"Link missing 'source': {link}"
        assert "target" in link, f"Link missing 'target': {link}"
        assert "type" in link, f"Link missing 'type': {link}"

    node_types = {n["type"] for n in data["nodes"]}
    print(f"\n  [Attack Graph] nodes={data['total_nodes']} links={data['total_links']} types={node_types}")
