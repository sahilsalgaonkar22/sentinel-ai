"""
SENTINEL AI — Full E2E Verification Test
Tests: real tool execution, scoring, PDF reports.
"""
import httpx
import time
import json
import sys

BASE = "http://127.0.0.1:8000"
passed = 0
failed = 0

def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        failed += 1
        print(f"  [FAIL] {name} -- {detail}")

client = httpx.Client(base_url=BASE, timeout=60, follow_redirects=True)

print("=" * 60)
print("SENTINEL AI - E2E PRODUCTION VERIFICATION")
print("=" * 60)

# 1. Health
print("\n[1] Health Check")
r = client.get("/health")
check("Health endpoint", r.status_code == 200)

# 2. Register + Login
print("\n[2] Auth")
client.post("/auth/register", json={
    "email": "test@sentinel.ai", "password": "TestPass123",
    "full_name": "Test User", "role": "admin", "org_id": "org-test"
})
r = client.post("/auth/login",
    data={"username": "test@sentinel.ai", "password": "TestPass123"},
    headers={"Content-Type": "application/x-www-form-urlencoded"})
check("Login", r.status_code == 200)
token = r.json().get("access_token", "")
headers = {"Authorization": f"Bearer {token}"}

# 3. Code Scan (real bandit execution on ./backend)
print("\n[3] Code Scan (bandit on ./backend)")
r = client.post("/scans/", json={
    "name": "Real Code Scan",
    "scan_type": "code",
    "target_raw": "./backend",
}, headers=headers)
check("Create code scan", r.status_code in (200, 201))
code_scan_id = r.json().get("id")
print(f"     Scan ID: {code_scan_id}")

# Wait for scan to complete
print("     Waiting for scan to complete...")
for i in range(30):
    time.sleep(2)
    r = client.get(f"/scans/{code_scan_id}", headers=headers)
    data = r.json()
    status = data.get("status", "")
    progress = data.get("progress", 0)
    print(f"     Status: {status} | Progress: {progress}%")
    if status in ("completed", "failed"):
        break

scan_data = r.json()
check("Scan completed", scan_data.get("status") == "completed", f"Got: {scan_data.get('status')}")
check("Has security score", scan_data.get("security_score") is not None, f"Score: {scan_data.get('security_score')}")
check("Has risk grade", scan_data.get("risk_grade") is not None, f"Grade: {scan_data.get('risk_grade')}")
check("Has input type", scan_data.get("input_type") is not None, f"Type: {scan_data.get('input_type')}")
check("Has findings", scan_data.get("total_findings", 0) > 0, f"Findings: {scan_data.get('total_findings')}")

print(f"\n     === SCAN RESULTS ===")
print(f"     Score: {scan_data.get('security_score')}/100")
print(f"     Grade: {scan_data.get('risk_grade')}")
print(f"     Input Type: {scan_data.get('input_type')}")
print(f"     Total Findings: {scan_data.get('total_findings')}")
print(f"     Critical: {scan_data.get('critical_count')} | High: {scan_data.get('high_count')} | Medium: {scan_data.get('medium_count')} | Low: {scan_data.get('low_count')}")

# 4. Verify findings are from real tools
print("\n[4] Finding Verification")
r = client.get(f"/scans/{code_scan_id}/findings", headers=headers)
check("Get findings", r.status_code == 200)
resp = r.json()
findings = resp.get("findings", resp.get("items", resp)) if isinstance(resp, dict) else resp
if isinstance(findings, list) and len(findings) > 0:
    first = findings[0]
    check("Finding has title", bool(first.get("title")))
    check("Finding has tool_name", first.get("tool_name") in ("bandit", "semgrep"))
    check("Finding has severity", first.get("severity") in ("critical", "high", "medium", "low", "info"))
    # Verify it's NOT a template finding
    template_titles = ["Remote Code Execution in Apache Struts", "SQL Injection in Login Form"]
    is_template = any(t in first.get("title", "") for t in template_titles)
    check("Finding is NOT template/fake", not is_template, f"Title: {first.get('title')}")
    print(f"     Sample finding: [{first.get('severity')}] {first.get('title')}")
else:
    check("Findings are a list", False, f"Got: {type(findings)}")

# 5. PDF Report
print("\n[5] PDF Report Generation")
r = client.post("/reporting/generate", json={"scan_id": code_scan_id}, headers=headers)
check("Generate report", r.status_code == 200, f"Status: {r.status_code}")
report_data = r.json()
report_id = report_data.get("id", "")
check("Report has ID", bool(report_id))
check("Report has score", report_data.get("security_score") is not None)
print(f"     Report: {report_data.get('name')} | Size: {report_data.get('size')}")

# Download
if report_id:
    r = client.get(f"/reporting/{report_id}/download", headers=headers)
    check("Download PDF", r.status_code == 200)
    check("PDF content type", "pdf" in r.headers.get("content-type", ""), r.headers.get("content-type", ""))
    check("PDF has content", len(r.content) > 1000, f"Size: {len(r.content)} bytes")
    print(f"     PDF size: {len(r.content)} bytes")

# 6. Network scan (port probe on localhost)
print("\n[6] Network Scan (port probe on 127.0.0.1)")
r = client.post("/scans/", json={
    "name": "Real Network Scan",
    "scan_type": "network",
    "target_raw": "127.0.0.1",
}, headers=headers)
check("Create network scan", r.status_code in (200, 201))
net_scan_id = r.json().get("id")

print("     Waiting for scan to complete...")
for i in range(20):
    time.sleep(2)
    r = client.get(f"/scans/{net_scan_id}", headers=headers)
    data = r.json()
    if data.get("status") in ("completed", "failed"):
        break

net_data = r.json()
check("Network scan completed", net_data.get("status") == "completed")
check("Network scan has score", net_data.get("security_score") is not None)
check("Network scan has findings", net_data.get("total_findings", 0) >= 0)
print(f"     Score: {net_data.get('security_score')}/100 ({net_data.get('risk_grade')})")
print(f"     Findings: {net_data.get('total_findings')}")

# 7. Attack Paths
print("\n[7] Attack Paths")
r = client.get(f"/scans/{code_scan_id}/attack-paths", headers=headers)
check("Get attack paths", r.status_code == 200)
paths_data = r.json()
check("Attack paths response has total", "total" in paths_data)
print(f"     Attack paths generated: {paths_data.get('total', 0)}")

# 8. Scan Comparison (Before vs After)
print("\n[8] Scan Comparison (Before vs After)")
r = client.post("/scans/compare", json={
    "scan_id_before": code_scan_id,
    "scan_id_after": net_scan_id,
}, headers=headers)
check("Compare scans", r.status_code == 200)
comp = r.json()
check("Comparison has score_delta", "score_delta" in comp)
check("Comparison has new_count", "new_count" in comp)
check("Comparison has resolved_count", "resolved_count" in comp)
check("Comparison has summary", bool(comp.get("summary")))
print(f"     Score: {comp.get('score_before')} -> {comp.get('score_after')} (delta: {comp.get('score_delta')})")
print(f"     New: {comp.get('new_count')} | Resolved: {comp.get('resolved_count')} | Persistent: {comp.get('persistent_count')}")
print(f"     Summary: {comp.get('summary', '')[:80]}")

# Summary
print("\n" + "=" * 60)
print(f"RESULTS: {passed} passed / {failed} failed / {passed + failed} total")
print("=" * 60)
sys.exit(0 if failed == 0 else 1)
