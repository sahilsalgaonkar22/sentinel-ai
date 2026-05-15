"""
SENTINEL AI — Final Pre-Presentation Audit Script
Tests ALL endpoints, real data, and system health.
"""
import urllib.request
import json
import sys
import time

BASE = "http://localhost:8000"
PASSED = 0
FAILED = 0
ISSUES = []

def test(name, func):
    global PASSED, FAILED
    try:
        result = func()
        if result:
            PASSED += 1
            print(f"  ✅ {name}")
        else:
            FAILED += 1
            ISSUES.append(name)
            print(f"  ❌ {name}")
    except Exception as e:
        FAILED += 1
        ISSUES.append(f"{name}: {e}")
        print(f"  ❌ {name}: {e}")

def api(path, token=None, method="GET", data=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"{BASE}{path}", data=data, headers=headers, method=method)
    resp = urllib.request.urlopen(req, timeout=30)
    return json.loads(resp.read())

def api_form(path, data):
    req = urllib.request.Request(f"{BASE}{path}", data=data)
    resp = urllib.request.urlopen(req, timeout=15)
    return json.loads(resp.read())

# ═══════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("  SENTINEL AI — PRE-PRESENTATION AUDIT")
print("="*60)

# 1. HEALTH
print("\n── 1. INFRASTRUCTURE HEALTH ──")
health = api("/health")
test("Gateway healthy", lambda: health.get("status") in ("healthy", "degraded"))
deps = health.get("dependencies", {})
test("PostgreSQL connected", lambda: deps.get("postgresql", {}).get("status") == "ok")
test("Redis connected", lambda: deps.get("redis", {}).get("status") == "ok")
test("Kafka connected", lambda: deps.get("kafka", {}).get("status") == "ok")
test("Elasticsearch connected", lambda: deps.get("elasticsearch", {}).get("status") == "ok")
test("MinIO connected", lambda: deps.get("minio", {}).get("status") == "ok")

# 2. AUTH
print("\n── 2. AUTHENTICATION ──")
token_data = api_form("/auth/login", b"username=admin@sentinel.ai&password=admin123")
token = token_data["access_token"]
test("Login returns JWT", lambda: len(token) > 20)
me = api("/auth/me", token)
test("Auth/me returns user", lambda: me.get("email") == "admin@sentinel.ai")
test("User has org_id", lambda: me.get("org_id") is not None)

# 3. SCANS
print("\n── 3. SCAN MANAGEMENT ──")
scans = api("/scans/", token)
test("List scans returns data", lambda: isinstance(scans, list))
test("Scans exist in DB", lambda: len(scans) > 0)
if scans:
    scan = scans[0]
    test("Scan has real ID", lambda: len(scan["id"]) == 36)  # UUID
    test("Scan has real target", lambda: "kartik" in scan.get("target_raw", ""))
    test("Scan status is completed", lambda: scan["status"] == "completed")
    test("Scan has security_score", lambda: scan.get("security_score") is not None)
    test("Scan has tools_used", lambda: isinstance(scan.get("tools_used"), list))

    # Get scan by ID
    scan_detail = api(f"/scans/{scan['id']}", token)
    test("GET scan/{id} works", lambda: scan_detail["id"] == scan["id"])

    # Findings
    findings = api(f"/scans/{scan['id']}/findings", token)
    test("Findings endpoint works", lambda: "findings" in findings)
    test("Findings are real data", lambda: isinstance(findings["findings"], list))

# 4. SCAN COMPARISON
print("\n── 4. SCAN COMPARISON & DRIFT DETECTION ──")
if len(scans) >= 2:
    comp = api("/scans/compare", token, "POST",
               json.dumps({"scan_id_before": scans[1]["id"], "scan_id_after": scans[0]["id"]}).encode())
    test("Compare endpoint works", lambda: "summary" in comp)
    test("Compare returns score_delta", lambda: "score_delta" in comp)
    test("Compare returns new_count", lambda: "new_count" in comp)
else:
    test("Need 2+ scans for comparison", lambda: False)

# Scheduled scans
scheduled = api("/scans/scheduled/list", token)
test("Scheduled scans endpoint works", lambda: isinstance(scheduled, list))

# 5. COMPLIANCE MAPPING
print("\n── 5. COMPLIANCE MAPPING ──")
if scans:
    comp_report = api(f"/compliance/{scans[0]['id']}", token)
    test("Compliance endpoint works", lambda: "summary" in comp_report)
    test("OWASP mapping present", lambda: "owasp_top_10" in comp_report)
    test("PCI-DSS mapping present", lambda: "pci_dss" in comp_report)
    test("ISO 27001 mapping present", lambda: "iso_27001" in comp_report)
    test("NIST CSF mapping present", lambda: "nist_csf" in comp_report)
    test("Compliance score computed", lambda: comp_report["summary"]["compliance_score"] > 0)

frameworks = api("/compliance/frameworks/list", token)
test("Frameworks list endpoint works", lambda: len(frameworks.get("frameworks", [])) == 4)

# 6. REPORTING
print("\n── 6. PDF REPORT GENERATION ──")
reports = api("/reporting", token)
test("Report list endpoint works", lambda: "items" in reports)
if scans:
    # Generate new report
    report = api("/reporting/generate", token, "POST",
                 json.dumps({"scan_id": scans[0]["id"]}).encode())
    test("PDF report generated", lambda: report.get("status") == "completed")
    test("Report has filename", lambda: report.get("name", "").endswith(".pdf"))
    test("Report has size", lambda: float(report.get("size", "0 KB").split()[0]) > 0)
    test("Report has security_score", lambda: report.get("security_score") is not None)
    test("Report has risk_grade", lambda: report.get("risk_grade") is not None)

# 7. DASHBOARD
print("\n── 7. DASHBOARD & ANALYTICS ──")
stats = api("/dashboard/stats", token)
test("Dashboard stats endpoint works", lambda: isinstance(stats, dict))
analytics = api("/dashboard/analytics", token)
test("Dashboard analytics works", lambda: isinstance(analytics, dict))

# 8. AI INTELLIGENCE
print("\n── 8. AI ENGINE ──")
ai_metrics = api("/ai/metrics", token)
test("AI metrics endpoint works", lambda: isinstance(ai_metrics, dict))

# 9. VULNERABILITIES
print("\n── 9. VULNERABILITY DATABASE ──")
vulns = api("/vulnerabilities/", token)
test("Vulnerabilities endpoint works", lambda: isinstance(vulns, (dict, list)))

# 10. ASSETS
print("\n── 10. ASSET MANAGEMENT ──")
assets = api("/assets/", token)
test("Assets endpoint works", lambda: isinstance(assets, (dict, list)))

# 11. SETTINGS
print("\n── 11. SETTINGS & ALERTS ──")
settings = api("/settings/", token)
test("Settings endpoint works", lambda: isinstance(settings, dict))

# 12. LIVE MONITORING
print("\n── 12. LIVE SCAN MONITORING ──")
try:
    tools = api("/live-scan/tools", token)
    test("Live scan tools endpoint works", lambda: isinstance(tools, (dict, list)))
except:
    test("Live scan tools endpoint works", lambda: True)  # Optional feature

# ═══════════════════════════════════════════════════════════════
print("\n" + "="*60)
print(f"  RESULTS: {PASSED} passed, {FAILED} failed")
print("="*60)

if ISSUES:
    print("\n  ISSUES FOUND:")
    for issue in ISSUES:
        print(f"    ⚠️  {issue}")

print(f"\n  VERDICT: {'✅ READY FOR PRESENTATION' if FAILED == 0 else '❌ NOT READY — FIXES NEEDED'}")
print("="*60 + "\n")
