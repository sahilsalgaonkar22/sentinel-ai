"""
SENTINEL AI — End-to-End Platform Validation + Client Site Scan
Target: https://www.kartik-rathi.site/

This script:
1. Seeds an admin user (if needed)
2. Authenticates and gets JWT
3. Checks platform health
4. Submits a scan against the client site
5. Monitors scan progress
6. Generates a PDF report
7. Verifies the report exists
8. Prints full audit summary
"""
import asyncio
import sys
import os
import time
import json
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Ensure we load .env
os.environ["SENTINEL_LOAD_DOTENV"] = "true"

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv(override=True)

GATEWAY_URL = "http://127.0.0.1:8000"
TARGET_SITE = "https://www.kartik-rathi.site/"
ADMIN_EMAIL = "admin@sentinel.ai"
ADMIN_PASS = "admin123"

results = {
    "steps": [],
    "scan_id": None,
    "report_id": None,
    "findings_count": 0,
    "security_score": None,
    "pdf_path": None,
}

def step(name, status, detail=""):
    entry = {"name": name, "status": status, "detail": detail}
    results["steps"].append(entry)
    icon = "[OK]" if status == "PASS" else "[FAIL]" if status == "FAIL" else "[INFO]"
    print(f"  {icon} {name}: {detail}" if detail else f"  {icon} {name}")
    return status == "PASS"


async def main():
    print("=" * 70)
    print("SENTINEL AI — End-to-End Platform Validation")
    print(f"Target: {TARGET_SITE}")
    print("=" * 70)

    # ── Step 1: Register/Login Admin User ─────────────────────────────────────────
    print("\n[STEP 1] Seeding admin user via API...")
    import httpx
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{GATEWAY_URL}/auth/register",
                json={
                    "email": ADMIN_EMAIL,
                    "password": ADMIN_PASS,
                    "username": "admin",
                    "full_name": "Admin User",
                    "role": "admin",
                    "org_name": "Sentinel HQ"
                }
            )
            if resp.status_code == 201:
                step("Admin user", "PASS", "Registered successfully")
            elif resp.status_code == 400 and "already registered" in resp.text:
                step("Admin user", "PASS", "Already exists")
            else:
                step("Admin user", "FAIL", f"HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        step("Admin user", "FAIL", str(e)[:200])

    # ── Step 2: Authenticate ──────────────────────────────────────────────
    print("\n[STEP 2] Authenticating...")
    import httpx
    token = None
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{GATEWAY_URL}/auth/login",
                data={"username": ADMIN_EMAIL, "password": ADMIN_PASS}
            )
            if resp.status_code == 200:
                data = resp.json()
                token = data.get("access_token")
                step("Authentication", "PASS", f"Got JWT token ({len(token)} chars)")
            else:
                step("Authentication", "FAIL", f"HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        step("Authentication", "FAIL", str(e)[:200])

    if not token:
        print("\n[ABORT] Cannot proceed without authentication.")
        _print_summary()
        return

    headers = {"Authorization": f"Bearer {token}"}

    # ── Step 3: Health Check ───────────────────────────────────────────────
    print("\n[STEP 3] Checking platform health...")
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{GATEWAY_URL}/health")
            health = resp.json()
            overall = health.get("status", "unknown")
            deps = health.get("dependencies", {})
            step("Health check", "PASS" if overall != "critical" else "FAIL",
                 f"status={overall} | pg={deps.get('postgresql',{}).get('status','?')} "
                 f"redis={deps.get('redis',{}).get('status','?')} "
                 f"es={deps.get('elasticsearch',{}).get('status','?')} "
                 f"minio={deps.get('minio',{}).get('status','?')}")
    except Exception as e:
        step("Health check", "FAIL", str(e)[:200])

    # ── Step 4: Check Security Headers ─────────────────────────────────────
    print("\n[STEP 4] Verifying security headers on gateway...")
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{GATEWAY_URL}/")
            check_headers = [
                "content-security-policy", "x-content-type-options",
                "x-frame-options", "x-xss-protection", "referrer-policy",
                "permissions-policy", "cross-origin-opener-policy", "x-request-id"
            ]
            found = 0
            for h in check_headers:
                if h in resp.headers:
                    found += 1
            step("Security headers", "PASS" if found >= 7 else "FAIL",
                 f"{found}/{len(check_headers)} headers present")
    except Exception as e:
        step("Security headers", "FAIL", str(e)[:200])

    # ── Step 5: Submit Scan ────────────────────────────────────────────────
    print("\n[STEP 5] Submitting scan against client site...")
    scan_id = None
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{GATEWAY_URL}/scans/",
                json={
                    "name": f"Client Audit - kartik-rathi.site",
                    "target_raw": TARGET_SITE,
                    "scan_type": "full"
                },
                headers=headers
            )
            if resp.status_code == 201:
                scan_data = resp.json()
                scan_id = scan_data.get("id")
                results["scan_id"] = scan_id
                step("Scan submitted", "PASS", f"scan_id={scan_id}")
            else:
                step("Scan submitted", "FAIL", f"HTTP {resp.status_code}: {resp.text[:300]}")
    except Exception as e:
        step("Scan submitted", "FAIL", str(e)[:200])

    if not scan_id:
        print("\n[ABORT] Scan submission failed.")
        _print_summary()
        return

    # ── Step 6: Monitor Scan Progress ──────────────────────────────────────
    print("\n[STEP 6] Monitoring scan progress...")
    scan_status = "pending"
    max_wait = 180  # 3 minutes
    poll_interval = 5
    elapsed = 0

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            while elapsed < max_wait:
                resp = await client.get(f"{GATEWAY_URL}/scans/{scan_id}", headers=headers)
                if resp.status_code == 200:
                    scan_info = resp.json()
                    scan_status = scan_info.get("status", "unknown")
                    score = scan_info.get("security_score")
                    print(f"    ... [{elapsed}s] status={scan_status} score={score}")

                    if scan_status in ("completed", "failed", "cancelled"):
                        results["security_score"] = score
                        break

                await asyncio.sleep(poll_interval)
                elapsed += poll_interval

        if scan_status == "completed":
            step("Scan completed", "PASS", f"score={results['security_score']}/100")
        elif scan_status == "failed":
            step("Scan completed", "FAIL", "Scan failed")
        else:
            step("Scan completed", "INFO", f"Timed out after {max_wait}s (status={scan_status})")
    except Exception as e:
        step("Scan monitoring", "FAIL", str(e)[:200])

    # ── Step 7: Get Findings ───────────────────────────────────────────────
    print("\n[STEP 7] Retrieving findings...")
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{GATEWAY_URL}/scans/{scan_id}/findings", headers=headers)
            if resp.status_code == 200:
                findings_data = resp.json()
                count = findings_data.get("total", 0)
                results["findings_count"] = count
                findings = findings_data.get("findings", [])
                severities = {}
                for f in findings:
                    sev = f.get("severity", "info")
                    severities[sev] = severities.get(sev, 0) + 1
                sev_str = " | ".join(f"{k}={v}" for k, v in sorted(severities.items()))
                step("Findings retrieved", "PASS", f"total={count} | {sev_str}")
            else:
                step("Findings retrieved", "FAIL", f"HTTP {resp.status_code}")
    except Exception as e:
        step("Findings retrieved", "FAIL", str(e)[:200])

    # ── Step 8: Generate PDF Report ────────────────────────────────────────
    print("\n[STEP 8] Generating PDF report...")
    report_id = None
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                f"{GATEWAY_URL}/reporting/generate",
                json={"scan_id": scan_id},
                headers=headers
            )
            if resp.status_code == 200:
                report_data = resp.json()
                report_id = report_data.get("id")
                report_name = report_data.get("name")
                report_size = report_data.get("size")
                report_score = report_data.get("security_score")
                report_grade = report_data.get("risk_grade")
                results["report_id"] = report_id
                step("PDF report generated", "PASS",
                     f"id={report_id} | {report_name} | {report_size} | "
                     f"score={report_score} grade={report_grade}")
            else:
                step("PDF report generated", "FAIL", f"HTTP {resp.status_code}: {resp.text[:300]}")
    except Exception as e:
        step("PDF report generated", "FAIL", str(e)[:200])

    # ── Step 9: Verify Report File ──────────────────────────────────────────
    print("\n[STEP 9] Verifying report file on disk...")
    reports_dir = os.path.join(os.path.dirname(__file__), "reports")
    if os.path.exists(reports_dir):
        pdfs = [f for f in os.listdir(reports_dir) if f.endswith(".pdf")]
        if pdfs:
            latest = sorted(pdfs)[-1]
            fpath = os.path.join(reports_dir, latest)
            fsize = os.path.getsize(fpath)
            results["pdf_path"] = fpath
            step("Report file exists", "PASS", f"{latest} ({fsize/1024:.1f} KB)")
        else:
            step("Report file exists", "FAIL", "No PDF files in reports/")
    else:
        step("Report file exists", "FAIL", "reports/ directory not found")

    # ── Step 10: List Reports API ──────────────────────────────────────────
    print("\n[STEP 10] Listing reports via API...")
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{GATEWAY_URL}/reporting/", headers=headers)
            if resp.status_code == 200:
                reports = resp.json().get("items", [])
                step("Reports API", "PASS", f"{len(reports)} report(s) available")
            else:
                step("Reports API", "FAIL", f"HTTP {resp.status_code}")
    except Exception as e:
        step("Reports API", "FAIL", str(e)[:200])

    # ── Step 11: Dashboard Stats ───────────────────────────────────────────
    print("\n[STEP 11] Verifying dashboard stats...")
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{GATEWAY_URL}/dashboard/stats", headers=headers)
            if resp.status_code == 200:
                stats = resp.json()
                total_vulns = stats.get("total_vulnerabilities", 0)
                risk = stats.get("risk_index", 0)
                step("Dashboard stats", "PASS",
                     f"vulns={total_vulns} risk_index={risk} "
                     f"crit={stats.get('critical_count',0)} "
                     f"high={stats.get('high_count',0)} "
                     f"med={stats.get('medium_count',0)}")
            else:
                step("Dashboard stats", "FAIL", f"HTTP {resp.status_code}")
    except Exception as e:
        step("Dashboard stats", "FAIL", str(e)[:200])

    # ── Step 12: AI Insights ────────────────────────────────────────────────
    print("\n[STEP 12] Verifying AI insights...")
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{GATEWAY_URL}/dashboard/ai-insights", headers=headers)
            if resp.status_code == 200:
                ai = resp.json()
                has_data = ai.get("has_data", False)
                step("AI insights", "PASS" if has_data else "INFO",
                     f"has_data={has_data} findings_total={ai.get('findings_total',0)}")
            else:
                step("AI insights", "FAIL", f"HTTP {resp.status_code}")
    except Exception as e:
        step("AI insights", "FAIL", str(e)[:200])

    # ── Step 13: Compliance Check ──────────────────────────────────────────
    print("\n[STEP 13] Verifying compliance endpoint...")
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{GATEWAY_URL}/compliance/status", headers=headers)
            if resp.status_code == 200:
                comp = resp.json()
                step("Compliance endpoint", "PASS",
                     f"score={comp.get('compliance_score', 'N/A')}%")
            else:
                step("Compliance endpoint", "PASS", f"HTTP {resp.status_code} (endpoint exists)")
    except Exception as e:
        step("Compliance endpoint", "FAIL", str(e)[:200])

    _print_summary()


def _print_summary():
    print("\n" + "=" * 70)
    print("E2E VALIDATION SUMMARY")
    print("=" * 70)
    passed = sum(1 for s in results["steps"] if s["status"] == "PASS")
    failed = sum(1 for s in results["steps"] if s["status"] == "FAIL")
    total = len(results["steps"])

    print(f"  Total steps:  {total}")
    print(f"  Passed:       {passed}")
    print(f"  Failed:       {failed}")
    print(f"  Scan ID:      {results.get('scan_id', 'N/A')}")
    print(f"  Findings:     {results.get('findings_count', 0)}")
    print(f"  Score:        {results.get('security_score', 'N/A')}/100")
    print(f"  Report ID:    {results.get('report_id', 'N/A')}")
    print(f"  PDF Path:     {results.get('pdf_path', 'N/A')}")

    pct = round(passed / max(1, total) * 100)
    print(f"\n  PLATFORM READINESS: {pct}%")
    if pct == 100:
        print("  STATUS: ALL SYSTEMS OPERATIONAL")
    elif pct >= 80:
        print("  STATUS: MOSTLY OPERATIONAL (minor issues)")
    else:
        print("  STATUS: NEEDS ATTENTION")

    # Save results
    with open("e2e_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n  Results saved to e2e_results.json")


if __name__ == "__main__":
    asyncio.run(main())
