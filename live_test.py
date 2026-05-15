"""
Live bandit scan test - proves real tool execution.
"""
import sys, subprocess, json, shutil
sys.path.insert(0, '.')

print("=== LIVE BANDIT SCAN TEST ===")
bandit_bin = shutil.which("bandit")
print("bandit binary:", bandit_bin)

if bandit_bin:
    cmd = [bandit_bin, "-r", "backend", "-f", "json", "-ll", "--quiet"]
    print("Running:", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    
    raw = result.stdout or result.stderr
    try:
        data = json.loads(raw)
        issues = data.get("results", [])
        print(f"\nSCAN COMPLETE: {len(issues)} findings from real code analysis")
        for i, issue in enumerate(issues[:5]):
            print(f"\n  [{i+1}] {issue.get('test_id')} - {issue.get('issue_text','')[:60]}")
            print(f"       File: {issue.get('filename','')} line {issue.get('line_number',0)}")
            print(f"       Severity: {issue.get('issue_severity','?')}")
    except json.JSONDecodeError:
        print("Parse error. Raw output (first 500 chars):", raw[:500])
else:
    print("BANDIT NOT FOUND - socket fallback would be used for network scans")

print("\n=== PORT PROBE TEST ===")
import socket
targets = [("localhost", 5432, "PostgreSQL"), ("localhost", 6379, "Redis"), ("localhost", 9092, "Kafka")]
for host, port, name in targets:
    s = socket.socket()
    s.settimeout(1)
    r = s.connect_ex((host, port))
    s.close()
    print(f"  {name} :{port}: {'OPEN' if r == 0 else 'CLOSED'}")

print("\n=== HTTP SECURITY CHECK TEST ===")
try:
    import httpx
    url = "https://httpbin.org"
    resp = httpx.get(url, timeout=10, follow_redirects=True)
    headers = dict(resp.headers)
    print(f"  Connected to {url} (status {resp.status_code})")
    security_headers = ["content-security-policy", "strict-transport-security", "x-frame-options"]
    for h in security_headers:
        present = h in headers
        print(f"  {h}: {'PRESENT' if present else 'MISSING'}")
    print("  Server:", headers.get("server", "not disclosed"))
    print("  REAL HTTP analysis confirmed - findings generated from actual response")
except Exception as e:
    print(f"  HTTP test error: {e}")
