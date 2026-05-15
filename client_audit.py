"""
SENTINEL AI - Client Site Comprehensive Audit Script
Target: https://www.kartik-rathi.site/
"""
import ssl
import socket
import json
import urllib.request
import urllib.error
import time
import sys
import io
from datetime import datetime
from urllib.parse import urlparse

# Fix Windows encoding
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

TARGET = "https://www.kartik-rathi.site/"
DOMAIN = "www.kartik-rathi.site"

results = {
    "target": TARGET,
    "domain": DOMAIN,
    "scan_time": datetime.now().isoformat(),
    "tests": {}
}

def log(section, msg):
    print(f"[{section}] {msg}")

# ============================================================
# TEST 1: DNS Resolution
# ============================================================
print("=" * 60)
print("TEST 1: DNS RESOLUTION")
print("=" * 60)
try:
    ip = socket.gethostbyname(DOMAIN)
    log("DNS", f"Resolved {DOMAIN} -> {ip}")
    results["tests"]["dns"] = {"status": "PASS", "ip": ip}
except Exception as e:
    log("DNS", f"FAILED: {e}")
    results["tests"]["dns"] = {"status": "FAIL", "error": str(e)}

# ============================================================
# TEST 2: SSL/TLS Certificate Analysis
# ============================================================
print("\n" + "=" * 60)
print("TEST 2: SSL/TLS CERTIFICATE ANALYSIS")
print("=" * 60)
try:
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=DOMAIN) as s:
        s.settimeout(10)
        s.connect((DOMAIN, 443))
        cert = s.getpeercert()
        cipher = s.cipher()
        protocol = s.version()

    subject = dict(x[0] for x in cert.get('subject', ()))
    issuer = dict(x[0] for x in cert.get('issuer', ()))
    not_before = cert.get('notBefore', 'N/A')
    not_after = cert.get('notAfter', 'N/A')
    san = [entry[1] for entry in cert.get('subjectAltName', ())]

    log("SSL", f"Protocol: {protocol}")
    log("SSL", f"Cipher: {cipher[0]} ({cipher[2]}-bit)")
    log("SSL", f"Subject CN: {subject.get('commonName', 'N/A')}")
    log("SSL", f"Issuer: {issuer.get('organizationName', 'N/A')}")
    log("SSL", f"Valid From: {not_before}")
    log("SSL", f"Valid Until: {not_after}")
    log("SSL", f"SANs: {', '.join(san)}")

    results["tests"]["ssl"] = {
        "status": "PASS",
        "protocol": protocol,
        "cipher": cipher[0],
        "bits": cipher[2],
        "issuer": issuer.get('organizationName', 'N/A'),
        "cn": subject.get('commonName', 'N/A'),
        "valid_from": not_before,
        "valid_until": not_after,
        "sans": san
    }
except Exception as e:
    log("SSL", f"FAILED: {e}")
    results["tests"]["ssl"] = {"status": "FAIL", "error": str(e)}

# ============================================================
# TEST 3: HTTP Response & Security Headers
# ============================================================
print("\n" + "=" * 60)
print("TEST 3: HTTP RESPONSE & SECURITY HEADERS")
print("=" * 60)

SECURITY_HEADERS = {
    "Strict-Transport-Security": {"critical": True, "desc": "HSTS - Forces HTTPS"},
    "Content-Security-Policy": {"critical": True, "desc": "CSP - Prevents XSS/injection"},
    "X-Content-Type-Options": {"critical": True, "desc": "Prevents MIME sniffing"},
    "X-Frame-Options": {"critical": True, "desc": "Prevents clickjacking"},
    "X-XSS-Protection": {"critical": False, "desc": "Legacy XSS filter"},
    "Referrer-Policy": {"critical": False, "desc": "Controls referer information"},
    "Permissions-Policy": {"critical": False, "desc": "Controls browser features"},
    "Cross-Origin-Opener-Policy": {"critical": False, "desc": "Cross-origin isolation"},
    "Cross-Origin-Resource-Policy": {"critical": False, "desc": "Cross-origin resource loading"},
}

try:
    req = urllib.request.Request(TARGET, method="GET")
    req.add_header("User-Agent", "SentinelAI-Scanner/1.0")
    start = time.time()
    resp = urllib.request.urlopen(req, timeout=15)
    elapsed = round(time.time() - start, 3)

    status = resp.status
    headers = dict(resp.headers)

    log("HTTP", f"Status: {status}")
    log("HTTP", f"Response Time: {elapsed}s")
    log("HTTP", f"Server: {headers.get('Server', 'Not disclosed')}")
    log("HTTP", f"Content-Type: {headers.get('Content-Type', 'N/A')}")

    print("\n--- Security Headers ---")
    header_results = {}
    found = 0
    missing = 0
    for h, info in SECURITY_HEADERS.items():
        val = headers.get(h)
        if val:
            found += 1
            log("HDR", f"  [OK] {h}: {val}")
        else:
            missing += 1
            sev = "CRITICAL" if info["critical"] else "WARNING"
            log("HDR", f"  [MISS] {h} -- {sev} -- {info['desc']}")
        header_results[h] = {"present": val is not None, "value": val, "critical": info["critical"]}

    log("HDR", f"\nScore: {found}/{found+missing} headers present")

    results["tests"]["http"] = {
        "status": "PASS",
        "response_code": status,
        "response_time_s": elapsed,
        "server": headers.get("Server", "Not disclosed"),
        "headers_found": found,
        "headers_missing": missing,
        "header_details": header_results,
        "all_headers": headers
    }
except Exception as e:
    log("HTTP", f"FAILED: {e}")
    results["tests"]["http"] = {"status": "FAIL", "error": str(e)}

# ============================================================
# TEST 4: HTTPS Redirect Check
# ============================================================
print("\n" + "=" * 60)
print("TEST 4: HTTP->HTTPS REDIRECT")
print("=" * 60)
try:
    req = urllib.request.Request(f"http://{DOMAIN}/", method="GET")
    req.add_header("User-Agent", "SentinelAI-Scanner/1.0")
    resp = urllib.request.urlopen(req, timeout=15)
    final_url = resp.url
    if final_url.startswith("https://"):
        log("REDIRECT", f"HTTP->HTTPS redirect: WORKING (-> {final_url})")
        results["tests"]["https_redirect"] = {"status": "PASS", "final_url": final_url}
    else:
        log("REDIRECT", f"WARNING: Final URL not HTTPS: {final_url}")
        results["tests"]["https_redirect"] = {"status": "WARN", "final_url": final_url}
except Exception as e:
    log("REDIRECT", f"Redirect check: {e}")
    results["tests"]["https_redirect"] = {"status": "CHECK", "note": str(e)}

# ============================================================
# TEST 5: robots.txt & sitemap.xml
# ============================================================
print("\n" + "=" * 60)
print("TEST 5: ROBOTS.TXT & SITEMAP.XML")
print("=" * 60)
for path in ["/robots.txt", "/sitemap.xml"]:
    try:
        req = urllib.request.Request(f"https://{DOMAIN}{path}", method="GET")
        req.add_header("User-Agent", "SentinelAI-Scanner/1.0")
        resp = urllib.request.urlopen(req, timeout=10)
        log("SEO", f"  {path}: {resp.status} (FOUND)")
        results["tests"][path.strip("/")] = {"status": "FOUND", "code": resp.status}
    except urllib.error.HTTPError as e:
        log("SEO", f"  {path}: {e.code} (MISSING)")
        results["tests"][path.strip("/")] = {"status": "MISSING", "code": e.code}
    except Exception as e:
        log("SEO", f"  {path}: ERROR ({e})")
        results["tests"][path.strip("/")] = {"status": "ERROR", "error": str(e)}

# ============================================================
# TEST 6: Subpage & Link Accessibility
# ============================================================
print("\n" + "=" * 60)
print("TEST 6: SUBPAGE & LINK ACCESSIBILITY")
print("=" * 60)
pages = [
    ("Main Site", "https://www.kartik-rathi.site/"),
    ("Agent Demos", "https://www.kartik-rathi.site/agent-demos"),
    ("RAG Experiments", "https://www.kartik-rathi.site/rag-experiments"),
    ("Statly (subdomain)", "https://statly.kartik-rathi.site/"),
    ("PathGenie (subdomain)", "https://pathgenie.kartik-rathi.site/"),
    ("Code Assist (subdomain)", "https://code-assist.kartik-rathi.site/"),
    ("Cal.com Booking", "https://cal.com/devkartikrathi/30min"),
]

page_results = {}
for name, url in pages:
    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "SentinelAI-Scanner/1.0")
        start = time.time()
        resp = urllib.request.urlopen(req, timeout=15)
        elapsed = round(time.time() - start, 3)
        log("PAGE", f"  [OK] {name}: {resp.status} ({elapsed}s)")
        page_results[name] = {"url": url, "status": resp.status, "time_s": elapsed, "result": "OK"}
    except urllib.error.HTTPError as e:
        log("PAGE", f"  [ERR] {name}: HTTP {e.code}")
        page_results[name] = {"url": url, "status": e.code, "result": "ERROR"}
    except Exception as e:
        log("PAGE", f"  [ERR] {name}: {e}")
        page_results[name] = {"url": url, "status": 0, "result": "UNREACHABLE", "error": str(e)}

results["tests"]["pages"] = page_results

# ============================================================
# TEST 7: Common Vulnerability Paths
# ============================================================
print("\n" + "=" * 60)
print("TEST 7: SENSITIVE PATH EXPOSURE CHECK")
print("=" * 60)
vuln_paths = [
    "/.env", "/.git/config", "/wp-admin", "/admin", "/api",
    "/.well-known/security.txt", "/server-status", "/phpinfo.php",
    "/.DS_Store", "/backup.zip", "/debug", "/.htaccess",
    "/graphql", "/api/v1", "/swagger.json", "/openapi.json"
]

path_results = {}
for path in vuln_paths:
    try:
        req = urllib.request.Request(f"https://{DOMAIN}{path}", method="GET")
        req.add_header("User-Agent", "SentinelAI-Scanner/1.0")
        resp = urllib.request.urlopen(req, timeout=8)
        code = resp.status
        if code == 200:
            log("VULN", f"  [!!] {path}: ACCESSIBLE (200) -- POTENTIAL EXPOSURE")
        else:
            log("VULN", f"  [~~] {path}: {code}")
        risk = "HIGH" if code == 200 and path in ["/.env","/.git/config"] else "INFO"
        path_results[path] = {"code": code, "risk": risk}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            log("VULN", f"  [OK] {path}: 404 (Safe)")
        elif e.code == 403:
            log("VULN", f"  [OK] {path}: 403 (Blocked)")
        else:
            log("VULN", f"  [~~] {path}: {e.code}")
        path_results[path] = {"code": e.code, "risk": "NONE"}
    except Exception as e:
        log("VULN", f"  [??] {path}: {e}")
        path_results[path] = {"code": 0, "risk": "UNKNOWN", "error": str(e)}

results["tests"]["sensitive_paths"] = path_results

# ============================================================
# TEST 8: Cookie Security
# ============================================================
print("\n" + "=" * 60)
print("TEST 8: COOKIE SECURITY")
print("=" * 60)
try:
    req = urllib.request.Request(TARGET, method="GET")
    req.add_header("User-Agent", "SentinelAI-Scanner/1.0")
    resp = urllib.request.urlopen(req, timeout=15)
    cookies = resp.headers.get_all("Set-Cookie") or []
    if not cookies:
        log("COOKIE", "No cookies set on main page (OK for static site)")
        results["tests"]["cookies"] = {"status": "NONE", "count": 0}
    else:
        cookie_analysis = []
        for c in cookies:
            flags = {
                "httponly": "httponly" in c.lower(),
                "secure": "secure" in c.lower(),
                "samesite": "samesite" in c.lower()
            }
            issues = [k for k, v in flags.items() if not v]
            log("COOKIE", f"  Cookie: {c[:60]}...")
            if issues:
                log("COOKIE", f"    Missing flags: {', '.join(issues)}")
            cookie_analysis.append({"value": c[:80], "flags": flags, "issues": issues})
        results["tests"]["cookies"] = {"status": "FOUND", "count": len(cookies), "details": cookie_analysis}
except Exception as e:
    log("COOKIE", f"Error: {e}")
    results["tests"]["cookies"] = {"status": "ERROR", "error": str(e)}

# ============================================================
# TEST 9: Technology Detection
# ============================================================
print("\n" + "=" * 60)
print("TEST 9: TECHNOLOGY FINGERPRINTING")
print("=" * 60)
try:
    req = urllib.request.Request(TARGET)
    req.add_header("User-Agent", "SentinelAI-Scanner/1.0")
    resp = urllib.request.urlopen(req, timeout=15)
    body = resp.read().decode("utf-8", errors="ignore")
    all_headers = dict(resp.headers)

    tech_signals = {
        "Next.js": ["_next/", "__next", "next/", "__NEXT_DATA__"],
        "React": ["react", "React", "__REACT"],
        "Vue.js": ["vue.js", "__vue__", "Vue."],
        "Vercel": ["vercel", ".vercel.app"],
        "Netlify": ["netlify", ".netlify.app"],
        "Cloudflare": ["cloudflare", "cf-ray"],
        "WordPress": ["wp-content", "wp-includes"],
        "Vite": ["vite", "@vitejs"],
        "TailwindCSS": ["tailwindcss", "tailwind"],
        "GSAP": ["gsap", "ScrollTrigger"],
        "Three.js": ["three.js", "THREE"],
        "Framer Motion": ["framer-motion"],
    }

    detected = []
    for tech, signals in tech_signals.items():
        for sig in signals:
            if sig in body or sig in str(all_headers):
                detected.append(tech)
                break

    server = all_headers.get("Server", "")
    x_powered = all_headers.get("X-Powered-By", "")
    cf_ray = all_headers.get("CF-Ray", "")

    if cf_ray:
        detected.append("Cloudflare CDN")
    if "vercel" in server.lower():
        detected.append("Vercel Hosting")
    if x_powered:
        detected.append(f"X-Powered-By: {x_powered}")

    log("TECH", f"Detected technologies: {', '.join(set(detected)) if detected else 'Unable to determine'}")
    results["tests"]["technology"] = {"detected": list(set(detected))}
except Exception as e:
    log("TECH", f"Error: {e}")
    results["tests"]["technology"] = {"error": str(e)}

# ============================================================
# TEST 10: Performance Metrics
# ============================================================
print("\n" + "=" * 60)
print("TEST 10: PERFORMANCE METRICS")
print("=" * 60)
try:
    times = []
    sizes = []
    for i in range(3):
        req = urllib.request.Request(TARGET)
        req.add_header("User-Agent", "SentinelAI-Scanner/1.0")
        start = time.time()
        resp = urllib.request.urlopen(req, timeout=15)
        data = resp.read()
        elapsed = round(time.time() - start, 3)
        times.append(elapsed)
        sizes.append(len(data))
        log("PERF", f"  Request {i+1}: {elapsed}s ({len(data)} bytes)")

    avg = round(sum(times) / len(times), 3)
    avg_size = round(sum(sizes) / len(sizes))
    log("PERF", f"  Average: {avg}s | Avg Size: {avg_size} bytes")
    log("PERF", f"  Rating: {'GOOD' if avg < 1 else 'FAIR' if avg < 2 else 'SLOW'}")
    results["tests"]["performance"] = {"times": times, "avg": avg, "avg_size_bytes": avg_size, "rating": 'GOOD' if avg < 1 else 'FAIR' if avg < 2 else 'SLOW'}
except Exception as e:
    log("PERF", f"Error: {e}")
    results["tests"]["performance"] = {"error": str(e)}

# ============================================================
# TEST 11: Subdomain SSL checks
# ============================================================
print("\n" + "=" * 60)
print("TEST 11: SUBDOMAIN SSL VERIFICATION")
print("=" * 60)
subdomains = ["statly.kartik-rathi.site", "pathgenie.kartik-rathi.site", "code-assist.kartik-rathi.site"]
subdomain_ssl = {}
for sub in subdomains:
    try:
        ctx2 = ssl.create_default_context()
        with ctx2.wrap_socket(socket.socket(), server_hostname=sub) as s2:
            s2.settimeout(10)
            s2.connect((sub, 443))
            cert2 = s2.getpeercert()
            proto2 = s2.version()
        issuer2 = dict(x[0] for x in cert2.get('issuer', ()))
        log("SUB-SSL", f"  [OK] {sub}: {proto2} | Issuer: {issuer2.get('organizationName','N/A')}")
        subdomain_ssl[sub] = {"status": "PASS", "protocol": proto2, "issuer": issuer2.get('organizationName','N/A')}
    except Exception as e:
        log("SUB-SSL", f"  [ERR] {sub}: {e}")
        subdomain_ssl[sub] = {"status": "FAIL", "error": str(e)}

results["tests"]["subdomain_ssl"] = subdomain_ssl

# ============================================================
# SAVE RESULTS
# ============================================================
print("\n" + "=" * 60)
print("SCAN COMPLETE")
print("=" * 60)
output_file = "client_audit_results.json"
with open(output_file, "w") as f:
    json.dump(results, f, indent=2)
print(f"\nResults saved to {output_file}")

# Print summary
print("\n" + "=" * 60)
print("EXECUTIVE SUMMARY")
print("=" * 60)
total_tests = len(results["tests"])
passed = sum(1 for t in results["tests"].values() if isinstance(t, dict) and t.get("status") in ["PASS", "FOUND", "NONE"])
print(f"Total test categories: {total_tests}")
print(f"Tests passed/ok: {passed}")
print(f"Scan completed at: {results['scan_time']}")
