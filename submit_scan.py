"""Submit a scan via the API."""
import urllib.request
import json

# Login
login_data = b"username=admin@sentinel.ai&password=admin123"
login_req = urllib.request.Request("http://localhost:8000/auth/login", data=login_data)
token = json.loads(urllib.request.urlopen(login_req).read())["access_token"]
print("Logged in OK")

# Submit scan
scan_data = json.dumps({
    "name": "Advanced Security Audit - kartik-rathi.site",
    "scan_type": "full",
    "target_raw": "https://www.kartik-rathi.site/"
}).encode()
scan_req = urllib.request.Request(
    "http://localhost:8000/scans/",
    data=scan_data,
    headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"}
)
result = json.loads(urllib.request.urlopen(scan_req).read())
print("Scan ID:", result["id"])
print("Status:", result["status"])
