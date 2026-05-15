"""
SENTINEL AI — Storage Validation Test
Verifies MinIO: upload, download, presigned URLs, expiry.
Usage: python storage_test.py
Requires: MinIO running at S3_ENDPOINT (default: http://localhost:9000)
"""
import os
import sys
import time
import asyncio
import uuid

S3_ENDPOINT = os.getenv("S3_ENDPOINT", "http://localhost:9000")
S3_ACCESS_KEY = os.getenv("S3_ACCESS_KEY", "sentinel_admin")
S3_SECRET_KEY = os.getenv("S3_SECRET_KEY", "sentinel_secret")
S3_BUCKET = os.getenv("S3_BUCKET", "sentinel-reports")

passed = 0
failed = 0

def check(name: str, condition: bool, detail: str = ""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        failed += 1
        print(f"  [FAIL] {name}" + (f" — {detail}" if detail else ""))


def get_client():
    import boto3
    from botocore.client import Config
    return boto3.client(
        "s3",
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
        config=Config(signature_version="s3v4"),
        region_name="us-east-1",
    )


print("=" * 60)
print("SENTINEL AI — MinIO/S3 Storage Validation")
print(f"Endpoint: {S3_ENDPOINT}  Bucket: {S3_BUCKET}")
print("=" * 60)

try:
    client = get_client()
except Exception as e:
    print(f"[FATAL] Cannot create S3 client: {e}")
    sys.exit(1)

# 1. Connectivity
print("\n[1] Connectivity")
try:
    client.list_buckets()
    check("MinIO reachable", True)
except Exception as e:
    check("MinIO reachable", False, str(e))
    print("\n[!] MinIO not reachable. Ensure docker-compose is running.")
    sys.exit(1)

# 2. Bucket creation
print("\n[2] Bucket")
try:
    client.head_bucket(Bucket=S3_BUCKET)
    check("Bucket exists", True)
except Exception:
    try:
        client.create_bucket(Bucket=S3_BUCKET)
        check("Bucket created", True)
    except Exception as e:
        check("Bucket create", False, str(e))

# 3. Upload scan log
print("\n[3] Upload Scan Log")
test_scan_id = f"test-{uuid.uuid4().hex[:8]}"
log_key = f"scans/{test_scan_id}/raw.log"
log_content = f"Test scan log for {test_scan_id}\nFindings: 5 (critical: 1, high: 2)\nScore: 72/100"

try:
    client.put_object(
        Bucket=S3_BUCKET, Key=log_key,
        Body=log_content.encode("utf-8"),
        ContentType="text/plain",
        Metadata={"scan-id": test_scan_id},
    )
    check("Upload scan log", True)
    print(f"     Key: s3://{S3_BUCKET}/{log_key}")
except Exception as e:
    check("Upload scan log", False, str(e))

# 4. Download and verify
print("\n[4] Download and Verify")
try:
    obj = client.get_object(Bucket=S3_BUCKET, Key=log_key)
    content = obj["Body"].read().decode("utf-8")
    check("Download scan log", True)
    check("Content matches", content == log_content, f"Got: {content[:50]}")
    check("Metadata preserved", obj.get("Metadata", {}).get("scan-id") == test_scan_id)
except Exception as e:
    check("Download scan log", False, str(e))

# 5. Upload PDF report (binary)
print("\n[5] Upload PDF Report")
report_key = f"reports/{test_scan_id}.pdf"
# Minimal valid PDF bytes
pdf_bytes = b"%PDF-1.4 fake-sentinel-report-for-testing-storage-pipeline"

try:
    client.put_object(
        Bucket=S3_BUCKET, Key=report_key,
        Body=pdf_bytes,
        ContentType="application/pdf",
        Metadata={"scan-id": test_scan_id},
    )
    check("Upload PDF report", True)
    print(f"     Key: s3://{S3_BUCKET}/{report_key}")
except Exception as e:
    check("Upload PDF report", False, str(e))

# 6. Presigned URL generation
print("\n[6] Presigned URLs")
try:
    url = client.generate_presigned_url(
        "get_object",
        Params={"Bucket": S3_BUCKET, "Key": report_key},
        ExpiresIn=3600,
    )
    check("Presigned URL generated", bool(url))
    check("URL contains correct key", report_key in url)
    check("URL has expiry param", "X-Amz-Expires" in url or "Expires" in url)
    print(f"     URL (first 80 chars): {url[:80]}...")
except Exception as e:
    check("Presigned URL", False, str(e))

# 7. Presigned URL accessibility
print("\n[7] URL Accessibility")
try:
    import urllib.request
    req = urllib.request.urlopen(url, timeout=10)
    data = req.read()
    check("Presigned URL is accessible", req.status == 200)
    check("Downloaded data matches upload", data == pdf_bytes)
    print(f"     Downloaded {len(data)} bytes via presigned URL")
except Exception as e:
    check("Presigned URL accessible", False, str(e)[:80])

# 8. List objects
print("\n[8] List Objects")
try:
    resp = client.list_objects_v2(Bucket=S3_BUCKET, Prefix=f"scans/{test_scan_id}/")
    keys = [o["Key"] for o in resp.get("Contents", [])]
    check("Scan log appears in listing", log_key in keys)
    check("Object count correct", len(keys) >= 1, f"Got: {keys}")
    print(f"     Objects in scan prefix: {keys}")
except Exception as e:
    check("List objects", False, str(e))

# 9. Cleanup
print("\n[9] Cleanup")
try:
    client.delete_object(Bucket=S3_BUCKET, Key=log_key)
    client.delete_object(Bucket=S3_BUCKET, Key=report_key)
    check("Test objects cleaned up", True)
except Exception as e:
    check("Cleanup", False, str(e))

# Summary
print("\n" + "=" * 60)
print(f"STORAGE TEST: {passed} PASS | {failed} FAIL | {passed + failed} total")
print("=" * 60)
sys.exit(0 if failed == 0 else 1)
