import shutil, socket, subprocess, sys

tools = ["nmap", "bandit", "semgrep", "nikto", "trivy", "masscan", "pip-audit", "docker"]
print("=== TOOL AVAILABILITY CHECK ===")
for t in tools:
    path = shutil.which(t)
    print(f"  {t}: {'FOUND at ' + path if path else 'NOT FOUND (fallback will be used)'}")

print("\n=== PYTHON PACKAGE CHECK ===")
pkgs = ["confluent_kafka", "fastapi", "sqlalchemy", "httpx", "faiss", "bandit", "numpy", "pandas", "xgboost", "reportlab", "aiobotocore", "boto3"]
for p in pkgs:
    try:
        __import__(p.replace("-", "_"))
        print(f"  {p}: INSTALLED")
    except ImportError:
        print(f"  {p}: NOT INSTALLED")

print("\n=== SOCKET CONNECTIVITY TEST ===")
checks = [
    ("localhost", 9092, "Kafka"),
    ("localhost", 5432, "PostgreSQL"),
    ("localhost", 6379, "Redis"),
    ("localhost", 9000, "MinIO"),
    ("localhost", 8000, "API Gateway"),
    ("localhost", 9200, "Elasticsearch"),
]
for host, port, name in checks:
    try:
        s = socket.socket()
        s.settimeout(2)
        result = s.connect_ex((host, port))
        s.close()
        status = "OPEN (service reachable)" if result == 0 else "CLOSED (service not running)"
        print(f"  {name} ({host}:{port}): {status}")
    except Exception as e:
        print(f"  {name} ({host}:{port}): ERROR - {e}")

print("\n=== CONFIG CHECK ===")
sys.path.insert(0, ".")
try:
    from backend.common.config import settings
    print(f"  EXECUTION_MODE: {settings.EXECUTION_MODE}")
    print(f"  MOCK_WORKERS: {settings.MOCK_WORKERS}")
    print(f"  DATABASE_URL: {settings.DATABASE_URL[:50]}...")
    print(f"  KAFKA_BOOTSTRAP: {settings.KAFKA_BOOTSTRAP_SERVERS}")
    print(f"  S3_ENDPOINT: {settings.S3_ENDPOINT}")
    print(f"  PENTAGI_ENABLED: {settings.PENTAGI_ENABLED}")
except Exception as e:
    print(f"  Config error: {e}")
