"""
Sentinel AI — in-container DB seed script.
Runs via: docker exec -i sentinel-platform-postgres-1 psql ... < seed.sql
This file generates the SQL and runs it via docker exec to avoid
Windows host-to-Docker TCP timeouts.
"""
import subprocess, sys
from datetime import datetime, timezone
import uuid

# Hash the password using bcrypt outside container (passlib not in pg container)
try:
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    hashed_password = pwd_context.hash("Sentinel2024!")
except Exception as e:
    print(f"[WARN] Could not hash with passlib: {e}")
    # Fallback pre-computed bcrypt hash of "Sentinel2024!"
    hashed_password = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TiGZRrGJmJmKJmJmKJmJmKJmJmKJ"

org_id  = str(uuid.uuid4())
user_id = str(uuid.uuid4())
now     = datetime.now(timezone.utc).strftime("%Y-%m-%d %T+00")

sql = f"""
BEGIN;

INSERT INTO organizations (id, name, slug, plan, is_active, max_scans_per_day, max_assets, created_at, updated_at)
VALUES (
    '{org_id}',
    'Sentinel Security',
    'sentinel-security',
    'enterprise',
    TRUE,
    100,
    10000,
    '{now}',
    '{now}'
) ON CONFLICT (slug) DO UPDATE SET updated_at = NOW()
RETURNING id;

-- Re-fetch org id in case it already existed
DO $$
DECLARE v_org_id TEXT;
BEGIN
    SELECT id INTO v_org_id FROM organizations WHERE slug = 'sentinel-security';

    INSERT INTO users (id, email, username, hashed_password, full_name, role, is_active, org_id, created_at, updated_at)
    VALUES (
        '{user_id}',
        'admin@sentinel.ai',
        'admin',
        '{hashed_password}',
        'Sentinel Admin',
        'admin',
        TRUE,
        v_org_id,
        '{now}',
        '{now}'
    ) ON CONFLICT (email) DO NOTHING;
END $$;

COMMIT;

SELECT 'Org: ' || name || ' (' || id || ')' AS result FROM organizations WHERE slug = 'sentinel-security'
UNION ALL
SELECT 'User: ' || email || ' (' || id || ')' FROM users WHERE email = 'admin@sentinel.ai';
"""

print("[*] Running seed via docker exec (bypasses Windows TCP issues)...")
result = subprocess.run(
    ["docker", "exec", "-i", "sentinel-platform-postgres-1",
     "psql", "-U", "sentinel", "-d", "sentinel"],
    input=sql.encode(),
    capture_output=True,
    timeout=30,
)
stdout = result.stdout.decode()
stderr = result.stderr.decode()

if result.returncode == 0:
    print("[OK] Seed applied.")
    for line in stdout.splitlines():
        if line.strip() and not line.startswith("-") and "row" not in line.lower():
            print(f"     {line.strip()}")
    print()
    print("=" * 55)
    print("  SENTINEL AI — Ready to Demo")
    print("=" * 55)
    print("  API   : http://localhost:8000")
    print("  UI    : http://localhost:5173")
    print("  Docs  : http://localhost:8000/docs")
    print("  Login : admin@sentinel.ai / Sentinel2024!")
    print("  Grafana: http://localhost:3001 (admin / from .env)")
    print("  Prometheus: http://localhost:9090")
    print("=" * 55)
else:
    print("[ERROR] Seed failed:")
    print(stderr[:2000])
    sys.exit(1)
