"""
Generate the full schema SQL from SQLAlchemy models,
then apply it inside the Docker PostgreSQL container.
"""
import os, sys, subprocess

os.environ["SENTINEL_LOAD_DOTENV"] = "true"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv(".env")

# Import models to register them with Base.metadata
from backend.services.identity.models import User, Organization          # noqa
from backend.services.scan_control.models import Scan, Asset, Finding, AttackPath  # noqa
from backend.common.database import Base

from sqlalchemy.schema import CreateTable
from sqlalchemy.dialects import postgresql

lines = [
    "-- SENTINEL AI — Auto-generated schema",
    "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";",
    "",
    "-- Alembic version tracking table",
    "CREATE TABLE IF NOT EXISTS alembic_version (",
    "    version_num VARCHAR(32) NOT NULL,",
    "    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)",
    ");",
    "",
]

for table in Base.metadata.sorted_tables:
    ddl = str(CreateTable(table).compile(dialect=postgresql.dialect()))
    # Wrap in IF NOT EXISTS
    ddl = ddl.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1)
    lines.append(ddl.strip() + ";")
    lines.append("")

# Stamp alembic version as 'manual'
lines.append("INSERT INTO alembic_version (version_num) VALUES ('initial_manual') ON CONFLICT DO NOTHING;")

sql = "\n".join(lines)

output_file = "schema_migration.sql"
with open(output_file, "w") as f:
    f.write(sql)

table_names = [t.name for t in Base.metadata.sorted_tables]
print(f"[OK] Generated {output_file}")
print(f"[OK] Tables ({len(table_names)}): {table_names}")
print(f"[OK] SQL length: {len(sql)} bytes")

# Apply using docker exec
print("\n[*] Applying schema to Docker postgres...")
result = subprocess.run(
    ["docker", "exec", "-i", "sentinel-platform-postgres-1",
     "psql", "-U", "sentinel", "-d", "sentinel"],
    input=sql.encode(),
    capture_output=True,
    timeout=60,
)
if result.returncode == 0:
    print("[OK] Schema applied successfully")
    print(result.stdout.decode()[:2000])
else:
    print("[ERROR] Schema application failed:")
    print(result.stderr.decode()[:3000])
    sys.exit(1)

# Verify tables
print("\n[*] Verifying tables...")
verify = subprocess.run(
    ["docker", "exec", "-i", "sentinel-platform-postgres-1",
     "psql", "-U", "sentinel", "-d", "sentinel", "-c", r"\dt"],
    capture_output=True, timeout=30
)
print(verify.stdout.decode())
