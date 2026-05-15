# SENTINEL AI — Production Setup Guide

## Quick Start

```bash
# 1. Clone and enter project
git clone <repo> && cd sentinel-platform

# 2. Create your .env from the template
cp .env.example .env

# 3. Fill in real secrets (see "Generating Secrets" below)
#    OR auto-generate everything:
python scripts/check_env.py --generate

# 4. Verify your configuration (REQUIRED before first start)
python scripts/check_env.py

# 5. Start all services
docker compose up -d

# 6. Check health
curl http://localhost:8000/health
```

---

## Generating Secrets

Run these commands to generate cryptographically secure values:

```bash
# 256-bit secrets (required: ≥64 chars)
export JWT_SECRET=$(openssl rand -hex 32)
export SECRET_KEY=$(openssl rand -hex 32)

# Service passwords (minimum 16 chars)
export POSTGRES_PASSWORD=$(openssl rand -hex 16)
export REDIS_PASSWORD=$(openssl rand -hex 16)
export KAFKA_SASL_PASSWORD=$(openssl rand -hex 16)
export S3_SECRET_KEY=$(openssl rand -hex 24)

# Write to .env
echo "JWT_SECRET=$JWT_SECRET" >> .env
echo "SECRET_KEY=$SECRET_KEY" >> .env
# ... repeat for others
```

---

## Required Environment Variables

| Variable | Min Length | Notes |
|---|---|---|
| `JWT_SECRET` | 64 chars | 256-bit signing key. `openssl rand -hex 32` |
| `SECRET_KEY` | 64 chars | 256-bit app key. `openssl rand -hex 32` |
| `POSTGRES_PASSWORD` | 16 chars | Must match password in `DATABASE_URL` |
| `DATABASE_URL` | — | `postgresql+asyncpg://sentinel:<PG_PASS>@postgres:5432/sentinel` |
| `REDIS_PASSWORD` | 16 chars | Must match password in `REDIS_URL` |
| `REDIS_URL` | — | `redis://:<REDIS_PASS>@redis:6379/0` |
| `KAFKA_SASL_USERNAME` | 3 chars | Kafka authentication username |
| `KAFKA_SASL_PASSWORD` | 16 chars | Kafka authentication password |
| `KAFKA_BOOTSTRAP_SERVERS` | — | `kafka:9093` (SASL listener) |
| `CORS_ALLOWED_ORIGINS` | — | Comma-separated HTTPS origins. Wildcard `*` is **never** allowed |
| `S3_ACCESS_KEY` | 8 chars | MinIO/S3 access key ID |
| `S3_SECRET_KEY` | 16 chars | MinIO/S3 secret key |
| `LLM_API_KEY` | — | Optional. AI features disabled if absent |

### Cross-Service Consistency Rules (enforced at startup)

- The password embedded in `DATABASE_URL` **must exactly match** `POSTGRES_PASSWORD`
- The password embedded in `REDIS_URL` **must exactly match** `REDIS_PASSWORD`
- These are validated before the app initializes — mismatch = startup failure

---

## Validation Tool

Run the check tool any time to validate your configuration:

```bash
# Full validation report
python scripts/check_env.py

# Validate a specific env file
python scripts/check_env.py --env-file /path/to/.env

# Print secret generation commands
python scripts/check_env.py --show-generation-hints

# Auto-generate .env from template (interactive)
python scripts/check_env.py --generate
```

**Example output:**
```
SENTINEL AI — Environment Validator
────────────────────────────────────

Environment File
────────────────
✔ PASS  .env file found: /app/.env

Variable Validation
───────────────────
✔ PASS  POSTGRES_PASSWORD  [a7f3****]
✔ PASS  JWT_SECRET         [1104****]
✔ PASS  DATABASE_URL       [post****]
...

════════════════════════════════════════════════════════════
  ✔  ALL CHECKS PASSED — Ready to start SENTINEL AI

  Start the application:
    docker compose up -d
════════════════════════════════════════════════════════════
```

---

## Startup Enforcement

The application **will not start** if any validation fails:

```
════════════════════════════════════════════════════════════════════════
  ⛔  SENTINEL AI — STARTUP BLOCKED: Invalid Environment
════════════════════════════════════════════════════════════════════════
  2 error(s) must be resolved before the app can start.

  [1] JWT_SECRET
       → Too short: 12 chars (minimum 64).

  [2] DATABASE_URL
       → Password in DATABASE_URL (abc1****) does not match
         POSTGRES_PASSWORD (xyz9****). These must be identical.

  Quick fix:
    cp .env.example .env
    # Fill in real secrets
    python scripts/check_env.py   # verify before starting
════════════════════════════════════════════════════════════════════════
```

This validation runs at **module import time** (before FastAPI, before DB, before Redis).

---

## Docker Compose Integration

The provided `docker-compose.yml` automatically loads `.env`:

```yaml
# All services inherit:
env_file:
  - .env
```

> ⛔ **Never** use `.env.example` as the `env_file` — it contains placeholder values.

Start services:

```bash
# First time
docker compose up -d --build

# Subsequent starts
docker compose up -d

# View logs
docker compose logs -f gateway

# Check all service health
docker compose ps
```

---

## Security Architecture

### Secret Storage by Environment

| Environment | Secret Source | `.env` file? |
|---|---|---|
| Local dev | `.env` file (git-ignored) | ✅ Yes |
| Docker Compose (staging) | `.env` file (not in image) | ✅ Yes |
| Kubernetes (prod) | K8s Secrets / AWS SSM | ❌ No |
| AWS ECS (prod) | ECS Task Secrets | ❌ No |

### What's Enforced

- ✅ No placeholder values at runtime (`REPLACE_WITH_*` fails startup)
- ✅ JWT minimum 64 chars (256-bit entropy)
- ✅ Service passwords minimum 16 chars
- ✅ CORS wildcard `*` is **never** allowed
- ✅ DATABASE_URL ↔ POSTGRES_PASSWORD consistency enforced
- ✅ REDIS_URL ↔ REDIS_PASSWORD consistency enforced
- ✅ Secrets are **never printed** in logs (only masked prefixes)
- ✅ SQLite rejected in DATABASE_URL
- ✅ `.env` is hard-excluded from git

---

## Migration Path to Vault / Docker Secrets

### Option A: Docker Secrets (Swarm)

```yaml
# docker-compose.yml
services:
  gateway:
    secrets:
      - jwt_secret
      - postgres_password

secrets:
  jwt_secret:
    external: true
  postgres_password:
    external: true
```

```bash
# Create secrets
echo "$(openssl rand -hex 32)" | docker secret create jwt_secret -
echo "$(openssl rand -hex 16)" | docker secret create postgres_password -
```

Secrets are mounted at `/run/secrets/<name>` inside the container. Update `env_validator.py` to check both `os.environ` and `/run/secrets/` paths.

### Option B: HashiCorp Vault

```bash
# Store secrets
vault kv put secret/sentinel \
  jwt_secret="$(openssl rand -hex 32)" \
  postgres_password="$(openssl rand -hex 16)"

# Inject into app (via Vault Agent or envconsul)
envconsul -config=vault-config.hcl python run.py
```

### Option C: AWS Secrets Manager (ECS/EKS)

```json
// ECS Task Definition
{
  "secrets": [
    {
      "name": "JWT_SECRET",
      "valueFrom": "arn:aws:secretsmanager:region:account:secret:sentinel/jwt_secret"
    }
  ]
}
```

> In all cases, `enforce_environment()` validates the injected values the same way — the source doesn't matter, only that the values are present and strong.

---

## Troubleshooting

**"STARTUP BLOCKED: Invalid Environment"**
→ Run `python scripts/check_env.py` to see exactly which variable failed and why.

**"DATABASE_URL password does not match POSTGRES_PASSWORD"**
→ Edit `.env` and ensure the password component in the URL matches `POSTGRES_PASSWORD` exactly. Copy-paste to avoid typos.

**"JWT_SECRET: Too short"**
→ Run `export JWT_SECRET=$(openssl rand -hex 32)` and update your `.env`.

**"CORS_ALLOWED_ORIGINS: No origins set"**
→ Set `CORS_ALLOWED_ORIGINS=https://your-frontend.com` in `.env`. Never use `*`.

**"LLM_API_KEY: not set (optional)"**
→ This is a warning, not an error. AI scan analysis is disabled but other features work normally.
