# ============================================================================
# SENTINEL AI — Full Stack Bring-Up Script (Fix A–G)
# Run from: sentinel-platform directory
# Usage: powershell -ExecutionPolicy Bypass -File scripts/bring_up.ps1
# ============================================================================

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $PSScriptRoot

Set-Location $ProjectDir
Write-Host "=== SENTINEL AI Stack Bring-Up ===" -ForegroundColor Cyan
Write-Host "Working directory: $ProjectDir"

# STEP 1 — Remove all stale/exited containers from previous runs
Write-Host "`n[1/6] Removing stale containers..." -ForegroundColor Yellow
docker rm -f sentinel-gateway sentinel-postgres sentinel-minio sentinel-redis sentinel-kafka sentinel-elasticsearch sentinel-worker sentinel-prometheus sentinel-grafana sentinel-minio-init 2>$null
Write-Host "Done." -ForegroundColor Green

# STEP 2 — Build & start the whole stack
Write-Host "`n[2/6] Building and starting all services (this may take a few minutes)..." -ForegroundColor Yellow
docker compose -f docker-compose.minimal.yml --env-file .env.docker up -d --build
if ($LASTEXITCODE -ne 0) { throw "docker compose failed to start." }
Write-Host "Done." -ForegroundColor Green

# STEP 3 — Wait for Postgres to be healthy
Write-Host "`n[3/6] Waiting for Postgres to be healthy..." -ForegroundColor Yellow
$retries = 0
do {
    Start-Sleep -Seconds 5
    $status = docker inspect --format='{{.State.Health.Status}}' sentinel-postgres 2>$null
    Write-Host "  Postgres status: $status"
    $retries++
    if ($retries -gt 24) { throw "Postgres did not become healthy in 120 seconds." }
} while ($status -ne "healthy")
Write-Host "Postgres is healthy." -ForegroundColor Green

# STEP 4 — Run Alembic migrations
Write-Host "`n[4/6] Running Alembic migrations..." -ForegroundColor Yellow
docker exec sentinel-gateway python -m alembic upgrade head
if ($LASTEXITCODE -ne 0) { throw "Alembic migrations failed." }
Write-Host "Migrations applied." -ForegroundColor Green

# STEP 5 — Wait for MinIO to be healthy, then create bucket via init container
Write-Host "`n[5/6] Waiting for MinIO init to complete..." -ForegroundColor Yellow
$retries = 0
do {
    Start-Sleep -Seconds 5
    $status = docker inspect --format='{{.State.Status}}' sentinel-minio-init 2>$null
    Write-Host "  MinIO init status: $status"
    $retries++
    if ($retries -gt 12) {
        Write-Host "  MinIO init timed out, creating bucket manually..." -ForegroundColor Yellow
        docker exec sentinel-minio mc alias set local http://localhost:9000 sentinel_admin $(grep S3_SECRET_KEY .env.docker | cut -d= -f2) 2>$null
        docker exec sentinel-minio mc mb local/sentinel-reports --ignore-existing 2>$null
        break
    }
} while ($status -ne "exited")
Write-Host "MinIO bucket ready." -ForegroundColor Green

# STEP 6 — Patch admin password
Write-Host "`n[6/6] Seeding admin user password..." -ForegroundColor Yellow
$hash = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TiGqY4K7O.9AEBLQSzf3MaQnIWGa'
docker exec sentinel-postgres psql -U sentinel -d sentinel -c "UPDATE users SET hashed_password='$hash' WHERE email='admin@sentinel.ai';" 2>$null
Write-Host "Admin password seeded (if user existed)." -ForegroundColor Green

# Final health check
Write-Host "`n=== Verifying gateway /health ===" -ForegroundColor Cyan
Start-Sleep -Seconds 3
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -TimeoutSec 10
    Write-Host "Gateway response: $($response.StatusCode)" -ForegroundColor Green
    Write-Host $response.Content
} catch {
    Write-Host "Gateway health check failed: $_" -ForegroundColor Red
    Write-Host "Check logs: docker logs sentinel-gateway --tail 50"
}

Write-Host "`n=== DONE ===" -ForegroundColor Cyan
Write-Host "Services:"
Write-Host "  API Gateway:   http://localhost:8000"
Write-Host "  Swagger UI:    http://localhost:8000/docs"
Write-Host "  Frontend:      http://localhost:5173"
Write-Host "  MinIO Console: http://localhost:9001"
Write-Host "  Grafana:       http://localhost:3001  (admin / S3nt1nel_Gr4fan4!Secure)"
Write-Host "  Prometheus:    http://localhost:9090"
Write-Host "  Kibana/ES:     http://localhost:9200"
