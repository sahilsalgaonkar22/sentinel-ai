#!/usr/bin/env bash
# ============================================================================
# SENTINEL AI — Kubernetes Deploy Script
# Applies all manifests in correct dependency order
# Usage: bash k8s/deploy.sh [--env prod|staging] [--dry-run]
# ============================================================================

set -euo pipefail

NAMESPACE="sentinel"
DRY_RUN=""
ENV="prod"

# Parse args
for arg in "$@"; do
  case $arg in
    --dry-run) DRY_RUN="--dry-run=client" ;;
    --env=*) ENV="${arg#*=}" ;;
  esac
done

K8S_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "╔══════════════════════════════════════════╗"
echo "║  SENTINEL AI — Kubernetes Deploy         ║"
echo "║  Namespace: ${NAMESPACE}                    ║"
echo "║  Environment: ${ENV}                        ║"
if [ -n "$DRY_RUN" ]; then
echo "║  MODE: DRY RUN                           ║"
fi
echo "╚══════════════════════════════════════════╝"
echo ""

check_prereqs() {
  echo "[*] Checking prerequisites..."
  if ! command -v kubectl &>/dev/null; then
    echo "[!] kubectl not found. Install it first."
    exit 1
  fi
  if ! kubectl cluster-info &>/dev/null; then
    echo "[!] kubectl cannot reach cluster. Check kubeconfig."
    exit 1
  fi
  echo "[+] kubectl OK — cluster reachable"
}

apply() {
  local file="$1"
  local label="$2"
  echo "  Applying: ${label}"
  kubectl apply -f "${file}" ${DRY_RUN}
}

wait_for() {
  local resource="$1"
  local name="$2"
  if [ -z "$DRY_RUN" ]; then
    echo "  Waiting for ${resource}/${name}..."
    kubectl rollout status "${resource}/${name}" -n "${NAMESPACE}" --timeout=120s || true
  fi
}

# ── Step 1: Namespace ────────────────────────────────────────────────────────
echo "[1] Namespace"
apply "${K8S_DIR}/namespace.yaml" "sentinel namespace"
echo ""

# ── Step 2: Config & Secrets ─────────────────────────────────────────────────
echo "[2] Configuration"
apply "${K8S_DIR}/configmap.yaml" "configmap"
apply "${K8S_DIR}/secrets.yaml"   "secrets"
echo ""

# ── Step 3: Infrastructure ───────────────────────────────────────────────────
echo "[3] Infrastructure (postgres, redis, kafka, minio, elasticsearch)"
apply "${K8S_DIR}/infrastructure.yaml" "all infrastructure"
echo "    [waiting 30s for infra to start...]"
[ -z "$DRY_RUN" ] && sleep 30
echo ""

# ── Step 4: Gateway ──────────────────────────────────────────────────────────
echo "[4] Gateway"
apply "${K8S_DIR}/gateway.yaml" "sentinel-gateway"
wait_for "deployment" "sentinel-gateway"
echo ""

# ── Step 5: Workers ──────────────────────────────────────────────────────────
echo "[5] Workers"
apply "${K8S_DIR}/workers.yaml" "all workers + HPAs"
echo ""

# ── Step 6: Frontend ─────────────────────────────────────────────────────────
echo "[6] Frontend"
apply "${K8S_DIR}/frontend.yaml" "sentinel-frontend"
echo ""

# ── Step 7: Ingress ──────────────────────────────────────────────────────────
echo "[7] Ingress"
apply "${K8S_DIR}/ingress.yaml" "ingress"
echo ""

# ── Status Report ────────────────────────────────────────────────────────────
if [ -z "$DRY_RUN" ]; then
  echo "════════ DEPLOYMENT STATUS ════════"
  kubectl get pods -n "${NAMESPACE}" -o wide
  echo ""
  kubectl get services -n "${NAMESPACE}"
  echo ""
  kubectl get hpa -n "${NAMESPACE}"
  echo ""
  echo "[✓] Sentinel AI deployment complete!"
  echo ""
  echo "Gateway URL (if using ingress): http://sentinel.local"
  echo "Port-forward locally:  kubectl port-forward svc/gateway-service 8000:80 -n sentinel"
else
  echo "[DRY RUN COMPLETE] — No changes applied"
fi
