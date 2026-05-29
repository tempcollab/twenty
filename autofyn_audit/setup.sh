#!/usr/bin/env bash
# =============================================================================
# setup.sh — Provision a LIVE, reproducible Twenty CRM audit instance
#
# Audited repo commit:
#   tempcollab/twenty @ fc90b4ba8bb0a5d7c12c846fe9b2305527a0f7a8
#
# Pinned image (Twenty v2.8.3):
#   twentycrm/twenty@sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad
#
# Usage:
#   bash autofyn_audit/setup.sh
#
# Safe to re-run — tears down existing containers before recreating.
# =============================================================================
set -euo pipefail

# ---- Pinned image ---------------------------------------------------------- #
TWENTY_IMAGE="twentycrm/twenty@sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad"

# ---- Container / network names ---------------------------------------------- #
NETWORK="twenty-audit-net"
CONTAINER_DB="audit-twenty-db"
CONTAINER_REDIS="audit-twenty-redis"
CONTAINER_SERVER="audit-twenty-server"
CONTAINER_WORKER="audit-twenty-worker"

# ---- Readiness timeout (seconds) -------------------------------------------- #
HEALTH_TIMEOUT=180

# ============================================================================= #
echo "==> [1/6] Removing any existing audit containers (idempotent)"
docker rm -f "${CONTAINER_SERVER}" "${CONTAINER_WORKER}" "${CONTAINER_REDIS}" "${CONTAINER_DB}" 2>/dev/null || true

# ============================================================================= #
echo "==> [2/6] Creating docker network: ${NETWORK}"
docker network create "${NETWORK}" || true

# ============================================================================= #
echo "==> [3/6] Starting postgres:16 (${CONTAINER_DB})"
docker run -d \
  --name "${CONTAINER_DB}" \
  --network "${NETWORK}" \
  -e POSTGRES_DB=default \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  postgres:16

# ============================================================================= #
echo "==> [4/6] Starting redis:7-alpine (${CONTAINER_REDIS})"
docker run -d \
  --name "${CONTAINER_REDIS}" \
  --network "${NETWORK}" \
  redis:7-alpine

# ============================================================================= #
echo "==> [5/6] Starting Twenty server (${CONTAINER_SERVER})"
# NOTE: The image entrypoint automatically runs database migrations on boot
# (equivalent to `yarn database:init:prod`). No separate migrate step is needed.
docker run -d \
  --name "${CONTAINER_SERVER}" \
  --network "${NETWORK}" \
  -p "127.0.0.1:3000:3000" \
  -e NODE_PORT=3000 \
  -e SERVER_URL=http://localhost:3000 \
  -e PG_DATABASE_URL=postgres://postgres:postgres@audit-twenty-db:5432/default \
  -e REDIS_URL=redis://audit-twenty-redis:6379 \
  -e APP_SECRET=bXktYXVkaXQtYXBwLXNlY3JldC1mb3ItdHdlbnR5LWF1ZGl0 \
  -e ENCRYPTION_KEY=bXktYXVkaXQtZW5jcnlwdGlvbi1rZXktMzJieXRlcw== \
  -e AUTH_PASSWORD_ENABLED=true \
  -e IS_SIGN_UP_ENABLED=true \
  -e SIGN_IN_PREFILLED=true \
  -e OUTBOUND_HTTP_SAFE_MODE_ENABLED=false \
  -e IS_IMAP_SMTP_CALDAV_CONNECTION_TEST_ENABLED=true \
  -e CODE_INTERPRETER_TYPE=LOCAL \
  -e LOGIC_FUNCTION_TYPE=LOCAL \
  -e STORAGE_TYPE=local \
  "${TWENTY_IMAGE}"
# Server CMD is the image default: node dist/main
# WORKDIR: /app/packages/twenty-server (not overridden)

# ============================================================================= #
echo "==> [5b/6] Starting Twenty worker (${CONTAINER_WORKER})"
docker run -d \
  --name "${CONTAINER_WORKER}" \
  --network "${NETWORK}" \
  -e NODE_PORT=3000 \
  -e SERVER_URL=http://localhost:3000 \
  -e PG_DATABASE_URL=postgres://postgres:postgres@audit-twenty-db:5432/default \
  -e REDIS_URL=redis://audit-twenty-redis:6379 \
  -e APP_SECRET=bXktYXVkaXQtYXBwLXNlY3JldC1mb3ItdHdlbnR5LWF1ZGl0 \
  -e ENCRYPTION_KEY=bXktYXVkaXQtZW5jcnlwdGlvbi1rZXktMzJieXRlcw== \
  -e AUTH_PASSWORD_ENABLED=true \
  -e IS_SIGN_UP_ENABLED=true \
  -e SIGN_IN_PREFILLED=true \
  -e OUTBOUND_HTTP_SAFE_MODE_ENABLED=false \
  -e IS_IMAP_SMTP_CALDAV_CONNECTION_TEST_ENABLED=true \
  -e CODE_INTERPRETER_TYPE=LOCAL \
  -e LOGIC_FUNCTION_TYPE=LOCAL \
  -e STORAGE_TYPE=local \
  "${TWENTY_IMAGE}" \
  yarn worker:prod

# ============================================================================= #
echo "==> [6/6] Waiting for server health check (timeout: ${HEALTH_TIMEOUT}s)"
ELAPSED=0
until curl -sf "http://127.0.0.1:3000/healthz" > /dev/null 2>&1; do
  if [ "${ELAPSED}" -ge "${HEALTH_TIMEOUT}" ]; then
    echo "ERROR: Server did not become healthy within ${HEALTH_TIMEOUT}s."
    echo "       Check logs: docker logs ${CONTAINER_SERVER}"
    exit 1
  fi
  sleep 2
  ELAPSED=$(( ELAPSED + 2 ))
  echo "    ... waiting (${ELAPSED}s elapsed)"
done

echo ""
echo "====================================================================="
echo "  Twenty CRM audit instance is LIVE"
echo "====================================================================="
echo "  External URL:  http://127.0.0.1:3000"
echo "  Internal DNS:  http://audit-twenty-server:3000  (from within ${NETWORK})"
echo "  Internal IP:   172.20.0.4:3000  (expected; verify with docker inspect)"
echo ""
echo "  Container logs:"
echo "    docker logs ${CONTAINER_SERVER}"
echo "    docker logs ${CONTAINER_WORKER}"
echo "====================================================================="
