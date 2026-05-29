#!/usr/bin/env bash
# Stand up the live Twenty CRM instance for the security audit.
# Reproducible: all images pinned by digest in docker-compose.audit.yml.
#
#   Image:  twentycrm/twenty@sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad
#   Source: repo commit fc90b4ba8bb0a5d7c12c846fe9b2305527a0f7a8
#   URL:    http://audit-twenty-server:3000 (from within audit network)
#           http://localhost:3000 (if ports are forwarded from host)
#
# NOTE: This script uses `docker run` directly because `docker compose` may not be
# available in all environments. The docker-compose.audit.yml documents the intended
# configuration for reference.
set -euo pipefail
cd "$(dirname "$0")"

BASE_URL="${BASE_URL:-http://audit-twenty-server:3000}"
NETWORK="twenty-audit-net"
IMAGE="twentycrm/twenty@sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad"
PG_IMAGE="postgres:16@sha256:4b7183ac05f8ef417db21fd72d71047a4238340c261d3cc3ddb6d579ab5071ae"
REDIS_IMAGE="redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99"

ENCRYPTION_KEY="bXktYXVkaXQtZW5jcnlwdGlvbi1rZXktMzJieXRlcw=="
APP_SECRET="bXktYXVkaXQtYXBwLXNlY3JldC1mb3ItdHdlbnR5LWF1ZGl0"
AUDIT_EMAIL="auditor@audit.test"
AUDIT_PASS="AuditTest123!"

echo "[setup] Starting Twenty CRM audit stack..."

# Create network
docker network create "${NETWORK}" 2>/dev/null || true

# Start PostgreSQL
if ! docker inspect audit-twenty-db >/dev/null 2>&1; then
  docker run -d \
    --name audit-twenty-db \
    --network "${NETWORK}" \
    -v audit-db-data:/var/lib/postgresql/data \
    -e POSTGRES_DB=default \
    -e POSTGRES_USER=postgres \
    -e POSTGRES_PASSWORD=postgres \
    "${PG_IMAGE}"
fi

# Start Redis
if ! docker inspect audit-twenty-redis >/dev/null 2>&1; then
  docker run -d \
    --name audit-twenty-redis \
    --network "${NETWORK}" \
    "${REDIS_IMAGE}" \
    --maxmemory-policy noeviction
fi

echo "[setup] Waiting for PostgreSQL..."
for i in $(seq 1 30); do
  if docker exec audit-twenty-db pg_isready -U postgres -h localhost -d postgres >/dev/null 2>&1; then
    echo "[setup] PostgreSQL ready."
    break
  fi
  sleep 2
done

# Create volume
docker volume create audit-server-data 2>/dev/null || true

# Start Twenty server with vulnerable configuration
if ! docker inspect audit-twenty-server >/dev/null 2>&1; then
  docker run -d \
    --name audit-twenty-server \
    --network "${NETWORK}" \
    -p 127.0.0.1:3000:3000 \
    -v audit-server-data:/app/packages/twenty-server/.local-storage \
    -e NODE_PORT=3000 \
    -e PG_DATABASE_URL="postgres://postgres:postgres@audit-twenty-db:5432/default" \
    -e SERVER_URL="http://localhost:3000" \
    -e REDIS_URL="redis://audit-twenty-redis:6379" \
    -e STORAGE_TYPE="local" \
    -e ENCRYPTION_KEY="${ENCRYPTION_KEY}" \
    -e APP_SECRET="${APP_SECRET}" \
    -e IS_SIGN_UP_ENABLED="true" \
    -e AUTH_PASSWORD_ENABLED="true" \
    -e SIGN_IN_PREFILLED="true" \
    -e LOGIC_FUNCTION_TYPE="LOCAL" \
    -e CODE_INTERPRETER_TYPE="LOCAL" \
    -e OUTBOUND_HTTP_SAFE_MODE_ENABLED="false" \
    -e IS_IMAP_SMTP_CALDAV_CONNECTION_TEST_ENABLED="true" \
    "${IMAGE}"
fi

echo "[setup] Waiting for Twenty server (up to 3min)..."
for i in $(seq 1 60); do
  if docker exec audit-twenty-server curl -fsS http://localhost:3000/healthz >/dev/null 2>&1; then
    echo "[setup] Server healthy after $((i*3))s."
    break
  fi
  if [ "$i" -eq 60 ]; then
    echo "[setup] ERROR: server did not start in time." >&2
    docker logs --tail=30 audit-twenty-server >&2 || true
    exit 1
  fi
  sleep 3
done

# Start worker
if ! docker inspect audit-twenty-worker >/dev/null 2>&1; then
  docker run -d \
    --name audit-twenty-worker \
    --network "${NETWORK}" \
    -v audit-server-data:/app/packages/twenty-server/.local-storage \
    -e PG_DATABASE_URL="postgres://postgres:postgres@audit-twenty-db:5432/default" \
    -e SERVER_URL="http://localhost:3000" \
    -e REDIS_URL="redis://audit-twenty-redis:6379" \
    -e STORAGE_TYPE="local" \
    -e ENCRYPTION_KEY="${ENCRYPTION_KEY}" \
    -e APP_SECRET="${APP_SECRET}" \
    -e LOGIC_FUNCTION_TYPE="LOCAL" \
    -e CODE_INTERPRETER_TYPE="LOCAL" \
    -e DISABLE_DB_MIGRATIONS="true" \
    -e DISABLE_CRON_JOBS_REGISTRATION="true" \
    "${IMAGE}" \
    yarn worker:prod
fi

# Connect this script's container to the audit network so curl can reach audit-twenty-server
# (gVisor sandbox isolation — attempt to join network, ignore failure)
OWN_CONTAINER=$(docker ps --format "{{.Names}}" 2>/dev/null | grep "autofyn-sandbox-" | head -1 || true)
if [ -n "${OWN_CONTAINER}" ]; then
  docker network connect "${NETWORK}" "${OWN_CONTAINER}" 2>/dev/null || true
fi

# Create audit test user and workspace
echo "[setup] Creating audit user and workspace..."
sleep 5

# Sign up
SIGNUP=$(curl -s --max-time 30 -X POST "${BASE_URL}/metadata" \
  -H "Content-Type: application/json" \
  -d "{\"query\":\"mutation { signUp(email: \\\"${AUDIT_EMAIL}\\\", password: \\\"${AUDIT_PASS}\\\", captchaToken: null) { tokens { accessOrWorkspaceAgnosticToken { token } } } }\"}" 2>/dev/null)

AGNOSTIC_TOKEN=$(echo "${SIGNUP}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['signUp']['tokens']['accessOrWorkspaceAgnosticToken']['token'])" 2>/dev/null || true)

if [ -z "${AGNOSTIC_TOKEN}" ]; then
  echo "[setup] User may already exist. Signing in..."
  AGNOSTIC_TOKEN=$(curl -s --max-time 30 -X POST "${BASE_URL}/metadata" \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"mutation { signIn(email: \\\"${AUDIT_EMAIL}\\\", password: \\\"${AUDIT_PASS}\\\", captchaToken: null) { tokens { accessOrWorkspaceAgnosticToken { token } } } }\"}" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['signIn']['tokens']['accessOrWorkspaceAgnosticToken']['token'])" 2>/dev/null || true)
fi

# Create workspace if none exists
EXISTING_WS=$(curl -s --max-time 30 -X POST "${BASE_URL}/metadata" \
  -H "Content-Type: application/json" \
  -d "{\"query\":\"mutation { signIn(email: \\\"${AUDIT_EMAIL}\\\", password: \\\"${AUDIT_PASS}\\\", captchaToken: null) { availableWorkspaces { availableWorkspacesForSignIn { id loginToken } } } }\"}" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); ws=d['data']['signIn']['availableWorkspaces']['availableWorkspacesForSignIn']; print(ws[0]['loginToken'] if ws else '')" 2>/dev/null || true)

if [ -z "${EXISTING_WS}" ]; then
  echo "[setup] Creating new workspace..."
  WS_RESULT=$(curl -s --max-time 30 -X POST "${BASE_URL}/metadata" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${AGNOSTIC_TOKEN}" \
    -d '{"query":"mutation { signUpInNewWorkspace { loginToken { token } workspace { id } } }"}' 2>/dev/null)
  LOGIN_TOKEN=$(echo "${WS_RESULT}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['signUpInNewWorkspace']['loginToken']['token'])" 2>/dev/null || true)

  # Exchange for workspace token
  ACCESS_TOKEN=$(curl -s --max-time 30 -X POST "${BASE_URL}/metadata" \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"mutation { getAuthTokensFromLoginToken(loginToken: \\\"${LOGIN_TOKEN}\\\", origin: \\\"http://localhost:3000\\\") { tokens { accessOrWorkspaceAgnosticToken { token } } } }\"}" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['getAuthTokensFromLoginToken']['tokens']['accessOrWorkspaceAgnosticToken']['token'])" 2>/dev/null || true)

  # Activate workspace
  curl -s --max-time 30 -X POST "${BASE_URL}/metadata" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    -d '{"query":"mutation { activateWorkspace(data: { displayName: \"Audit Workspace\" }) { id } }"}' >/dev/null 2>&1 || true

  echo "[setup] Workspace created and activated."
  sleep 5
else
  echo "[setup] Existing workspace found."
fi

echo "[setup] Done. Twenty CRM is ready."
echo "[setup] Run ./run_all_exploits.sh next."
echo ""
echo "  BASE_URL: ${BASE_URL}"
echo "  Audit credentials: ${AUDIT_EMAIL} / ${AUDIT_PASS}"
echo "  Vulnerable config: LOGIC_FUNCTION_TYPE=LOCAL, CODE_INTERPRETER_TYPE=LOCAL"
echo "                     OUTBOUND_HTTP_SAFE_MODE_ENABLED=false"
