#!/usr/bin/env bash
# setup.sh — idempotent audit environment setup
# Verifies network, pinned image digest, server health, and attacker listener.
# Target: Twenty CRM release v2.8.3 | image sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# ---------------------------------------------------------------------------
# Step 1: Assert docker is available and network exists
# ---------------------------------------------------------------------------
echo "=== [1/5] Checking docker + network ==="
if ! command -v docker &>/dev/null; then
    echo "[ABORT] docker not found on PATH" >&2
    exit 1
fi

if ! docker network inspect "$AUDIT_NET" &>/dev/null; then
    echo "[ABORT] Docker network '${AUDIT_NET}' not found. Harness network missing." >&2
    exit 1
fi
echo "  docker OK; network '${AUDIT_NET}' exists"

# ---------------------------------------------------------------------------
# Step 2: Assert audit-twenty-server is running with the pinned image digest
# ---------------------------------------------------------------------------
echo "=== [2/5] Verifying pinned image digest on audit-twenty-server ==="
if ! docker inspect audit-twenty-server &>/dev/null; then
    echo "[ABORT] Container 'audit-twenty-server' not found. Harness not running." >&2
    exit 1
fi

CONTAINER_IMAGE_ID=$(docker inspect audit-twenty-server --format '{{.Image}}')
if [[ -z "$CONTAINER_IMAGE_ID" ]]; then
    echo "[ABORT] Could not read image ID from audit-twenty-server" >&2
    exit 1
fi

# Check that the container's image RepoDigests contains the pinned digest
IMAGE_DIGESTS=$(docker inspect "$CONTAINER_IMAGE_ID" --format '{{range .RepoDigests}}{{.}} {{end}}' 2>/dev/null || echo "")
if echo "$IMAGE_DIGESTS" | grep -qF "$TWENTY_IMAGE_DIGEST"; then
    echo "  Pinned digest confirmed: ${TWENTY_IMAGE_DIGEST}"
else
    echo "[ABORT] Pinned digest '${TWENTY_IMAGE_DIGEST}' NOT found in image RepoDigests: ${IMAGE_DIGESTS}" >&2
    echo "[ABORT] Image mismatch — refusing to run against an unpinned image. Verify the correct image is running." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 3: Health check — retry up to 10 times (max ~60s total)
# ---------------------------------------------------------------------------
echo "=== [3/5] Health check: ${SERVER_URL}/healthz ==="
HEALTH_OK=false
for i in $(seq 1 10); do
    HTTP_CODE=$(net_curl -o /dev/null -w '%{http_code}' "${SERVER_URL}/healthz" 2>/dev/null || echo "000")
    if [[ "$HTTP_CODE" == "200" ]]; then
        HEALTH_OK=true
        echo "  Health check OK (attempt ${i}, HTTP ${HTTP_CODE})"
        break
    fi
    echo "  Attempt ${i}: HTTP ${HTTP_CODE} — waiting 5s..."
    sleep 5
done

if [[ "$HEALTH_OK" != "true" ]]; then
    echo "[ABORT] Server at ${SERVER_URL}/healthz did not return 200 after 10 attempts" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 3b: Reclaim workspace slots in the audit DB (idempotent)
#
# Every bootstrap run creates a new core.workspace row and never reclaims it.
# The free/community edition caps the instance at 5 total workspaces.  After
# a few audit runs the cap is hit and signUpInNewWorkspace returns ENV_SATURATED.
# We wipe PENDING_CREATION orphans and cap the total at 2 so there are always
# ≥3 free slots for the exploit suite.
#
# The audit DB is disposable infrastructure we created; no exploit depends on a
# pre-existing workspace (each self-bootstraps).  FKs are ON DELETE CASCADE so
# deleting workspace rows is safe.
# ---------------------------------------------------------------------------
echo "=== [3b] Reclaiming workspace slots in audit DB ==="

if docker inspect audit-twenty-db &>/dev/null 2>&1; then
    # Delete PENDING_CREATION orphans (failed/partial bootstraps)
    PENDING_DELETED=$(docker exec audit-twenty-db \
        psql -U postgres -d default -t -c \
        "DELETE FROM core.workspace WHERE \"activationStatus\"='PENDING_CREATION' RETURNING id;" \
        2>/dev/null | grep -c '[0-9a-f]' || echo "0")
    echo "  Deleted PENDING_CREATION orphans: ${PENDING_DELETED}"

    # Ensure at most 2 active workspace rows remain (leaves ≥3 free of the 5-cap)
    WS_COUNT=$(docker exec audit-twenty-db \
        psql -U postgres -d default -t -c \
        "SELECT count(*) FROM core.workspace;" \
        2>/dev/null | tr -d '[:space:]' || echo "0")
    echo "  Current workspace count: ${WS_COUNT}"

    if [[ -n "$WS_COUNT" && "$WS_COUNT" -ge 3 ]]; then
        # Calculate how many rows to remove: keep the 2 newest, delete the rest
        DELETE_N=$(( WS_COUNT - 2 ))
        echo "  Trimming ${DELETE_N} oldest workspace row(s) to reach count=2..."
        TRIMMED=$(docker exec audit-twenty-db \
            psql -U postgres -d default -t -c \
            "DELETE FROM core.workspace WHERE id IN (SELECT id FROM core.workspace ORDER BY \"createdAt\" ASC LIMIT ${DELETE_N}) RETURNING id;" \
            2>/dev/null | grep -c '[0-9a-f]' || echo "0")
        echo "  Trimmed ${TRIMMED} workspace row(s)"
    else
        echo "  Workspace count within limit — no trim needed"
    fi
else
    echo "  [SKIP] audit-twenty-db container not found — skipping slot reclaim (not an audit-DB environment)"
fi

# ---------------------------------------------------------------------------
# Step 4: Stand up attacker listener container
# ---------------------------------------------------------------------------
echo "=== [4/5] Setting up attacker listener '${LISTENER_NAME}' ==="

LISTENER_RUNNING=false
if docker inspect "$LISTENER_NAME" &>/dev/null; then
    LISTENER_STATE=$(docker inspect "$LISTENER_NAME" --format '{{.State.Status}}' 2>/dev/null || echo "")
    if [[ "$LISTENER_STATE" == "running" ]]; then
        echo "  Listener already running — skipping start"
        LISTENER_RUNNING=true
    else
        echo "  Listener exists but not running (state=${LISTENER_STATE}) — restarting"
        docker rm -f "$LISTENER_NAME" &>/dev/null || true
    fi
fi

if [[ "$LISTENER_RUNNING" != "true" ]]; then
    # Use BusyBox nc loop inside alpine — logs each request path to stdout
    # Each nc invocation handles one connection; the while loop accepts the next.
    # The server echoes HTTP/1.1 200 OK and logs the full request to stdout.
    docker run -d \
        --name "$LISTENER_NAME" \
        --network "$AUDIT_NET" \
        "$LISTENER_IMAGE" \
        sh -c 'while true; do
            echo "=== listener waiting on port '"$LISTENER_PORT"' ===" >&2
            (nc -l -p '"$LISTENER_PORT"' || true) | tee /proc/1/fd/1 | (
                read -r request_line
                echo "REQUEST: ${request_line}"
                printf "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nOK"
            )
        done'
    echo "  Listener container started"
fi

# ---------------------------------------------------------------------------
# Step 5: Verify listener is reachable via the audit network
# ---------------------------------------------------------------------------
echo "=== [5/5] Verifying listener reachability ==="
PROBE_PATH="/setup-probe-$(unique_token)"
PROBE_RESP=$(net_curl --max-time 10 -o /dev/null -w '%{http_code}' \
    "http://${LISTENER_NAME}:${LISTENER_PORT}${PROBE_PATH}" 2>/dev/null || echo "000")

if [[ "$PROBE_RESP" == "200" ]]; then
    echo "  Listener reachable (HTTP ${PROBE_RESP})"
else
    echo "[WARN] Listener probe returned HTTP ${PROBE_RESP} (expected 200); may still function for log-based checks"
fi

# Verify probe path appears in logs
sleep 1
if docker logs "$LISTENER_NAME" 2>&1 | grep -qF "setup-probe"; then
    echo "  Probe path visible in listener logs — listener logging confirmed"
else
    echo "[WARN] Probe path not yet visible in listener logs — nc loop may take a moment"
fi

echo ""
echo "=== SETUP OK ==="
echo "  Network:        ${AUDIT_NET}"
echo "  Server:         ${SERVER_URL}"
echo "  Release:        ${TWENTY_RELEASE}"
echo "  Image digest:   ${TWENTY_IMAGE_DIGEST}"
echo "  Listener:       ${LISTENER_NAME}:${LISTENER_PORT}"
