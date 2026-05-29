#!/usr/bin/env bash
# teardown.sh — remove ONLY audit-created auxiliary infra
# NEVER touches audit-twenty-* containers or any unrelated containers.
# Idempotent: safe to run if listener already gone.
# Target: Twenty CRM commit fc90b4ba | image sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

echo "=== Teardown: removing audit-created infra only ==="

# ---------------------------------------------------------------------------
# Remove the attacker listener container
# ---------------------------------------------------------------------------
if docker inspect "$LISTENER_NAME" &>/dev/null; then
    echo "  Stopping and removing ${LISTENER_NAME}..."
    docker stop "$LISTENER_NAME" &>/dev/null || true
    docker rm -f "$LISTENER_NAME" &>/dev/null || true
    echo "  ${LISTENER_NAME} removed"
else
    echo "  ${LISTENER_NAME} not found — already gone"
fi

# ---------------------------------------------------------------------------
# Best-effort cleanup of in-app workflows recorded in state file
# (The harness DB reset is the canonical cleanup; this is best-effort only.)
# ---------------------------------------------------------------------------
CREATED_FILE="${STATE_DIR}/created.json"
if [[ -f "$CREATED_FILE" ]]; then
    echo "  Found state file ${CREATED_FILE} — skipping in-app cleanup (DB reset handles it)"
    # Do not fail if cleanup of in-app data is not possible
    rm -f "$CREATED_FILE" || true
else
    echo "  No state file found — nothing to clean up"
fi

echo "=== Teardown complete ==="
echo "  NOTE: audit-twenty-{server,worker,db,redis} were NOT touched."
