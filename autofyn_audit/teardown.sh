#!/usr/bin/env bash
# =============================================================================
# teardown.sh — Destroy the Twenty CRM audit instance
#
# Audited repo commit:
#   tempcollab/twenty @ fc90b4ba8bb0a5d7c12c846fe9b2305527a0f7a8
#
# Pinned image (Twenty v2.8.3):
#   twentycrm/twenty@sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad
#
# Usage:
#   bash autofyn_audit/teardown.sh
#
# Safe to re-run — uses || true so missing resources are not errors.
# =============================================================================
set -euo pipefail

echo "==> Removing audit containers"
docker rm -f audit-twenty-server  || true
docker rm -f audit-twenty-worker  || true
docker rm -f audit-twenty-redis   || true
docker rm -f audit-twenty-db      || true

echo "==> Removing audit network"
docker network rm twenty-audit-net || true

echo ""
echo "Teardown complete. All audit containers and network removed."
