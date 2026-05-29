#!/usr/bin/env bash
# Tear down the Twenty CRM audit stack and remove its volumes.
set -euo pipefail
cd "$(dirname "$0")"
echo "[teardown] Stopping and removing audit stack + volumes..."
docker compose -f docker-compose.audit.yml down -v
echo "[teardown] Done."
