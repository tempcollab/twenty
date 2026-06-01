#!/bin/bash
set -e

# Twenty CRM Security Audit - Teardown Script

NETWORK_NAME="twenty-audit-net"
CONTAINERS=(
    "audit-twenty-server"
    "audit-twenty-worker"
    "audit-twenty-db"
    "audit-twenty-redis"
)

echo "[+] Stopping and removing audit containers..."
for container in "${CONTAINERS[@]}"; do
    if docker ps -aq -f name="$container" | grep -q .; then
        echo "    Removing $container..."
        docker rm -f "$container" 2>/dev/null || true
    fi
done

echo "[+] Removing audit network..."
docker network rm "$NETWORK_NAME" 2>/dev/null || true

echo "[+] Teardown complete!"
