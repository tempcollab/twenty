#!/bin/bash
set -e

# Twenty CRM Security Audit - Setup Script
# Commit: fc90b4ba8bb0a5d7c12c846fe9b2305527a0f7a8
# Docker image: twentycrm/twenty:v2.8.3

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK_NAME="twenty-audit-net"
SERVER_CONTAINER="audit-twenty-server"
WORKER_CONTAINER="audit-twenty-worker"
DB_CONTAINER="audit-twenty-db"
REDIS_CONTAINER="audit-twenty-redis"

# Pinned versions for reproducibility
POSTGRES_IMAGE="postgres:16@sha256:7c4bac7f2a7c6c9d6f5e9b7a3c8d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d"
REDIS_IMAGE="redis:7-alpine@sha256:a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5"
TWENTY_IMAGE="twentycrm/twenty:v2.8.3"

echo "[+] Creating audit network..."
docker network create "$NETWORK_NAME" 2>/dev/null || true

echo "[+] Starting PostgreSQL..."
if ! docker ps -q -f name="$DB_CONTAINER" | grep -q .; then
    docker run -d \
        --name "$DB_CONTAINER" \
        --network "$NETWORK_NAME" \
        -e POSTGRES_DB=default \
        -e POSTGRES_USER=postgres \
        -e POSTGRES_PASSWORD=postgres \
        postgres:16

    echo "[+] Waiting for PostgreSQL to be ready..."
    sleep 10
fi

echo "[+] Starting Redis..."
if ! docker ps -q -f name="$REDIS_CONTAINER" | grep -q .; then
    docker run -d \
        --name "$REDIS_CONTAINER" \
        --network "$NETWORK_NAME" \
        --cmd "--maxmemory-policy noeviction" \
        redis:7-alpine
fi

echo "[+] Starting Twenty Server..."
if ! docker ps -q -f name="$SERVER_CONTAINER" | grep -q .; then
    docker run -d \
        --name "$SERVER_CONTAINER" \
        --network "$NETWORK_NAME" \
        -p 127.0.0.1:3000:3000 \
        -e NODE_PORT=3000 \
        -e PG_DATABASE_URL="postgres://postgres:postgres@$DB_CONTAINER:5432/default" \
        -e REDIS_URL="redis://$REDIS_CONTAINER:6379" \
        -e SERVER_URL="http://localhost:3000" \
        -e SIGN_IN_PREFILLED=true \
        -e IS_SIGN_UP_ENABLED=true \
        -e IS_MULTIWORKSPACE_ENABLED=true \
        -e LOGIC_FUNCTION_TYPE=LOCAL \
        -e CODE_INTERPRETER_TYPE=LOCAL \
        -e OUTBOUND_HTTP_SAFE_MODE_ENABLED=false \
        -e IS_WORKSPACE_CREATION_LIMITED_TO_SERVER_ADMINS=false \
        "$TWENTY_IMAGE"
fi

echo "[+] Starting Twenty Worker..."
if ! docker ps -q -f name="$WORKER_CONTAINER" | grep -q .; then
    docker run -d \
        --name "$WORKER_CONTAINER" \
        --network "$NETWORK_NAME" \
        -e PG_DATABASE_URL="postgres://postgres:postgres@$DB_CONTAINER:5432/default" \
        -e REDIS_URL="redis://$REDIS_CONTAINER:6379" \
        -e SERVER_URL="http://localhost:3000" \
        -e DISABLE_DB_MIGRATIONS=true \
        -e DISABLE_CRON_JOBS_REGISTRATION=true \
        -e LOGIC_FUNCTION_TYPE=LOCAL \
        -e CODE_INTERPRETER_TYPE=LOCAL \
        "$TWENTY_IMAGE" \
        yarn worker:prod
fi

echo "[+] Waiting for Twenty to be ready..."
for i in {1..60}; do
    if docker exec "$SERVER_CONTAINER" curl -s http://localhost:3000/healthz 2>/dev/null | grep -q ok; then
        echo "[+] Twenty is ready!"
        break
    fi
    echo "    Waiting... ($i/60)"
    sleep 5
done

echo ""
echo "[+] Setup complete!"
echo "    Server: docker exec $SERVER_CONTAINER curl -s http://localhost:3000/graphql"
echo "    Database: docker exec -it $DB_CONTAINER psql -U postgres -d default"
echo ""
echo "Run exploits with: ./run_all_exploits.sh"
