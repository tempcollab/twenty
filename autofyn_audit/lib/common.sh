#!/usr/bin/env bash
# lib/common.sh — shared helpers for autofyn_audit PoC scripts
# Sourced by every script; must be idempotent.
# Target: Twenty CRM commit fc90b4ba | image sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad

set -euo pipefail

# ---------------------------------------------------------------------------
# Pinned constants
# ---------------------------------------------------------------------------
TWENTY_IMAGE_DIGEST="sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad"
TWENTY_COMMIT="fc90b4ba8bb0a5d7c12c846fe9b2305527a0f7a8"
AUDIT_NET="twenty-audit-net"
SERVER_URL="http://audit-twenty-server:3000"

# Helper container image — pinned digest resolved at build time via `docker images --digests`
HELPER_IMAGE="curlimages/curl@sha256:b3f1fb2a51d923260350d21b8654bbc607164a987e2f7c84a0ac199a67df812a"

# Attacker listener image — alpine:3.18, pinned digest
LISTENER_IMAGE="alpine@sha256:de0eb0b3f2a47ba1eb89389859a9bd88b28e82f5826b6969ad604979713c2d4f"

LISTENER_NAME="audit-attacker-listener"
LISTENER_PORT=8888
DEFAULT_TIMEOUT=15

# Bootstrap credentials (seeded dev account — may not exist on prod image)
BOOTSTRAP_EMAIL="tim@apple.dev"
BOOTSTRAP_PASSWORD="tim@apple.dev"

# Bootstrap state — set by bootstrap_login
BOOTSTRAP_STATUS=""
BOOTSTRAP_TOKEN=""
BOOTSTRAP_WORKSPACE_ID=""

# State directory for created resources
STATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.state"
mkdir -p "$STATE_DIR"

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

log_pass() {
    local name="$1"
    local evidence="$2"
    echo -e "${GREEN}RESULT=CONFIRMED exploit=${name} :: ${evidence}${NC}"
}

log_fail() {
    local name="$1"
    local reason="$2"
    echo -e "${RED}RESULT=NOT-CONFIRMED exploit=${name} :: ${reason}${NC}"
}

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $*"
}

# ---------------------------------------------------------------------------
# net_curl — run curl inside a helper container on AUDIT_NET
# Always injects --max-time $DEFAULT_TIMEOUT. All positional args forwarded.
# ---------------------------------------------------------------------------
net_curl() {
    docker run --rm \
        --network "$AUDIT_NET" \
        "$HELPER_IMAGE" \
        curl --max-time "$DEFAULT_TIMEOUT" -s "$@"
}

# ---------------------------------------------------------------------------
# gql — unauthenticated GraphQL POST to /graphql
# Usage: gql '<json-string>'
# ---------------------------------------------------------------------------
gql() {
    local payload="$1"
    net_curl \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "${SERVER_URL}/graphql"
}

# ---------------------------------------------------------------------------
# gql_auth — authenticated GraphQL POST to /graphql
# Usage: gql_auth <token> '<json-string>'
# ---------------------------------------------------------------------------
gql_auth() {
    local token="$1"
    local payload="$2"
    net_curl \
        -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${token}" \
        -d "$payload" \
        "${SERVER_URL}/graphql"
}

# ---------------------------------------------------------------------------
# json_get — extract a value from JSON using jq (requires jq on the host)
# Usage: json_get '<json-string>' '<jq-filter>'
# Fails with a clear message if jq is not installed on the host.
# ---------------------------------------------------------------------------
json_get() {
    local json="$1"
    local filter="$2"
    if ! command -v jq &>/dev/null; then
        echo "[ERROR] jq not found on host. Install jq to run audit scripts." >&2
        exit 1
    fi
    echo "$json" | jq -r "$filter" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# unique_token — random hex string for correlating SSRF callbacks
# ---------------------------------------------------------------------------
unique_token() {
    head -c 16 /dev/urandom | od -A n -t x1 | tr -d ' \n'
}

# ---------------------------------------------------------------------------
# signup_user — RECON-ONLY probe; records signup posture
# Result stored in SIGNUP_RESULT (do NOT use as auth for PoCs 01/02/03)
# ---------------------------------------------------------------------------
SIGNUP_RESULT=""
signup_user() {
    local email="$1"
    local password="${2:-Audit1234!}"
    local payload
    payload=$(printf '{"query":"mutation SignUp($email:String!,$password:String!){signUp(email:$email,password:$password){loginToken{token}}}","variables":{"email":"%s","password":"%s"}}' "$email" "$password")
    local resp
    resp=$(gql "$payload" 2>/dev/null || echo "")
    if echo "$resp" | grep -q '"SIGNUP_DISABLED"'; then
        SIGNUP_RESULT="SIGNUP_DISABLED"
    elif echo "$resp" | grep -q '"token"'; then
        SIGNUP_RESULT="SUCCESS_no_email_verification"
    elif echo "$resp" | grep -q '"EMAIL_NOT_VERIFIED"'; then
        SIGNUP_RESULT="requires_email_verification"
    elif echo "$resp" | grep -q '"errors"'; then
        local errmsg
        errmsg=$(json_get "$resp" '.errors[0].message // .errors[0].extensions.code // "unknown_error"')
        SIGNUP_RESULT="error:${errmsg}"
    else
        SIGNUP_RESULT="unknown:${resp:0:120}"
    fi
}

# ---------------------------------------------------------------------------
# bootstrap_login — obtain a workspace-scoped access token for PoCs 01/02/03
# Sets BOOTSTRAP_STATUS, BOOTSTRAP_TOKEN, BOOTSTRAP_WORKSPACE_ID.
# Cached: repeated calls within one run reuse the token.
# Returns 0 on success, non-zero on failure.
# ---------------------------------------------------------------------------
bootstrap_login() {
    # Return cached result if already resolved
    if [[ -n "$BOOTSTRAP_STATUS" ]]; then
        [[ "$BOOTSTRAP_STATUS" == "ok" ]] && return 0 || return 1
    fi

    log_info "bootstrap_login: attempting login as ${BOOTSTRAP_EMAIL}"

    # Step 1: getLoginTokenFromCredentials
    local login_payload
    login_payload=$(printf \
        '{"query":"mutation Login($email:String!,$password:String!,$origin:String!){getLoginTokenFromCredentials(email:$email,password:$password,origin:$origin){loginToken{token}}}","variables":{"email":"%s","password":"%s","origin":"%s"}}' \
        "$BOOTSTRAP_EMAIL" "$BOOTSTRAP_PASSWORD" "$SERVER_URL")

    local login_resp
    login_resp=$(gql "$login_payload" 2>/dev/null || echo "")

    if [[ -z "$login_resp" ]]; then
        BOOTSTRAP_STATUS="login_step1_no_response"
        return 1
    fi

    if echo "$login_resp" | grep -q '"errors"'; then
        local err_code
        err_code=$(json_get "$login_resp" '.errors[0].extensions.code // .errors[0].message // "UNKNOWN"')
        BOOTSTRAP_STATUS="login_step1_error:${err_code}"
        return 1
    fi

    local login_token
    login_token=$(json_get "$login_resp" '.data.getLoginTokenFromCredentials.loginToken.token')

    if [[ -z "$login_token" || "$login_token" == "null" ]]; then
        BOOTSTRAP_STATUS="login_step1_null_token"
        return 1
    fi

    log_info "bootstrap_login: got loginToken, exchanging for access token"

    # Step 2: getAuthTokensFromLoginToken
    local auth_payload
    auth_payload=$(printf \
        '{"query":"mutation Tokens($loginToken:String!,$origin:String!){getAuthTokensFromLoginToken(loginToken:$loginToken,origin:$origin){tokens{accessOrWorkspaceAgnosticToken{token}}}}","variables":{"loginToken":"%s","origin":"%s"}}' \
        "$login_token" "$SERVER_URL")

    local auth_resp
    auth_resp=$(gql "$auth_payload" 2>/dev/null || echo "")

    if [[ -z "$auth_resp" ]]; then
        BOOTSTRAP_STATUS="login_step2_no_response"
        return 1
    fi

    if echo "$auth_resp" | grep -q '"errors"'; then
        local err_code2
        err_code2=$(json_get "$auth_resp" '.errors[0].extensions.code // .errors[0].message // "UNKNOWN"')
        BOOTSTRAP_STATUS="login_step2_error:${err_code2}"
        return 1
    fi

    local access_token
    access_token=$(json_get "$auth_resp" '.data.getAuthTokensFromLoginToken.tokens.accessOrWorkspaceAgnosticToken.token')

    if [[ -z "$access_token" || "$access_token" == "null" ]]; then
        BOOTSTRAP_STATUS="login_step2_null_access_token"
        return 1
    fi

    BOOTSTRAP_TOKEN="$access_token"

    log_info "bootstrap_login: access token obtained, fetching workspaceId"

    # Step 3: get workspaceId via currentWorkspace query
    local ws_payload
    ws_payload='{"query":"query{currentWorkspace{id}}"}'
    local ws_resp
    ws_resp=$(gql_auth "$BOOTSTRAP_TOKEN" "$ws_payload" 2>/dev/null || echo "")

    local workspace_id
    workspace_id=$(json_get "$ws_resp" '.data.currentWorkspace.id')

    if [[ -z "$workspace_id" || "$workspace_id" == "null" ]]; then
        BOOTSTRAP_STATUS="workspaceId_not_found"
        return 1
    fi

    BOOTSTRAP_WORKSPACE_ID="$workspace_id"
    BOOTSTRAP_STATUS="ok"
    log_info "bootstrap_login: status=ok workspaceId=${BOOTSTRAP_WORKSPACE_ID}"
    return 0
}

# ---------------------------------------------------------------------------
# require_bootstrap_or_fail — convenience for PoCs 01/02/03
# Usage: require_bootstrap_or_fail <exploit-name>
# Calls bootstrap_login; if not ok, logs NOT-CONFIRMED and exits 0.
# ---------------------------------------------------------------------------
require_bootstrap_or_fail() {
    local exploit_name="$1"
    if ! bootstrap_login; then
        log_fail "$exploit_name" "bootstrap unavailable: ${BOOTSTRAP_STATUS}"
        exit 0
    fi
}
