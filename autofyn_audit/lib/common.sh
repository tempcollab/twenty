#!/usr/bin/env bash
# lib/common.sh — shared helpers for autofyn_audit PoC scripts
# Sourced by every script; must be idempotent.
# Target: Twenty CRM v2.8.3 | image sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad

set -euo pipefail

# ---------------------------------------------------------------------------
# Pinned constants
# ---------------------------------------------------------------------------
TWENTY_IMAGE_DIGEST="sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad"
TWENTY_RELEASE="v2.8.3"
AUDIT_NET="twenty-audit-net"
SERVER_URL="http://audit-twenty-server:3000"

# Helper container image — pinned digest
HELPER_IMAGE="curlimages/curl@sha256:b3f1fb2a51d923260350d21b8654bbc607164a987e2f7c84a0ac199a67df812a"

# Attacker listener image — alpine:3.18, pinned digest
LISTENER_IMAGE="alpine@sha256:de0eb0b3f2a47ba1eb89389859a9bd88b28e82f5826b6969ad604979713c2d4f"

LISTENER_NAME="audit-attacker-listener"
LISTENER_PORT=8888
DEFAULT_TIMEOUT=15

# Bootstrap state — set by bootstrap_access_token
BOOTSTRAP_STATUS=""
BOOTSTRAP_TOKEN=""
BOOTSTRAP_WORKSPACE_ID=""
BOOTSTRAP_SUBDOMAIN_URL=""
BOOTSTRAP_EMAIL=""

# State directory for created resources
STATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.state"
mkdir -p "$STATE_DIR"

# ---------------------------------------------------------------------------
# Logging helpers
# Disable ANSI color when not writing to a TTY so that grep on the output
# can match RESULT= lines without anchor failures from escape prefixes.
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

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
# gql — unauthenticated GraphQL POST to /graphql (workspace/core scope)
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
# gql_auth — authenticated GraphQL POST to /graphql (workspace/core scope)
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
# gql_metadata — unauthenticated GraphQL POST to /metadata
# Auth resolvers (signUp, checkUserExists, getAuthTokensFromLoginToken, etc.)
# are served at /metadata in v2.8.3, NOT at /graphql.
# Usage: gql_metadata '<json-string>'
# ---------------------------------------------------------------------------
gql_metadata() {
    local payload="$1"
    net_curl \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "${SERVER_URL}/metadata"
}

# ---------------------------------------------------------------------------
# gql_metadata_auth — authenticated GraphQL POST to /metadata
# Usage: gql_metadata_auth <token> '<json-string>'
# ---------------------------------------------------------------------------
gql_metadata_auth() {
    local token="$1"
    local payload="$2"
    net_curl \
        -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${token}" \
        -d "$payload" \
        "${SERVER_URL}/metadata"
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
# bootstrap_access_token — obtain a workspace-scoped ACCESS token for PoCs
#
# Implements the v2.8.3 bootstrap chain (all ops on /metadata):
#   1. signUp(email, password) → WORKSPACE_AGNOSTIC token
#      Input type: UserCredentialsInput (fields: email, password)
#      Returns: AvailableWorkspacesAndAccessTokensDTO
#                .tokens.accessOrWorkspaceAgnosticToken.token
#   2. signUpInNewWorkspace (with WORKSPACE_AGNOSTIC token) → loginToken + subdomainUrl
#      Returns: SignUpDTO
#                .loginToken.token
#                .workspace.workspaceUrls.subdomainUrl
#                .workspace.id
#   3. getAuthTokensFromLoginToken(loginToken, origin=subdomainUrl) → ACCESS token
#      Returns: AuthTokens
#                .tokens.accessOrWorkspaceAgnosticToken.token
#
# Sets: BOOTSTRAP_STATUS, BOOTSTRAP_TOKEN, BOOTSTRAP_WORKSPACE_ID,
#       BOOTSTRAP_SUBDOMAIN_URL, BOOTSTRAP_EMAIL
# Returns 0 on success, non-zero on failure.
# Cached: repeated calls within one run reuse the token.
# ---------------------------------------------------------------------------
bootstrap_access_token() {
    # Return cached result if already resolved
    if [[ -n "$BOOTSTRAP_STATUS" ]]; then
        [[ "$BOOTSTRAP_STATUS" == "ok" ]] && return 0 || return 1
    fi

    # Generate a unique email for this run — avoids conflicts across runs
    local rand_email="audit-poc-${RANDOM}-$(date +%s)@example.com"
    local password="AuditPoC1234!"

    log_info "bootstrap_access_token: step 1 — signUp on /metadata with ${rand_email}"

    # Step 1: signUp → WORKSPACE_AGNOSTIC token
    # Mutation name: signUp
    # Input type: UserCredentialsInput (ArgsType) — fields: email, password
    # Returns: AvailableWorkspacesAndAccessTokensDTO
    local signup_payload
    signup_payload=$(printf \
        '{"query":"mutation SignUp($email:String!,$password:String!){signUp(email:$email,password:$password){tokens{accessOrWorkspaceAgnosticToken{token}}}}","variables":{"email":"%s","password":"%s"}}' \
        "$rand_email" "$password")

    local signup_resp
    signup_resp=$(gql_metadata "$signup_payload" 2>/dev/null || echo "")

    if [[ -z "$signup_resp" ]]; then
        BOOTSTRAP_STATUS="step1_no_response"
        log_info "bootstrap_access_token: step1 error — no response from server"
        return 1
    fi

    if echo "$signup_resp" | grep -q '"errors"'; then
        local err1
        err1=$(json_get "$signup_resp" '.errors[0].message // .errors[0].extensions.code // "UNKNOWN"')
        BOOTSTRAP_STATUS="step1_error:${err1}"
        log_info "bootstrap_access_token: step1 error — ${err1}"
        log_info "  full response: ${signup_resp:0:400}"
        return 1
    fi

    local ws_agnostic_token
    ws_agnostic_token=$(json_get "$signup_resp" '.data.signUp.tokens.accessOrWorkspaceAgnosticToken.token')

    if [[ -z "$ws_agnostic_token" || "$ws_agnostic_token" == "null" ]]; then
        BOOTSTRAP_STATUS="step1_null_token"
        log_info "bootstrap_access_token: step1 — got null/empty WORKSPACE_AGNOSTIC token"
        log_info "  full response: ${signup_resp:0:400}"
        return 1
    fi

    log_info "bootstrap_access_token: step1 OK — WORKSPACE_AGNOSTIC token obtained"

    # Step 2: signUpInNewWorkspace (requires UserAuthGuard → send the ws-agnostic token)
    # Returns: SignUpDTO { loginToken{token}, workspace{id, workspaceUrls{subdomainUrl}} }
    log_info "bootstrap_access_token: step 2 — signUpInNewWorkspace on /metadata"

    local new_ws_payload
    new_ws_payload='{"query":"mutation SignUpInNewWorkspace{signUpInNewWorkspace{loginToken{token}workspace{id workspaceUrls{subdomainUrl}}}}"}'

    local new_ws_resp
    new_ws_resp=$(gql_metadata_auth "$ws_agnostic_token" "$new_ws_payload" 2>/dev/null || echo "")

    if [[ -z "$new_ws_resp" ]]; then
        BOOTSTRAP_STATUS="step2_no_response"
        log_info "bootstrap_access_token: step2 error — no response from server"
        return 1
    fi

    if echo "$new_ws_resp" | grep -q '"errors"'; then
        local err2
        err2=$(json_get "$new_ws_resp" '.errors[0].message // .errors[0].extensions.code // "UNKNOWN"')
        # Distinguish workspace-cap saturation from other step2 errors so callers can
        # tell environment problems from refuted vulnerabilities.
        if echo "$new_ws_resp" | grep -qF "Cannot create more than 5 workspaces"; then
            BOOTSTRAP_STATUS="ENV_SATURATED (workspace cap reached)"
        else
            BOOTSTRAP_STATUS="step2_error:${err2}"
        fi
        log_info "bootstrap_access_token: step2 error — ${err2}"
        log_info "  full response: ${new_ws_resp:0:400}"
        return 1
    fi

    local login_token
    login_token=$(json_get "$new_ws_resp" '.data.signUpInNewWorkspace.loginToken.token')

    local subdomain_url
    subdomain_url=$(json_get "$new_ws_resp" '.data.signUpInNewWorkspace.workspace.workspaceUrls.subdomainUrl')

    local workspace_id
    workspace_id=$(json_get "$new_ws_resp" '.data.signUpInNewWorkspace.workspace.id')

    if [[ -z "$login_token" || "$login_token" == "null" ]]; then
        BOOTSTRAP_STATUS="step2_null_login_token"
        log_info "bootstrap_access_token: step2 — got null/empty loginToken"
        log_info "  full response: ${new_ws_resp:0:400}"
        return 1
    fi

    if [[ -z "$subdomain_url" || "$subdomain_url" == "null" ]]; then
        BOOTSTRAP_STATUS="step2_null_subdomain_url"
        log_info "bootstrap_access_token: step2 — got null/empty subdomainUrl"
        log_info "  full response: ${new_ws_resp:0:400}"
        return 1
    fi

    log_info "bootstrap_access_token: step2 OK — loginToken obtained, subdomainUrl=${subdomain_url}, workspaceId=${workspace_id}"

    # Step 3: getAuthTokensFromLoginToken(loginToken, origin=subdomainUrl) → ACCESS token
    # origin MUST equal the workspace subdomainUrl or the server returns WORKSPACE_NOT_FOUND
    log_info "bootstrap_access_token: step 3 — getAuthTokensFromLoginToken on /metadata (origin=${subdomain_url})"

    local auth_payload
    auth_payload=$(printf \
        '{"query":"mutation GetTokens($loginToken:String!,$origin:String!){getAuthTokensFromLoginToken(loginToken:$loginToken,origin:$origin){tokens{accessOrWorkspaceAgnosticToken{token}}}}","variables":{"loginToken":"%s","origin":"%s"}}' \
        "$login_token" "$subdomain_url")

    # Retry on WORKSPACE_NOT_FOUND: a freshly created workspace is occasionally not yet
    # visible to the token-exchange resolver (creation race). Retry only that error.
    local auth_resp="" err3="" step3_try
    for step3_try in $(seq 1 10); do
        auth_resp=$(gql_metadata "$auth_payload" 2>/dev/null || echo "")

        if [[ -z "$auth_resp" ]]; then
            log_info "bootstrap_access_token: step3 try ${step3_try} — no response, retrying"
            sleep 2
            continue
        fi

        if echo "$auth_resp" | grep -q '"errors"'; then
            err3=$(json_get "$auth_resp" '.errors[0].message // .errors[0].extensions.code // "UNKNOWN"')
            if echo "$err3" | grep -qi 'WORKSPACE_NOT_FOUND\|workspace not found'; then
                log_info "bootstrap_access_token: step3 try ${step3_try} — WORKSPACE_NOT_FOUND (creation race), retrying"
                sleep 2
                continue
            fi
            BOOTSTRAP_STATUS="step3_error:${err3}"
            log_info "bootstrap_access_token: step3 error — ${err3}"
            log_info "  full response: ${auth_resp:0:400}"
            return 1
        fi

        # No errors — proceed.
        break
    done

    if [[ -z "$auth_resp" ]] || echo "$auth_resp" | grep -q '"errors"'; then
        BOOTSTRAP_STATUS="step3_error:${err3:-WORKSPACE_NOT_FOUND_retries_exhausted}"
        log_info "bootstrap_access_token: step3 — retries exhausted (${err3:-WORKSPACE_NOT_FOUND})"
        return 1
    fi

    local access_token
    access_token=$(json_get "$auth_resp" '.data.getAuthTokensFromLoginToken.tokens.accessOrWorkspaceAgnosticToken.token')

    if [[ -z "$access_token" || "$access_token" == "null" ]]; then
        BOOTSTRAP_STATUS="step3_null_access_token"
        log_info "bootstrap_access_token: step3 — got null/empty ACCESS token"
        log_info "  full response: ${auth_resp:0:400}"
        return 1
    fi

    # NOTE: Do NOT set BOOTSTRAP_TOKEN here (pre-activation token lacks workspaceMember
    # context and fails actor guard on record creates). BOOTSTRAP_* globals are set
    # after step 5 (re-mint post-activation). Keep local vars for the activation call.

    # Step 4: activateWorkspace — Twenty only syncs standard object metadata
    # (the ~24 core.objectMetadata rows incl. workflowVersion) at workspace
    # activation.  The workspace stays PENDING_CREATION with ZERO objectMetadata
    # until this mutation is called, so any exploit that queries metadata objects
    # will see an empty list without this step.
    # Guarded by WorkspaceAuthGuard — requires the workspace-scoped access token.
    log_info "bootstrap_access_token: step 4 — activateWorkspace on /graphql (workspaceId=${workspace_id})"

    # Use jq -n --arg to build the payload — NO inline \" quoting (prior C1 lesson).
    local activate_payload
    activate_payload=$(jq -n \
        --arg displayName "Audit WS ${workspace_id}" \
        '{query: "mutation ActivateWS($displayName:String!){activateWorkspace(data:{displayName:$displayName}){id}}", variables: {displayName: $displayName}}')

    local activate_resp
    activate_resp=$(gql_auth "$access_token" "$activate_payload" 2>/dev/null || echo "")

    if [[ -z "$activate_resp" ]]; then
        log_info "bootstrap_access_token: step4 no response from /graphql — trying /metadata" >&2
        activate_resp=$(gql_metadata_auth "$access_token" "$activate_payload" 2>/dev/null || echo "")
    fi

    # If /graphql returns "Cannot query field" for activateWorkspace, fall back to /metadata
    if echo "$activate_resp" | grep -qF "Cannot query field"; then
        log_info "bootstrap_access_token: step4 /graphql lacks activateWorkspace — retrying on /metadata" >&2
        activate_resp=$(gql_metadata_auth "$access_token" "$activate_payload" 2>/dev/null || echo "")
    fi

    if [[ -z "$activate_resp" ]]; then
        BOOTSTRAP_STATUS="step4_no_response"
        log_info "bootstrap_access_token: step4 error — no response from server on either endpoint" >&2
        return 1
    fi

    if echo "$activate_resp" | grep -q '"errors"'; then
        local err4
        err4=$(json_get "$activate_resp" '.errors[0].message // .errors[0].extensions.code // "UNKNOWN"')
        BOOTSTRAP_STATUS="step4_error:${err4}"
        log_info "bootstrap_access_token: step4 error — ${err4}" >&2
        log_info "  full response: ${activate_resp:0:400}" >&2
        return 1
    fi

    log_info "bootstrap_access_token: step4 OK — workspace activated (response: ${activate_resp:0:200})"

    # Step 5: Re-mint the ACCESS token AFTER activateWorkspace.
    # The token created in step 3 (before activation) has no workspaceMember in its
    # auth context.  Any record create that injects an actor (createdBy/updatedBy)
    # fails with INTERNAL_SERVER_ERROR "Unable to build actor metadata".
    # After activation the server creates the workspaceMember row; the re-minted
    # token carries it and satisfies the actor guard.
    log_info "bootstrap_access_token: step 5 — re-minting ACCESS token post-activation (origin=${subdomain_url})"

    local post_activate_token
    set +e
    post_activate_token=$(login_access_token "$rand_email" "$password" "$subdomain_url" 2>/dev/null)
    local post_login_exit=$?
    set -e

    if [[ "$post_login_exit" -ne 0 || -z "$post_activate_token" || "$post_activate_token" == "null" ]]; then
        BOOTSTRAP_STATUS="step5_post_activate_login_failed"
        log_info "bootstrap_access_token: step5 error — re-mint after activation failed; actor guard will block record creates" >&2
        return 1
    fi
    access_token="$post_activate_token"
    log_info "bootstrap_access_token: step5 OK — ACCESS token re-minted with workspaceMember context"

    # Step 6: Poll for object metadata readiness.
    # The worker container syncs the standard object metadata rows asynchronously
    # after activation.  We poll until BOTH conditions hold (max 20 × 3s = 60s):
    #   (a) /metadata objects list includes a node with nameSingular=="workflowVersion"
    #       AND nameSingular=="company" (indicating full standard-object sync)
    #   (b) /graphql workflowVersions query returns WITHOUT "Cannot query field"
    # The old nodes>=1 check raced because it returned before workflowVersion synced.
    log_info "bootstrap_access_token: step 6 — polling for metadata readiness (workflowVersion + graphql queryable, max 60s)"

    # Fetch all objects and filter client-side — ObjectFilter does NOT support nameSingular
    local poll_objects_payload
    poll_objects_payload='{"query":"query{objects(paging:{first:200}){edges{node{nameSingular isSystem}}}}"}'
    local poll_wfv_payload
    poll_wfv_payload='{"query":"query{workflowVersions(first:1){edges{node{id}}}}"}'

    local meta_ready=false
    local poll_attempt
    for poll_attempt in $(seq 1 20); do
        local poll_meta_resp
        poll_meta_resp=$(gql_metadata_auth "$access_token" "$poll_objects_payload" 2>/dev/null || echo "")

        local has_wfv
        has_wfv=$(json_get "$poll_meta_resp" \
            '([.data.objects.edges[].node | select(.nameSingular == "workflowVersion")] | length > 0)' \
            2>/dev/null || echo "false")
        local has_company
        has_company=$(json_get "$poll_meta_resp" \
            '([.data.objects.edges[].node | select(.nameSingular == "company")] | length > 0)' \
            2>/dev/null || echo "false")

        if [[ "$has_wfv" == "true" && "$has_company" == "true" ]]; then
            # Confirm data API is also ready: workflowVersions must not return "Cannot query field"
            local poll_gql_resp
            poll_gql_resp=$(gql_auth "$access_token" "$poll_wfv_payload" 2>/dev/null || echo "")
            if ! echo "$poll_gql_resp" | grep -qF "Cannot query field"; then
                meta_ready=true
                log_info "bootstrap_access_token: step6 OK — metadata synced (attempt ${poll_attempt}, workflowVersion=true, company=true, /graphql queryable)"
                break
            else
                log_info "bootstrap_access_token: step6 attempt ${poll_attempt}/20 — metadata objects ready but /graphql workflowVersions not yet queryable..."
            fi
        else
            log_info "bootstrap_access_token: step6 attempt ${poll_attempt}/20 — waiting for metadata sync (workflowVersion=${has_wfv} company=${has_company})..."
        fi
        sleep 3
    done

    if [[ "$meta_ready" != "true" ]]; then
        BOOTSTRAP_STATUS="step6_metadata_timeout"
        log_info "bootstrap_access_token: step6 error — workflowVersion/company objects never fully synced after 60s; worker container may not be running" >&2
        return 1
    fi

    BOOTSTRAP_TOKEN="$access_token"
    BOOTSTRAP_WORKSPACE_ID="$workspace_id"
    BOOTSTRAP_SUBDOMAIN_URL="$subdomain_url"
    BOOTSTRAP_EMAIL="$rand_email"
    BOOTSTRAP_STATUS="ok"

    log_info "bootstrap_access_token: status=ok email=${BOOTSTRAP_EMAIL} workspaceId=${BOOTSTRAP_WORKSPACE_ID} subdomainUrl=${BOOTSTRAP_SUBDOMAIN_URL}"
    return 0
}

# Keep the old name as an alias so existing callers that use bootstrap_login still work
bootstrap_login() {
    bootstrap_access_token
}

# ---------------------------------------------------------------------------
# register_known_email — register a user via signUp ONLY (step 1).
#
# signUp persists the User row and returns a WORKSPACE_AGNOSTIC token; it does
# NOT require creating a workspace, so it is unaffected by the free-tier
# "max 5 workspaces" limit that blocks signUpInNewWorkspace. This is all that
# Finding 03 (user enumeration) needs: a known-existing email to probe.
#
# Sets REGISTERED_EMAIL on success. Returns 0 on success, non-zero otherwise.
# ---------------------------------------------------------------------------
REGISTERED_EMAIL=""
register_known_email() {
    local rand_email="audit-enum-${RANDOM}-$(date +%s)@example.com"
    local password="AuditPoC1234!"
    local payload
    payload=$(printf \
        '{"query":"mutation SignUp($email:String!,$password:String!){signUp(email:$email,password:$password){tokens{accessOrWorkspaceAgnosticToken{token}}}}","variables":{"email":"%s","password":"%s"}}' \
        "$rand_email" "$password")
    local resp
    resp=$(gql_metadata "$payload" 2>/dev/null || echo "")
    if echo "$resp" | grep -q '"token"'; then
        REGISTERED_EMAIL="$rand_email"
        return 0
    fi
    REGISTERED_EMAIL=""
    REGISTER_ERROR=$(json_get "$resp" '.errors[0].message // "no_token_in_response"')
    return 1
}

# ---------------------------------------------------------------------------
# require_bootstrap_or_fail — convenience for PoCs 01/02/03
# Usage: require_bootstrap_or_fail <exploit-name>
# Calls bootstrap_access_token; if not ok, logs NOT-CONFIRMED and exits 0.
# ---------------------------------------------------------------------------
require_bootstrap_or_fail() {
    local exploit_name="$1"
    if ! bootstrap_access_token; then
        log_fail "$exploit_name" "bootstrap unavailable: ${BOOTSTRAP_STATUS}"
        exit 0
    fi
}

# ---------------------------------------------------------------------------
# register_second_user — register a second, workspace-agnostic user via signUp.
#
# Like register_known_email but also captures the WORKSPACE_AGNOSTIC token for
# later invitation-acceptance steps.
#
# Sets: SECOND_USER_EMAIL, SECOND_USER_PASSWORD, SECOND_USER_AGNOSTIC_TOKEN
# Returns 0 on success, non-zero on failure.
# ---------------------------------------------------------------------------
SECOND_USER_EMAIL=""
SECOND_USER_PASSWORD=""
SECOND_USER_AGNOSTIC_TOKEN=""
register_second_user() {
    local rand_email="audit-member-${RANDOM}-$(date +%s)@example.com"
    local password="AuditPoC1234!"
    local payload
    payload=$(printf \
        '{"query":"mutation SignUp($email:String!,$password:String!){signUp(email:$email,password:$password){tokens{accessOrWorkspaceAgnosticToken{token}}}}","variables":{"email":"%s","password":"%s"}}' \
        "$rand_email" "$password")
    local resp
    resp=$(gql_metadata "$payload" 2>/dev/null || echo "")
    if echo "$resp" | grep -q '"errors"'; then
        local err
        err=$(echo "$resp" | (command -v jq &>/dev/null && jq -r '.errors[0].message // .errors[0].extensions.code // "UNKNOWN"' 2>/dev/null || echo "UNKNOWN"))
        log_info "register_second_user: signUp error — ${err}" >&2
        log_info "  full response: ${resp:0:400}" >&2
        SECOND_USER_EMAIL=""
        SECOND_USER_PASSWORD=""
        SECOND_USER_AGNOSTIC_TOKEN=""
        return 1
    fi
    local agnostic_token
    agnostic_token=$(echo "$resp" | (command -v jq &>/dev/null && jq -r '.data.signUp.tokens.accessOrWorkspaceAgnosticToken.token // empty' 2>/dev/null || echo ""))
    if [[ -z "$agnostic_token" || "$agnostic_token" == "null" ]]; then
        log_info "register_second_user: got null/empty agnostic token; response: ${resp:0:400}" >&2
        SECOND_USER_EMAIL=""
        SECOND_USER_PASSWORD=""
        SECOND_USER_AGNOSTIC_TOKEN=""
        return 1
    fi
    SECOND_USER_EMAIL="$rand_email"
    SECOND_USER_PASSWORD="$password"
    SECOND_USER_AGNOSTIC_TOKEN="$agnostic_token"
    return 0
}

# ---------------------------------------------------------------------------
# login_access_token — two-step login chain to obtain a workspace-scoped token.
#
# Step 1: getLoginTokenFromCredentials(email, password, origin) -> loginToken
# Step 2: getAuthTokensFromLoginToken(loginToken, origin) -> ACCESS token
#
# CRITICAL: All diagnostics go to stderr. Only the raw token string is echoed
# to stdout — do NOT pollute stdout with anything else (caller captures via $()).
#
# Usage: TOKEN=$(login_access_token "email" "password" "https://subdomain.example.com")
# Returns 0 on success, non-zero on failure (caller must check).
# ---------------------------------------------------------------------------
login_access_token() {
    local email="$1"
    local password="$2"
    local origin="$3"

    # Step 1: getLoginTokenFromCredentials
    local login_payload
    login_payload=$(printf \
        '{"query":"mutation GetLoginToken($email:String!,$password:String!,$origin:String!){getLoginTokenFromCredentials(email:$email,password:$password,origin:$origin){loginToken{token}}}","variables":{"email":"%s","password":"%s","origin":"%s"}}' \
        "$email" "$password" "$origin")

    local login_resp
    login_resp=$(gql_metadata "$login_payload" 2>/dev/null || echo "")

    if [[ -z "$login_resp" ]]; then
        echo "login_access_token: step1 no response from server" >&2
        return 1
    fi

    if echo "$login_resp" | grep -q '"errors"'; then
        local err1
        err1=$(echo "$login_resp" | (command -v jq &>/dev/null && jq -r '.errors[0].message // .errors[0].extensions.code // "UNKNOWN"' 2>/dev/null || echo "UNKNOWN"))
        echo "login_access_token: step1 error — ${err1}; response: ${login_resp:0:300}" >&2
        return 1
    fi

    local login_token
    login_token=$(echo "$login_resp" | (command -v jq &>/dev/null && jq -r '.data.getLoginTokenFromCredentials.loginToken.token // empty' 2>/dev/null || echo ""))

    if [[ -z "$login_token" || "$login_token" == "null" ]]; then
        echo "login_access_token: step1 null/empty loginToken; response: ${login_resp:0:300}" >&2
        return 1
    fi

    # Step 2: getAuthTokensFromLoginToken
    local auth_payload
    auth_payload=$(printf \
        '{"query":"mutation GetTokens($loginToken:String!,$origin:String!){getAuthTokensFromLoginToken(loginToken:$loginToken,origin:$origin){tokens{accessOrWorkspaceAgnosticToken{token}}}}","variables":{"loginToken":"%s","origin":"%s"}}' \
        "$login_token" "$origin")

    local auth_resp
    auth_resp=$(gql_metadata "$auth_payload" 2>/dev/null || echo "")

    if [[ -z "$auth_resp" ]]; then
        echo "login_access_token: step2 no response from server" >&2
        return 1
    fi

    if echo "$auth_resp" | grep -q '"errors"'; then
        local err2
        err2=$(echo "$auth_resp" | (command -v jq &>/dev/null && jq -r '.errors[0].message // .errors[0].extensions.code // "UNKNOWN"' 2>/dev/null || echo "UNKNOWN"))
        echo "login_access_token: step2 error — ${err2}; response: ${auth_resp:0:300}" >&2
        return 1
    fi

    local access_token
    access_token=$(echo "$auth_resp" | (command -v jq &>/dev/null && jq -r '.data.getAuthTokensFromLoginToken.tokens.accessOrWorkspaceAgnosticToken.token // empty' 2>/dev/null || echo ""))

    if [[ -z "$access_token" || "$access_token" == "null" ]]; then
        echo "login_access_token: step2 null/empty access token; response: ${auth_resp:0:300}" >&2
        return 1
    fi

    echo "$access_token"
    return 0
}

# ---------------------------------------------------------------------------
# gen_uuid — generate a random UUID v4 (for negative-control test values)
# ---------------------------------------------------------------------------
gen_uuid() {
    if command -v uuidgen &>/dev/null; then
        uuidgen | tr '[:upper:]' '[:lower:]'
    else
        # POSIX fallback via /dev/urandom
        local hex
        hex=$(head -c 16 /dev/urandom | od -A n -t x1 | tr -d ' \n')
        printf '%s-%s-%s-%s-%s\n' \
            "${hex:0:8}" "${hex:8:4}" \
            "4${hex:13:3}" \
            "$(printf '%x' $(( (0x${hex:16:2} & 0x3f) | 0x80 )))${hex:18:2}" \
            "${hex:20:12}"
    fi
}

# ---------------------------------------------------------------------------
# reclaim_workspace_slots — delete PENDING_CREATION orphans and trim to 2
# active workspaces so repeated standalone runs do not saturate the 5-cap.
# Mirrors the identical logic in setup.sh Step 3b.
# No-ops silently if audit-twenty-db container is not present.
# ---------------------------------------------------------------------------
reclaim_workspace_slots() {
    if ! docker inspect audit-twenty-db &>/dev/null 2>&1; then
        return 0
    fi

    local pending_deleted
    pending_deleted=$(docker exec audit-twenty-db \
        psql -U postgres -d default -t -c \
        "DELETE FROM core.workspace WHERE \"activationStatus\"='PENDING_CREATION' RETURNING id;" \
        2>/dev/null | grep -c '[0-9a-f]' || echo "0")
    log_info "reclaim_workspace_slots: deleted PENDING_CREATION orphans=${pending_deleted}"

    local ws_count
    ws_count=$(docker exec audit-twenty-db \
        psql -U postgres -d default -t -c \
        "SELECT count(*) FROM core.workspace;" \
        2>/dev/null | tr -d '[:space:]' || echo "0")
    log_info "reclaim_workspace_slots: current workspace count=${ws_count}"

    if [[ -n "$ws_count" && "$ws_count" -ge 3 ]]; then
        local delete_n=$(( ws_count - 2 ))
        local trimmed
        trimmed=$(docker exec audit-twenty-db \
            psql -U postgres -d default -t -c \
            "DELETE FROM core.workspace WHERE id IN (SELECT id FROM core.workspace ORDER BY \"createdAt\" ASC LIMIT ${delete_n}) RETURNING id;" \
            2>/dev/null | grep -c '[0-9a-f]' || echo "0")
        log_info "reclaim_workspace_slots: trimmed ${trimmed} oldest workspace row(s)"
    fi
}

# ---------------------------------------------------------------------------
# signup_user — RECON-ONLY probe; records signup posture
# Result stored in SIGNUP_RESULT (do NOT use as auth for PoCs 01/02/03)
# Uses /metadata endpoint (v2.8.3 correct).
# ---------------------------------------------------------------------------
SIGNUP_RESULT=""
signup_user() {
    local email="$1"
    local password="${2:-Audit1234!}"
    local payload
    payload=$(printf '{"query":"mutation SignUp($email:String!,$password:String!){signUp(email:$email,password:$password){tokens{accessOrWorkspaceAgnosticToken{token}}}}","variables":{"email":"%s","password":"%s"}}' "$email" "$password")
    local resp
    resp=$(gql_metadata "$payload" 2>/dev/null || echo "")
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
