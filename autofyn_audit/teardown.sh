#!/usr/bin/env bash
# Twenty CRM Security Audit — Teardown / Cleanup
# Best-effort: reads evidence/created_objects.json and attempts to delete
# created logic functions using the workspace-scoped admin access token.
#
# IMPORTANT: The workspace-scoped admin token (not the agnostic token) is
# required for deleteOneLogicFunction because it is guarded by WorkspaceAuthGuard
# + SettingsPermissionGuard(WORKFLOWS). Teardown persists the workspace-scoped
# token in created_objects.json (see exploit A).
#
# NOT CLEANABLE via API:
#   - connectedAccounts created by saveImapSmtpCaldavAccount (no public delete mutation
#     in imap-smtp-caldav-connection.resolver.ts)
#   - Attacker user accounts and workspaces (no public self-delete mutation)
# Manual DB cleanup (read-only audit mandate — do NOT perform):
#   - DELETE FROM core."user" WHERE email LIKE '%@audit-evil.example.com';
#   - DELETE FROM core."workspace" WHERE ... (audit firm does not do this)
#
# Docker network:
#   - The orchestrator container can optionally run:
#     docker network disconnect twenty-audit-net $(hostname)
#   - This script does NOT modify container network state.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVIDENCE_DIR="${SCRIPT_DIR}/evidence"
CREATED_OBJECTS_FILE="${EVIDENCE_DIR}/created_objects.json"
CONFIG_FILE="${SCRIPT_DIR}/config.env"

if [[ -f "${CONFIG_FILE}" ]]; then
    set -o allexport
    # shellcheck disable=SC1090
    source "${CONFIG_FILE}"
    set +o allexport
fi

export TARGET_BASE_URL="${TARGET_BASE_URL:-http://172.20.0.4:3000}"
GRAPHQL_ENDPOINT="${TARGET_BASE_URL}/graphql"

echo "============================================================"
echo " Twenty CRM Audit — Teardown"
echo " Target: ${TARGET_BASE_URL}"
echo "============================================================"

if [[ ! -f "${CREATED_OBJECTS_FILE}" ]]; then
    echo "[+] No created_objects.json found — nothing to clean up."
    exit 0
fi

# -------------------------------------------------------------------------
# Helper: call GraphQL mutation with Bearer token
# -------------------------------------------------------------------------
graphql_delete_lf() {
    local lf_id="$1"
    local token="$2"
    local body
    body=$(python3 -c "import json; print(json.dumps({
        'query': 'mutation DeleteLF(\$input: DeleteOneObjectInput!) { deleteOneLogicFunction(input: \$input) { id } }',
        'variables': {'input': {'id': '${lf_id}'}}
    }))")
    curl -sS --max-time 15 \
        -X POST "${GRAPHQL_ENDPOINT}" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${token}" \
        -d "${body}"
}

# -------------------------------------------------------------------------
# Delete logic functions
# -------------------------------------------------------------------------
echo ""
echo "[*] Deleting logic functions..."

python3 - <<'PYEOF'
import json
import os
import sys

created_objects_file = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "evidence", "created_objects.json",
)

if not os.path.exists(created_objects_file):
    print("[+] No created_objects.json — nothing to do.")
    sys.exit(0)

with open(created_objects_file) as fh:
    obj = json.load(fh)

lf_list = obj.get("logicFunctions", [])
if not lf_list:
    print("[+] No logic functions recorded.")
    sys.exit(0)

import urllib.request
import urllib.error
import ssl

base_url = os.environ.get("TARGET_BASE_URL", "http://172.20.0.4:3000")
endpoint = f"{base_url}/graphql"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

DELETE_MUTATION = """
mutation DeleteLF($input: DeleteOneObjectInput!) {
  deleteOneLogicFunction(input: $input) { id }
}
"""

for lf in lf_list:
    lf_id = lf.get("id")
    # Use workspace-scoped admin access token (review fix #8)
    token = lf.get("workspace_access_token") or lf.get("access_token")
    name = lf.get("name", lf_id)
    if not lf_id or not token:
        print(f"  [!] Skipping entry missing id or token: {lf}")
        continue
    print(f"  [*] Deleting logic function: {name} (id={lf_id})...")
    payload = json.dumps({
        "query": DELETE_MUTATION,
        "variables": {"input": {"id": lf_id}},
    }).encode()
    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            body = resp.read().decode()
        result = json.loads(body)
        if result.get("errors"):
            msgs = " | ".join(e.get("message", str(e)) for e in result["errors"])
            print(f"  [!] Delete error for {lf_id}: {msgs}")
        else:
            print(f"  [+] Deleted: {lf_id}")
    except Exception as exc:
        print(f"  [!] Network error deleting {lf_id}: {exc}")

PYEOF

echo ""
echo "[*] Un-cleanable items (documented for audit record):"
echo "    - connectedAccounts (saveImapSmtpCaldavAccount): no public delete mutation"
echo "      in imap-smtp-caldav-connection.resolver.ts; must be removed via DB."
echo "    - Attacker user accounts (email *@audit-evil.example.com): no self-delete API."
echo "    - Attacker workspaces: no public delete API."
echo ""
echo "    Manual DB cleanup (audit firm does NOT perform — read-only mandate):"
echo "      psql -U postgres -d default -c \\"
echo "        \"DELETE FROM core.\\\"user\\\" WHERE email LIKE '%@audit-evil.example.com';\""
echo ""
echo "[+] Teardown complete."
