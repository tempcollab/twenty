#!/usr/bin/env bash
# run_all.sh — run all audit PoCs in order, print summary table
# Usage: bash run_all.sh [exploit_name]  (e.g. 00_recon, 01, 02, 03)
# Target: Twenty CRM release v2.8.3 | image sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

FILTER="${1:-}"

# ---------------------------------------------------------------------------
# Ensure setup is valid before running exploits
# ---------------------------------------------------------------------------
echo "=== Running setup.sh ==="
bash "${SCRIPT_DIR}/setup.sh"
echo ""

# ---------------------------------------------------------------------------
# Exploit manifest — ordered list of PoCs run against live.
# CONFIRMED FINDINGS (reported in audit_report.md §3):
#   03  (Medium) unauth captcha-less user enumeration — reproduces every run.
#   04  (CRITICAL) system-object RBAC bypass: cross-privilege secret plant + read-back + write.
#   04b (CRITICAL) system-object RBAC bypass: blast radius across all isSystem objects.
#       04/04b require the worker container running (metadata sync) and call
#       reclaim_workspace_slots internally.
# RULED-OUT MECHANISM DEMOS (NOT findings — see audit_report.md §4):
#   01  unauth webhook trigger — public-by-design, gated on two unguessable UUIDs;
#       does NOT reproduce as an exploit without those secrets (typically NOT-CONFIRMED).
#   02  SSRF via HTTP_REQUEST — only reachable when the non-default
#       OUTBOUND_HTTP_SAFE_MODE_ENABLED=false; intermittent on this container.
#   Kept in the runner only so maintainers can observe the underlying behavior;
#   their RESULT line is NOT a product-vulnerability claim.
# ---------------------------------------------------------------------------
EXPLOITS=(
    "00_recon.sh"
    "01_unauth_webhook_trigger.sh"
    "02_ssrf_via_webhook_http_request.sh"
    "03_user_enumeration_no_captcha.sh"
    "04_system_object_permission_bypass.sh"
    "04b_system_object_blast_radius.sh"
)

# Per-exploit wall-clock cap (seconds)
EXPLOIT_TIMEOUT=120

# Portable timeout resolution.
# GNU coreutils ships `timeout`; macOS/BSD does not (it may have `gtimeout` via
# `brew install coreutils`). Fall back to a no-op wrapper so the runner still
# executes the PoCs on stock macOS — the per-exploit caps are advisory, not
# load-bearing for a CONFIRMED verdict.
TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_BIN="gtimeout"
fi
run_with_timeout() {
    # usage: run_with_timeout <seconds> <cmd...>
    local secs="$1"; shift
    if [[ -n "$TIMEOUT_BIN" ]]; then
        "$TIMEOUT_BIN" "$secs" "$@"
    else
        "$@"
    fi
}

# ---------------------------------------------------------------------------
# Run loop
# ---------------------------------------------------------------------------
# Indexed array of "name: RESULT_LINE" entries — Bash 3.2 compatible (stock
# macOS ships Bash 3.2, which has no associative arrays / `declare -A`).
RESULT_ENTRIES=()
TOTAL=0
CONFIRMED=0

for exploit_file in "${EXPLOITS[@]}"; do
    exploit_path="${SCRIPT_DIR}/exploits/${exploit_file}"
    exploit_name="${exploit_file%.sh}"

    # Apply name filter if provided
    if [[ -n "$FILTER" ]] && ! echo "$exploit_name" | grep -qF "$FILTER"; then
        continue
    fi

    TOTAL=$((TOTAL + 1))
    echo "--- Running: ${exploit_name} ---"

    # Run exploit in subshell with timeout; capture output; never abort run
    set +e
    EXPLOIT_EXIT=0
    EXPLOIT_OUTPUT=$(run_with_timeout "$EXPLOIT_TIMEOUT" bash "$exploit_path" 2>&1) || EXPLOIT_EXIT=$?
    set -e

    echo "$EXPLOIT_OUTPUT"
    echo ""

    # Extract the RESULT= line.
    # Strip ANSI escape sequences before grepping so that color prefixes from
    # log_pass/log_fail do not break the match (the round-1 ANSI-grep bug).
    PLAIN_OUTPUT=$(echo "$EXPLOIT_OUTPUT" | sed 's/\x1b\[[0-9;]*m//g')
    RESULT_LINE=$(echo "$PLAIN_OUTPUT" | grep 'RESULT=' | tail -1 || true)

    if [[ -z "$RESULT_LINE" ]]; then
        if [[ "$EXPLOIT_EXIT" -eq 124 ]]; then
            RESULT_LINE="RESULT=NOT-CONFIRMED exploit=${exploit_name} :: timeout after ${EXPLOIT_TIMEOUT}s"
        else
            RESULT_LINE="RESULT=NOT-CONFIRMED exploit=${exploit_name} :: script_error exit=${EXPLOIT_EXIT}"
        fi
    fi

    RESULT_ENTRIES+=("${exploit_name}: ${RESULT_LINE}")

    if echo "$RESULT_LINE" | grep -q 'RESULT=CONFIRMED'; then
        CONFIRMED=$((CONFIRMED + 1))
    fi
done

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------
echo "======================================"
echo "  AUDIT RUN SUMMARY"
echo "======================================"
for entry in "${RESULT_ENTRIES[@]}"; do
    echo "  ${entry}"
done | sort
echo "--------------------------------------"
echo "  ${CONFIRMED} CONFIRMED / ${TOTAL} total"
echo "======================================"

# Exit 0: this is an audit runner, not a test gate
exit 0
