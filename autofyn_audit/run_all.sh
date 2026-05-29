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
# 01 (unauth webhook) and 02 (SSRF) are intentionally EXCLUDED: both were
# investigated and ruled out as product vulnerabilities (webhook trigger is a
# by-design public endpoint secured by two unguessable UUIDs; SSRF safe mode
# OUTBOUND_HTTP_SAFE_MODE_ENABLED defaults to ON in v2.8.3 — only our test env
# disabled it). Their scripts are retained, marked RULED OUT, for transparency.
# See audit_report.md "Investigated and ruled out".
# ---------------------------------------------------------------------------
EXPLOITS=(
    "00_recon.sh"
    "03_user_enumeration_no_captcha.sh"
    "04_system_object_permission_bypass.sh"
)

# Per-exploit wall-clock cap (seconds)
EXPLOIT_TIMEOUT=120

# ---------------------------------------------------------------------------
# Run loop
# ---------------------------------------------------------------------------
declare -A RESULTS
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
    EXPLOIT_OUTPUT=$(timeout "$EXPLOIT_TIMEOUT" bash "$exploit_path" 2>&1) || EXPLOIT_EXIT=$?
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

    RESULTS["$exploit_name"]="$RESULT_LINE"

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
for exploit_name in "${!RESULTS[@]}"; do
    echo "  ${exploit_name}: ${RESULTS[$exploit_name]}"
done | sort
echo "--------------------------------------"
echo "  ${CONFIRMED} CONFIRMED / ${TOTAL} total"
echo "======================================"

# Exit 0: this is an audit runner, not a test gate
exit 0
