#!/usr/bin/env bash
# run_all.sh — run all audit PoCs in order, print summary table
# Usage: bash run_all.sh [exploit_name]  (e.g. 00_recon, 01, 02, 03)
# Target: Twenty CRM commit fc90b4ba | image sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad

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
# Exploit manifest — ordered list
# ---------------------------------------------------------------------------
EXPLOITS=(
    "00_recon.sh"
    "01_unauth_webhook_trigger.sh"
    "02_ssrf_via_webhook_http_request.sh"
    "03_user_enumeration_no_captcha.sh"
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

    # Run exploit in subshell with timeout; capture RESULT= line; never abort run
    set +e
    EXPLOIT_OUTPUT=$(timeout "$EXPLOIT_TIMEOUT" bash "$exploit_path" 2>&1) || EXPLOIT_EXIT=$?
    set -e

    # Extract RESULT= line from output
    RESULT_LINE=$(echo "$EXPLOIT_OUTPUT" | grep '^RESULT=' | tail -1 || echo "RESULT=NOT-CONFIRMED exploit=${exploit_name} :: script_error_or_timeout")
    echo "$EXPLOIT_OUTPUT"
    echo ""

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
