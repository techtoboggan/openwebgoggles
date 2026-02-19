#!/usr/bin/env bash
# Block until the user performs an action in the webview, then print it.
#
# Usage:
#   bash scripts/wait_for_action.sh                          # Wait indefinitely
#   bash scripts/wait_for_action.sh --timeout 300            # Wait up to 5 minutes
#   bash scripts/wait_for_action.sh --action-type approve    # Wait for a specific action type
#   bash scripts/wait_for_action.sh --clear                  # Clear actions after reading
#
# Exit codes:
#   0 — Actions found, printed to stdout as JSON
#   1 — Timeout reached with no actions

set -euo pipefail

DATA_DIR=".opencode/webview"
TIMEOUT=0  # 0 = no timeout
ACTION_TYPE=""
CLEAR=false
POLL_INTERVAL=1

while [[ $# -gt 0 ]]; do
    case $1 in
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --action-type) ACTION_TYPE="$2"; shift 2 ;;
        --clear) CLEAR=true; shift ;;
        --data-dir) DATA_DIR="$2"; shift 2 ;;
        --poll-interval) POLL_INTERVAL="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Validate numeric parameters
if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]]; then
    echo "Error: --timeout must be a non-negative integer" >&2
    exit 1
fi
if ! [[ "$POLL_INTERVAL" =~ ^[0-9]+$ ]] || [[ "$POLL_INTERVAL" -lt 1 ]]; then
    echo "Error: --poll-interval must be a positive integer" >&2
    exit 1
fi

ACTIONS_FILE="$DATA_DIR/actions.json"
ELAPSED=0

while true; do
    if [[ -f "$ACTIONS_FILE" ]]; then
        # Check if there are any actions (optionally filtered by type)
        RESULT=$(python3 - "$ACTIONS_FILE" "$ACTION_TYPE" <<'PYEOF' 2>/dev/null || echo ""
import json, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

actions = data.get('actions', [])
action_type = sys.argv[2] if len(sys.argv) > 2 else ""

if action_type:
    actions = [a for a in actions if a.get('type') == action_type]

if actions:
    print(json.dumps({'version': data.get('version', 0), 'actions': actions}))
PYEOF
)

        if [[ -n "$RESULT" ]]; then
            echo "$RESULT"

            # Clear actions if requested
            if [[ "$CLEAR" == "true" ]]; then
                TMP_FILE="${ACTIONS_FILE}.tmp"
                echo '{"version": 0, "actions": []}' > "$TMP_FILE"
                mv "$TMP_FILE" "$ACTIONS_FILE"
            fi
            exit 0
        fi
    fi

    # Check timeout
    if [[ "$TIMEOUT" -gt 0 ]] && [[ "$ELAPSED" -ge "$TIMEOUT" ]]; then
        echo "Timeout: No actions received within ${TIMEOUT}s" >&2
        exit 1
    fi

    sleep "$POLL_INTERVAL"
    ELAPSED=$((ELAPSED + POLL_INTERVAL))
done
