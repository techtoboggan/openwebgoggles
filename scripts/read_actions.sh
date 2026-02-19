#!/usr/bin/env bash
# Read actions from the webview data contract.
#
# Usage:
#   bash scripts/read_actions.sh            # Print actions.json to stdout
#   bash scripts/read_actions.sh --clear    # Print and then clear actions
#   bash scripts/read_actions.sh --count    # Print number of pending actions

set -euo pipefail

DATA_DIR=".opencode/webview"
CLEAR=false
COUNT_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --clear) CLEAR=true; shift ;;
        --count) COUNT_ONLY=true; shift ;;
        --data-dir) DATA_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

ACTIONS_FILE="$DATA_DIR/actions.json"

if [[ ! -f "$ACTIONS_FILE" ]]; then
    echo '{"version": 0, "actions": []}'
    exit 0
fi

if [[ "$COUNT_ONLY" == "true" ]]; then
    python3 -c "import json,sys; data=json.load(open(sys.argv[1])); print(len(data.get('actions',[])))" "$ACTIONS_FILE"
    exit 0
fi

# Print current actions
cat "$ACTIONS_FILE"

# Clear if requested
if [[ "$CLEAR" == "true" ]]; then
    TMP_FILE="${ACTIONS_FILE}.tmp"
    echo '{"version": 0, "actions": []}' > "$TMP_FILE"
    mv "$TMP_FILE" "$ACTIONS_FILE"
fi
