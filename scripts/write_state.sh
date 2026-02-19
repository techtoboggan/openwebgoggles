#!/usr/bin/env bash
# Write state to the webview data contract (atomic write).
#
# Usage:
#   bash scripts/write_state.sh '<json-string>'
#   bash scripts/write_state.sh --file <path-to-json-file>
#
# The JSON must conform to the state.json schema (version, status, data, etc.)

set -euo pipefail

DATA_DIR=".opencode/webview"
STATE_FILE="$DATA_DIR/state.json"
JSON_INPUT=""
FROM_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --file) FROM_FILE="$2"; shift 2 ;;
        --data-dir) DATA_DIR="$2"; STATE_FILE="$DATA_DIR/state.json"; shift 2 ;;
        *) JSON_INPUT="$1"; shift ;;
    esac
done

if [[ -n "$FROM_FILE" ]]; then
    if [[ ! -f "$FROM_FILE" ]]; then
        echo "Error: File not found: $FROM_FILE" >&2
        exit 1
    fi
    JSON_INPUT=$(cat "$FROM_FILE")
elif [[ -z "$JSON_INPUT" ]]; then
    # Read from stdin
    JSON_INPUT=$(cat)
fi

if [[ -z "$JSON_INPUT" ]]; then
    echo "Error: No JSON input provided." >&2
    echo "Usage: bash scripts/write_state.sh '<json>' | --file <path> | stdin" >&2
    exit 1
fi

# Validate JSON
if ! python3 -c "import json,sys; json.loads(sys.argv[1])" "$JSON_INPUT" 2>/dev/null; then
    echo "Error: Invalid JSON" >&2
    exit 1
fi

# Ensure data directory exists
mkdir -p "$DATA_DIR"

# Atomic write: write to temp file, then rename
TMP_FILE="${STATE_FILE}.tmp"
echo "$JSON_INPUT" | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(json.dumps(data, indent=2))
" > "$TMP_FILE"

mv "$TMP_FILE" "$STATE_FILE"
echo "State written (version: $(python3 -c "import json,sys; print(json.loads(open(sys.argv[1]).read()).get('version','?'))" "$STATE_FILE"))"
