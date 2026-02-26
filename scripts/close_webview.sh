#!/usr/bin/env bash
# Close all webview windows for the current session.
#
# Sends a WebSocket "close" message to all connected clients (they self-close),
# then kills any tracked Chrome PIDs. Does NOT stop the server.
#
# Usage:
#   bash scripts/close_webview.sh [--message "text"] [--delay-ms 1500] [--data-dir <path>]
#
# Options:
#   --message   Message shown to user before closing (default: "Session complete.")
#   --delay-ms  Milliseconds before window closes after message (default: 1500)
#   --data-dir  Path to .openwebgoggles directory (default: .openwebgoggles)

set -euo pipefail

DATA_DIR=".openwebgoggles"
CLOSE_MESSAGE="Session complete."
DELAY_MS=1500

while [[ $# -gt 0 ]]; do
    case $1 in
        --message)   CLOSE_MESSAGE="$2"; shift 2 ;;
        --delay-ms)  DELAY_MS="$2"; shift 2 ;;
        --data-dir)  DATA_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Validate DELAY_MS is a non-negative integer
if ! [[ "$DELAY_MS" =~ ^[0-9]+$ ]]; then
    echo "Error: --delay-ms must be a non-negative integer" >&2
    exit 1
fi

# 1. Notify connected browser clients via the API (they'll self-close after delay)
if [[ -f "$DATA_DIR/manifest.json" ]]; then
    TOKEN=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['session']['token'])" "$DATA_DIR/manifest.json" 2>/dev/null || echo "")
    HTTP_PORT=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['server']['http_port'])" "$DATA_DIR/manifest.json" 2>/dev/null || echo "18420")

    if [[ -n "$TOKEN" ]]; then
        PAYLOAD=$(python3 -c "import json,sys; print(json.dumps({'message': sys.argv[1], 'delay_ms': int(sys.argv[2])}))" "$CLOSE_MESSAGE" "$DELAY_MS")
        # Use --config with process substitution to keep token out of ps output
        RESPONSE=$(curl --config <(printf 'header = "Authorization: Bearer %s"\n' "$TOKEN") \
            -s -X POST "http://127.0.0.1:$HTTP_PORT/_api/close" \
            -H "Content-Type: application/json" \
            -d "$PAYLOAD" 2>/dev/null || echo "")
        if [[ -n "$RESPONSE" ]]; then
            CLIENTS=$(echo "$RESPONSE" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('clients_notified',0))" 2>/dev/null || echo "0")
            echo "Close message sent to $CLIENTS connected client(s)."
        fi
    fi
fi

# 2. Wait for the delay so clients have time to self-close gracefully
if [[ $DELAY_MS -gt 0 ]]; then
    WAIT_SECS=$(python3 -c "import sys; print(float(sys.argv[1]) / 1000 + 0.5)" "$DELAY_MS")
    sleep "$WAIT_SECS"
fi

# 3. Kill any tracked Chrome PIDs (catches windows that may have lost WS connection)
CHROME_PIDS_FILE="$DATA_DIR/.chrome.pids"
KILLED=0
if [[ -f "$CHROME_PIDS_FILE" ]]; then
    while IFS= read -r cpid; do
        # Validate each PID is a positive integer
        if [[ -n "$cpid" ]] && [[ "$cpid" =~ ^[0-9]+$ ]] && kill -0 "$cpid" 2>/dev/null; then
            kill "$cpid" 2>/dev/null && KILLED=$((KILLED + 1)) || true
        fi
    done < "$CHROME_PIDS_FILE"
    rm -f "$CHROME_PIDS_FILE"
    [[ $KILLED -gt 0 ]] && echo "Closed $KILLED Chrome window(s)."
fi

echo "Done."
