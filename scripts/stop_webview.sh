#!/usr/bin/env bash
# Stop the OpenWebGoggles server.
#
# Usage:
#   bash scripts/stop_webview.sh [--data-dir <path>]

set -euo pipefail

DATA_DIR=".openwebgoggles"

while [[ $# -gt 0 ]]; do
    case $1 in
        --data-dir) DATA_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

PID_FILE="$DATA_DIR/.server.pid"

if [[ ! -f "$PID_FILE" ]]; then
    echo "No server PID file found at $PID_FILE"
    echo "Server may not be running."
    exit 0
fi

PID=$(cat "$PID_FILE")

# Validate PID is a positive integer (prevent injection via corrupted PID file)
if ! [[ "$PID" =~ ^[0-9]+$ ]] || [[ "$PID" -lt 1 ]]; then
    echo "Error: Invalid PID in $PID_FILE: $PID" >&2
    rm -f "$PID_FILE"
    exit 1
fi

if kill -0 "$PID" 2>/dev/null; then
    echo "Stopping webview server (PID: $PID)..."
    kill "$PID"

    # Wait for graceful shutdown
    RETRIES=0
    while [[ $RETRIES -lt 10 ]]; do
        if ! kill -0 "$PID" 2>/dev/null; then
            break
        fi
        sleep 0.5
        RETRIES=$((RETRIES + 1))
    done

    # Force kill if still running
    if kill -0 "$PID" 2>/dev/null; then
        echo "Force killing server..."
        kill -9 "$PID" 2>/dev/null
    fi

    echo "Server stopped."
else
    echo "Server process $PID is not running."
fi

rm -f "$PID_FILE"

# Close any tracked Chrome windows
CHROME_PIDS_FILE="$DATA_DIR/.chrome.pids"
if [[ -f "$CHROME_PIDS_FILE" ]]; then
    while IFS= read -r cpid; do
        # Validate each PID is a positive integer
        if [[ -n "$cpid" ]] && [[ "$cpid" =~ ^[0-9]+$ ]] && kill -0 "$cpid" 2>/dev/null; then
            echo "Closing Chrome window (PID: $cpid)..."
            kill "$cpid" 2>/dev/null || true
        fi
    done < "$CHROME_PIDS_FILE"
    rm -f "$CHROME_PIDS_FILE"
fi
