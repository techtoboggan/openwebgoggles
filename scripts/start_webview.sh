#!/usr/bin/env bash
# Start the OpenWebGoggles server and open the browser.
#
# Usage:
#   bash scripts/start_webview.sh --app <app-name> [--port <http-port>] [--ws-port <ws-port>] [--no-browser]
#
# The app must exist in assets/template/ (built-in) or examples/ (demo apps).
# Creates .openwebgoggles/ in the current working directory.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"
DATA_DIR=".openwebgoggles"
HTTP_PORT=18420
WS_PORT=18421
OPEN_BROWSER=true
APP_NAME=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --app) APP_NAME="$2"; shift 2 ;;
        --port) HTTP_PORT="$2"; shift 2 ;;
        --ws-port) WS_PORT="$2"; shift 2 ;;
        --no-browser) OPEN_BROWSER=false; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ -z "$APP_NAME" ]]; then
    echo "Error: --app <name> is required"
    echo "Usage: bash scripts/start_webview.sh --app <app-name>"
    exit 1
fi

# Validate port numbers (must be integers in valid range)
if ! [[ "$HTTP_PORT" =~ ^[0-9]+$ ]] || [[ "$HTTP_PORT" -lt 1 ]] || [[ "$HTTP_PORT" -gt 65535 ]]; then
    echo "Error: --port must be an integer between 1 and 65535" >&2
    exit 1
fi
if ! [[ "$WS_PORT" =~ ^[0-9]+$ ]] || [[ "$WS_PORT" -lt 1 ]] || [[ "$WS_PORT" -gt 65535 ]]; then
    echo "Error: --ws-port must be an integer between 1 and 65535" >&2
    exit 1
fi

# Validate app name: prevent path traversal and shell metacharacter injection
if ! [[ "$APP_NAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]; then
    echo "Error: App name must match /^[a-zA-Z0-9][a-zA-Z0-9._-]*$/" >&2
    exit 1
fi

# Check if server is already running
if [[ -f "$DATA_DIR/.server.pid" ]]; then
    OLD_PID=$(cat "$DATA_DIR/.server.pid")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        echo "Webview server already running (PID: $OLD_PID)"
        echo "Stop it first with: bash scripts/stop_webview.sh"
        exit 1
    fi
    rm -f "$DATA_DIR/.server.pid"
fi

# Create data directory structure
mkdir -p "$DATA_DIR/apps"

# Find and copy the app
APP_SRC=""
if [[ -d "$SKILL_DIR/assets/apps/$APP_NAME" ]]; then
    # Built-in apps (dynamic, template, etc.)
    APP_SRC="$SKILL_DIR/assets/apps/$APP_NAME"
elif [[ -d "$SKILL_DIR/examples/$APP_NAME" ]]; then
    APP_SRC="$SKILL_DIR/examples/$APP_NAME"
elif [[ -d "$APP_NAME" ]]; then
    # Absolute or relative path to a custom app
    APP_SRC="$APP_NAME"
    APP_NAME="$(basename "$APP_NAME")"
fi

if [[ -z "$APP_SRC" ]]; then
    echo "Error: App '$APP_NAME' not found."
    echo "Searched in:"
    echo "  - $SKILL_DIR/assets/apps/$APP_NAME (built-in)"
    echo "  - $SKILL_DIR/examples/$APP_NAME"
    echo "  - $APP_NAME (as direct path)"
    exit 1
fi

# Copy app files to data dir
echo "Copying app '$APP_NAME' from $APP_SRC..."
rm -rf "$DATA_DIR/apps/$APP_NAME"
cp -r "$APP_SRC" "$DATA_DIR/apps/$APP_NAME"

# Copy all SDK files into app directory (SDK, marked.min.js, purify.min.js, etc.)
SDK_DIR="$SKILL_DIR/assets/sdk"
if [[ -d "$SDK_DIR" ]]; then
    for sdk_file in "$SDK_DIR"/*.js; do
        [[ -f "$sdk_file" ]] && cp "$sdk_file" "$DATA_DIR/apps/$APP_NAME/"
    done
fi
SDK_PATH="$SDK_DIR/openwebgoggles-sdk.js"

# Generate session token
SESSION_TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(32))")
SESSION_ID=$(python3 -c "import uuid; print(uuid.uuid4())")
CREATED_AT=$(python3 -c "import time; print(time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))")

# Write manifest.json
cat > "$DATA_DIR/manifest.json" << MANIFEST_EOF
{
  "version": "1.0",
  "app": {
    "name": "$APP_NAME",
    "entry": "$APP_NAME/index.html",
    "title": "$APP_NAME"
  },
  "session": {
    "id": "$SESSION_ID",
    "created_at": "$CREATED_AT",
    "token": "REDACTED"
  },
  "server": {
    "http_port": $HTTP_PORT,
    "ws_port": $WS_PORT,
    "host": "127.0.0.1"
  }
}
MANIFEST_EOF

# Initialize state.json if it doesn't exist
if [[ ! -f "$DATA_DIR/state.json" ]]; then
    cat > "$DATA_DIR/state.json" << STATE_EOF
{
  "version": 0,
  "status": "initializing",
  "updated_at": "$CREATED_AT",
  "title": "Initializing...",
  "message": "",
  "data": {},
  "actions_requested": []
}
STATE_EOF
fi

# Initialize actions.json if it doesn't exist
if [[ ! -f "$DATA_DIR/actions.json" ]]; then
    cat > "$DATA_DIR/actions.json" << ACTIONS_EOF
{
  "version": 0,
  "actions": []
}
ACTIONS_EOF
fi

# Restrict file permissions on sensitive data contract files
chmod 0700 "$DATA_DIR"
chmod 0600 "$DATA_DIR/manifest.json"
chmod 0600 "$DATA_DIR/state.json" 2>/dev/null || true
chmod 0600 "$DATA_DIR/actions.json" 2>/dev/null || true

# --- Python environment via uv ---
VENV_DIR="$SKILL_DIR/scripts/.venv"
PYTHON="$VENV_DIR/bin/python"
REQUIREMENTS="$SKILL_DIR/scripts/requirements.txt"

if command -v uv > /dev/null 2>&1; then
    # Create venv if it doesn't exist
    if [[ ! -f "$PYTHON" ]]; then
        echo "Creating Python venv with uv..."
        uv venv "$VENV_DIR" --quiet
    fi
    # Sync dependencies (fast no-op if already installed)
    uv pip install --quiet --python "$PYTHON" -r "$REQUIREMENTS"
else
    # uv not available — fall back to system python3 with pip
    echo "Warning: uv not found. Using system python3 (consider installing uv for isolation)."
    PYTHON="$(command -v python3 2>/dev/null || command -v python 2>/dev/null || echo '')"
    if [[ -z "$PYTHON" ]]; then
        echo "Error: No Python found. Install uv or python3."
        exit 1
    fi
    "$PYTHON" -c "import websockets" 2>/dev/null || {
        "$PYTHON" -m pip install --quiet websockets || \
            echo "Warning: Could not install websockets. Running HTTP-only mode."
    }
fi

# Start the server in the background (token passed via env, never on disk)
echo "Starting webview server on http://127.0.0.1:$HTTP_PORT..."
OCV_SESSION_TOKEN="$SESSION_TOKEN" "$PYTHON" "$SCRIPT_DIR/webview_server.py" \
    --data-dir "$DATA_DIR" \
    --http-port "$HTTP_PORT" \
    --ws-port "$WS_PORT" \
    --sdk-path "$SDK_PATH" &

SERVER_PID=$!
echo "$SERVER_PID" > "$DATA_DIR/.server.pid"

# Wait for server to be ready (poll the health endpoint)
echo "Waiting for server to be ready..."
RETRIES=0
MAX_RETRIES=30
while [[ $RETRIES -lt $MAX_RETRIES ]]; do
    if curl -s "http://127.0.0.1:$HTTP_PORT/_health" > /dev/null 2>&1; then
        break
    fi
    sleep 0.5
    RETRIES=$((RETRIES + 1))
done

if [[ $RETRIES -ge $MAX_RETRIES ]]; then
    echo "Error: Server failed to start within 15 seconds."
    kill "$SERVER_PID" 2>/dev/null
    exit 1
fi

echo "Server ready (PID: $SERVER_PID)"

# Open the browser
URL="http://127.0.0.1:$HTTP_PORT"
if [[ "$OPEN_BROWSER" == "true" ]]; then
    # Use a per-session sandboxed Chrome app window (no profile, no address bar, no tabs)
    CHROME_PROFILE_DIR=$(mktemp -d)
    # Clean up the temp profile on exit or interruption
    trap "rm -rf \"$CHROME_PROFILE_DIR\"" EXIT INT TERM

    # Detect Chromium-based browser
    CHROME_BIN=""
    for candidate in \
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
        "/Applications/Chromium.app/Contents/MacOS/Chromium" \
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" \
        "$(command -v google-chrome-stable 2>/dev/null)" \
        "$(command -v chromium-browser 2>/dev/null)" \
        "$(command -v chromium 2>/dev/null)"; do
        if [[ -n "$candidate" && -f "$candidate" ]]; then
            CHROME_BIN="$candidate"
            break
        fi
    done

    if [[ -n "$CHROME_BIN" ]]; then
        echo "Opening app window..."
        # --app=URL: removes all browser chrome (address bar, tabs, toolbar)
        # --user-data-dir: isolated sandboxed profile, no history/cookies/extensions
        # --no-first-run: skip the "welcome to chrome" setup
        # --disable-extensions: no extensions leaking into the session
        # --window-size: sensible default for a side panel / review UI
        "$CHROME_BIN" \
            --app="$URL" \
            --user-data-dir="$CHROME_PROFILE_DIR" \
            --no-first-run \
            --disable-default-apps \
            --window-size=960,800 \
            2>/dev/null &
        CHROME_PID=$!
        # Track Chrome PID for lifecycle management (close_webview.sh)
        echo "$CHROME_PID" >> "$DATA_DIR/.chrome.pids"
        echo "App window opened (Chrome PID: $CHROME_PID)"
    else
        # Fallback: regular browser open
        echo "Chrome not found. Opening in default browser..."
        if [[ "$(uname)" == "Darwin" ]]; then
            open "$URL"
        elif command -v xdg-open > /dev/null; then
            xdg-open "$URL"
        else
            echo "Open $URL in your browser."
        fi
    fi
fi

echo ""
echo "=== OpenWebGoggles ==="
echo "  HTTP:      $URL"
echo "  WebSocket: ws://127.0.0.1:$WS_PORT"
echo "  App:       $APP_NAME"
echo "  Data dir:  $DATA_DIR"
echo "  PID:       $SERVER_PID"
echo "========================"
