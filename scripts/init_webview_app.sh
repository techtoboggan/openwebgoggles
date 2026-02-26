#!/usr/bin/env bash
# Scaffold a new webview app from the built-in template.
#
# Usage:
#   bash scripts/init_webview_app.sh <app-name>
#   bash scripts/init_webview_app.sh <app-name> --dest <directory>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"
TEMPLATE_DIR="$SKILL_DIR/assets/template"
APP_NAME=""
DEST_DIR=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --dest) DEST_DIR="$2"; shift 2 ;;
        -*) echo "Unknown option: $1"; exit 1 ;;
        *) APP_NAME="$1"; shift ;;
    esac
done

if [[ -z "$APP_NAME" ]]; then
    echo "Error: App name is required"
    echo "Usage: bash scripts/init_webview_app.sh <app-name> [--dest <directory>]"
    exit 1
fi

# Validate app name to prevent sed injection and path traversal
if ! [[ "$APP_NAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]; then
    echo "Error: App name must match /^[a-zA-Z0-9][a-zA-Z0-9._-]*$/" >&2
    exit 1
fi

if [[ -z "$DEST_DIR" ]]; then
    DEST_DIR="./$APP_NAME"
fi

if [[ -d "$DEST_DIR" ]]; then
    echo "Error: Directory already exists: $DEST_DIR"
    exit 1
fi

if [[ ! -d "$TEMPLATE_DIR" ]]; then
    echo "Error: Template directory not found: $TEMPLATE_DIR"
    exit 1
fi

echo "Scaffolding webview app '$APP_NAME'..."
cp -r "$TEMPLATE_DIR" "$DEST_DIR"

# Copy SDK into the app directory
SDK_PATH="$SKILL_DIR/assets/sdk/openwebgoggles-sdk.js"
if [[ -f "$SDK_PATH" ]]; then
    cp "$SDK_PATH" "$DEST_DIR/openwebgoggles-sdk.js"
fi

# Replace placeholder app name in files (use | delimiter since APP_NAME is validated
# to only contain [a-zA-Z0-9._-] — no risk of delimiter collision)
if [[ "$(uname)" == "Darwin" ]]; then
    find "$DEST_DIR" -type f \( -name "*.html" -o -name "*.js" -o -name "*.json" \) \
        -exec sed -i '' "s|{{APP_NAME}}|$APP_NAME|g" {} +
else
    find "$DEST_DIR" -type f \( -name "*.html" -o -name "*.js" -o -name "*.json" \) \
        -exec sed -i "s|{{APP_NAME}}|$APP_NAME|g" {} +
fi

echo ""
echo "Created webview app at: $DEST_DIR"
echo ""
echo "Files:"
ls -la "$DEST_DIR"
echo ""
echo "Next steps:"
echo "  1. Edit $DEST_DIR/app.js to implement your UI logic"
echo "  2. Edit $DEST_DIR/style.css for custom styling"
echo "  3. Launch: bash scripts/start_webview.sh --app $DEST_DIR"
