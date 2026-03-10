#!/bin/sh
# OpenWebGoggles Docker entrypoint
#
# Discovers the installed SDK path at runtime (works regardless of Python
# minor version) and starts the webview server with sensible defaults.
#
# If arguments are provided, they are forwarded to the webview server as-is.
# If no arguments are given, the default data-dir and sdk-path are used.

set -e

# Locate the installed SDK file using Python
SDK_PATH="$(python -c "
import pathlib, sys
try:
    import scripts.assets
    base = pathlib.Path(scripts.assets.__file__).parent
except (ImportError, AttributeError):
    # Fallback: look relative to the scripts package
    import scripts
    base = pathlib.Path(scripts.__path__[0]) / 'assets'
sdk = base / 'sdk' / 'openwebgoggles-sdk.js'
if not sdk.exists():
    print('ERROR: SDK not found at ' + str(sdk), file=__import__('sys').stderr)
    sys.exit(1)
print(sdk)
")"

# If arguments were passed, forward them directly to the webview server
if [ "$#" -gt 0 ]; then
    exec python -m scripts.webview_server "$@"
fi

# Default: start the webview server with the discovered SDK path
exec python -m scripts.webview_server \
    --data-dir "/app/data" \
    --sdk-path "$SDK_PATH" \
    --http-port 18420 \
    --ws-port 18421
