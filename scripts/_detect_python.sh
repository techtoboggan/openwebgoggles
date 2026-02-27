#!/usr/bin/env bash
# Shared helper: detect the correct Python interpreter.
#
# Sources into other scripts via:
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   source "$SCRIPT_DIR/_detect_python.sh"
#
# After sourcing, $PYTHON is set to the best available interpreter:
#   1. The project venv at scripts/.venv/bin/python (if it exists)
#   2. python3 on PATH
#   3. python on PATH
#
# Exits with an error if no Python is found.

if [[ -z "${PYTHON:-}" ]]; then
    _VENV_PYTHON="${BASH_SOURCE[0]%/*}/.venv/bin/python"
    if [[ -x "$_VENV_PYTHON" ]]; then
        PYTHON="$_VENV_PYTHON"
    elif command -v python3 > /dev/null 2>&1; then
        PYTHON="$(command -v python3)"
    elif command -v python > /dev/null 2>&1; then
        PYTHON="$(command -v python)"
    else
        echo "Error: No Python interpreter found. Install python3 or create a venv." >&2
        exit 1
    fi
fi
