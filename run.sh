#!/bin/bash
# Run PacketTracer with the virtual environment

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$SCRIPT_DIR/.venv/bin/python"

if [ ! -f "$VENV_PYTHON" ]; then
    echo "Error: Virtual environment not found at $SCRIPT_DIR/.venv"
    echo "Create it with: python -m venv .venv && .venv/bin/pip install -r requirements.txt"
    exit 1
fi

sudo "$VENV_PYTHON" "$SCRIPT_DIR/main.py" "$@"
