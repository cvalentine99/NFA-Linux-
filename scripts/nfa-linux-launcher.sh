#!/bin/bash
# NFA-Linux Launcher Script
# Handles capability setup, WebKit workarounds, and proper execution

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_NAME="nfa-linux"
BINARY_PATH=""

setup_webkit_env() {
    export WEBKIT_DISABLE_DMABUF_RENDERER=1
}

find_binary() {
    if [ -f "$SCRIPT_DIR/$BINARY_NAME" ]; then
        BINARY_PATH="$SCRIPT_DIR/$BINARY_NAME"
    elif [ -f "$SCRIPT_DIR/../bin/$BINARY_NAME" ]; then
        BINARY_PATH="$SCRIPT_DIR/../bin/$BINARY_NAME"
    elif [ -f "/opt/nfa-linux/$BINARY_NAME" ]; then
        BINARY_PATH="/opt/nfa-linux/$BINARY_NAME"
    else
        echo "Error: Cannot find $BINARY_NAME binary"
        exit 1
    fi
}

find_binary

if [[ ! " $* " =~ " -headless " ]]; then
    setup_webkit_env
fi

echo "NFA-Linux Launcher"
echo "Binary: $BINARY_PATH"
echo "Kernel: $(uname -r)"

exec "$BINARY_PATH" "$@"
