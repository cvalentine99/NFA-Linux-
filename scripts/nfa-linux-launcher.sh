#!/bin/bash
# NFA-Linux Launcher Script
# Handles capability setup and proper execution

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_NAME="nfa-linux"
BINARY_PATH=""

# Find the binary
if [ -f "$SCRIPT_DIR/$BINARY_NAME" ]; then
    BINARY_PATH="$SCRIPT_DIR/$BINARY_NAME"
elif [ -f "$SCRIPT_DIR/../$BINARY_NAME" ]; then
    BINARY_PATH="$SCRIPT_DIR/../$BINARY_NAME"
elif [ -f "/usr/bin/$BINARY_NAME" ]; then
    BINARY_PATH="/usr/bin/$BINARY_NAME"
elif [ -f "/usr/local/bin/$BINARY_NAME" ]; then
    BINARY_PATH="/usr/local/bin/$BINARY_NAME"
else
    echo "Error: Cannot find $BINARY_NAME binary"
    exit 1
fi

echo "NFA-Linux Launcher"
echo "=================="
echo "Binary: $BINARY_PATH"

# Check if we have required capabilities
check_caps() {
    if command -v getcap &> /dev/null; then
        caps=$(getcap "$BINARY_PATH" 2>/dev/null || true)
        if echo "$caps" | grep -q "cap_net_raw" && echo "$caps" | grep -q "cap_net_admin"; then
            return 0
        fi
    fi
    return 1
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "Running as root - full permissions available"
    exec "$BINARY_PATH" "$@"
fi

# Check for existing capabilities
if check_caps; then
    echo "Capabilities already set - running directly"
    exec "$BINARY_PATH" "$@"
fi

# Need to set capabilities
echo ""
echo "Network capture requires elevated privileges."
echo "Options:"
echo "  1. Run with sudo (recommended for first use)"
echo "  2. Set capabilities on binary (requires sudo once)"
echo ""

# Check if we can use sudo
if command -v sudo &> /dev/null; then
    echo "Attempting to set capabilities..."
    
    # Create a copy with proper permissions
    TEMP_BINARY="/tmp/nfa-linux-$$"
    cp "$BINARY_PATH" "$TEMP_BINARY"
    chmod 755 "$TEMP_BINARY"
    
    if sudo setcap cap_net_raw,cap_net_admin+ep "$TEMP_BINARY" 2>/dev/null; then
        echo "Capabilities set successfully"
        exec "$TEMP_BINARY" "$@"
    else
        echo "Failed to set capabilities. Running with sudo..."
        exec sudo "$BINARY_PATH" "$@"
    fi
else
    echo "Error: sudo not available and capabilities not set"
    echo "Please run: sudo setcap cap_net_raw,cap_net_admin+ep $BINARY_PATH"
    exit 1
fi
