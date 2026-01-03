#!/bin/bash
# Build script for NFA-Linux packages
# Usage: ./build-packages.sh [deb|appimage|all] [version]

set -e

PACKAGE_TYPE="${1:-all}"
VERSION="${2:-1.0.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
PACKAGING_DIR="$PROJECT_ROOT/packaging"
OUTPUT_DIR="$BUILD_DIR/packages"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  NFA-Linux Package Builder v${VERSION}                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Check for Wails binary
check_binary() {
    if [ ! -f "$BUILD_DIR/bin/nfa-linux" ]; then
        echo "Error: Binary not found at $BUILD_DIR/bin/nfa-linux"
        echo "Building with Wails..."
        cd "$PROJECT_ROOT"
        # Use webkit2_41 tag for Ubuntu 24.04+ compatibility
        wails build -clean -tags webkit2_41
    fi
}

# Build Debian package
build_deb() {
    echo "Building Debian package..."
    
    DEB_DIR="$BUILD_DIR/deb-build"
    rm -rf "$DEB_DIR"
    cp -r "$PACKAGING_DIR/debian" "$DEB_DIR"
    
    # Update version in control file
    sed -i "s/^Version:.*/Version: $VERSION/" "$DEB_DIR/DEBIAN/control"
    
    # Copy binary
    cp "$BUILD_DIR/bin/nfa-linux" "$DEB_DIR/usr/bin/"
    chmod 755 "$DEB_DIR/usr/bin/nfa-linux"
    
    # Set permissions on scripts
    chmod 755 "$DEB_DIR/DEBIAN/postinst"
    chmod 755 "$DEB_DIR/DEBIAN/prerm"
    chmod 755 "$DEB_DIR/DEBIAN/postrm"
    
    # Calculate installed size
    INSTALLED_SIZE=$(du -sk "$DEB_DIR" | cut -f1)
    echo "Installed-Size: $INSTALLED_SIZE" >> "$DEB_DIR/DEBIAN/control"
    
    # Build package
    dpkg-deb --build --root-owner-group "$DEB_DIR" "$OUTPUT_DIR/nfa-linux_${VERSION}_amd64.deb"
    
    echo "✓ Debian package built: $OUTPUT_DIR/nfa-linux_${VERSION}_amd64.deb"
    echo "  Size: $(du -h "$OUTPUT_DIR/nfa-linux_${VERSION}_amd64.deb" | cut -f1)"
}

# Build AppImage
build_appimage() {
    echo "Building AppImage..."
    
    # Download and extract appimagetool if not present
    if [ ! -f "/tmp/squashfs-root/AppRun" ]; then
        echo "Downloading appimagetool..."
        wget -q "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage" \
            -O /tmp/appimagetool
        chmod +x /tmp/appimagetool
        cd /tmp && rm -rf squashfs-root && /tmp/appimagetool --appimage-extract > /dev/null 2>&1
    fi
    APPIMAGETOOL="/tmp/squashfs-root/AppRun"
    
    APPDIR="$BUILD_DIR/NFA-Linux.AppDir"
    rm -rf "$APPDIR"
    mkdir -p "$APPDIR/usr/bin"
    mkdir -p "$APPDIR/usr/share/applications"
    mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"
    mkdir -p "$APPDIR/usr/share/metainfo"
    
    # Copy binary
    cp "$BUILD_DIR/bin/nfa-linux" "$APPDIR/usr/bin/"
    chmod 755 "$APPDIR/usr/bin/nfa-linux"
    
    # Copy icon
    cp "$PACKAGING_DIR/debian/usr/share/icons/hicolor/256x256/apps/nfa-linux.svg" "$APPDIR/nfa-linux.svg"
    cp "$PACKAGING_DIR/debian/usr/share/icons/hicolor/256x256/apps/nfa-linux.svg" "$APPDIR/usr/share/icons/hicolor/256x256/apps/"
    
    # Copy desktop entry
    cp "$PACKAGING_DIR/debian/usr/share/applications/nfa-linux.desktop" "$APPDIR/"
    cp "$PACKAGING_DIR/debian/usr/share/applications/nfa-linux.desktop" "$APPDIR/usr/share/applications/"
    
    # Create AppRun
    cat > "$APPDIR/AppRun" << 'EOF'
#!/bin/bash
SELF=$(readlink -f "$0")
HERE=${SELF%/*}
export PATH="${HERE}/usr/bin/:${PATH}"
export LD_LIBRARY_PATH="${HERE}/usr/lib/:${LD_LIBRARY_PATH}"
export XDG_DATA_DIRS="${HERE}/usr/share/:${XDG_DATA_DIRS}"
exec "${HERE}/usr/bin/nfa-linux" "$@"
EOF
    chmod +x "$APPDIR/AppRun"
    
    # Build AppImage
    cd "$BUILD_DIR"
    ARCH=x86_64 $APPIMAGETOOL --no-appstream "$APPDIR" "$OUTPUT_DIR/NFA-Linux-${VERSION}-x86_64.AppImage"
    chmod +x "$OUTPUT_DIR/NFA-Linux-${VERSION}-x86_64.AppImage"
    
    echo "✓ AppImage built: $OUTPUT_DIR/NFA-Linux-${VERSION}-x86_64.AppImage"
    echo "  Size: $(du -h "$OUTPUT_DIR/NFA-Linux-${VERSION}-x86_64.AppImage" | cut -f1)"
}

# Main
check_binary

case "$PACKAGE_TYPE" in
    deb)
        build_deb
        ;;
    appimage)
        build_appimage
        ;;
    all)
        build_deb
        build_appimage
        ;;
    *)
        echo "Usage: $0 [deb|appimage|all] [version]"
        exit 1
        ;;
esac

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Build complete! Packages available in:                     ║"
echo "║  $OUTPUT_DIR"
echo "╚══════════════════════════════════════════════════════════════╝"
ls -lh "$OUTPUT_DIR"
