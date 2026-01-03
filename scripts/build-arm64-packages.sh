#!/bin/bash
# Build script for NFA-Linux ARM64 packages
# Usage: ./build-arm64-packages.sh [deb|appimage|all] [version]

set -e

PACKAGE_TYPE="${1:-all}"
VERSION="${2:-1.0.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
PACKAGING_DIR="$PROJECT_ROOT/packaging"
OUTPUT_DIR="$BUILD_DIR/packages"
ARCH="arm64"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  NFA-Linux ARM64 Package Builder v${VERSION}                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Check for ARM64 binary
check_binary() {
    if [ ! -f "$BUILD_DIR/bin-arm64/nfa-linux" ]; then
        echo "Error: ARM64 binary not found at $BUILD_DIR/bin-arm64/nfa-linux"
        echo "Building ARM64 binary with Wails..."
        cd "$PROJECT_ROOT"
        export CGO_ENABLED=1
        export GOOS=linux
        export GOARCH=arm64
        export CC=aarch64-linux-gnu-gcc
        export CXX=aarch64-linux-gnu-g++
        export PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig
        wails build -clean -tags webkit2_41 -platform linux/arm64
        mkdir -p "$BUILD_DIR/bin-arm64"
        mv "$BUILD_DIR/bin/nfa-linux" "$BUILD_DIR/bin-arm64/"
    fi
}

# Build ARM64 Debian package
build_deb() {
    echo "Building ARM64 Debian package..."
    
    DEB_DIR="$BUILD_DIR/deb-build-arm64"
    rm -rf "$DEB_DIR"
    cp -r "$PACKAGING_DIR/debian" "$DEB_DIR"
    
    # Update version and architecture in control file
    sed -i "s/^Version:.*/Version: $VERSION/" "$DEB_DIR/DEBIAN/control"
    sed -i "s/^Architecture:.*/Architecture: arm64/" "$DEB_DIR/DEBIAN/control"
    
    # Copy ARM64 binary
    cp "$BUILD_DIR/bin-arm64/nfa-linux" "$DEB_DIR/usr/bin/"
    chmod 755 "$DEB_DIR/usr/bin/nfa-linux"
    
    # Set permissions on scripts
    chmod 755 "$DEB_DIR/DEBIAN/postinst"
    chmod 755 "$DEB_DIR/DEBIAN/prerm"
    chmod 755 "$DEB_DIR/DEBIAN/postrm"
    
    # Calculate installed size
    INSTALLED_SIZE=$(du -sk "$DEB_DIR" | cut -f1)
    echo "Installed-Size: $INSTALLED_SIZE" >> "$DEB_DIR/DEBIAN/control"
    
    # Build package
    dpkg-deb --build --root-owner-group "$DEB_DIR" "$OUTPUT_DIR/nfa-linux_${VERSION}_arm64.deb"
    
    echo "✓ ARM64 Debian package built: $OUTPUT_DIR/nfa-linux_${VERSION}_arm64.deb"
    echo "  Size: $(du -h "$OUTPUT_DIR/nfa-linux_${VERSION}_arm64.deb" | cut -f1)"
}

# Build ARM64 AppImage
build_appimage() {
    echo "Building ARM64 AppImage..."
    
    # Download ARM64 appimagetool if not present
    if [ ! -f "/tmp/appimagetool-arm64" ]; then
        echo "Downloading ARM64 appimagetool..."
        wget -q "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-aarch64.AppImage" \
            -O /tmp/appimagetool-arm64
        chmod +x /tmp/appimagetool-arm64
        cd /tmp && rm -rf squashfs-root-arm64 && /tmp/appimagetool-arm64 --appimage-extract > /dev/null 2>&1
        mv squashfs-root squashfs-root-arm64
    fi
    APPIMAGETOOL="/tmp/squashfs-root-arm64/AppRun"
    
    APPDIR="$BUILD_DIR/NFA-Linux-arm64.AppDir"
    rm -rf "$APPDIR"
    mkdir -p "$APPDIR/usr/bin"
    mkdir -p "$APPDIR/usr/share/applications"
    mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"
    mkdir -p "$APPDIR/usr/share/metainfo"
    
    # Copy ARM64 binary
    cp "$BUILD_DIR/bin-arm64/nfa-linux" "$APPDIR/usr/bin/"
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
    
    # Build AppImage (note: appimagetool is x86_64, but can create arm64 AppImages)
    cd "$BUILD_DIR"
    ARCH=aarch64 $APPIMAGETOOL --no-appstream "$APPDIR" "$OUTPUT_DIR/NFA-Linux-${VERSION}-aarch64.AppImage" 2>/dev/null || {
        echo "Note: appimagetool may not run on this architecture."
        echo "Creating tarball instead..."
        tar -czvf "$OUTPUT_DIR/NFA-Linux-${VERSION}-aarch64.tar.gz" -C "$BUILD_DIR" "NFA-Linux-arm64.AppDir"
        echo "✓ ARM64 tarball created: $OUTPUT_DIR/NFA-Linux-${VERSION}-aarch64.tar.gz"
        return
    }
    chmod +x "$OUTPUT_DIR/NFA-Linux-${VERSION}-aarch64.AppImage"
    
    echo "✓ ARM64 AppImage built: $OUTPUT_DIR/NFA-Linux-${VERSION}-aarch64.AppImage"
    echo "  Size: $(du -h "$OUTPUT_DIR/NFA-Linux-${VERSION}-aarch64.AppImage" | cut -f1)"
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
echo "║  ARM64 Build complete! Packages available in:               ║"
echo "║  $OUTPUT_DIR"
echo "╚══════════════════════════════════════════════════════════════╝"
ls -lh "$OUTPUT_DIR"/*arm64* "$OUTPUT_DIR"/*aarch64* 2>/dev/null || true
