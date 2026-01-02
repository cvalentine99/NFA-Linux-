#!/bin/bash
# NFA-Linux AppImage Builder
# Creates a portable AppImage for any Linux distribution

set -e

VERSION="${1:-0.1.0}"
APP_NAME="nfa-linux"
ARCH="x86_64"

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
DIST_DIR="$PROJECT_DIR/dist"
APPDIR="$DIST_DIR/AppDir"
APPIMAGE_FILE="$DIST_DIR/${APP_NAME}-${VERSION}-${ARCH}.AppImage"

echo "=== Building AppImage ==="
echo "Version: $VERSION"
echo "Architecture: $ARCH"

# Check for required tools
if ! command -v appimagetool &> /dev/null; then
    echo "Installing appimagetool..."
    wget -q "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage" \
        -O /tmp/appimagetool
    chmod +x /tmp/appimagetool
    APPIMAGETOOL="/tmp/appimagetool"
else
    APPIMAGETOOL="appimagetool"
fi

# Clean previous build
rm -rf "$APPDIR"
mkdir -p "$APPDIR"

# Create AppDir structure
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/lib"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"
mkdir -p "$APPDIR/usr/share/metainfo"

# Copy binary
cp "$BUILD_DIR/$APP_NAME" "$APPDIR/usr/bin/$APP_NAME"
chmod 755 "$APPDIR/usr/bin/$APP_NAME"

# Create desktop file
cat > "$APPDIR/usr/share/applications/$APP_NAME.desktop" << EOF
[Desktop Entry]
Name=NFA-Linux
GenericName=Network Forensic Analyzer
Comment=Next-Generation Network Forensic Analyzer for Linux
Exec=nfa-linux
Icon=nfa-linux
Terminal=false
Type=Application
Categories=Network;Security;System;Monitor;
Keywords=network;forensics;packet;capture;security;analysis;
StartupNotify=true
X-AppImage-Version=$VERSION
EOF

# Copy desktop file to root
cp "$APPDIR/usr/share/applications/$APP_NAME.desktop" "$APPDIR/"

# Create icon (placeholder - generate a simple SVG icon)
cat > "$APPDIR/usr/share/icons/hicolor/256x256/apps/$APP_NAME.svg" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg width="256" height="256" viewBox="0 0 256 256" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#1a1a2e"/>
      <stop offset="100%" style="stop-color:#16213e"/>
    </linearGradient>
    <linearGradient id="accent" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#7c3aed"/>
      <stop offset="100%" style="stop-color:#a855f7"/>
    </linearGradient>
  </defs>
  <!-- Background -->
  <rect width="256" height="256" rx="32" fill="url(#bg)"/>
  <!-- Network nodes -->
  <circle cx="128" cy="80" r="20" fill="url(#accent)"/>
  <circle cx="60" cy="160" r="16" fill="url(#accent)" opacity="0.8"/>
  <circle cx="196" cy="160" r="16" fill="url(#accent)" opacity="0.8"/>
  <circle cx="90" cy="200" r="12" fill="url(#accent)" opacity="0.6"/>
  <circle cx="166" cy="200" r="12" fill="url(#accent)" opacity="0.6"/>
  <!-- Connection lines -->
  <line x1="128" y1="100" x2="60" y2="144" stroke="#a855f7" stroke-width="3" opacity="0.6"/>
  <line x1="128" y1="100" x2="196" y2="144" stroke="#a855f7" stroke-width="3" opacity="0.6"/>
  <line x1="60" y1="176" x2="90" y2="188" stroke="#a855f7" stroke-width="2" opacity="0.4"/>
  <line x1="196" y1="176" x2="166" y2="188" stroke="#a855f7" stroke-width="2" opacity="0.4"/>
  <line x1="90" y1="200" x2="166" y2="200" stroke="#a855f7" stroke-width="2" opacity="0.4"/>
  <!-- Magnifying glass overlay -->
  <circle cx="160" cy="120" r="35" fill="none" stroke="#22d3ee" stroke-width="4" opacity="0.8"/>
  <line x1="185" y1="145" x2="210" y2="170" stroke="#22d3ee" stroke-width="6" stroke-linecap="round" opacity="0.8"/>
</svg>
EOF

# Copy icon to root
cp "$APPDIR/usr/share/icons/hicolor/256x256/apps/$APP_NAME.svg" "$APPDIR/$APP_NAME.svg"
ln -sf "$APP_NAME.svg" "$APPDIR/.DirIcon"

# Create AppStream metainfo
cat > "$APPDIR/usr/share/metainfo/$APP_NAME.appdata.xml" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>io.nfa-linux.$APP_NAME</id>
  <name>NFA-Linux</name>
  <summary>Next-Generation Network Forensic Analyzer</summary>
  <metadata_license>MIT</metadata_license>
  <project_license>MIT</project_license>
  <description>
    <p>
      NFA-Linux is a high-performance network forensic analyzer designed
      for security professionals and incident responders. It provides
      real-time packet capture, protocol analysis, file carving, and
      AI-powered anomaly detection.
    </p>
    <p>Features:</p>
    <ul>
      <li>10Gbps+ packet capture with AF_XDP</li>
      <li>Protocol analysis (DNS, HTTP, TLS, QUIC, SMB)</li>
      <li>File carving with 40+ file signatures</li>
      <li>JA3/JA4 TLS fingerprinting</li>
      <li>CASE/UCO evidence packaging</li>
      <li>Real-time 3D network topology</li>
      <li>AI-powered anomaly detection</li>
    </ul>
  </description>
  <launchable type="desktop-id">$APP_NAME.desktop</launchable>
  <url type="homepage">https://github.com/cvalentine99/nfa-linux</url>
  <url type="bugtracker">https://github.com/cvalentine99/nfa-linux/issues</url>
  <screenshots>
    <screenshot type="default">
      <caption>Main Dashboard</caption>
      <image>https://raw.githubusercontent.com/cvalentine99/nfa-linux/main/docs/screenshots/dashboard.png</image>
    </screenshot>
  </screenshots>
  <content_rating type="oars-1.1"/>
  <releases>
    <release version="$VERSION" date="$(date +%Y-%m-%d)">
      <description>
        <p>Initial release with full feature set.</p>
      </description>
    </release>
  </releases>
  <developer_name>NFA-Linux Team</developer_name>
  <update_contact>team@nfa-linux.io</update_contact>
</component>
EOF

# Create AppRun script
cat > "$APPDIR/AppRun" << 'EOF'
#!/bin/bash
SELF=$(readlink -f "$0")
HERE=${SELF%/*}
export PATH="${HERE}/usr/bin:${PATH}"
export LD_LIBRARY_PATH="${HERE}/usr/lib:${LD_LIBRARY_PATH}"

# Check for required capabilities
if [ "$EUID" -ne 0 ]; then
    # Try to run with capabilities
    if command -v setcap &> /dev/null; then
        echo "Note: For packet capture, run with sudo or set capabilities:"
        echo "  sudo setcap cap_net_raw,cap_net_admin=eip ${HERE}/usr/bin/nfa-linux"
    fi
fi

exec "${HERE}/usr/bin/nfa-linux" "$@"
EOF
chmod 755 "$APPDIR/AppRun"

# Bundle required libraries (optional - for better portability)
echo "Bundling libraries..."
mkdir -p "$APPDIR/usr/lib"

# Copy essential libraries if they exist
for lib in libpcap.so.0.8 libpcap.so.1; do
    if [ -f "/usr/lib/x86_64-linux-gnu/$lib" ]; then
        cp "/usr/lib/x86_64-linux-gnu/$lib" "$APPDIR/usr/lib/" 2>/dev/null || true
    fi
done

# Build AppImage
echo "Building AppImage..."
ARCH=$ARCH $APPIMAGETOOL "$APPDIR" "$APPIMAGE_FILE"

# Clean up
rm -rf "$APPDIR"
rm -f /tmp/appimagetool 2>/dev/null || true

# Make executable
chmod +x "$APPIMAGE_FILE"

echo ""
echo "=== AppImage Created Successfully ==="
echo "AppImage: $APPIMAGE_FILE"
echo ""
echo "To run: chmod +x $APPIMAGE_FILE && ./$APPIMAGE_FILE"
echo ""
echo "Note: For packet capture capabilities, run with sudo or:"
echo "  sudo setcap cap_net_raw,cap_net_admin=eip $APPIMAGE_FILE"
