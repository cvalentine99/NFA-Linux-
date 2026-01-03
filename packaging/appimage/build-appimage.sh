#!/bin/bash
# Build script for NFA-Linux AppImage
# Usage: ./build-appimage.sh [version]

set -e

VERSION="${1:-1.0.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
APPDIR="$BUILD_DIR/NFA-Linux.AppDir"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Building NFA-Linux AppImage v${VERSION}                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# Check for appimagetool
if ! command -v appimagetool &> /dev/null; then
    echo "Downloading appimagetool..."
    wget -q "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage" \
        -O /tmp/appimagetool
    chmod +x /tmp/appimagetool
    APPIMAGETOOL="/tmp/appimagetool"
else
    APPIMAGETOOL="appimagetool"
fi

# Check for built binary
if [ ! -f "$BUILD_DIR/bin/nfa-linux" ]; then
    echo "Error: Binary not found at $BUILD_DIR/bin/nfa-linux"
    echo "Please run 'wails build' first."
    exit 1
fi

# Clean previous AppDir
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/lib"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"
mkdir -p "$APPDIR/usr/share/metainfo"

echo "Creating AppDir structure..."

# Copy binary
cp "$BUILD_DIR/bin/nfa-linux" "$APPDIR/usr/bin/"
chmod +x "$APPDIR/usr/bin/nfa-linux"

# Copy icon
if [ -f "$PROJECT_ROOT/frontend/public/nfa-icon.svg" ]; then
    cp "$PROJECT_ROOT/frontend/public/nfa-icon.svg" "$APPDIR/nfa-linux.svg"
    cp "$PROJECT_ROOT/frontend/public/nfa-icon.svg" "$APPDIR/usr/share/icons/hicolor/256x256/apps/nfa-linux.svg"
else
    # Create a placeholder icon
    echo '<?xml version="1.0" encoding="UTF-8"?>
<svg width="256" height="256" viewBox="0 0 256 256" xmlns="http://www.w3.org/2000/svg">
  <rect width="256" height="256" rx="32" fill="#8b5cf6"/>
  <text x="128" y="150" font-family="sans-serif" font-size="120" font-weight="bold" fill="white" text-anchor="middle">N</text>
</svg>' > "$APPDIR/nfa-linux.svg"
    cp "$APPDIR/nfa-linux.svg" "$APPDIR/usr/share/icons/hicolor/256x256/apps/"
fi

# Create desktop entry
cat > "$APPDIR/nfa-linux.desktop" << 'EOF'
[Desktop Entry]
Type=Application
Name=NFA-Linux
GenericName=Network Forensics Analyzer
Comment=Next-generation network forensics and packet analysis
Exec=nfa-linux
Icon=nfa-linux
Terminal=false
Categories=Network;Security;System;Monitor;
Keywords=network;forensics;packet;capture;analysis;security;wireshark;
StartupWMClass=nfa-linux
MimeType=application/vnd.tcpdump.pcap;application/x-pcapng;
EOF

cp "$APPDIR/nfa-linux.desktop" "$APPDIR/usr/share/applications/"

# Create AppStream metainfo
cat > "$APPDIR/usr/share/metainfo/io.nfa-linux.NFA-Linux.appdata.xml" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>io.nfa-linux.NFA-Linux</id>
  <metadata_license>MIT</metadata_license>
  <project_license>MIT</project_license>
  <name>NFA-Linux</name>
  <summary>Network Forensics Analyzer</summary>
  <description>
    <p>
      NFA-Linux is a high-performance network forensics analyzer designed for
      digital forensics and incident response (DFIR) professionals.
    </p>
    <p>Features include:</p>
    <ul>
      <li>10Gbps packet capture with AF_XDP/eBPF</li>
      <li>JA3/JA4 TLS fingerprinting</li>
      <li>ML-based anomaly detection</li>
      <li>CASE/UCO evidence export</li>
      <li>3D network topology visualization</li>
      <li>File carving and extraction</li>
    </ul>
  </description>
  <launchable type="desktop-id">nfa-linux.desktop</launchable>
  <url type="homepage">https://github.com/cvalentine99/NFA-Linux-</url>
  <url type="bugtracker">https://github.com/cvalentine99/NFA-Linux-/issues</url>
  <screenshots>
    <screenshot type="default">
      <caption>Main dashboard showing network traffic analysis</caption>
      <image>https://raw.githubusercontent.com/cvalentine99/NFA-Linux-/main/docs/screenshots/dashboard.png</image>
    </screenshot>
  </screenshots>
  <provides>
    <binary>nfa-linux</binary>
  </provides>
  <releases>
    <release version="${VERSION}" date="$(date +%Y-%m-%d)">
      <description>
        <p>Initial release with full forensic analysis capabilities.</p>
      </description>
    </release>
  </releases>
  <content_rating type="oars-1.1"/>
  <categories>
    <category>Network</category>
    <category>Security</category>
    <category>System</category>
  </categories>
</component>
EOF

# Create AppRun script
cat > "$APPDIR/AppRun" << 'EOF'
#!/bin/bash
SELF=$(readlink -f "$0")
HERE=${SELF%/*}
export PATH="${HERE}/usr/bin/:${PATH}"
export LD_LIBRARY_PATH="${HERE}/usr/lib/:${LD_LIBRARY_PATH}"
export XDG_DATA_DIRS="${HERE}/usr/share/:${XDG_DATA_DIRS}"

# Set capabilities if running as root
if [ "$(id -u)" = "0" ]; then
    setcap cap_net_raw,cap_net_admin=eip "${HERE}/usr/bin/nfa-linux" 2>/dev/null || true
fi

exec "${HERE}/usr/bin/nfa-linux" "$@"
EOF
chmod +x "$APPDIR/AppRun"

# Bundle required libraries (GTK3 and WebKit2GTK are too large, rely on system)
echo "Note: GTK3 and WebKit2GTK libraries are not bundled."
echo "      The AppImage requires these to be installed on the target system."

# Build AppImage
echo "Building AppImage..."
cd "$BUILD_DIR"

ARCH=x86_64 "$APPIMAGETOOL" "$APPDIR" "NFA-Linux-${VERSION}-x86_64.AppImage"

if [ -f "NFA-Linux-${VERSION}-x86_64.AppImage" ]; then
    chmod +x "NFA-Linux-${VERSION}-x86_64.AppImage"
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  AppImage built successfully!                               ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  Output: $BUILD_DIR/NFA-Linux-${VERSION}-x86_64.AppImage"
    echo "║  Size: $(du -h "NFA-Linux-${VERSION}-x86_64.AppImage" | cut -f1)"
    echo "╚══════════════════════════════════════════════════════════════╝"
else
    echo "Error: AppImage build failed"
    exit 1
fi
