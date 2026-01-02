#!/bin/bash
# NFA-Linux DEB Package Builder
# Creates a Debian package for Ubuntu/Debian systems

set -e

VERSION="${1:-0.1.0}"
APP_NAME="nfa-linux"
ARCH="amd64"
MAINTAINER="NFA-Linux Team <team@nfa-linux.io>"
DESCRIPTION="Next-Generation Network Forensic Analyzer for Linux"

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
DIST_DIR="$PROJECT_DIR/dist"
DEB_ROOT="$DIST_DIR/deb-build"
DEB_FILE="$DIST_DIR/${APP_NAME}_${VERSION}_${ARCH}.deb"

echo "=== Building DEB Package ==="
echo "Version: $VERSION"
echo "Architecture: $ARCH"

# Clean previous build
rm -rf "$DEB_ROOT"
mkdir -p "$DEB_ROOT"

# Create directory structure
mkdir -p "$DEB_ROOT/DEBIAN"
mkdir -p "$DEB_ROOT/usr/bin"
mkdir -p "$DEB_ROOT/usr/lib/$APP_NAME"
mkdir -p "$DEB_ROOT/usr/share/applications"
mkdir -p "$DEB_ROOT/usr/share/icons/hicolor/256x256/apps"
mkdir -p "$DEB_ROOT/usr/share/icons/hicolor/128x128/apps"
mkdir -p "$DEB_ROOT/usr/share/icons/hicolor/64x64/apps"
mkdir -p "$DEB_ROOT/usr/share/doc/$APP_NAME"
mkdir -p "$DEB_ROOT/usr/share/man/man1"
mkdir -p "$DEB_ROOT/etc/$APP_NAME"
mkdir -p "$DEB_ROOT/lib/systemd/system"
mkdir -p "$DEB_ROOT/var/lib/$APP_NAME"
mkdir -p "$DEB_ROOT/var/log/$APP_NAME"

# Copy binary
cp "$BUILD_DIR/$APP_NAME" "$DEB_ROOT/usr/bin/$APP_NAME"
chmod 755 "$DEB_ROOT/usr/bin/$APP_NAME"

# Copy documentation
cp "$PROJECT_DIR/README.md" "$DEB_ROOT/usr/share/doc/$APP_NAME/"
cp "$PROJECT_DIR/docs/"*.md "$DEB_ROOT/usr/share/doc/$APP_NAME/" 2>/dev/null || true

# Create control file
cat > "$DEB_ROOT/DEBIAN/control" << EOF
Package: $APP_NAME
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: $MAINTAINER
Depends: libpcap0.8 (>= 1.9.0), libgtk-3-0 (>= 3.22), libwebkit2gtk-4.1-0 | libwebkit2gtk-4.0-0
Recommends: wireshark, tcpdump
Suggests: docker.io
Installed-Size: $(du -sk "$DEB_ROOT" | cut -f1)
Homepage: https://github.com/cvalentine99/nfa-linux
Description: $DESCRIPTION
 NFA-Linux is a high-performance network forensic analyzer designed
 for security professionals and incident responders. It provides
 real-time packet capture, protocol analysis, file carving, and
 AI-powered anomaly detection.
 .
 Features:
  - 10Gbps+ packet capture with AF_XDP
  - Protocol analysis (DNS, HTTP, TLS, QUIC, SMB)
  - File carving with 40+ file signatures
  - JA3/JA4 TLS fingerprinting
  - CASE/UCO evidence packaging
  - Real-time 3D network topology
EOF

# Create conffiles
cat > "$DEB_ROOT/DEBIAN/conffiles" << EOF
/etc/$APP_NAME/config.yaml
EOF

# Create default config
cat > "$DEB_ROOT/etc/$APP_NAME/config.yaml" << EOF
# NFA-Linux Configuration
# See documentation for all options

capture:
  interface: ""
  mode: "afpacket"
  snaplen: 65535
  promiscuous: true
  bpf_filter: ""
  ring_buffer_size: 67108864
  batch_size: 64
  num_workers: 0  # 0 = auto (number of CPUs)

reassembly:
  max_buffered_pages_per_connection: 4000
  max_buffered_pages_total: 150000
  max_connections: 100000
  flush_interval: "30s"

carver:
  output_dir: "/var/lib/$APP_NAME/carved"
  max_file_size: 104857600
  enable_hashing: true
  hash_algorithm: "blake3"
  extract_executables: true
  extract_archives: true
  extract_documents: true

evidence:
  output_dir: "/var/lib/$APP_NAME/evidence"
  enable_timestamps: true
  tsa_url: "http://timestamp.digicert.com"

ml:
  enable: false
  sidecar_address: "localhost:50051"
  onnx_model_path: ""
  anomaly_threshold: 3.0

logging:
  level: "info"
  file: "/var/log/$APP_NAME/nfa.log"
  max_size: 100
  max_backups: 5
  max_age: 30
EOF

# Create preinst script
cat > "$DEB_ROOT/DEBIAN/preinst" << 'EOF'
#!/bin/bash
set -e

# Create nfa-linux user if it doesn't exist
if ! getent group nfa-linux > /dev/null 2>&1; then
    groupadd --system nfa-linux
fi

if ! getent passwd nfa-linux > /dev/null 2>&1; then
    useradd --system --gid nfa-linux --home-dir /var/lib/nfa-linux \
        --shell /usr/sbin/nologin --comment "NFA-Linux Service Account" nfa-linux
fi

exit 0
EOF
chmod 755 "$DEB_ROOT/DEBIAN/preinst"

# Create postinst script
cat > "$DEB_ROOT/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e

APP_NAME="nfa-linux"

# Set capabilities for packet capture
if [ -x /usr/bin/$APP_NAME ]; then
    setcap cap_net_raw,cap_net_admin=eip /usr/bin/$APP_NAME || true
fi

# Set ownership
chown -R nfa-linux:nfa-linux /var/lib/$APP_NAME
chown -R nfa-linux:nfa-linux /var/log/$APP_NAME
chmod 750 /var/lib/$APP_NAME
chmod 750 /var/log/$APP_NAME

# Reload systemd
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi

# Update desktop database
if command -v update-desktop-database > /dev/null 2>&1; then
    update-desktop-database -q || true
fi

# Update icon cache
if command -v gtk-update-icon-cache > /dev/null 2>&1; then
    gtk-update-icon-cache -q /usr/share/icons/hicolor || true
fi

echo ""
echo "=== NFA-Linux Installation Complete ==="
echo ""
echo "To start the GUI application:"
echo "  nfa-linux"
echo ""
echo "To run in headless mode:"
echo "  nfa-linux -headless -interface eth0"
echo ""
echo "To start as a service:"
echo "  sudo systemctl enable nfa-linux"
echo "  sudo systemctl start nfa-linux"
echo ""
echo "Configuration file: /etc/nfa-linux/config.yaml"
echo "Documentation: /usr/share/doc/nfa-linux/"
echo ""

exit 0
EOF
chmod 755 "$DEB_ROOT/DEBIAN/postinst"

# Create prerm script
cat > "$DEB_ROOT/DEBIAN/prerm" << 'EOF'
#!/bin/bash
set -e

# Stop service if running
if [ -d /run/systemd/system ]; then
    systemctl stop nfa-linux || true
    systemctl disable nfa-linux || true
fi

exit 0
EOF
chmod 755 "$DEB_ROOT/DEBIAN/prerm"

# Create postrm script
cat > "$DEB_ROOT/DEBIAN/postrm" << 'EOF'
#!/bin/bash
set -e

case "$1" in
    purge)
        # Remove user and group
        if getent passwd nfa-linux > /dev/null 2>&1; then
            userdel nfa-linux || true
        fi
        if getent group nfa-linux > /dev/null 2>&1; then
            groupdel nfa-linux || true
        fi
        
        # Remove data directories
        rm -rf /var/lib/nfa-linux
        rm -rf /var/log/nfa-linux
        rm -rf /etc/nfa-linux
        ;;
    
    remove|upgrade|failed-upgrade|abort-install|abort-upgrade|disappear)
        ;;
    
    *)
        echo "postrm called with unknown argument \`$1'" >&2
        exit 1
        ;;
esac

# Reload systemd
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi

exit 0
EOF
chmod 755 "$DEB_ROOT/DEBIAN/postrm"

# Create desktop file
cat > "$DEB_ROOT/usr/share/applications/$APP_NAME.desktop" << EOF
[Desktop Entry]
Name=NFA-Linux
GenericName=Network Forensic Analyzer
Comment=$DESCRIPTION
Exec=$APP_NAME
Icon=$APP_NAME
Terminal=false
Type=Application
Categories=Network;Security;System;Monitor;
Keywords=network;forensics;packet;capture;security;analysis;
StartupNotify=true
StartupWMClass=$APP_NAME
EOF

# Create systemd service file
cat > "$DEB_ROOT/lib/systemd/system/$APP_NAME.service" << EOF
[Unit]
Description=NFA-Linux Network Forensic Analyzer
Documentation=https://github.com/cvalentine99/nfa-linux
After=network.target

[Service]
Type=simple
User=nfa-linux
Group=nfa-linux
ExecStart=/usr/bin/$APP_NAME -headless -config /etc/$APP_NAME/config.yaml
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$APP_NAME

# Security hardening
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/$APP_NAME /var/log/$APP_NAME

# Required capabilities for packet capture
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

# Create man page
cat > "$DEB_ROOT/usr/share/man/man1/$APP_NAME.1" << EOF
.TH NFA-LINUX 1 "January 2026" "nfa-linux $VERSION" "User Commands"
.SH NAME
nfa-linux \- Next-Generation Network Forensic Analyzer
.SH SYNOPSIS
.B nfa-linux
[\fIOPTIONS\fR]
.SH DESCRIPTION
NFA-Linux is a high-performance network forensic analyzer designed for
security professionals and incident responders. It provides real-time
packet capture, protocol analysis, file carving, and AI-powered anomaly
detection.
.SH OPTIONS
.TP
.BR \-version
Print version information and exit.
.TP
.BR \-headless
Run in headless mode (no GUI).
.TP
.BR \-interface " " \fIINTERFACE\fR
Network interface to capture from.
.TP
.BR \-pcap " " \fIFILE\fR
PCAP file to analyze.
.TP
.BR \-filter " " \fIEXPRESSION\fR
BPF filter expression.
.TP
.BR \-duration " " \fIDURATION\fR
Capture duration (e.g., 60s, 5m, 1h).
.TP
.BR \-output " " \fIDIRECTORY\fR
Output directory for results.
.TP
.BR \-debug
Enable debug logging.
.SH FILES
.TP
.I /etc/nfa-linux/config.yaml
Configuration file.
.TP
.I /var/lib/nfa-linux/
Data directory for carved files and evidence.
.TP
.I /var/log/nfa-linux/
Log files.
.SH EXAMPLES
.TP
Start the GUI application:
.B nfa-linux
.TP
Capture from interface eth0:
.B nfa-linux -headless -interface eth0
.TP
Analyze a PCAP file:
.B nfa-linux -headless -pcap capture.pcap -output ./results
.SH SEE ALSO
.BR tcpdump (1),
.BR wireshark (1),
.BR tshark (1)
.SH AUTHOR
NFA-Linux Team <team@nfa-linux.io>
.SH BUGS
Report bugs at https://github.com/cvalentine99/nfa-linux/issues
EOF
gzip -9 "$DEB_ROOT/usr/share/man/man1/$APP_NAME.1"

# Build the package
echo "Building DEB package..."
dpkg-deb --build --root-owner-group "$DEB_ROOT" "$DEB_FILE"

# Verify the package
echo "Verifying package..."
dpkg-deb --info "$DEB_FILE"

# Clean up
rm -rf "$DEB_ROOT"

echo ""
echo "=== DEB Package Created Successfully ==="
echo "Package: $DEB_FILE"
echo ""
echo "To install: sudo dpkg -i $DEB_FILE"
echo "To install with dependencies: sudo apt install ./$DEB_FILE"
