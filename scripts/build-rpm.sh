#!/bin/bash
# NFA-Linux RPM Package Builder
# Creates an RPM package for Fedora/RHEL/CentOS systems

set -e

VERSION="${1:-0.1.0}"
RELEASE="1"
APP_NAME="nfa-linux"
ARCH="x86_64"

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
DIST_DIR="$PROJECT_DIR/dist"
RPM_BUILD_DIR="$DIST_DIR/rpmbuild"
RPM_FILE="$DIST_DIR/${APP_NAME}-${VERSION}-${RELEASE}.${ARCH}.rpm"

echo "=== Building RPM Package ==="
echo "Version: $VERSION"
echo "Release: $RELEASE"
echo "Architecture: $ARCH"

# Clean previous build
rm -rf "$RPM_BUILD_DIR"

# Create RPM build directory structure
mkdir -p "$RPM_BUILD_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Create tarball for source
TARBALL_NAME="${APP_NAME}-${VERSION}"
TARBALL_DIR="$RPM_BUILD_DIR/SOURCES/$TARBALL_NAME"
mkdir -p "$TARBALL_DIR"

# Copy files to tarball directory
cp "$BUILD_DIR/$APP_NAME" "$TARBALL_DIR/"
cp "$PROJECT_DIR/README.md" "$TARBALL_DIR/"
cp -r "$PROJECT_DIR/docs" "$TARBALL_DIR/" 2>/dev/null || mkdir -p "$TARBALL_DIR/docs"

# Create tarball
cd "$RPM_BUILD_DIR/SOURCES"
tar -czvf "${TARBALL_NAME}.tar.gz" "$TARBALL_NAME"
rm -rf "$TARBALL_NAME"
cd -

# Create spec file
cat > "$RPM_BUILD_DIR/SPECS/$APP_NAME.spec" << EOF
Name:           $APP_NAME
Version:        $VERSION
Release:        $RELEASE%{?dist}
Summary:        Next-Generation Network Forensic Analyzer for Linux

License:        MIT
URL:            https://github.com/cvalentine99/nfa-linux
Source0:        %{name}-%{version}.tar.gz

BuildArch:      $ARCH
Requires:       libpcap >= 1.9.0
Requires:       gtk3 >= 3.22
Requires:       webkit2gtk4.1 >= 2.36 or webkit2gtk3 >= 2.36
Recommends:     wireshark
Recommends:     tcpdump
Suggests:       docker

%description
NFA-Linux is a high-performance network forensic analyzer designed
for security professionals and incident responders. It provides
real-time packet capture, protocol analysis, file carving, and
AI-powered anomaly detection.

Features:
- 10Gbps+ packet capture with AF_XDP
- Protocol analysis (DNS, HTTP, TLS, QUIC, SMB)
- File carving with 40+ file signatures
- JA3/JA4 TLS fingerprinting
- CASE/UCO evidence packaging
- Real-time 3D network topology

%prep
%setup -q

%install
rm -rf %{buildroot}

# Binary
install -D -m 755 %{name} %{buildroot}%{_bindir}/%{name}

# Documentation
install -D -m 644 README.md %{buildroot}%{_docdir}/%{name}/README.md
cp -r docs/* %{buildroot}%{_docdir}/%{name}/ 2>/dev/null || true

# Config directory
install -d -m 750 %{buildroot}%{_sysconfdir}/%{name}

# Data directories
install -d -m 750 %{buildroot}%{_sharedstatedir}/%{name}
install -d -m 750 %{buildroot}%{_sharedstatedir}/%{name}/carved
install -d -m 750 %{buildroot}%{_sharedstatedir}/%{name}/evidence
install -d -m 750 %{buildroot}%{_localstatedir}/log/%{name}

# Systemd service
install -d -m 755 %{buildroot}%{_unitdir}
cat > %{buildroot}%{_unitdir}/%{name}.service << 'SERVICEEOF'
[Unit]
Description=NFA-Linux Network Forensic Analyzer
Documentation=https://github.com/cvalentine99/nfa-linux
After=network.target

[Service]
Type=simple
User=nfa-linux
Group=nfa-linux
ExecStart=/usr/bin/nfa-linux -headless -config /etc/nfa-linux/config.yaml
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=nfa-linux
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/nfa-linux /var/log/nfa-linux
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
SERVICEEOF

# Desktop file
install -d -m 755 %{buildroot}%{_datadir}/applications
cat > %{buildroot}%{_datadir}/applications/%{name}.desktop << 'DESKTOPEOF'
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
StartupWMClass=nfa-linux
DESKTOPEOF

# Default config
cat > %{buildroot}%{_sysconfdir}/%{name}/config.yaml << 'CONFIGEOF'
# NFA-Linux Configuration
capture:
  interface: ""
  mode: "afpacket"
  snaplen: 65535
  promiscuous: true
  bpf_filter: ""
  ring_buffer_size: 67108864
  batch_size: 64
  num_workers: 0

reassembly:
  max_buffered_pages_per_connection: 4000
  max_buffered_pages_total: 150000
  max_connections: 100000
  flush_interval: "30s"

carver:
  output_dir: "/var/lib/nfa-linux/carved"
  max_file_size: 104857600
  enable_hashing: true
  hash_algorithm: "blake3"

evidence:
  output_dir: "/var/lib/nfa-linux/evidence"
  enable_timestamps: true

ml:
  enable: false
  sidecar_address: "localhost:50051"

logging:
  level: "info"
  file: "/var/log/nfa-linux/nfa.log"
CONFIGEOF

%pre
# Create user and group
getent group nfa-linux > /dev/null || groupadd -r nfa-linux
getent passwd nfa-linux > /dev/null || useradd -r -g nfa-linux -d /var/lib/nfa-linux -s /sbin/nologin -c "NFA-Linux Service Account" nfa-linux
exit 0

%post
# Set capabilities
setcap cap_net_raw,cap_net_admin=eip %{_bindir}/%{name} || true

# Set ownership
chown -R nfa-linux:nfa-linux %{_sharedstatedir}/%{name}
chown -R nfa-linux:nfa-linux %{_localstatedir}/log/%{name}

# Reload systemd
%systemd_post %{name}.service

# Update desktop database
update-desktop-database &> /dev/null || true

echo ""
echo "=== NFA-Linux Installation Complete ==="
echo "To start: nfa-linux"
echo "To start service: sudo systemctl enable --now nfa-linux"
echo ""

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

if [ \$1 -eq 0 ]; then
    # Package removal
    userdel nfa-linux 2>/dev/null || true
    groupdel nfa-linux 2>/dev/null || true
fi

%files
%license LICENSE
%doc README.md
%{_bindir}/%{name}
%{_unitdir}/%{name}.service
%{_datadir}/applications/%{name}.desktop
%dir %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/config.yaml
%dir %attr(750,nfa-linux,nfa-linux) %{_sharedstatedir}/%{name}
%dir %attr(750,nfa-linux,nfa-linux) %{_sharedstatedir}/%{name}/carved
%dir %attr(750,nfa-linux,nfa-linux) %{_sharedstatedir}/%{name}/evidence
%dir %attr(750,nfa-linux,nfa-linux) %{_localstatedir}/log/%{name}
%{_docdir}/%{name}

%changelog
* $(date "+%a %b %d %Y") NFA-Linux Team <team@nfa-linux.io> - $VERSION-$RELEASE
- Initial release
- High-speed packet capture with AF_XDP
- Protocol analysis (DNS, HTTP, TLS, QUIC, SMB)
- File carving with 40+ signatures
- AI/ML anomaly detection
- CASE/UCO evidence packaging
EOF

# Build the RPM
echo "Building RPM package..."
rpmbuild --define "_topdir $RPM_BUILD_DIR" -bb "$RPM_BUILD_DIR/SPECS/$APP_NAME.spec"

# Move RPM to dist directory
mv "$RPM_BUILD_DIR/RPMS/$ARCH/"*.rpm "$DIST_DIR/"

# Clean up
rm -rf "$RPM_BUILD_DIR"

echo ""
echo "=== RPM Package Created Successfully ==="
echo "Package: $RPM_FILE"
echo ""
echo "To install: sudo rpm -i $RPM_FILE"
echo "To install with dependencies: sudo dnf install $RPM_FILE"
