# NFA-Linux Packaging Guide

This document describes how to build and distribute NFA-Linux packages for Linux systems.

## Supported Package Formats

| Format | File | Target Systems |
|--------|------|----------------|
| **Debian** | `nfa-linux_1.0.0_amd64.deb` | Ubuntu, Debian, Linux Mint, Pop!_OS |
| **AppImage** | `NFA-Linux-1.0.0-x86_64.AppImage` | Any Linux distribution |

## Quick Start

```bash
# Build all packages
./scripts/build-packages.sh all 1.0.0

# Build only Debian package
./scripts/build-packages.sh deb 1.0.0

# Build only AppImage
./scripts/build-packages.sh appimage 1.0.0
```

## Prerequisites

### Build Dependencies

```bash
# Ubuntu/Debian
sudo apt-get install -y \
    build-essential \
    libgtk-3-dev \
    libwebkit2gtk-4.0-dev \
    libfuse2 \
    wget
```

### Wails Binary

The packaging scripts require a pre-built Wails binary. If not present, run:

```bash
# For Ubuntu 24.04+ / Debian 13+ (webkit2gtk-4.1)
wails build -clean -tags webkit2_41

# For Ubuntu 22.04 / Debian 12 (webkit2gtk-4.0)
wails build -clean
```

**Important:** Ubuntu 24.04 and newer require the `-tags webkit2_41` flag because `libwebkit2gtk-4.0` was removed in favor of `libwebkit2gtk-4.1`.

## Debian Package

### Package Contents

```
/usr/bin/nfa-linux                              # Main binary
/usr/share/applications/nfa-linux.desktop       # Desktop entry
/usr/share/icons/hicolor/256x256/apps/nfa-linux.svg  # Application icon
/usr/share/doc/nfa-linux/copyright              # License information
/etc/nfa-linux/config.yaml                      # Default configuration
/lib/systemd/system/nfa-linux-capture.service   # Systemd service
/lib/systemd/system/nfa-linux-capture@.service  # Interface-specific service
```

### Installation

```bash
# Install
sudo dpkg -i nfa-linux_1.0.0_amd64.deb

# Fix dependencies if needed
sudo apt-get install -f

# Or use apt directly
sudo apt install ./nfa-linux_1.0.0_amd64.deb
```

### Post-Installation

The package automatically:
- Creates the `nfa-linux` system group
- Sets network capture capabilities on the binary
- Creates data directories at `/var/lib/nfa-linux/`

To capture packets without root:

```bash
sudo usermod -aG nfa-linux $USER
# Log out and back in
```

### Uninstallation

```bash
# Remove package (keep config)
sudo apt remove nfa-linux

# Remove package and config
sudo apt purge nfa-linux
```

## AppImage

### Usage

```bash
# Make executable (if needed)
chmod +x NFA-Linux-1.0.0-x86_64.AppImage

# Run
./NFA-Linux-1.0.0-x86_64.AppImage
```

### System Requirements

The AppImage requires these libraries on the host system:
- GTK 3.22+
- WebKit2GTK 4.0
- libfuse2 (for running AppImages)

### Desktop Integration

To integrate with your desktop environment:

```bash
# Using AppImageLauncher (recommended)
# https://github.com/TheAssassin/AppImageLauncher

# Or manually
cp NFA-Linux-1.0.0-x86_64.AppImage ~/.local/bin/
# Create desktop entry manually
```

## Systemd Services

### Headless Capture Mode

For server deployments without a GUI:

```bash
# Start capture on eth0
sudo systemctl start nfa-linux-capture@eth0

# Enable at boot
sudo systemctl enable nfa-linux-capture@eth0

# Check status
sudo systemctl status nfa-linux-capture@eth0

# View logs
journalctl -u nfa-linux-capture@eth0 -f
```

### Multiple Interfaces

```bash
# Capture on multiple interfaces
sudo systemctl start nfa-linux-capture@eth0
sudo systemctl start nfa-linux-capture@eth1
```

## Configuration

The default configuration file is at `/etc/nfa-linux/config.yaml`:

```yaml
capture:
  interface: ""           # Auto-detect
  mode: afpacket          # afpacket, afxdp, pcap
  promiscuous: true
  snaplen: 65535
  buffer_size_mb: 64

storage:
  evidence_dir: /var/lib/nfa-linux/evidence
  capture_dir: /var/lib/nfa-linux/captures
  max_storage_gb: 100

analysis:
  ml_enabled: true
  tls_fingerprinting: true
  dns_analysis: true
  file_carving: true
```

## Building Custom Packages

### Modifying the Debian Package

1. Edit files in `packaging/debian/`
2. Update version in `DEBIAN/control`
3. Run `./scripts/build-packages.sh deb <version>`

### Modifying the AppImage

1. Edit `packaging/appimage/build-appimage.sh`
2. Run `./scripts/build-packages.sh appimage <version>`

## Release Checklist

Before releasing a new version:

- [ ] Update version in `wails.json`
- [ ] Update version in `DEBIAN/control`
- [ ] Update CHANGELOG.md
- [ ] Build and test Debian package
- [ ] Build and test AppImage
- [ ] Test installation on clean Ubuntu system
- [ ] Test systemd service
- [ ] Create GitHub release with packages

## Troubleshooting

### Debian Package Issues

**Missing dependencies:**
```bash
sudo apt-get install -f
```

**Permission denied for capture:**
```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/nfa-linux
```

### AppImage Issues

**FUSE not available:**
```bash
sudo apt-get install libfuse2
```

**Extract and run without FUSE:**
```bash
./NFA-Linux-1.0.0-x86_64.AppImage --appimage-extract
./squashfs-root/AppRun
```

## Package Sizes

### x86_64 (AMD64)

| Package | Size | Notes |
|---------|------|-------|
| Debian | ~4.0 MB | Compressed with dpkg |
| AppImage | ~4.9 MB | Compressed with squashfs |
| Raw Binary | ~13 MB | Uncompressed |

### ARM64 (aarch64)

| Package | Size | Notes |
|---------|------|-------|
| Debian | ~3.7 MB | Compressed with dpkg |
| Tarball | ~4.3 MB | Compressed with gzip |
| Raw Binary | ~12 MB | Uncompressed |

## Building ARM64 Packages

For ARM64 systems (NVIDIA Grace, Raspberry Pi 4/5, Apple Silicon VMs, AWS Graviton):

### Prerequisites

```bash
# Install cross-compilation toolchain
sudo apt-get install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu

# Add ARM64 architecture
sudo dpkg --add-architecture arm64

# Add ARM64 repositories
sudo bash -c 'cat > /etc/apt/sources.list.d/arm64.list << EOF
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports jammy main restricted universe multiverse
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports jammy-updates main restricted universe multiverse
EOF'

# Install ARM64 development libraries
sudo apt-get update
sudo apt-get install -y libgtk-3-dev:arm64 libwebkit2gtk-4.1-dev:arm64 libpcap-dev:arm64
```

### Build ARM64 Binary

```bash
export CGO_ENABLED=1
export GOOS=linux
export GOARCH=arm64
export CC=aarch64-linux-gnu-gcc
export CXX=aarch64-linux-gnu-g++
export PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig

wails build -clean -tags webkit2_41 -platform linux/arm64
```

### Build ARM64 Packages

```bash
./scripts/build-arm64-packages.sh all 1.0.0
```

## Security Considerations

- The binary requires `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities for packet capture
- The `nfa-linux` group provides controlled access to capture functionality
- Evidence files are stored with restricted permissions (0640)
- Systemd services run with security hardening options
