#!/bin/bash
# NFA-Linux Installation Script
# Installs NFA-Linux system-wide with proper permissions and services

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
APP_NAME="nfa-linux"
INSTALL_DIR="/opt/$APP_NAME"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/$APP_NAME"
DATA_DIR="/var/lib/$APP_NAME"
LOG_DIR="/var/log/$APP_NAME"
SYSTEMD_DIR="/etc/systemd/system"

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    local missing=()
    
    # Check for required packages
    if ! command -v setcap &> /dev/null; then
        missing+=("libcap2-bin")
    fi
    
    if ! ldconfig -p | grep -q libpcap; then
        missing+=("libpcap0.8")
    fi
    
    if [ ${#missing[@]} -ne 0 ]; then
        log_warning "Missing dependencies: ${missing[*]}"
        log_info "Installing missing dependencies..."
        apt-get update
        apt-get install -y "${missing[@]}"
    fi
    
    log_success "All dependencies satisfied"
}

create_user() {
    log_info "Creating service user..."
    
    if ! getent group $APP_NAME > /dev/null 2>&1; then
        groupadd --system $APP_NAME
        log_success "Created group: $APP_NAME"
    else
        log_info "Group $APP_NAME already exists"
    fi
    
    if ! getent passwd $APP_NAME > /dev/null 2>&1; then
        useradd --system \
            --gid $APP_NAME \
            --home-dir $DATA_DIR \
            --shell /usr/sbin/nologin \
            --comment "NFA-Linux Service Account" \
            $APP_NAME
        log_success "Created user: $APP_NAME"
    else
        log_info "User $APP_NAME already exists"
    fi
}

create_directories() {
    log_info "Creating directories..."
    
    # Installation directory
    mkdir -p $INSTALL_DIR
    
    # Configuration directory
    mkdir -p $CONFIG_DIR
    
    # Data directories
    mkdir -p $DATA_DIR
    mkdir -p $DATA_DIR/carved
    mkdir -p $DATA_DIR/evidence
    mkdir -p $DATA_DIR/pcaps
    
    # Log directory
    mkdir -p $LOG_DIR
    
    log_success "Directories created"
}

install_binary() {
    log_info "Installing binary..."
    
    local binary="$BUILD_DIR/$APP_NAME"
    
    if [ ! -f "$binary" ]; then
        # Try alternative locations
        if [ -f "$PROJECT_DIR/$APP_NAME" ]; then
            binary="$PROJECT_DIR/$APP_NAME"
        elif [ -f "/tmp/$APP_NAME" ]; then
            binary="/tmp/$APP_NAME"
        else
            log_error "Binary not found. Please build the application first."
            log_info "Run: make build"
            exit 1
        fi
    fi
    
    # Copy binary
    cp "$binary" "$INSTALL_DIR/$APP_NAME"
    chmod 755 "$INSTALL_DIR/$APP_NAME"
    
    # Create symlink
    ln -sf "$INSTALL_DIR/$APP_NAME" "$BIN_DIR/$APP_NAME"
    
    # Set capabilities for packet capture
    setcap cap_net_raw,cap_net_admin=eip "$INSTALL_DIR/$APP_NAME"
    
    log_success "Binary installed to $INSTALL_DIR/$APP_NAME"
}

install_config() {
    log_info "Installing configuration..."
    
    # Only install if config doesn't exist (preserve user config)
    if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
        cat > "$CONFIG_DIR/config.yaml" << 'EOF'
# NFA-Linux Configuration
# Documentation: https://github.com/cvalentine99/nfa-linux

capture:
  # Network interface to capture from (empty = prompt user)
  interface: ""
  # Capture mode: afxdp (fastest), afpacket (compatible), pcap (fallback)
  mode: "afpacket"
  # Snapshot length (max bytes per packet)
  snaplen: 65535
  # Enable promiscuous mode
  promiscuous: true
  # BPF filter expression (empty = capture all)
  bpf_filter: ""
  # Ring buffer size in bytes
  ring_buffer_size: 67108864
  # Batch size for packet processing
  batch_size: 64
  # Number of worker threads (0 = auto)
  num_workers: 0

reassembly:
  # Max buffered pages per TCP connection
  max_buffered_pages_per_connection: 4000
  # Max total buffered pages
  max_buffered_pages_total: 150000
  # Max concurrent connections
  max_connections: 100000
  # Flush interval for idle connections
  flush_interval: "30s"

carver:
  # Output directory for carved files
  output_dir: "/var/lib/nfa-linux/carved"
  # Maximum file size to carve (bytes)
  max_file_size: 104857600
  # Enable file hashing
  enable_hashing: true
  # Hash algorithm: blake3, sha256, md5
  hash_algorithm: "blake3"
  # Extract executable files
  extract_executables: true
  # Extract archive files
  extract_archives: true
  # Extract document files
  extract_documents: true

evidence:
  # Output directory for evidence packages
  output_dir: "/var/lib/nfa-linux/evidence"
  # Enable RFC 3161 timestamps
  enable_timestamps: true
  # TSA URL for timestamps
  tsa_url: "http://timestamp.digicert.com"

ml:
  # Enable ML-based analysis
  enable: false
  # ML sidecar gRPC address
  sidecar_address: "localhost:50051"
  # ONNX model path (for local inference)
  onnx_model_path: ""
  # Anomaly detection threshold
  anomaly_threshold: 3.0

logging:
  # Log level: debug, info, warn, error
  level: "info"
  # Log file path
  file: "/var/log/nfa-linux/nfa.log"
  # Max log file size (MB)
  max_size: 100
  # Max number of backup files
  max_backups: 5
  # Max age of backup files (days)
  max_age: 30
EOF
        log_success "Default configuration installed"
    else
        log_info "Configuration already exists, preserving user config"
    fi
}

install_systemd() {
    log_info "Installing systemd service..."
    
    cat > "$SYSTEMD_DIR/$APP_NAME.service" << EOF
[Unit]
Description=NFA-Linux Network Forensic Analyzer
Documentation=https://github.com/cvalentine99/nfa-linux
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_NAME
Group=$APP_NAME
ExecStart=$INSTALL_DIR/$APP_NAME -headless -config $CONFIG_DIR/config.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
TimeoutStartSec=30
TimeoutStopSec=30

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$APP_NAME

# Security hardening
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=false
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true

# Required paths
ReadWritePaths=$DATA_DIR $LOG_DIR

# Required capabilities for packet capture
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd
    systemctl daemon-reload
    
    log_success "Systemd service installed"
}

set_permissions() {
    log_info "Setting permissions..."
    
    # Set ownership
    chown -R $APP_NAME:$APP_NAME $DATA_DIR
    chown -R $APP_NAME:$APP_NAME $LOG_DIR
    chown root:$APP_NAME $CONFIG_DIR
    chown root:$APP_NAME $CONFIG_DIR/config.yaml
    
    # Set permissions
    chmod 750 $DATA_DIR
    chmod 750 $LOG_DIR
    chmod 750 $CONFIG_DIR
    chmod 640 $CONFIG_DIR/config.yaml
    
    log_success "Permissions set"
}

install_desktop() {
    log_info "Installing desktop integration..."
    
    # Desktop file
    cat > /usr/share/applications/$APP_NAME.desktop << EOF
[Desktop Entry]
Name=NFA-Linux
GenericName=Network Forensic Analyzer
Comment=Next-Generation Network Forensic Analyzer for Linux
Exec=$APP_NAME
Icon=$APP_NAME
Terminal=false
Type=Application
Categories=Network;Security;System;Monitor;
Keywords=network;forensics;packet;capture;security;analysis;
StartupNotify=true
StartupWMClass=$APP_NAME
EOF
    
    # Update desktop database
    if command -v update-desktop-database &> /dev/null; then
        update-desktop-database -q 2>/dev/null || true
    fi
    
    log_success "Desktop integration installed"
}

print_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║          NFA-Linux Installation Complete!                    ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Installation Summary:${NC}"
    echo "  Binary:        $INSTALL_DIR/$APP_NAME"
    echo "  Symlink:       $BIN_DIR/$APP_NAME"
    echo "  Config:        $CONFIG_DIR/config.yaml"
    echo "  Data:          $DATA_DIR/"
    echo "  Logs:          $LOG_DIR/"
    echo "  Service:       $APP_NAME.service"
    echo ""
    echo -e "${BLUE}Quick Start:${NC}"
    echo "  Start GUI:     $APP_NAME"
    echo "  Headless:      $APP_NAME -headless -interface eth0"
    echo "  Analyze PCAP:  $APP_NAME -headless -pcap capture.pcap"
    echo ""
    echo -e "${BLUE}Service Management:${NC}"
    echo "  Enable:        sudo systemctl enable $APP_NAME"
    echo "  Start:         sudo systemctl start $APP_NAME"
    echo "  Status:        sudo systemctl status $APP_NAME"
    echo "  Logs:          sudo journalctl -u $APP_NAME -f"
    echo ""
    echo -e "${BLUE}Configuration:${NC}"
    echo "  Edit config:   sudo nano $CONFIG_DIR/config.yaml"
    echo ""
    echo -e "${YELLOW}Note: For packet capture, the binary has been granted${NC}"
    echo -e "${YELLOW}CAP_NET_RAW and CAP_NET_ADMIN capabilities.${NC}"
    echo ""
}

# Main installation
main() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║          NFA-Linux Installation Script                       ║${NC}"
    echo -e "${BLUE}║          Next-Generation Network Forensic Analyzer           ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    check_root
    check_dependencies
    create_user
    create_directories
    install_binary
    install_config
    install_systemd
    set_permissions
    install_desktop
    print_summary
}

main "$@"
