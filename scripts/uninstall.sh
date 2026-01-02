#!/bin/bash
# NFA-Linux Uninstallation Script
# Removes NFA-Linux from the system

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
APP_NAME="nfa-linux"
INSTALL_DIR="/opt/$APP_NAME"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/$APP_NAME"
DATA_DIR="/var/lib/$APP_NAME"
LOG_DIR="/var/log/$APP_NAME"
SYSTEMD_DIR="/etc/systemd/system"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[ERROR]${NC} This script must be run as root (use sudo)"
        exit 1
    fi
}

confirm_uninstall() {
    echo ""
    echo -e "${YELLOW}This will remove NFA-Linux from your system.${NC}"
    echo ""
    read -p "Do you want to remove configuration files? [y/N] " -n 1 -r
    echo
    REMOVE_CONFIG=$REPLY
    
    read -p "Do you want to remove data files (carved files, evidence)? [y/N] " -n 1 -r
    echo
    REMOVE_DATA=$REPLY
    
    read -p "Do you want to remove log files? [y/N] " -n 1 -r
    echo
    REMOVE_LOGS=$REPLY
    
    echo ""
    read -p "Proceed with uninstallation? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Uninstallation cancelled."
        exit 0
    fi
}

stop_service() {
    log_info "Stopping service..."
    
    if systemctl is-active --quiet $APP_NAME 2>/dev/null; then
        systemctl stop $APP_NAME
        log_success "Service stopped"
    fi
    
    if systemctl is-enabled --quiet $APP_NAME 2>/dev/null; then
        systemctl disable $APP_NAME
        log_success "Service disabled"
    fi
}

remove_files() {
    log_info "Removing files..."
    
    # Remove binary and symlink
    rm -f "$BIN_DIR/$APP_NAME"
    rm -rf "$INSTALL_DIR"
    log_success "Binary removed"
    
    # Remove systemd service
    rm -f "$SYSTEMD_DIR/$APP_NAME.service"
    systemctl daemon-reload
    log_success "Systemd service removed"
    
    # Remove desktop file
    rm -f /usr/share/applications/$APP_NAME.desktop
    update-desktop-database -q 2>/dev/null || true
    log_success "Desktop integration removed"
    
    # Remove config if requested
    if [[ $REMOVE_CONFIG =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR"
        log_success "Configuration removed"
    else
        log_info "Configuration preserved at $CONFIG_DIR"
    fi
    
    # Remove data if requested
    if [[ $REMOVE_DATA =~ ^[Yy]$ ]]; then
        rm -rf "$DATA_DIR"
        log_success "Data files removed"
    else
        log_info "Data files preserved at $DATA_DIR"
    fi
    
    # Remove logs if requested
    if [[ $REMOVE_LOGS =~ ^[Yy]$ ]]; then
        rm -rf "$LOG_DIR"
        log_success "Log files removed"
    else
        log_info "Log files preserved at $LOG_DIR"
    fi
}

remove_user() {
    log_info "Removing service user..."
    
    # Only remove user if data was also removed
    if [[ $REMOVE_DATA =~ ^[Yy]$ ]]; then
        if getent passwd $APP_NAME > /dev/null 2>&1; then
            userdel $APP_NAME 2>/dev/null || true
            log_success "User removed"
        fi
        
        if getent group $APP_NAME > /dev/null 2>&1; then
            groupdel $APP_NAME 2>/dev/null || true
            log_success "Group removed"
        fi
    else
        log_info "User preserved (data files exist)"
    fi
}

print_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║          NFA-Linux Uninstallation Complete!                  ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [[ ! $REMOVE_CONFIG =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Configuration preserved:${NC} $CONFIG_DIR"
    fi
    if [[ ! $REMOVE_DATA =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Data preserved:${NC} $DATA_DIR"
    fi
    if [[ ! $REMOVE_LOGS =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Logs preserved:${NC} $LOG_DIR"
    fi
    echo ""
}

main() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║          NFA-Linux Uninstallation Script                     ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    
    check_root
    confirm_uninstall
    stop_service
    remove_files
    remove_user
    print_summary
}

main "$@"
