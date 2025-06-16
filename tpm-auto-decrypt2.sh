#!/bin/bash

# ========== Metadata ==========
SCRIPT_NAME="TPM2 LUKS Auto-Unlock Setup"
VERSION="1.0"

# ========== Color Output ==========
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m' # No Color

# ========== Sudo Keep-Alive ==========
SUDO_STAT="/tmp/sudo_status_$$"

sudo_keep_alive() {
    echo $$ > "$SUDO_STAT"
    trap 'rm -f "$SUDO_STAT" >/dev/null 2>&1' EXIT
    trap 'cleanup; exit 2' HUP INT QUIT TERM
    (
        while [ -f "$SUDO_STAT" ]; do
            sudo -v
            sleep 10
        done
    ) &
}

cleanup() {
    rm -f "$SUDO_STAT" >/dev/null 2>&1
}

# ========== Logging ==========
log() { echo -e "${GREEN}[✔] $*${NC}"; }
warn() { echo -e "${YELLOW}[!] $*${NC}"; }
err() { echo -e "${RED}[✘] $*${NC}" >&2; exit 1; }

# ========== Help ==========
show_help() {
    cat << EOF
${BLUE}${SCRIPT_NAME} - TPM2 Auto-Unlock for LUKS${NC}
Usage: $0 --stage1 | --stage2 <device>

Options:
  --stage1            Install TPM2 tools and Clevis, set up tpm2-abrmd
  --stage2 <device>   Bind a LUKS-encrypted device to TPM2 (e.g., /dev/sda5)
  --help              Display this help message

Instructions:
  1. Run '$0 --stage1', then reboot.
  2. After reboot, run '$0 --stage2 /dev/your_partition'.
     Use 'lsblk' to find the correct LUKS partition (usually ends in '_crypt').
EOF
}

# ========== TPM2 & Clevis Installation ==========
install_dependencies() {
    log "Updating package lists..."
    sudo apt update || err "Failed to update package lists."

    log "Installing TPM2 and Clevis dependencies..."
    sudo apt install -y tpm2-abrmd tpm2-tools clevis clevis-luks clevis-tpm2 clevis-initramfs \
        || err "Failed to install required packages."

    log "Enabling tpm2-abrmd service..."
    sudo systemctl enable --now tpm2-abrmd || err "Failed to start tpm2-abrmd."

    log "Adding user '$USER' to 'tss' group..."
    sudo usermod -aG tss "$USER" || err "Failed to add user to 'tss' group."
}

# ========== Bind LUKS to TPM2 ==========
bind_luks_to_tpm2() {
    local device="$1"
    if [[ -z "$device" ]]; then
        err "Device path is required for stage2."
    fi
    if [[ ! -b "$device" ]]; then
        err "$device is not a valid block device."
    fi

    log "Binding LUKS device $device to TPM2..."
    sudo clevis luks bind -d "$device" tpm2 '{"pcr_bank":"sha256","pcr_ids":"7"}' \
        || err "Failed to bind LUKS to TPM2."

    log "Updating initramfs..."
    sudo update-initramfs -u -k all || err "Failed to update initramfs."
}

# ========== Root Check ==========
if [ "$(id -u)" -eq 0 ]; then
    err "Do not run this script as root. Please run as a regular user."
fi

# ========== Entry Point ==========
main() {
    if [ $# -eq 0 ]; then
        show_help
        exit 1
    fi

    sudo -v || err "Sudo authentication failed."
    sudo_keep_alive

    case "$1" in
        --stage1)
            log "Stage 1: Installing TPM2 tools and Clevis..."
            install_dependencies
            warn "Stage 1 complete. Please REBOOT your system now."
            ;;
        --stage2)
            if [ -z "$2" ]; then
                err "Missing device argument. Usage: $0 --stage2 /dev/sdX"
            fi
            log "Stage 2: Binding LUKS device to TPM2..."
            bind_luks_to_tpm2 "$2"
            log "Stage 2 complete. Please REBOOT to test auto-unlock."
            ;;
        --help)
            show_help
            ;;
        *)
            err "Unknown option: $1"
            ;;
    esac
}

main "$@"
