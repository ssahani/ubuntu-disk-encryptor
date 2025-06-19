#!/bin/bash

###############################################################################
# TPM2 LUKS Auto-Unlock Configuration Script
# Version: 3.0
#
# Purpose: Automates TPM2 binding for LUKS encrypted partitions to enable
#          automatic disk decryption during boot using TPM2 security chip
#
# Features:
# - Detects and installs required packages automatically
# - Supports both setup and removal of TPM2 binding
# - Configures PCR banks for flexible security policies
# - Updates crypttab and initramfs automatically
# - Comprehensive error checking and user feedback
#
# Usage:
#   sudo ./tpm2-luks-config.sh --device /dev/sda1 [OPTIONS]
#
# Safety Notes:
# - Always keep a backup of your LUKS recovery key
# - Test in a non-production environment first
# - Rebooting is required after configuration
#
# Dependencies (auto-installed if missing):
# - cryptsetup
# - tpm2-tools
# - systemd (with systemd-cryptenroll)
###############################################################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
DEVICE=""
PCRS="7" # Default to PCR7 (Secure Boot)
ACTION="setup"
FORCE=false
VERBOSE=false

# Display usage information
show_help() {
    cat << EOF
${GREEN}TPM2 LUKS Auto-Unlock Configuration Script${NC}
${YELLOW}Version: 3.0${NC}

${BLUE}Purpose:${NC} Configure TPM2-based automatic decryption for LUKS encrypted partitions

${YELLOW}Usage:${NC} $0 [OPTIONS]

${YELLOW}Required Options:${NC}
  ${BLUE}--device DEVICE${NC}    Specify LUKS encrypted device (e.g., /dev/sda1)

${YELLOW}Additional Options:${NC}
  ${BLUE}--pcrs PCR_LIST${NC}    Specify PCR banks (comma separated, default: 7)
  ${BLUE}--remove${NC}           Remove TPM2 binding instead of adding
  ${BLUE}--force${NC}            Skip all confirmation prompts
  ${BLUE}--verbose${NC}          Show detailed output
  ${BLUE}--help${NC}             Display this help message

${YELLOW}Examples:${NC}
  # Basic setup with default PCR7
  sudo $0 --device /dev/sda1

  # Custom PCR configuration (PCR0 + PCR7)
  sudo $0 --device /dev/nvme0n1p3 --pcrs 0,7

  # Remove TPM2 binding
  sudo $0 --device /dev/sda1 --remove

${YELLOW}PCR Selection Guide:${NC}
  PCR0: Core system firmware executable code
  PCR4: Boot Manager
  PCR7: Secure Boot state (recommended default)
  Combine multiple PCRs for stricter policies (e.g., 0,4,7)

${YELLOW}Important Notes:${NC}
1. You'll need to enter your LUKS passphrase during setup
2. Always keep a backup of your recovery key
3. System reboot is required after configuration
4. Test in non-production environment first

${YELLOW}Package Dependencies:${NC}
The script will automatically install:
- cryptsetup
- tpm2-tools
- systemd (with systemd-cryptenroll)
EOF
    exit 0
}

# Install required packages
install_dependencies() {
    local pkgs=("cryptsetup" "tpm2-tools")
    local missing=()

    # Check which packages are missing
    for pkg in "${pkgs[@]}"; do
        if ! dpkg -l | grep -q "^ii  $pkg "; then
            missing+=("$pkg")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${YELLOW}Installing missing packages: ${missing[*]}${NC}"
        sudo apt-get update || {
            echo -e "${RED}Failed to update package list${NC}"
            exit 1
        }
        sudo apt-get install -y "${missing[@]}" || {
            echo -e "${RED}Failed to install required packages${NC}"
            exit 1
        }
    fi

    # Verify systemd-cryptenroll is available
    if ! command -v systemd-cryptenroll >/dev/null 2>&1; then
        echo -e "${RED}Error: systemd-cryptenroll not found${NC}"
        echo -e "${YELLOW}This usually requires systemd version 247+ (Ubuntu 21.04+)${NC}"
        exit 1
    fi
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --device)
                DEVICE="$2"
                shift 2
                ;;
            --pcrs)
                PCRS="$2"
                shift 2
                ;;
            --remove)
                ACTION="remove"
                shift
                ;;
            --force)
                FORCE=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --help|-h)
                show_help
                ;;
            *)
                echo -e "${RED}Error: Unknown option $1${NC}"
                show_help
                exit 1
                ;;
        esac
    done

    # Validate required arguments
    if [ -z "$DEVICE" ]; then
        echo -e "${RED}Error: --device argument is required${NC}"
        show_help
        exit 1
    fi
}

# Verify LUKS partition
verify_luks_partition() {
    if [ ! -b "$DEVICE" ]; then
        echo -e "${RED}Error: $DEVICE is not a valid block device${NC}"
        exit 1
    fi

    if ! sudo cryptsetup isLuks "$DEVICE"; then
        echo -e "${RED}Error: $DEVICE is not a LUKS encrypted partition${NC}"
        exit 1
    fi

    LUKS_UUID=$(sudo blkid -s UUID -o value "$DEVICE")
    if [ -z "$LUKS_UUID" ]; then
        echo -e "${RED}Error: Could not get UUID for $DEVICE${NC}"
        exit 1
    fi

    if $VERBOSE; then
        echo -e "${BLUE}Verified LUKS partition:${NC}"
        echo -e "  Device: $DEVICE"
        echo -e "  UUID: $LUKS_UUID"
    fi
}

# Check existing TPM2 binding
check_tpm_binding() {
    if sudo cryptsetup luksDump "$DEVICE" | grep -q "TPM2"; then
        echo -e "${YELLOW}Warning: TPM2 binding already exists on $DEVICE${NC}"
        if ! $FORCE; then
            read -p "Do you want to proceed? This may overwrite existing binding. (y/N) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 0
            fi
        fi
    fi
}

# Add TPM2 binding
add_tpm_binding() {
    echo -e "${GREEN}Adding TPM2 binding to $DEVICE...${NC}"
    echo -e "${YELLOW}You'll need to enter your LUKS passphrase when prompted${NC}"

    local tpm_options=("--tpm2-device=auto")
    IFS=',' read -ra pcrs <<< "$PCRS"
    for pcr in "${pcrs[@]}"; do
        tpm_options+=("--tpm2-pcrs=$pcr")
    done

    if $VERBOSE; then
        echo -e "${BLUE}Using options:${NC} ${tpm_options[*]}"
    fi

    if ! sudo systemd-cryptenroll "${tpm_options[@]}" "$DEVICE"; then
        echo -e "${RED}Failed to add TPM2 binding${NC}"
        exit 1
    fi
}

# Remove TPM2 binding
remove_tpm_binding() {
    echo -e "${YELLOW}Removing TPM2 binding from $DEVICE...${NC}"
    if ! sudo systemd-cryptenroll --wipe-slot=tpm2 "$DEVICE"; then
        echo -e "${RED}Failed to remove TPM2 binding${NC}"
        exit 1
    fi
}

# Configure crypttab
configure_crypttab() {
    local crypt_name="luks-$(basename "$DEVICE")"
    local options="luks,discard,tpm2-device=auto"

    if [ "$ACTION" = "remove" ]; then
        echo -e "${YELLOW}Removing TPM2 options from crypttab...${NC}"
        sudo sed -i "/$crypt_name/s/,tpm2-device=auto//g" /etc/crypttab
        return
    fi

    local entry="$crypt_name UUID=$LUKS_UUID none $options"

    if grep -q "^$crypt_name" /etc/crypttab; then
        echo -e "${YELLOW}Updating existing crypttab entry${NC}"
        sudo sed -i "/^$crypt_name/c\\$entry" /etc/crypttab
    else
        echo -e "${GREEN}Adding new entry to crypttab${NC}"
        echo "$entry" | sudo tee -a /etc/crypttab > /dev/null
    fi

    if $VERBOSE; then
        echo -e "${BLUE}Current crypttab:${NC}"
        cat /etc/crypttab
    fi
}

# Update initramfs
update_initramfs() {
    echo -e "${GREEN}Updating initramfs...${NC}"
    if ! sudo update-initramfs -u -k all; then
        echo -e "${RED}Failed to update initramfs${NC}"
        exit 1
    fi
}

# Main execution
main() {
    parse_arguments "$@"
    
    echo -e "${GREEN}=== TPM2 LUKS Auto-Unlock Configuration ===${NC}"
    echo -e "  Device: ${YELLOW}$DEVICE${NC}"
    echo -e "  Action: ${YELLOW}$ACTION${NC}"
    echo -e "  PCRs: ${YELLOW}$PCRS${NC}"
    
    install_dependencies
    verify_luks_partition
    
    if [ "$ACTION" = "remove" ]; then
        remove_tpm_binding
    else
        check_tpm_binding
        add_tpm_binding
    fi
    
    configure_crypttab
    update_initramfs
    
    echo -e "\n${GREEN}=== Operation Complete ===${NC}"
    echo -e "LUKS device ${YELLOW}$DEVICE${NC} has been configured for:"
    [ "$ACTION" = "remove" ] && echo -e "  ${RED}TPM2 binding REMOVED${NC}" || echo -e "  ${GREEN}TPM2 auto-unlock ENABLED${NC}"
    echo -e "\n${YELLOW}Important Next Steps:${NC}"
    echo -e "1. Verify you have a working LUKS recovery key"
    echo -e "2. Reboot your system to test the configuration"
    echo -e "3. Check console output during boot for any errors"
}

# Start the script
main "$@"
