#!/bin/bash

# TPM2 LUKS Auto-Unlock Configuration Script
# Version: 2.0
# Description: Automates TPM2 binding for LUKS encrypted partitions with user-friendly options

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

${YELLOW}Usage:${NC} $0 [OPTIONS]

${YELLOW}Options:${NC}
  ${BLUE}--device DEVICE${NC}    Specify LUKS encrypted device (e.g., /dev/sda1) ${RED}(Required)${NC}
  ${BLUE}--pcrs PCR_LIST${NC}    Specify PCR banks to use (comma separated, default: 7)
  ${BLUE}--remove${NC}           Remove TPM2 binding instead of adding it
  ${BLUE}--force${NC}            Skip all confirmation prompts
  ${BLUE}--verbose${NC}          Show detailed output
  ${BLUE}--help${NC}             Display this help message

${YELLOW}Examples:${NC}
  $0 --device /dev/sda1                 # Setup TPM2 binding with default PCR7
  $0 --device /dev/nvme0n1p3 --pcrs 0,7 # Use PCR0 and PCR7
  $0 --device /dev/sda1 --remove        # Remove TPM2 binding

${YELLOW}What PCRs to use?${NC}
  PCR0: Core system firmware executable code
  PCR7: Secure Boot state (recommended)
  Multiple PCRs can be specified (e.g., 0,7 for dual protection)

${YELLOW}Note:${NC} You'll need to enter your LUKS passphrase during setup
EOF
    exit 0
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

# Check system requirements
check_requirements() {
    local missing=()
    local required=("sudo" "cryptsetup" "systemd-cryptenroll" "blkid")

    for cmd in "${required[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}Missing required commands:${NC} ${missing[*]}"
        echo -e "${YELLOW}On Ubuntu/Debian, try:${NC} sudo apt install cryptsetup tpm2-tools"
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
    
    check_requirements
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
    echo -e "\n${YELLOW}Important: Reboot your system to apply changes${NC}"
}

# Start the script
main "$@"
