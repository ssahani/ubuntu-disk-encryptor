#!/bin/bash

# Installation Instructions:
# 1. Install Ubuntu like you would normally, just remember to setup LVM with encryption when asked for the advanced features
# 2. Download the install script however you like
# 3. Run the first stage with bash install.sh --stage1. You will be asked for your user password. This is to install every dependency needed.
# 4. Very important: reboot your machine
# 5. Get the device name of the encrypted partition (it would be /dev/something). It should be under the name something_crypt or similar. Take that name without the _crypt
# 6. Run bash install.sh --stage2 /dev/something. You will be asked for your user password and your decryption key.
# 7. After the script is done, reboot. You might see the decryption prompt again, don't do anything and wait, it will go on its own

# File to track sudo keep-alive process
SUDO_STAT="sudo_status.txt"

# Maintain sudo credentials in the background
sudo_keep_alive() {
    echo $$ > "$SUDO_STAT"
    # Clean up on script exit or signals
    trap 'rm -f "$SUDO_STAT" >/dev/null 2>&1' EXIT
    trap 'cleanup; exit 2' HUP INT QUIT TERM
    # Refresh sudo every 10 seconds
    while [ -f "$SUDO_STAT" ]; do
        sudo -v || { echo "Sudo authentication failed"; exit 1; }
        sleep 10
    done &
}

# Clean up sudo keep-alive process
cleanup() {
    rm -f "$SUDO_STAT" >/dev/null 2>&1
}

# Install and enable tpm2-abrmd service
setup_tpm2_abrmd() {
    sudo apt update || { echo "Failed to update package lists"; exit 1; }
    sudo apt install -y tpm2-abrmd || { echo "Failed to install tpm2-abrmd"; exit 1; }
    sudo systemctl enable --now tpm2-abrmd || { echo "Failed to enable tpm2-abrmd"; exit 1; }
}

# Install required dependencies
setup_dependencies() {
    sudo apt update || { echo "Failed to update package lists"; exit 1; }
    sudo apt install -y clevis clevis-luks clevis-tpm2 tpm2-tools clevis-initramfs || { echo "Failed to install dependencies"; exit 1; }
}

# Bind LUKS partition to TPM2
setup_luks_for_device() {
    local device="$1"
    if [ -z "$device" ]; then
        echo "Error: Device parameter is required"
        exit 1
    fi
    if [ ! -b "$device" ]; then
        echo "Error: $device is not a valid block device"
        exit 1
    fi
    sudo clevis luks bind -d "$device" tpm2 '{"pcr_bank":"sha256","pcr_ids":"7"}' || { echo "Failed to bind LUKS to TPM2"; exit 1; }
}

# Update initramfs
update_initramfs() {
    sudo update-initramfs -u -k all || { echo "Failed to update initramfs"; exit 1; }
}

# Display usage information
show_help() {
    cat << EOF
Usage: $0 [--stage1 | --stage2 <device>]
  --stage1            Install dependencies and configure TPM2
  --stage2 <device>   Bind LUKS partition (e.g., /dev/sda5) to TPM2
  --help              Display this help message

To find the device name, use 'lsblk' or 'fdisk -l' to identify the encrypted partition (e.g., /dev/sda5).
EOF
}

# Prevent running as root
if [ "$(id -u)" -eq 0 ]; then
    echo "Error: Do not run as root or with sudo"
    exit 1
fi

# Validate arguments
if [ $# -eq 0 ]; then
    show_help
    exit 1
fi

# Prompt for sudo credentials
sudo -v || { echo "Sudo authentication failed"; exit 1; }
sudo_keep_alive

# Process command-line arguments
case "$1" in
    --stage1)
        echo "Running Stage 1: Installing dependencies..."
        setup_tpm2_abrmd
        setup_dependencies
        sudo usermod -aG tss "$USER" || { echo "Failed to add user to tss group"; exit 1; }
        echo "Stage 1 complete. Please reboot your system."
        ;;
    --stage2)
        if [ -z "$2" ]; then
            echo "Error: Device parameter is required"
            exit 1
        fi
        echo "Running Stage 2: Configuring LUKS for $2..."
        setup_luks_for_device "$2"
        update_initramfs
        echo "Stage 2 complete. Reboot the system to apply changes."
        ;;
    --help)
        show_help
        exit 0
        ;;
    *)
        show_help
        exit 1
        ;;
esac
