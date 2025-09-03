#!/bin/bash
set -euo pipefail

# === SCRIPT METADATA ===
# encrypt_ubuntu_image.sh - Encrypts Ubuntu disk images with LUKS2
# Version: 2.2.0
# Author: Linux System Administrator
# Last Updated: 2024-03-15

# === COMPREHENSIVE HELP ===
show_help() {
    cat <<EOF
Encrypt Ubuntu Disk Image Tool

Purpose:
  Transforms an unencrypted Ubuntu 22.04+ raw disk image into an encrypted
  image with LUKS2 encryption on the root partition while preserving the
  EFI and boot partitions.

Features:
  - Creates LUKS2-encrypted root partition
  - Generates secure random key stored in /boot
  - Maintains bootability with GRUB updates
  - Preserves original partition structure
  - Automatically increases root partition size
  - Comprehensive logging and debugging

Usage:
  ${0##*/} [OPTIONS] <input_image> <output_image>

Required Arguments:
  input_image    Path to unencrypted raw disk image
  output_image   Path for encrypted output image

Options:
  -c CIPHER      LUKS encryption cipher (default: aes-xts-plain64)
                 Recommended alternatives: aes-cbc-essiv:sha256, serpent-xts-plain64
  -k KEY_SIZE    Key size in bits (default: 512)
                 Common values: 128, 192, 256, 384, 512
  -r ROOT_RESIZE Additional space for root partition in GB (default: 2)
  -d             Enable debug output (verbose logging)
  -h, --help     Show this help message

Key Management:
  - Key file is stored at /boot/root_crypt.key in the output image
  - Backup copy is created in current directory as root_crypt.key.backup
  - Key file contains 4096 bytes of cryptographically secure random data

Security Considerations:
  WARNING: The /boot partition remains unencrypted and contains:
  - The encryption key file
  - Kernel and initramfs
  - GRUB configuration
  Ensure physical security of the /boot partition or use Secure Boot.

Examples:
  1. Basic usage with defaults (2GB root expansion):
     ${0##*/} ubuntu.raw encrypted_ubuntu.raw

  2. Custom cipher and key size with 4GB root expansion:
     ${0##*/} -c serpent-xts-plain64 -k 512 -r 4 ubuntu.raw encrypted_ubuntu.raw

  3. With debug output and 1GB root expansion:
     ${0##*/} -d -r 1 ubuntu.raw encrypted_ubuntu.raw

Exit Codes:
  0 - Success
  1 - General error
  2 - Invalid arguments
  3 - Missing dependencies
  4 - Filesystem error
  5 - Partitioning error
  6 - Encryption failure

Debugging:
  - Full debug log is written to: ./encrypt_debug.log
  - Use -d option for real-time debug output
EOF
    exit 0
}

# === CONFIGURATION ===
MAPPER_NAME="root_crypt"
KEYFILE_NAME="root_crypt.key"
KEYFILE="/boot/$KEYFILE_NAME"
LUKS_HEADER_SIZE=$((16 * 1024 * 1024))  # 16 MiB for LUKS2
SECTOR_SIZE=512
ALIGNMENT=$((1 * 1024 * 1024))  # 1 MiB alignment
DEFAULT_CIPHER="aes-xts-plain64"
DEFAULT_KEY_SIZE=512
DEFAULT_ROOT_RESIZE=2  # Default root expansion in GB
DEBUG_LOG="./encrypt_debug.log"

# === LOGGING SYSTEM ===
init_logging() {
    exec > >(tee -a "$DEBUG_LOG") 2>&1
    : > "$DEBUG_LOG"  # Truncate existing log
}

if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' NC=''
fi

log() { 
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" 
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1" >> "$DEBUG_LOG"
}

debug() {
    if [[ "${DEBUG:-}" == "true" ]]; then
        echo -e "${CYAN}[DEBUG][$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
    fi
    echo "[DEBUG][$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$DEBUG_LOG"
}

error() { 
    local exit_code=${2:-1}
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$DEBUG_LOG"
    exit $exit_code
}

warn() { 
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARN:${NC} $1" >&2
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARN: $1" >> "$DEBUG_LOG"
}

# === FUNCTIONS ===
cleanup() {
    debug "Executing cleanup procedures..."
    
    local cleanup_actions=(
        "cryptsetup luksClose $MAPPER_NAME || true"
        "losetup -d ${LOOP_INPUT:-} || true"
        "losetup -d ${LOOP_OUTPUT:-} || true"
        "umount -R ${TEMP_MOUNT:-} 2>/dev/null || true"
        "umount ${TEMP_BOOT_MOUNT:-} 2>/dev/null || true"
        "umount ${TEMP_ROOT_MOUNT:-} 2>/dev/null || true"
        "rmdir ${TEMP_MOUNT:-} ${TEMP_BOOT_MOUNT:-} ${TEMP_ROOT_MOUNT:-} 2>/dev/null || true"
    )
    
    for action in "${cleanup_actions[@]}"; do
        debug "Attempting: $action"
        eval "sudo $action" || true
    done
}

check_dependencies() {
    debug "Verifying system dependencies..."
    
    local required_tools=(
        "jq" "qemu-img" "cryptsetup" "partx"
        "blkid" "parted" "grub-install" "rsync"
        "losetup" "mkfs.ext4" "mkfs.vfat" "awk"
    )
    
    local missing=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing+=("$tool")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing required tools: ${missing[*]}" 3
    fi
}

validate_input_image() {
    debug "Validating input image structure..."
    
    [[ -f "$INPUT_RAW" ]] || error "Input file not found: $INPUT_RAW" 2
    
    # Verify partitions
    local parts=("${LOOP_INPUT}p1" "${LOOP_INPUT}p2" "${LOOP_INPUT}p3")
    for part in "${parts[@]}"; do
        [[ -e "$part" ]] || error "Missing partition in input image: $part" 5
    done
    
    # Verify filesystems
    local efi_type=$(sudo parted -s "$LOOP_INPUT" print | awk '/^ 1/{print $5}')
    [[ "$efi_type" == "fat32" ]] || error "EFI partition is not FAT32" 4
    
    local root_type=$(sudo blkid -s TYPE -o value "${LOOP_INPUT}p3")
    [[ "$root_type" == "ext4" ]] || error "Root partition is not ext4" 4
}

calculate_sizes() {
    debug "Calculating partition sizes..."
    
    EFI_SIZE=$(sudo blockdev --getsize64 "${LOOP_INPUT}p1")
    BOOT_SIZE=$(sudo blockdev --getsize64 "${LOOP_INPUT}p2")
    ROOT_SIZE=$(sudo blockdev --getsize64 "${LOOP_INPUT}p3")
    
    # Apply root resize (user specified or default 2GB)
    ROOT_SIZE=$((ROOT_SIZE + ROOT_RESIZE * 1024 * 1024 * 1024))
    
    # Align sizes to 1MiB
    align_size() {
        echo $(( ($1 + ALIGNMENT - 1) / ALIGNMENT * ALIGNMENT ))
    }
    
    EFI_SIZE=$(align_size "$EFI_SIZE")
    BOOT_SIZE=$(align_size "$BOOT_SIZE")
    ROOT_SIZE=$(align_size "$ROOT_SIZE")
    
    TOTAL_SIZE=$((ALIGNMENT + EFI_SIZE + BOOT_SIZE + ROOT_SIZE + LUKS_HEADER_SIZE + ALIGNMENT))
    
    debug "Calculated sizes:"
    debug "  EFI:  $((EFI_SIZE/1024/1024)) MiB"
    debug "  Boot: $((BOOT_SIZE/1024/1024)) MiB"
    debug "  Root: $((ROOT_SIZE/1024/1024)) MiB (including +${ROOT_RESIZE}GB)"
    debug "  LUKS Header: $((LUKS_HEADER_SIZE/1024/1024)) MiB"
    debug "  Total: $((TOTAL_SIZE/1024/1024/1024)) GiB"
    
    # Verify disk space
    local free_space=$(df --output=avail -B1 "$(dirname "$ENCRYPTED_RAW")" | tail -n1)
    [[ "$free_space" -gt "$TOTAL_SIZE" ]] || {
        error "Insufficient disk space. Need $((TOTAL_SIZE/1024/1024)) MiB, available $((free_space/1024/1024)) MiB" 5
    }
}

create_encrypted_image() {
    log "Creating encrypted disk image..."
    
    # Create blank image with additional space for root
    qemu-img create -f raw "$ENCRYPTED_RAW" "$TOTAL_SIZE" || {
        error "Failed to create output image" 5
    }
    
    # Setup loop device
    LOOP_OUTPUT=$(sudo losetup --show --find "$ENCRYPTED_RAW") || {
        error "Failed to setup output loop device" 5
    }
    debug "Output loop device: $LOOP_OUTPUT"
    
    # Create partition table with proper alignment
    local efi_start=$((ALIGNMENT / SECTOR_SIZE))
    local efi_end=$((efi_start + EFI_SIZE / SECTOR_SIZE - 1))
    local boot_start=$((efi_end + 1))
    local boot_end=$((boot_start + BOOT_SIZE / SECTOR_SIZE - 1))
    local root_start=$((boot_end + 1))
    local root_end=$((root_start + (ROOT_SIZE + LUKS_HEADER_SIZE) / SECTOR_SIZE - 1))
    
    debug "Partition layout:"
    debug "  EFI:  ${efi_start}s-${efi_end}s"
    debug "  Boot: ${boot_start}s-${boot_end}s"
    debug "  Root: ${root_start}s-${root_end}s"
    
    sudo parted -s "$LOOP_OUTPUT" -- \
        mklabel gpt \
        mkpart EFI fat32 ${efi_start}s ${efi_end}s \
        set 1 esp on \
        set 1 boot on \
        mkpart boot ext4 ${boot_start}s ${boot_end}s \
        mkpart root ext4 ${root_start}s ${root_end}s || {
        error "Failed to partition disk" 5
    }
    
    sudo partx -u "$LOOP_OUTPUT" || error "Failed to update partition table" 5
    
    TARGET_EFI="${LOOP_OUTPUT}p1"
    TARGET_BOOT="${LOOP_OUTPUT}p2"
    TARGET_ROOT="${LOOP_OUTPUT}p3"
}

copy_and_encrypt() {
    log "Copying and encrypting partitions..."
    
    # Copy EFI and boot partitions
    debug "Copying EFI partition..."
    sudo dd if="${LOOP_INPUT}p1" of="$TARGET_EFI" bs=4M status=progress conv=fsync || {
        error "Failed to copy EFI partition" 4
    }
    
    debug "Copying boot partition..."
    sudo dd if="${LOOP_INPUT}p2" of="$TARGET_BOOT" bs=4M status=progress conv=fsync || {
        error "Failed to copy boot partition" 4
    }
    
    # Generate encryption key
    log "Generating LUKS encryption key..."
    TEMP_KEYFILE=$(mktemp)
    debug "Key file temp path: $TEMP_KEYFILE"
    
    sudo dd if=/dev/urandom of="$TEMP_KEYFILE" bs=1024 count=4 || {
        error "Failed to generate key file" 6
    }
    sudo chmod 0400 "$TEMP_KEYFILE"
    
    # Create key backup
    BACKUP_KEYFILE="./${KEYFILE_NAME}.backup"
    sudo cp "$TEMP_KEYFILE" "$BACKUP_KEYFILE" || {
        error "Failed to create key backup" 6
    }
    sudo chmod 0400 "$BACKUP_KEYFILE"
    log "Key backup created: $BACKUP_KEYFILE"
    debug "Key fingerprint: $(sudo sha256sum "$BACKUP_KEYFILE")"
    
    # Encrypt root partition
    log "Encrypting root partition with LUKS2..."
    debug "Using cipher: $LUKS_CIPHER with $LUKS_KEY_SIZE-bit key"
    
    sudo cryptsetup luksFormat \
        --type luks2 \
        --cipher "$LUKS_CIPHER" \
        --key-size "$LUKS_KEY_SIZE" \
        --batch-mode "$TARGET_ROOT" "$TEMP_KEYFILE" || {
        error "LUKS formatting failed" 6
    }
    
    # Open encrypted volume
    sudo cryptsetup luksOpen "$TARGET_ROOT" "$MAPPER_NAME" --key-file "$TEMP_KEYFILE" || {
        error "Failed to open LUKS container" 6
    }
    
    # Copy root filesystem
    log "Copying root filesystem to encrypted partition..."
    TEMP_ROOT_MOUNT=$(mktemp -d)
    debug "Mounting source root at $TEMP_ROOT_MOUNT"
    sudo mount "${LOOP_INPUT}p3" "$TEMP_ROOT_MOUNT" || {
        error "Failed to mount source root" 4
    }
    
    TEMP_MOUNT=$(mktemp -d)
    debug "Formatting encrypted partition as ext4"
    sudo mkfs.ext4 "/dev/mapper/$MAPPER_NAME" || {
        error "Failed to create filesystem" 4
    }
    
    debug "Mounting encrypted partition at $TEMP_MOUNT"
    sudo mount "/dev/mapper/$MAPPER_NAME" "$TEMP_MOUNT" || {
        error "Failed to mount encrypted partition" 4
    }
    
    debug "Copying files with rsync..."
    sudo rsync -aAX --exclude={"/dev/*","/proc/*","/sys/*","/tmp/*","/run/*","/mnt/*","/media/*","/lost+found"} \
        "$TEMP_ROOT_MOUNT/" "$TEMP_MOUNT/" || {
        error "Failed to copy root filesystem" 4
    }
}

configure_system() {
    log "Configuring encrypted system..."
    
    # Mount target boot partition
    TEMP_BOOT_MOUNT=$(mktemp -d)
    debug "Mounting target boot at $TEMP_BOOT_MOUNT"
    sudo mount "$TARGET_BOOT" "$TEMP_BOOT_MOUNT" || {
        error "Failed to mount target boot" 4
    }
    
    # Install key file
    debug "Installing key file to $TEMP_BOOT_MOUNT/$KEYFILE_NAME"
    sudo cp "$TEMP_KEYFILE" "$TEMP_BOOT_MOUNT/$KEYFILE_NAME" || {
        error "Failed to install key file" 6
    }
    sudo chmod 0400 "$TEMP_BOOT_MOUNT/$KEYFILE_NAME"
    rm -f "$TEMP_KEYFILE"
    
    # Bind mount boot
    debug "Bind mounting boot to $TEMP_MOUNT/boot"
    sudo mkdir -p "$TEMP_MOUNT/boot"
    sudo mount --bind "$TEMP_BOOT_MOUNT" "$TEMP_MOUNT/boot" || {
        error "Failed to bind mount boot" 4
    }
    
    # Update crypttab
    ROOT_UUID=$(sudo blkid -s UUID -o value "$TARGET_ROOT")
    debug "Updating crypttab with UUID $ROOT_UUID"
    sudo tee "$TEMP_MOUNT/etc/crypttab" > /dev/null <<EOF
$MAPPER_NAME UUID=$ROOT_UUID $KEYFILE luks,discard
EOF
    
    # Update fstab with proper handling of duplicates
    BOOT_UUID=$(sudo blkid -s UUID -o value "$TARGET_BOOT")
    ROOT_MAPPER="/dev/mapper/$MAPPER_NAME"
    
    log "Updating /etc/fstab with proper entries..."
    TEMP_FSTAB=$(mktemp)
    
    # Process existing fstab to remove duplicates and add new entries
    {
        # Process existing fstab lines
        sudo awk -v boot_uuid="$BOOT_UUID" -v root_mapper="$ROOT_MAPPER" '
        {
            # Skip any existing /boot or / entries
            if ($2 == "/boot" || $2 == "/boot/" || $2 == "/" || $2 == "/ ") {
                print "# " $0 " (commented out during encryption)"
                next
            }
            # Skip any existing entries for our root mapper
            if ($1 == root_mapper) {
                print "# " $0 " (commented out during encryption)"
                next
            }
            # Keep all other entries
            print
        }
        ' "$TEMP_MOUNT/etc/fstab" || true
        
        # Add new entries with comments
        echo "# /boot was on ${LOOP_INPUT}p2 during encryption"
        echo "UUID=$BOOT_UUID /boot ext4 defaults 0 2"
        echo "# / was on ${LOOP_INPUT}p3 during encryption"
        echo "$ROOT_MAPPER / ext4 defaults 0 1"
    } | sudo tee "$TEMP_FSTAB" > /dev/null
    
    debug "New fstab contents:"
    debug "$(cat "$TEMP_FSTAB")"
    
    sudo mv "$TEMP_FSTAB" "$TEMP_MOUNT/etc/fstab"
    sudo chmod 644 "$TEMP_MOUNT/etc/fstab"
    
    # Prepare chroot environment
    log "Preparing chroot environment..."
    debug "Mounting special filesystems"
    sudo mount --bind /dev "$TEMP_MOUNT/dev"
    sudo mount --bind /sys "$TEMP_MOUNT/sys"
    sudo mount --bind /proc "$TEMP_MOUNT/proc"
    
    # Configure initramfs
    debug "Configuring cryptsetup initramfs hook"
    sudo mkdir -p "$TEMP_MOUNT/etc/cryptsetup-initramfs"
    sudo tee "$TEMP_MOUNT/etc/cryptsetup-initramfs/conf-hook" > /dev/null <<EOF
CRYPTSETUP=y
KEYFILE_PATTERN=/boot/*.key
EOF
    
    # Configure GRUB
    debug "Configuring GRUB"
    sudo tee "$TEMP_MOUNT/etc/default/grub.d/99-crypt.cfg" > /dev/null <<EOF
GRUB_ENABLE_CRYPTODISK=y
EOF
    
    GRUB_CMDLINE="cryptdevice=UUID=$ROOT_UUID:$MAPPER_NAME root=$ROOT_MAPPER"
    GRUB_FILE="$TEMP_MOUNT/etc/default/grub"
    
    debug "Updating GRUB_CMDLINE_LINUX_DEFAULT"
    if grep -q "^GRUB_CMDLINE_LINUX_DEFAULT=" "$GRUB_FILE"; then
        sudo sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"$GRUB_CMDLINE\"|" "$GRUB_FILE" || {
            sudo sed -i "/^GRUB_CMDLINE_LINUX_DEFAULT=/d" "$GRUB_FILE"
            echo "GRUB_CMDLINE_LINUX_DEFAULT=\"$GRUB_CMDLINE\"" | sudo tee -a "$GRUB_FILE" > /dev/null
        }
    else
        echo "GRUB_CMDLINE_LINUX_DEFAULT=\"$GRUB_CMDLINE\"" | sudo tee -a "$GRUB_FILE" > /dev/null
    fi
    
    # Update initramfs
    log "Updating initramfs..."
    sudo chroot "$TEMP_MOUNT" update-initramfs -u -k all || {
        error "Failed to update initramfs" 6
    }
    
    # Verify key in initramfs
    KERNEL_VERSION=$(sudo chroot "$TEMP_MOUNT" ls /boot | grep -oP 'initrd\.img-\K[^ ]+' | head -n1)
    if [[ -n "$KERNEL_VERSION" ]]; then
        if sudo lsinitramfs "$TEMP_MOUNT/boot/initrd.img-$KERNEL_VERSION" | grep -q "$KEYFILE_NAME"; then
            debug "Key file verified in initramfs"
        else
            warn "Key file not found in initramfs!"
        fi
    else
        warn "Could not verify key in initramfs - kernel version not found"
    fi
    
    # Update GRUB
    log "Updating GRUB configuration..."
    sudo chroot "$TEMP_MOUNT" update-grub || {
        error "Failed to update GRUB" 6
    }
}

# === MAIN SCRIPT ===
trap cleanup EXIT

# Parse arguments
LUKS_CIPHER="$DEFAULT_CIPHER"
LUKS_KEY_SIZE="$DEFAULT_KEY_SIZE"
ROOT_RESIZE="$DEFAULT_ROOT_RESIZE"
DEBUG=""

while getopts ":c:k:r:dh" opt; do
    case $opt in
        c) LUKS_CIPHER="$OPTARG" ;;
        k) LUKS_KEY_SIZE="$OPTARG" ;;
        r) ROOT_RESIZE="$OPTARG" ;;
        d) DEBUG="true" ;;
        h) show_help ;;
        \?) error "Invalid option: -$OPTARG" 2 ;;
        :) error "Option -$OPTARG requires an argument" 2 ;;
    esac
done
shift $((OPTIND-1))

INPUT_RAW="${1:-}"
ENCRYPTED_RAW="${2:-}"

# Validate arguments
[[ -z "$INPUT_RAW" || -z "$ENCRYPTED_RAW" ]] && {
    show_help
    exit 2
}

# Initialize logging
init_logging
log "Starting Ubuntu disk image encryption"
debug "Command line: $0 $*"

# Check dependencies
check_dependencies

# Setup input loop device
log "Setting up input image..."
LOOP_INPUT=$(sudo losetup --show --find --partscan "$INPUT_RAW") || {
    error "Failed to setup input loop device" 5
}
debug "Input loop device: $LOOP_INPUT"
sudo partx -u "$LOOP_INPUT" || error "Failed to update partition table" 5

# Validate input image structure
validate_input_image

# Calculate partition sizes with user-specified root expansion
calculate_sizes

# Create and partition output image
create_encrypted_image

# Copy data and encrypt
copy_and_encrypt

# Configure the encrypted system
configure_system

# Cleanup
cleanup

# Final output
log "Encryption process completed successfully"
log "Output image: $ENCRYPTED_RAW"
log "Key backup: $BACKUP_KEYFILE"
log "Root partition expanded by: ${ROOT_RESIZE}GB"
log "Debug log: $DEBUG_LOG"
echo -e "${YELLOW}WARNING: The encryption key is stored in unencrypted /boot partition."
echo -e "Ensure physical security or use Secure Boot to protect this key.${NC}"

