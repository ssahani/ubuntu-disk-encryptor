#!/bin/bash
set -euo pipefail

# === SCRIPT DESCRIPTION ===
# Purpose:
#   Creates an encrypted raw disk image from an unencrypted Ubuntu 22.04 raw disk
#   image with EFI, boot, and root partitions. Copies EFI and boot partitions as-is,
#   encrypts the root partition with LUKS2 using a key file stored in /boot.
#
# Key Features:
#   - Generates a random LUKS key file stored in /boot
#   - Creates backup of the key file in current directory
#   - Supports custom ciphers and key sizes
#   - Increases root partition size by 1GB
#   - Properly updates system configurations for encrypted root
#
# Usage:
#   ./encrypt_ubuntu_image.sh [OPTIONS] <input_raw_image> <output_encrypted_raw>
#
# Options:
#   -c          LUKS cipher (default: aes-xts-plain64)
#   -k          LUKS key size in bits (default: 512)
#   -h, --help  Show this help message
#
# Input:
#   <input_raw_image>        Unencrypted Ubuntu 22.04 raw disk image
#                           Must have EFI, boot, and root partitions
#
# Output:
#   <output_encrypted_raw>   Encrypted raw disk image with:
#                           - Original EFI and boot partitions
#                           - Encrypted root partition (LUKS2)
#                           - Key file stored in /boot/root_crypt.key
#                           - Backup key in current directory
#
# Key Information:
#   - Primary key location: /boot/root_crypt.key (inside image)
#   - Backup key location: ./root_crypt.key.backup (current directory)
#   - Key contents (example): 4K random data (change this for production!)
#
# Example:
#   ./encrypt_ubuntu_image.sh -c aes-xts-plain64 -k 512 \
#       ubuntu-2204.raw encrypted-ubuntu-2204.raw
#
# WARNING:
#   The key file is stored in /boot, which is unencrypted. Ensure /boot is secured
#   (e.g., physical access control, Secure Boot) to prevent unauthorized access.

# === CONFIGURATION ===
MAPPER_NAME="root_crypt"
KEYFILE_NAME="root_crypt.key"  # Key file name (in /boot)
KEYFILE="/boot/$KEYFILE_NAME"  # Full path to key file in image
LUKS_HEADER_SIZE=$((16 * 1024 * 1024))  # 16 MiB for LUKS2 header
SECTOR_SIZE=512
ALIGNMENT=$((1 * 1024 * 1024))  # 1 MiB alignment
DEFAULT_CIPHER="aes-xts-plain64"
DEFAULT_KEY_SIZE=512

# === COLOR LOGGING ===
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
else
    RED='' GREEN='' YELLOW='' BLUE='' NC=''
fi

log() { echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"; }
error() { echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2; }
warn() { echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARN:${NC} $1"; }
info() { echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO:${NC} $1"; }

# === HELP FUNCTION ===
show_help() {
    awk '/^# === SCRIPT DESCRIPTION ===/,/^# ===/ { if ($0 !~ /^# ===/) print substr($0, 3) }' "$0"
    exit 0
}

# === CLEANUP FUNCTION ===
cleanup() {
    log "Cleaning up..."
    if [[ -e "/dev/mapper/$MAPPER_NAME" ]]; then
        sudo cryptsetup luksClose "$MAPPER_NAME" 2>/dev/null || true
    fi
    if [[ -n "${LOOP_INPUT:-}" && -e "$LOOP_INPUT" ]]; then
        sudo losetup -d "$LOOP_INPUT" 2>/dev/null || true
    fi
    if [[ -n "${LOOP_OUTPUT:-}" && -e "$LOOP_OUTPUT" ]]; then
        sudo losetup -d "$LOOP_OUTPUT" 2>/dev/null || true
    fi
    if [[ -n "${TEMP_MOUNT:-}" && -d "$TEMP_MOUNT" ]]; then
        sudo umount "$TEMP_MOUNT/boot" 2>/dev/null || true
        sudo umount "$TEMP_MOUNT/dev" 2>/dev/null || true
        sudo umount "$TEMP_MOUNT/proc" 2>/dev/null || true
        sudo umount "$TEMP_MOUNT/sys" 2>/dev/null || true
        sudo umount "$TEMP_MOUNT" 2>/dev/null || true
        rmdir "$TEMP_MOUNT" 2>/dev/null || true
    fi
    if [[ -n "${TEMP_BOOT_MOUNT:-}" && -d "$TEMP_BOOT_MOUNT" ]]; then
        sudo umount "$TEMP_BOOT_MOUNT" 2>/dev/null || true
        rmdir "$TEMP_BOOT_MOUNT" 2>/dev/null || true
    fi
    if [[ -n "${TEMP_ROOT_MOUNT:-}" && -d "$TEMP_ROOT_MOUNT" ]]; then
        sudo umount "$TEMP_ROOT_MOUNT" 2>/dev/null || true
        rmdir "$TEMP_ROOT_MOUNT" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# === DEPENDENCY CHECK ===
check_and_install() {
    local cmd="$1" pkg="$2"
    if ! command -v "$cmd" &>/dev/null; then
        log "Installing $pkg for $cmd..."
        sudo apt-get update -qq && sudo apt-get install -y "$pkg" || {
            error "Failed to install $pkg"; exit 1
        }
    fi
}

# === MAIN SCRIPT ===

# Parse arguments
LUKS_CIPHER="$DEFAULT_CIPHER"
LUKS_KEY_SIZE="$DEFAULT_KEY_SIZE"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -c) LUKS_CIPHER="$2"; shift ;;
        -k) LUKS_KEY_SIZE="$2"; shift ;;
        -h|--help) show_help ;;
        *) break ;;
    esac
    shift
done

INPUT_RAW="${1:-}"
ENCRYPTED_RAW="${2:-}"

# Validate inputs
if [[ -z "$INPUT_RAW" || -z "$ENCRYPTED_RAW" ]]; then
    error "Missing required arguments"
    show_help
    exit 1
fi

[[ -f "$INPUT_RAW" ]] || { error "Input file '$INPUT_RAW' not found"; exit 1; }
[[ -e "$ENCRYPTED_RAW" ]] && { error "Output file '$ENCRYPTED_RAW' already exists"; exit 1; }
OUTPUT_DIR=$(dirname "$ENCRYPTED_RAW")
[[ -d "$OUTPUT_DIR" && -w "$OUTPUT_DIR" ]] || { error "Output directory '$OUTPUT_DIR' is not writable"; exit 1; }

# Check dependencies
for dep in jq:jq qemu-img:qemu-utils cryptsetup:cryptsetup partx:util-linux kpartx:kpartx \
           blkid:util-linux parted:parted fdisk:util-linux grub-install:grub2-common rsync:rsync; do
    check_and_install "${dep%%:*}" "${dep##*:}"
done

# Pre-execution cleanup
log "Performing pre-execution cleanup..."
if [[ -e "/dev/mapper/$MAPPER_NAME" ]]; then
    sudo cryptsetup luksClose "$MAPPER_NAME" 2>/dev/null || { warn "Failed to close existing $MAPPER_NAME mapping, proceeding..."; }
fi
for loopdev in $(losetup -j "$INPUT_RAW" -O NAME 2>/dev/null | awk '{print $1}'); do
    sudo losetup -d "$loopdev" 2>/dev/null || true
done
for loopdev in $(losetup -j "$ENCRYPTED_RAW" -O NAME 2>/dev/null | awk '{print $1}'); do
    sudo losetup -d "$loopdev" 2>/dev/null || true
done

# Setup input loop device
log "Setting up input loop device..."
LOOP_INPUT=$(sudo losetup --show --find --partscan "$INPUT_RAW") || { error "Failed to set up loop device for input"; exit 1; }
sudo partx -u "$LOOP_INPUT" || { error "Failed to update partition table for input"; exit 1; }
EFI_PART="${LOOP_INPUT}p1"
BOOT_PART="${LOOP_INPUT}p2"
ROOT_PART="${LOOP_INPUT}p3"

# Validate partitions
for part in "$EFI_PART" "$BOOT_PART" "$ROOT_PART"; do
    [[ -e "$part" ]] || { error "Missing partition $part"; exit 1; }
done

# Verify filesystems
EFI_FSTYPE=$(sudo parted -s "$LOOP_INPUT" print | grep "^ 1" | awk '{print $5}')
[[ "$EFI_FSTYPE" == "fat32" ]] || { error "EFI partition is not fat32 (found: $EFI_FSTYPE)"; exit 1; }

ROOT_FSTYPE=$(sudo blkid -s TYPE -o value "$ROOT_PART" 2>/dev/null || echo "")
[[ "$ROOT_FSTYPE" == "ext4" ]] || { error "Root partition ($ROOT_PART) is not ext4 (found: $ROOT_FSTYPE)"; exit 1; }

# Calculate sizes with 1GB larger root
EFI_SIZE=$(sudo blockdev --getsize64 "$EFI_PART")
BOOT_SIZE=$(sudo blockdev --getsize64 "$BOOT_PART")
ROOT_SIZE=$(sudo blockdev --getsize64 "$ROOT_PART")
ROOT_SIZE=$((ROOT_SIZE + 1024*1024*1024))  # Add 1GB to original size

# Align sizes
align_size() {
    local size=$1
    echo $(( (size + SECTOR_SIZE - 1) / SECTOR_SIZE * SECTOR_SIZE ))
}
EFI_SIZE=$(align_size "$EFI_SIZE")
BOOT_SIZE=$(align_size "$BOOT_SIZE")
ROOT_SIZE=$(align_size "$ROOT_SIZE")
TOTAL_SIZE=$((ALIGNMENT + EFI_SIZE + BOOT_SIZE + ROOT_SIZE + LUKS_HEADER_SIZE + ALIGNMENT))

# Space check
FREE_SPACE=$(df --output=avail -B1 "$OUTPUT_DIR" | tail -n1)
[[ "$FREE_SPACE" -gt "$TOTAL_SIZE" ]] || { error "Not enough disk space: need $((TOTAL_SIZE/1024/1024)) MiB, available $((FREE_SPACE/1024/1024)) MiB"; exit 1; }

# Create and partition output image
log "Creating encrypted image..."
qemu-img create -f raw "$ENCRYPTED_RAW" "$TOTAL_SIZE" || { error "Failed to create output image"; exit 1; }
LOOP_OUTPUT=$(sudo losetup --show --find "$ENCRYPTED_RAW") || { error "Failed to set up loop device for output"; exit 1; }

# Calculate partition boundaries
EFI_START=$((ALIGNMENT / SECTOR_SIZE))
EFI_END=$((EFI_START + EFI_SIZE / SECTOR_SIZE - 1))
BOOT_START=$((EFI_END + 1))
BOOT_END=$((BOOT_START + BOOT_SIZE / SECTOR_SIZE - 1))
ROOT_START=$((BOOT_END + 1))
ROOT_END=$((ROOT_START + (ROOT_SIZE + LUKS_HEADER_SIZE) / SECTOR_SIZE - 1))

sudo parted -s "$LOOP_OUTPUT" -- mklabel gpt \
    mkpart EFI fat32 ${EFI_START}s ${EFI_END}s \
    set 1 esp on \
    set 1 boot on \
    mkpart boot ext4 ${BOOT_START}s ${BOOT_END}s \
    mkpart root ext4 ${ROOT_START}s ${ROOT_END}s || { error "Failed to create partition table"; exit 1; }
sudo partx -u "$LOOP_OUTPUT" || { error "Failed to update partition table for output"; exit 1; }

TARGET_EFI="${LOOP_OUTPUT}p1"
TARGET_BOOT="${LOOP_OUTPUT}p2"
TARGET_ROOT="${LOOP_OUTPUT}p3"

# Copy EFI and boot partitions
log "Copying EFI and boot partitions..."
sudo dd if="$EFI_PART" of="$TARGET_EFI" bs=4M status=progress conv=fsync || { error "Failed to copy EFI partition"; exit 1; }
sudo dd if="$BOOT_PART" of="$TARGET_BOOT" bs=4M status=progress conv=fsync || { error "Failed to copy boot partition"; exit 1; }

# Generate and backup key file
log "Generating LUKS key file..."
TEMP_KEYFILE=$(mktemp)
sudo dd if=/dev/urandom of="$TEMP_KEYFILE" bs=1024 count=4 || { error "Failed to generate key file"; exit 1; }
sudo chmod 0400 "$TEMP_KEYFILE"

# Create backup of key file
BACKUP_KEYFILE="./${KEYFILE_NAME}.backup"
sudo cp "$TEMP_KEYFILE" "$BACKUP_KEYFILE" || { error "Failed to create key file backup"; exit 1; }
sudo chmod 0400 "$BACKUP_KEYFILE"
log "Key file backup created: $BACKUP_KEYFILE"
info "Key file contents (first 32 bytes): $(sudo head -c 32 "$BACKUP_KEYFILE" | xxd -p)"

# Encrypt root partition
log "Encrypting root partition with LUKS2..."
sudo cryptsetup luksFormat \
    --type luks2 \
    --cipher "$LUKS_CIPHER" \
    --key-size "$LUKS_KEY_SIZE" \
    --batch-mode "$TARGET_ROOT" "$TEMP_KEYFILE" || { error "Failed to format LUKS partition"; exit 1; }

# Open LUKS volume
sudo cryptsetup luksOpen "$TARGET_ROOT" "$MAPPER_NAME" --key-file "$TEMP_KEYFILE" || { error "Failed to open LUKS volume"; exit 1; }

# Copy root partition
log "Copying root partition..."
TEMP_ROOT_MOUNT=$(mktemp -d)
sudo mount "$ROOT_PART" "$TEMP_ROOT_MOUNT" || { error "Failed to mount input root partition"; exit 1; }
TEMP_MOUNT=$(mktemp -d)
sudo mkfs.ext4 "/dev/mapper/$MAPPER_NAME" || { error "Failed to create ext4 filesystem on /dev/mapper/$MAPPER_NAME"; exit 1; }
sudo mount "/dev/mapper/$MAPPER_NAME" "$TEMP_MOUNT" || { error "Failed to mount LUKS volume"; exit 1; }
sudo rsync -aAX --exclude={"/dev/*","/proc/*","/sys/*","/tmp/*","/run/*","/mnt/*","/media/*","/lost+found"} "$TEMP_ROOT_MOUNT/" "$TEMP_MOUNT/" || { error "Failed to copy root filesystem with rsync"; exit 1; }

# Update system configurations
log "Updating system configurations..."

# Mount boot partition
TEMP_BOOT_MOUNT=$(mktemp -d)
sudo mount "$TARGET_BOOT" "$TEMP_BOOT_MOUNT" || { error "Failed to mount boot partition"; exit 1; }

# Copy key file to /boot
sudo cp "$TEMP_KEYFILE" "$TEMP_BOOT_MOUNT/$KEYFILE_NAME" || { error "Failed to copy key file to boot partition"; exit 1; }
sudo chmod 0400 "$TEMP_BOOT_MOUNT/$KEYFILE_NAME"
rm -f "$TEMP_KEYFILE"

# Bind-mount boot partition
sudo mkdir -p "$TEMP_MOUNT/boot"
sudo mount --bind "$TEMP_BOOT_MOUNT" "$TEMP_MOUNT/boot"

# Update crypttab
ROOT_UUID=$(sudo blkid -s UUID -o value "$TARGET_ROOT")
sudo tee "$TEMP_MOUNT/etc/crypttab" > /dev/null <<EOF
$MAPPER_NAME UUID=$ROOT_UUID $KEYFILE luks,discard
EOF

# Update fstab
BOOT_UUID=$(sudo blkid -s UUID -o value "$TARGET_BOOT")
ROOT_MAPPER="/dev/mapper/$MAPPER_NAME"

TEMP_FSTAB=$(mktemp)
{
    grep -Ev "^(UUID=$BOOT_UUID|/boot|\s/\s|$ROOT_MAPPER)" "$TEMP_MOUNT/etc/fstab" || true
    echo "UUID=$BOOT_UUID /boot ext4 defaults 0 2"
    echo "$ROOT_MAPPER / ext4 defaults 0 1"
} | sudo tee "$TEMP_FSTAB" > /dev/null

sudo mv "$TEMP_FSTAB" "$TEMP_MOUNT/etc/fstab"
sudo chmod 644 "$TEMP_MOUNT/etc/fstab"

# Mount required filesystems for chroot
sudo mount --bind /dev "$TEMP_MOUNT/dev"
sudo mount --bind /sys "$TEMP_MOUNT/sys"
sudo mount --bind /proc "$TEMP_MOUNT/proc"

# Configure cryptsetup hook
sudo mkdir -p "$TEMP_MOUNT/etc/cryptsetup-initramfs"
sudo tee "$TEMP_MOUNT/etc/cryptsetup-initramfs/conf-hook" > /dev/null <<EOF
CRYPTSETUP=y
KEYFILE_PATTERN=/boot/*.key
EOF

# Update GRUB configuration
sudo tee "$TEMP_MOUNT/etc/default/grub.d/99-crypt.cfg" > /dev/null <<EOF
GRUB_ENABLE_CRYPTODISK=y
EOF

GRUB_CMDLINE="cryptdevice=UUID=$ROOT_UUID:$MAPPER_NAME root=$ROOT_MAPPER"
GRUB_FILE="$TEMP_MOUNT/etc/default/grub"
if grep -q "^GRUB_CMDLINE_LINUX_DEFAULT=" "$GRUB_FILE"; then
    sudo sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"$GRUB_CMDLINE\"|" "$GRUB_FILE" || {
        sudo sed -i "/^GRUB_CMDLINE_LINUX_DEFAULT=/d" "$GRUB_FILE"
        echo "GRUB_CMDLINE_LINUX_DEFAULT=\"$GRUB_CMDLINE\"" | sudo tee -a "$GRUB_FILE" > /dev/null
    }
else
    echo "GRUB_CMDLINE_LINUX_DEFAULT=\"$GRUB_CMDLINE\"" | sudo tee -a "$GRUB_FILE" > /dev/null
fi

# Regenerate initramfs
log "Regenerating initramfs..."
sudo chroot "$TEMP_MOUNT" update-initramfs -u -k all || { error "Failed to update initramfs"; exit 1; }

# Verify key in initramfs
KERNEL_VERSION=$(sudo chroot "$TEMP_MOUNT" ls /boot | grep -oP 'initrd\.img-\K[^ ]+' | head -n1)
if [[ -n "$KERNEL_VERSION" ]]; then
    if ! sudo lsinitramfs "$TEMP_MOUNT/boot/initrd.img-$KERNEL_VERSION" | grep -q "$KEYFILE_NAME"; then
        warn "Key file $KEYFILE_NAME not found in initramfs. Boot may fail."
    else
        log "Key file $KEYFILE_NAME confirmed in initramfs."
    fi
else
    warn "Could not determine kernel version for initramfs verification."
fi

# Update GRUB
log "Updating GRUB..."
sudo chroot "$TEMP_MOUNT" update-grub || { error "Failed to update GRUB"; exit 1; }

# Final output
log "Encrypted image creation complete: $ENCRYPTED_RAW"
info "Key file location in image: $KEYFILE"
info "Backup key location: $BACKUP_KEYFILE"
info "Key contents (first 32 bytes): $(sudo head -c 32 "$BACKUP_KEYFILE" | xxd -p)"
log "WARNING: The key file is stored in unencrypted /boot. Secure /boot properly."
