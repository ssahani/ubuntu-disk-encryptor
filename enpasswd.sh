#!/bin/bash
set -euo pipefail

# === SCRIPT DESCRIPTION ===
# Purpose:
#   Creates an encrypted raw disk image from an unencrypted Ubuntu 22.04 raw disk
#   image with EFI, boot, and root partitions. Copies EFI and boot partitions as-is,
#   encrypts the root partition with LUKS2 using a password. The output is a raw disk
#   image suitable for VMs or physical disks.
#
# Usage:
#   export LUKS_PASSWORD='your_secure_password'
#   ./script.sh [-c cipher] [-k key_size] <input_raw_image> <output_encrypted_raw>
#   Options:
#     -c: LUKS cipher (default: aes-xts-plain64).
#     -k: LUKS key size in bits (default: 512).
#   Example:
#     export LUKS_PASSWORD='secure123'
#     ./script.sh -c aes-xts-plain64 -k 512 ubuntu-2204-efi-kube-v1.32.4.raw encrypted-ubuntu-2204.raw

# === CONFIGURATION ===
MAPPER_NAME="root_crypt"
LUKS_HEADER_SIZE=$((16 * 1024 * 1024))  # 16 MiB for LUKS2 header
SECTOR_SIZE=512
ALIGNMENT=$((1 * 1024 * 1024))  # 1 MiB alignment
LUKS_CIPHER="aes-xts-plain64"
LUKS_KEY_SIZE=512

# === COLOR LOGGING ===
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m' # No Color
else
    RED='' GREEN='' YELLOW='' NC=''
fi

log() { echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"; }
error() { echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2; }
warn() { echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARN:${NC} $1"; }

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
for dep in jq:jq qemu-img:qemu-utils cryptsetup:cryptsetup partx:util-linux kpartx:kpartx blkid:util-linux parted:parted fdisk:util-linux grub-install:grub2-common rsync:rsync; do
    check_and_install "${dep%%:*}" "${dep##*:}"
done

# === PARSE ARGUMENTS ===
while getopts "c:k:" opt; do
    case "$opt" in
        c) LUKS_CIPHER="$OPTARG" ;;
        k) LUKS_KEY_SIZE="$OPTARG" ;;
        *) error "Invalid option"; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

INPUT_RAW="$1"
ENCRYPTED_RAW="$2"

# === VALIDATE INPUTS ===
[[ -n "$INPUT_RAW" && -n "$ENCRYPTED_RAW" ]] || { error "Usage: $0 [-c cipher] [-k key_size] <input_raw_image> <output_encrypted_raw>"; exit 1; }
[[ -f "$INPUT_RAW" ]] || { error "Input file '$INPUT_RAW' not found"; exit 1; }
[[ -z "${LUKS_PASSWORD:-}" ]] && { error "LUKS_PASSWORD not set. Use: export LUKS_PASSWORD='your_password'"; exit 1; }
[[ -e "$ENCRYPTED_RAW" ]] && { error "Output file '$ENCRYPTED_RAW' already exists"; exit 1; }
OUTPUT_DIR=$(dirname "$ENCRYPTED_RAW")
[[ -d "$OUTPUT_DIR" && -w "$OUTPUT_DIR" ]] || { error "Output directory '$OUTPUT_DIR' is not writable"; exit 1; }

# === PRE-EXECUTION CLEANUP ===
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

# === SETUP INPUT LOOP DEVICE ===
log "Setting up input loop device..."
LOOP_INPUT=$(sudo losetup --show --find --partscan "$INPUT_RAW") || { error "Failed to set up loop device for input"; exit 1; }
sudo partx -u "$LOOP_INPUT" || { error "Failed to update partition table for input"; exit 1; }
EFI_PART="${LOOP_INPUT}p1"
BOOT_PART="${LOOP_INPUT}p2"
ROOT_PART="${LOOP_INPUT}p3"

# === VALIDATE PARTITIONS ===
for part in "$EFI_PART" "$BOOT_PART" "$ROOT_PART"; do
    [[ -e "$part" ]] || { error "Missing partition $part"; exit 1; }
done
# Check EFI partition type and filesystem
EFI_PART_TYPE=$(sudo fdisk -l "$LOOP_INPUT" | grep "^${EFI_PART}" | awk '{print $5,$6,$7}' | grep -i "EFI System")
if [[ -z "$EFI_PART_TYPE" ]]; then
    EFI_PART_TYPE=$(sudo fdisk -l "$LOOP_INPUT" | grep "^${EFI_PART}" | awk '{print $5,$6,$7}')
    warn "EFI partition type is not EFI System (found: $EFI_PART_TYPE); proceeding, but may not be UEFI-compatible"
else
    log "EFI partition confirmed as EFI System type"
fi
EFI_FSTYPE=$(sudo parted -s "$LOOP_INPUT" print | grep "^ 1" | awk '{print $5}')
if [[ "$EFI_FSTYPE" != "fat32" ]]; then
    error "EFI partition is not fat32 (parted reports: $EFI_FSTYPE)"; exit 1
fi
BLKID_FSTYPE=$(sudo blkid -s TYPE -o value "$EFI_PART" 2>/dev/null || echo "")
if [[ "$BLKID_FSTYPE" != "vfat" ]]; then
    warn "blkid did not detect vfat for EFI partition (found: $BLKID_FSTYPE), but parted confirms fat32; proceeding"
else
    log "EFI partition confirmed as vfat by blkid"
fi
if ! sudo file -s "$EFI_PART" | grep -q "FAT (32-bit)"; then
    warn "file command did not confirm FAT32, but parted reports fat32; proceeding"
else
    log "EFI partition confirmed as FAT32 by file command"
fi
# Verify root partition filesystem
log "Verifying root partition filesystem..."
ROOT_FSTYPE=$(sudo blkid -s TYPE -o value "$ROOT_PART" 2>/dev/null || echo "")
if [[ "$ROOT_FSTYPE" != "ext4" ]]; then
    error "Root partition ($ROOT_PART) is not ext4 (found: $ROOT_FSTYPE)"; exit 1
fi
log "Root partition confirmed as ext4"

# === CALCULATE SIZES ===
EFI_SIZE=$(sudo blockdev --getsize64 "$EFI_PART")
BOOT_SIZE=$(sudo blockdev --getsize64 "$BOOT_PART")
ROOT_SIZE=$(sudo blockdev --getsize64 "$ROOT_PART")

# Align sizes to SECTOR_SIZE for precision
align_size() {
    local size=$1
    echo $(( (size + SECTOR_SIZE - 1) / SECTOR_SIZE * SECTOR_SIZE ))
}
EFI_SIZE=$(align_size "$EFI_SIZE")
BOOT_SIZE=$(align_size "$BOOT_SIZE")
ROOT_SIZE=$(align_size "$ROOT_SIZE")
TOTAL_SIZE=$((ALIGNMENT + EFI_SIZE + BOOT_SIZE + ROOT_SIZE + LUKS_HEADER_SIZE + ALIGNMENT))

log "Partition sizes: EFI=$((EFI_SIZE/1024/1024)) MiB, Boot=$((BOOT_SIZE/1024/1024)) MiB, Root=$((ROOT_SIZE/1024/1024)) MiB"
log "LUKS header: $((LUKS_HEADER_SIZE/1024/1024)) MiB, Alignment: $((ALIGNMENT/1024/1024)) MiB x 2"
log "Total size: $((TOTAL_SIZE/1024/1024/1024)) GiB ($TOTAL_SIZE bytes)"

# === SPACE CHECK ===
FREE_SPACE=$(df --output=avail -B1 "$OUTPUT_DIR" | tail -n1)
[[ "$FREE_SPACE" -gt "$TOTAL_SIZE" ]] || { error "Not enough disk space: need $((TOTAL_SIZE/1024/1024)) MiB, available $((FREE_SPACE/1024/1024)) MiB"; exit 1; }

# === CREATE AND PARTITION OUTPUT IMAGE ===
log "Creating encrypted image..."
qemu-img create -f raw "$ENCRYPTED_RAW" "$TOTAL_SIZE" || { error "Failed to create output image"; exit 1; }
LOOP_OUTPUT=$(sudo losetup --show --find "$ENCRYPTED_RAW") || { error "Failed to set up loop device for output"; exit 1; }

# Calculate partition boundaries in sectors
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

# === COPY EFI + BOOT ===
log "Copying EFI and /boot partitions..."
sudo dd if="$EFI_PART" of="$TARGET_EFI" bs=4M status=progress conv=fsync || { error "Failed to copy EFI partition"; exit 1; }
sudo dd if="$BOOT_PART" of="$TARGET_BOOT" bs=4M status=progress conv=fsync || { error "Failed to copy boot partition"; exit 1; }

# === ENCRYPT ROOT ===
log "Encrypting root partition with LUKS2..."
echo "$LUKS_PASSWORD" | sudo cryptsetup luksFormat \
    --type luks2 \
    --cipher "$LUKS_CIPHER" \
    --key-size "$LUKS_KEY_SIZE" \
    --batch-mode "$TARGET_ROOT" || { error "Failed to format LUKS partition"; exit 1; }

# Open LUKS volume
log "Checking for existing LUKS mapping..."
if [[ -e "/dev/mapper/$MAPPER_NAME" ]]; then
    error "LUKS mapping '/dev/mapper/$MAPPER_NAME' already exists. Run 'sudo cryptsetup luksClose $MAPPER_NAME' and try again."; exit 1
fi
echo "$LUKS_PASSWORD" | sudo cryptsetup luksOpen "$TARGET_ROOT" "$MAPPER_NAME" || { error "Failed to open LUKS volume"; exit 1; }
log "Verifying LUKS mapping..."
if [[ ! -e "/dev/mapper/$MAPPER_NAME" ]]; then
    error "LUKS mapping /dev/mapper/$MAPPER_NAME does not exist after luksOpen"; exit 1
fi
log "LUKS mapping /dev/mapper/$MAPPER_NAME created successfully"

# Copy root partition
log "Copying root partition..."
TEMP_ROOT_MOUNT=$(mktemp -d)
sudo mount "$ROOT_PART" "$TEMP_ROOT_MOUNT" || { error "Failed to mount input root partition"; exit 1; }
TEMP_MOUNT=$(mktemp -d)
log "TEMP_MOUNT set to $TEMP_MOUNT"
sudo mkfs.ext4 "/dev/mapper/$MAPPER_NAME" || { error "Failed to create ext4 filesystem on /dev/mapper/$MAPPER_NAME"; exit 1; }
sudo mount "/dev/mapper/$MAPPER_NAME" "$TEMP_MOUNT" || { error "Failed to mount LUKS volume"; exit 1; }
sudo rsync -aAX --exclude={"/dev/*","/proc/*","/sys/*","/tmp/*","/run/*","/mnt/*","/media/*","/lost+found"} "$TEMP_ROOT_MOUNT/" "$TEMP_MOUNT/" || { error "Failed to copy root filesystem with rsync"; exit 1; }
sudo umount "$TEMP_ROOT_MOUNT" || true
rmdir "$TEMP_ROOT_MOUNT" || true
TEMP_ROOT_MOUNT=""

# Verify filesystem
log "Verifying filesystem on /dev/mapper/$MAPPER_NAME..."
FSTYPE=$(sudo blkid -s TYPE -o value "/dev/mapper/$MAPPER_NAME" 2>/dev/null || echo "")
if [[ "$FSTYPE" != "ext4" ]]; then
    error "LUKS volume /dev/mapper/$MAPPER_NAME is not ext4 (found: $FSTYPE)"; exit 1
fi
log "LUKS volume confirmed as ext4"

# === UPDATE ROOT FILESYSTEM CONFIGURATIONS ===
log "Updating root filesystem for password-based LUKS unlocking..."
# Mount boot partition
TEMP_BOOT_MOUNT=$(mktemp -d)
sudo mount "$TARGET_BOOT" "$TEMP_BOOT_MOUNT" || { error "Failed to mount boot partition"; exit 1; }

# Bind-mount boot partition to /boot in chroot
log "Bind-mounting boot partition to $TEMP_MOUNT/boot..."
sudo mkdir -p "$TEMP_MOUNT/boot" || { error "Failed to create $TEMP_MOUNT/boot"; exit 1; }
sudo mount --bind "$TEMP_BOOT_MOUNT" "$TEMP_MOUNT/boot" || { error "Failed to bind-mount $TEMP_BOOT_MOUNT to $TEMP_MOUNT/boot"; exit 1; }
log "Contents of $TEMP_MOUNT/boot:"
sudo ls -l "$TEMP_MOUNT/boot"

# Update /etc/crypttab
log "Updating /etc/crypttab..."
ROOT_UUID=$(sudo blkid -s UUID -o value "$TARGET_ROOT")
sudo tee "$TEMP_MOUNT/etc/crypttab" > /dev/null <<EOF
$MAPPER_NAME UUID=$ROOT_UUID none luks,discard
EOF

# Update /etc/fstab
log "Ensuring /boot is mounted in /etc/fstab..."
BOOT_UUID=$(sudo blkid -s UUID -o value "$TARGET_BOOT")
if ! grep -q "$BOOT_UUID" "$TEMP_MOUNT/etc/fstab"; then
    echo "UUID=$BOOT_UUID /boot ext4 defaults 0 2" | sudo tee -a "$TEMP_MOUNT/etc/fstab" > /dev/null
fi
# Ensure root filesystem is correctly mapped
ROOT_MAPPER="/dev/mapper/$MAPPER_NAME"
if ! grep -q "$ROOT_MAPPER" "$TEMP_MOUNT/etc/fstab"; then
    if grep -q "/dev/[a-zA-Z0-9]*[0-9] / " "$TEMP_MOUNT/etc/fstab"; then
        sudo sed -i "s|/dev/[a-zA-Z0-9]*[0-9] / |$ROOT_MAPPER / |" "$TEMP_MOUNT/etc/fstab" || { error "Failed to update /etc/fstab"; exit 1; }
    else
        echo "$ROOT_MAPPER / ext4 defaults 0 1" | sudo tee -a "$TEMP_MOUNT/etc/fstab" > /dev/null
    fi
fi

# Mount required filesystems for chroot
log "Mounting /proc, /sys, /dev for chroot..."
sudo mount --bind /dev "$TEMP_MOUNT/dev"
sudo mount --bind /sys "$TEMP_MOUNT/sys"
sudo mount --bind /proc "$TEMP_MOUNT/proc"

# Update GRUB configuration
log "Configuring GRUB for LUKS..."
sudo tee "$TEMP_MOUNT/etc/default/grub.d/99-crypt.cfg" > /dev/null <<EOF
GRUB_ENABLE_CRYPTODISK=y
EOF
# Update GRUB cmdline
GRUB_CMDLINE="cryptdevice=UUID=$ROOT_UUID:$MAPPER_NAME root=$ROOT_MAPPER"
GRUB_FILE="$TEMP_MOUNT/etc/default/grub"
log "Current /etc/default/grub content:"
sudo cat "$GRUB_FILE"
if grep -q "^GRUB_CMDLINE_LINUX_DEFAULT=" "$GRUB_FILE"; then
    log "Updating existing GRUB_CMDLINE_LINUX_DEFAULT..."
    SED_EXPR="s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"$GRUB_CMDLINE\"|"
    log "Executing sed: $SED_EXPR"
    if ! sudo sed -i "$SED_EXPR" "$GRUB_FILE"; then
        error "Failed to update GRUB cmdline with sed: $SED_EXPR"
        log "Falling back to direct write..."
        sudo sed -i "/^GRUB_CMDLINE_LINUX_DEFAULT=/d" "$GRUB_FILE" || { error "Failed to remove old GRUB_CMDLINE_LINUX_DEFAULT"; exit 1; }
        echo "GRUB_CMDLINE_LINUX_DEFAULT=\"$GRUB_CMDLINE\"" | sudo tee -a "$GRUB_FILE" > /dev/null || { error "Failed to add GRUB cmdline"; exit 1; }
    fi
else
    log "Adding new GRUB_CMDLINE_LINUX_DEFAULT..."
    echo "GRUB_CMDLINE_LINUX_DEFAULT=\"$GRUB_CMDLINE\"" | sudo tee -a "$GRUB_FILE" > /dev/null || { error "Failed to add GRUB cmdline"; exit 1; }
fi
log "Updated /etc/default/grub content:"
sudo cat "$GRUB_FILE"

# Regenerate initramfs inside chroot
log "Regenerating initramfs inside chroot..."
sudo chroot "$TEMP_MOUNT" update-initramfs -u || { error "Failed to update initramfs"; exit 1; }

# Update GRUB inside chroot
log "Updating GRUB configuration..."
if [[ ! -d "$TEMP_MOUNT/boot/grub" ]]; then
    error "Directory $TEMP_MOUNT/boot/grub does not exist"
    exit 1
fi
sudo chroot "$TEMP_MOUNT" update-grub || { error "Failed to update GRUB"; exit 1; }

# === DONE ===
log "Encrypted image creation complete: $ENCRYPTED_RAW"
log "Sizes: EFI=$((EFI_SIZE/1024/1024)) MiB, Boot=$((BOOT_SIZE/1024/1024)) MiB, Root=$((ROOT_SIZE/1024/1024)) MiB + LUKS header ($((LUKS_HEADER_SIZE/1024/1024)) MiB)"
log "Total: $((TOTAL_SIZE/1024/1024/1024)) GiB ($TOTAL_SIZE bytes)"
log "System will prompt for LUKS password ($LUKS_PASSWORD) during boot"
