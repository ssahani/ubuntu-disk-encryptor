#!/bin/bash
set -euo pipefail

# === SCRIPT DESCRIPTION ===
# Purpose:
# Creates an encrypted raw disk image from an unencrypted Ubuntu 22.04 raw disk
# image with EFI, boot, and root partitions. Copies EFI and boot partitions as-is,
# encrypts the root partition with LUKS2 using a key file stored in /boot.
# The output is a raw disk image suitable for VMs or physical disks.
#
# Usage:
# ./script.sh [-c cipher] [-k key_size] [-h hash] [-v] [-t] <input_raw_image> <output_encrypted_raw>
# Options:
# -c: LUKS cipher (default: aes-xts-plain64).
# -k: LUKS key size in bits (default: 512).
# -h: LUKS hash algorithm (default: sha256).
# -v: Enable verification mode (mounts output image after creation to test).
# -t: Enable test mode (launches QEMU VM after creation to test the image).
# Example:
# ./script.sh -c aes-xts-plain64 -k 512 -h sha512 -v -t ubuntu-2204-efi-kube-v1.32.4.raw encrypted-ubuntu-2204.raw
#
# WARNING:
# The key file is stored in /boot, which is unencrypted. Ensure /boot is secured
# (e.g., physical access control, Secure Boot) to prevent unauthorized access.

# === ASCII ART FOR COOLNESS ===
echo -e "\033[1;34m"
cat << "EOF"
   _____                              _   _ 
  / ____|                            | | | |
 | |    _   _  ___  ___  _ __   ___ | |_| |
 | |   | | | |/ _ \/ _ \| '_ \ / _ \| __| |
 | |___| |_| |  __/ (_) | | | | (_) | |_|_|
  \_____\__,_|\___|\___/|_| |_|\___/ \__(_)
                                           
Encrypting your disk like a cyber ninja! 🥷🔒
EOF
echo -e "\033[0m"

# === CONFIGURATION ===
MAPPER_NAME="root_crypt"
KEYFILE="/boot/root_crypt.key" # Path to key file in /boot
LUKS_HEADER_SIZE=$((16 * 1024 * 1024)) # 16 MiB for LUKS2 header
SECTOR_SIZE=512
ALIGNMENT=$((1 * 1024 * 1024)) # 1 MiB alignment
LUKS_CIPHER="aes-xts-plain64"
LUKS_KEY_SIZE=512
LUKS_HASH="sha256"
VERIFICATION_MODE=false
TEST_MODE=false
QEMU_RAM="2048M"
QEMU_CPUS="2"
OVMF_PATH="/usr/share/OVMF/OVMF_CODE.fd" # Default path for OVMF on Ubuntu

# === COLOR LOGGING WITH EMOJI ===
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[1;34m'
    NC='\033[0m' # No Color
    EMOJI=true
else
    RED='' GREEN='' YELLOW='' BLUE='' NC=''
    EMOJI=false
fi

log() {
    local emoji=""
    if $EMOJI; then emoji="✅ "; fi
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} ${emoji}$1"
}
error() {
    local emoji=""
    if $EMOJI; then emoji="❌ "; fi
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} ${emoji}$1" >&2
}
warn() {
    local emoji=""
    if $EMOJI; then emoji="⚠️ "; fi
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARN:${NC} ${emoji}$1"
}
info() {
    local emoji=""
    if $EMOJI; then emoji="ℹ️ "; fi
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO:${NC} ${emoji}$1"
}

# === TIMING FUNCTION ===
time_op() {
    local start=$(date +%s)
    "$@"
    local end=$(date +%s)
    local duration=$((end - start))
    info "Operation completed in ${duration} seconds. ⏱️"
}

# === CLEANUP FUNCTION ===
cleanup() {
    log "Cleaning up resources... 🧹"
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
    if [[ -n "${TEMP_KEYFILE:-}" && -f "$TEMP_KEYFILE" ]]; then
        rm -f "$TEMP_KEYFILE" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# === DEPENDENCY CHECK WITH VERSION LOGGING ===
check_and_install() {
    local cmd="$1" pkg="$2"
    if ! command -v "$cmd" &>/dev/null; then
        log "Installing $pkg for $cmd... 📦"
        sudo apt-get update -qq && sudo apt-get install -y "$pkg" || {
            error "Failed to install $pkg"; exit 1
        }
    fi
    info "$cmd version: $($cmd --version | head -n1)"
}
for dep in jq:jq qemu-img:qemu-utils cryptsetup:cryptsetup partx:util-linux kpartx:kpartx blkid:util-linux parted:parted fdisk:util-linux grub-install:grub2-common rsync:rsync; do
    check_and_install "${dep%%:*}" "${dep##*:}"
done
# Additional dependencies for QEMU testing
check_and_install qemu-system-x86_64 qemu-system-x86
check_and_install qemu-efi-aarch64 qemu-efi # For OVMF, but on x86 it's qemu-efi

# Check for OVMF
if [[ ! -f "$OVMF_PATH" ]]; then
    log "Installing OVMF for UEFI support..."
    sudo apt-get install -y ovmf || { error "Failed to install ovmf package"; exit 1; }
    OVMF_PATH="/usr/share/OVMF/OVMF_CODE.fd"
    if [[ ! -f "$OVMF_PATH" ]]; then
        error "OVMF firmware not found at $OVMF_PATH"; exit 1;
    fi
fi

# === PARSE ARGUMENTS ===
while getopts "c:k:h:vt" opt; do
    case "$opt" in
        c) LUKS_CIPHER="$OPTARG" ;;
        k) LUKS_KEY_SIZE="$OPTARG" ;;
        h) LUKS_HASH="$OPTARG" ;;
        v) VERIFICATION_MODE=true ;;
        t) TEST_MODE=true ;;
        *) error "Invalid option"; exit 1 ;;
    esac
done
shift $((OPTIND - 1))
INPUT_RAW="$1"
ENCRYPTED_RAW="$2"

# === VALIDATE INPUTS ===
[[ -n "$INPUT_RAW" && -n "$ENCRYPTED_RAW" ]] || { error "Usage: $0 [-c cipher] [-k key_size] [-h hash] [-v] [-t] <input_raw_image> <output_encrypted_raw>"; exit 1; }
[[ -f "$INPUT_RAW" ]] || { error "Input file '$INPUT_RAW' not found"; exit 1; }
[[ -e "$ENCRYPTED_RAW" ]] && { error "Output file '$ENCRYPTED_RAW' already exists"; exit 1; }
OUTPUT_DIR=$(dirname "$ENCRYPTED_RAW")
[[ -d "$OUTPUT_DIR" && -w "$OUTPUT_DIR" ]] || { error "Output directory '$OUTPUT_DIR' is not writable"; exit 1; }

# === PRE-EXECUTION CLEANUP ===
log "Performing pre-execution cleanup... 🧼"
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
log "Setting up input loop device... 🔄"
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
log "Validating EFI partition... 🔍"
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
log "Verifying root partition filesystem... 📁"
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
log "Creating encrypted image... 💾"
time_op qemu-img create -f raw "$ENCRYPTED_RAW" "$TOTAL_SIZE" || { error "Failed to create output image"; exit 1; }
LOOP_OUTPUT=$(sudo losetup --show --find "$ENCRYPTED_RAW") || { error "Failed to set up loop device for output"; exit 1; }
# Calculate partition boundaries in sectors
EFI_START=$((ALIGNMENT / SECTOR_SIZE))
EFI_END=$((EFI_START + EFI_SIZE / SECTOR_SIZE - 1))
BOOT_START=$((EFI_END + 1))
BOOT_END=$((BOOT_START + BOOT_SIZE / SECTOR_SIZE - 1))
ROOT_START=$((BOOT_END + 1))
ROOT_END=$((ROOT_START + (ROOT_SIZE + LUKS_HEADER_SIZE) / SECTOR_SIZE - 1))
time_op sudo parted -s "$LOOP_OUTPUT" -- mklabel gpt \
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
log "Copying EFI and /boot partitions... 📋"
time_op sudo dd if="$EFI_PART" of="$TARGET_EFI" bs=4M status=progress conv=fsync || { error "Failed to copy EFI partition"; exit 1; }
time_op sudo dd if="$BOOT_PART" of="$TARGET_BOOT" bs=4M status=progress conv=fsync || { error "Failed to copy boot partition"; exit 1; }

# === ENCRYPT ROOT ===
log "Encrypting root partition with LUKS2... 🔐 Like a boss!"
# Generate a random key file
TEMP_KEYFILE=$(mktemp)
sudo dd if=/dev/urandom of="$TEMP_KEYFILE" bs=1024 count=4 || { error "Failed to generate key file"; exit 1; }
sudo chmod 0400 "$TEMP_KEYFILE"
# Format LUKS partition with the key file
time_op sudo cryptsetup luksFormat \
    --type luks2 \
    --cipher "$LUKS_CIPHER" \
    --key-size "$LUKS_KEY_SIZE" \
    --hash "$LUKS_HASH" \
    --batch-mode "$TARGET_ROOT" "$TEMP_KEYFILE" || { error "Failed to format LUKS partition"; exit 1; }
# Open LUKS volume
log "Checking for existing LUKS mapping... 🕵️"
if [[ -e "/dev/mapper/$MAPPER_NAME" ]]; then
    error "LUKS mapping '/dev/mapper/$MAPPER_NAME' already exists. Run 'sudo cryptsetup luksClose $MAPPER_NAME' and try again."; exit 1
fi
sudo cryptsetup luksOpen "$TARGET_ROOT" "$MAPPER_NAME" --key-file "$TEMP_KEYFILE" || { error "Failed to open LUKS volume"; exit 1; }
log "Verifying LUKS mapping..."
if [[ ! -e "/dev/mapper/$MAPPER_NAME" ]]; then
    error "LUKS mapping /dev/mapper/$MAPPER_NAME does not exist after luksOpen"; exit 1
fi
log "LUKS mapping /dev/mapper/$MAPPER_NAME created successfully"

# Copy root partition
log "Copying root partition... 📂"
TEMP_ROOT_MOUNT=$(mktemp -d)
sudo mount "$ROOT_PART" "$TEMP_ROOT_MOUNT" || { error "Failed to mount input root partition"; exit 1; }
TEMP_MOUNT=$(mktemp -d)
log "TEMP_MOUNT set to $TEMP_MOUNT"
sudo mkfs.ext4 "/dev/mapper/$MAPPER_NAME" || { error "Failed to create ext4 filesystem on /dev/mapper/$MAPPER_NAME"; exit 1; }
sudo mount "/dev/mapper/$MAPPER_NAME" "$TEMP_MOUNT" || { error "Failed to mount LUKS volume"; exit 1; }
time_op sudo rsync -aAX --exclude={"/dev/*","/proc/*","/sys/*","/tmp/*","/run/*","/mnt/*","/media/*","/lost+found"} "$TEMP_ROOT_MOUNT/" "$TEMP_MOUNT/" || { error "Failed to copy root filesystem with rsync"; exit 1; }
sudo umount "$TEMP_ROOT_MOUNT" || true
rmdir "$TEMP_ROOT_MOUNT" || true
TEMP_ROOT_MOUNT=""

# Verify filesystem
log "Verifying filesystem on /dev/mapper/$MAPPER_NAME... ✅"
FSTYPE=$(sudo blkid -s TYPE -o value "/dev/mapper/$MAPPER_NAME" 2>/dev/null || echo "")
if [[ "$FSTYPE" != "ext4" ]]; then
    error "LUKS volume /dev/mapper/$MAPPER_NAME is not ext4 (found: $FSTYPE)"; exit 1
fi
log "LUKS volume confirmed as ext4"

# === UPDATE ROOT FILESYSTEM CONFIGURATIONS ===
log "Updating root filesystem for key-based LUKS unlocking... ⚙️"
# Mount boot partition
TEMP_BOOT_MOUNT=$(mktemp -d)
sudo mount "$TARGET_BOOT" "$TEMP_BOOT_MOUNT" || { error "Failed to mount boot partition"; exit 1; }
# Copy key file to /boot
log "Copying key file to $TEMP_BOOT_MOUNT/root_crypt.key... 🔑"
sudo cp "$TEMP_KEYFILE" "$TEMP_BOOT_MOUNT/root_crypt.key" || { error "Failed to copy key file to boot partition"; exit 1; }
sudo chmod 0400 "$TEMP_BOOT_MOUNT/root_crypt.key"
# Bind-mount boot partition to /boot in chroot
log "Bind-mounting boot partition to $TEMP_MOUNT/boot... 🔗"
sudo mkdir -p "$TEMP_MOUNT/boot" || { error "Failed to create $TEMP_MOUNT/boot"; exit 1; }
sudo mount --bind "$TEMP_BOOT_MOUNT" "$TEMP_MOUNT/boot" || { error "Failed to bind-mount $TEMP_BOOT_MOUNT to $TEMP_MOUNT/boot"; exit 1; }
log "Contents of $TEMP_MOUNT/boot:"
sudo ls -l "$TEMP_MOUNT/boot"
# Update /etc/crypttab
log "Updating /etc/crypttab for key file..."
ROOT_UUID=$(sudo blkid -s UUID -o value "$TARGET_ROOT")
sudo tee "$TEMP_MOUNT/etc/crypttab" > /dev/null <<EOF
$MAPPER_NAME UUID=$ROOT_UUID $KEYFILE luks,discard
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
log "Mounting /proc, /sys, /dev for chroot... 🛠️"
sudo mount --bind /dev "$TEMP_MOUNT/dev"
sudo mount --bind /sys "$TEMP_MOUNT/sys"
sudo mount --bind /proc "$TEMP_MOUNT/proc"
# Configure cryptsetup hook for initramfs
log "Configuring cryptsetup hook for key file..."
sudo mkdir -p "$TEMP_MOUNT/etc/cryptsetup-initramfs"
sudo tee "$TEMP_MOUNT/etc/cryptsetup-initramfs/conf-hook" > /dev/null <<EOF
CRYPTSETUP=y
KEYFILE_PATTERN=/boot/*.key
EOF
# (Optional) Disable floppy errors
log "Disabling floppy module to prevent initramfs errors..."
sudo tee "$TEMP_MOUNT/etc/modprobe.d/blacklist-floppy.conf" > /dev/null <<EOF
blacklist floppy
EOF
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
log "Regenerating initramfs inside chroot... 🔄"
time_op sudo chroot "$TEMP_MOUNT" update-initramfs -u -k all || { error "Failed to update initramfs"; exit 1; }
# Verify key file in initramfs
log "Verifying key file in initramfs... 🔑"
KERNEL_VERSION=$(sudo chroot "$TEMP_MOUNT" ls /boot | grep -oP 'initrd\.img-\K[^ ]+' | head -n1)
if [[ -n "$KERNEL_VERSION" ]]; then
    if ! sudo lsinitramfs "$TEMP_MOUNT/boot/initrd.img-$KERNEL_VERSION" | grep -q "$(basename $KEYFILE)"; then
        warn "Key file $KEYFILE not found in initramfs. Boot may fail."
    else
        log "Key file $KEYFILE confirmed in initramfs."
    fi
else
    warn "Could not determine kernel version for initramfs verification."
fi
# Update GRUB inside chroot
log "Updating GRUB configuration... 📝"
if [[ ! -d "$TEMP_MOUNT/boot/grub" ]]; then
    error "Directory $TEMP_MOUNT/boot/grub does not exist"
    exit 1
fi
time_op sudo chroot "$TEMP_MOUNT" update-grub || { error "Failed to update GRUB"; exit 1; }

# === VERIFICATION MODE ===
if $VERIFICATION_MODE; then
    log "Verification mode enabled: Testing mount of output image... 🧪"
    # Close current mappings
    cleanup
    # Setup loop for output
    LOOP_VERIFY=$(sudo losetup --show --find --partscan "$ENCRYPTED_RAW") || { error "Failed to set up loop for verification"; exit 1; }
    VERIFY_ROOT="${LOOP_VERIFY}p3"
    sudo cryptsetup luksOpen "$VERIFY_ROOT" "${MAPPER_NAME}_verify" --key-file "$TEMP_BOOT_MOUNT/root_crypt.key" || { error "Failed to open LUKS in verification"; exit 1; }
    VERIFY_MOUNT=$(mktemp -d)
    sudo mount "/dev/mapper/${MAPPER_NAME}_verify" "$VERIFY_MOUNT" || { error "Failed to mount encrypted root in verification"; exit 1; }
    log "Verification successful: Encrypted root mounted at $VERIFY_MOUNT"
    sudo umount "$VERIFY_MOUNT"
    rmdir "$VERIFY_MOUNT"
    sudo cryptsetup luksClose "${MAPPER_NAME}_verify"
    sudo losetup -d "$LOOP_VERIFY"
fi

# === TEST MODE WITH QEMU ===
if $TEST_MODE; then
    log "Test mode enabled: Launching QEMU VM to test the encrypted image... 🚀"
    # Ensure cleanup is done before launching QEMU
    cleanup
    # Launch QEMU
    qemu-system-x86_64 \
        -enable-kvm \
        -m "$QEMU_RAM" \
        -smp "$QEMU_CPUS" \
        -drive file="$ENCRYPTED_RAW",format=raw,if=virtio \
        -bios "$OVMF_PATH" \
        -net none \
        -display default \
        || { error "Failed to launch QEMU VM"; exit 1; }
    log "QEMU VM launched. Close the VM window to continue."
fi

# === DONE ===
log "Encrypted image creation complete: $ENCRYPTED_RAW 🎉"
log "Sizes: EFI=$((EFI_SIZE/1024/1024)) MiB, Boot=$((BOOT_SIZE/1024/1024)) MiB, Root=$((ROOT_SIZE/1024/1024)) MiB + LUKS header ($((LUKS_HEADER_SIZE/1024/1024)) MiB)"
log "Total: $((TOTAL_SIZE/1024/1024/1024)) GiB ($TOTAL_SIZE bytes)"
log "System will automatically unlock LUKS using key file $KEYFILE"
warn "WARNING: Key file is stored in unencrypted /boot. Secure /boot with physical access control or Secure Boot."

# === FINAL ASCII ART ===
echo -e "\033[1;32m"
cat << "EOF"
  ____             _       _   _ 
 / __ \           | |     | | | |
| |  | |_   _  ___| | __ _| |_| |
| |  | | | | |/ _ \ |/ _` | __| |
| |__| | |_| |  __/ | (_| | |_|_|
 \____/ \__,_|\___|_|\__,_|\__(_)
                                 
Your disk is now encrypted and awesome! 🚀🔒
EOF
echo -e "\033[0m"
