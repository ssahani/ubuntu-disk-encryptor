#!/bin/bash
set -euo pipefail

# Configuration
IMAGE="ubuntu-2204-efi-kube-v1.30.5-en"
MOUNT_BOOT="/mnt/boot"
MOUNT_ROOT="/mnt/root"
LOOP_DEVICE=""
CRYPT_NAME="luks-root"

# Logging functions
log_info() {
  echo "[INFO] $1"
}

log_error() {
  echo "[ERROR] $1" >&2
  exit 1
}

# Mount image
mount_image() {
  log_info "Mounting image $IMAGE"
  
  # Setup loop device
  LOOP_DEVICE=$(sudo losetup --partscan --find --show "$IMAGE") || log_error "Failed to create loop device"
  
  # First mount boot partition to access the key file
  sudo mkdir -p "${MOUNT_BOOT}"
  sudo mount -t ext4 "${LOOP_DEVICE}p2" "${MOUNT_BOOT}" || log_error "Failed to mount boot partition"
  
  # Verify LUKS key exists
  KEYFILE="${MOUNT_BOOT}/root_crypt.key"
  [[ -f "$KEYFILE" ]] || log_error "LUKS keyfile not found: $KEYFILE"
  
  # Open LUKS container
  sudo cryptsetup luksOpen --key-file="$KEYFILE" "${LOOP_DEVICE}p3" "$CRYPT_NAME" || log_error "Failed to open LUKS container"
  
  # Mount root filesystem
  sudo mkdir -p "${MOUNT_ROOT}"
  sudo mount "/dev/mapper/${CRYPT_NAME}" "${MOUNT_ROOT}" || log_error "Failed to mount root filesystem"
}

# Create user and set root password
create_user_and_set_root_password() {
  log_info "Creating user sus with password max"
  log_info "Setting root password to max"
  
  sudo chroot "${MOUNT_ROOT}" bash -c "
    # Create user sus
    useradd -m -s /bin/bash sus
    echo 'sus:max' | chpasswd
    usermod -aG sudo sus
    echo 'sus ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/99-sus
    chmod 440 /etc/sudoers.d/99-sus
    
    # Set root password
    echo 'root:max' | chpasswd
  " || log_error "Failed to create user or set root password"
}

# Cleanup
cleanup() {
  # Unmount boot partition if mounted
  if mountpoint -q "${MOUNT_BOOT}"; then
    sudo umount "${MOUNT_BOOT}" 2>/dev/null
  fi
  
  # Unmount root filesystem if mounted
  if mountpoint -q "${MOUNT_ROOT}"; then
    sudo umount "${MOUNT_ROOT}" 2>/dev/null
  fi
  
  # Close LUKS container if open
  if [[ -e "/dev/mapper/${CRYPT_NAME}" ]]; then
    sudo cryptsetup luksClose "${CRYPT_NAME}" 2>/dev/null
  fi
  
  # Detach loop device if attached
  if [[ -n "$LOOP_DEVICE" ]]; then
    sudo losetup -d "$LOOP_DEVICE" 2>/dev/null
  fi
  
  # Cleanup mount directories
  sudo rmdir "${MOUNT_BOOT}" 2>/dev/null
  sudo rmdir "${MOUNT_ROOT}" 2>/dev/null
}

# Main execution
trap cleanup EXIT
mount_image
create_user_and_set_root_password
log_info "User sus created and root password set successfully - both passwords are 'max'"
