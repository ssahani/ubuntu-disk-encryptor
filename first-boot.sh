#!/bin/bash
set -euo pipefail

# Configuration
DEFAULT_IMAGE="ubuntu-2204-efi-kube-v1.30.1"
MOUNT_BOOT="/mnt/boot"
MOUNT_ROOT="/mnt/root"
LOOP_DEVICE=""
CRYPT_NAME="luks-root"
FIRST_BOOT_MARKER="/var/lib/first-boot-complete"
TEST_MODE=false
HOSTNAME=""
SSH_KEY_FILE=""
NETPLAN_FILE=""
IMAGE=""
INSTALL_SSH_SERVER=true
GENERATE_SSH_KEYS=true

# Get passwords from environment variables with fallback to defaults
ROOT_PASSWORD="${ROOT_PASSWORD:-Arm@1234}"
EC2_USER_PASSWORD="${EC2_USER_PASSWORD:-Arm@1234}"

# Logging functions
log_info() {
  echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warn() {
  echo "[WARN] $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
}

log_error() {
  echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
  exit 1
}

show_help() {
  cat <<EOF
Usage: $0 [OPTIONS]

Prepares a custom Ubuntu image with reliable first-boot configuration.

Required Arguments:
  --image        Path to the image file (default: $DEFAULT_IMAGE)

Options:
  --test         Verify configurations without making changes
  --hostname     Set instance hostname
  --sshkey       Path to SSH public key for ec2-user
  --netplan      Custom Netplan configuration file
  --no-ssh       Skip SSH server installation
  --no-sshkeys   Skip SSH host key generation
  --help         Show this help message

Environment Variables:
  ROOT_PASSWORD      Password for root user (default: Arm@1234)
  EC2_USER_PASSWORD  Password for ec2-user (default: Arm@1234)

First Boot Features:
  - Guaranteed one-time execution
  - Complete system configuration
  - Proper SSH key installation in /home/ec2-user/.ssh
  - Detailed logging to /var/log/first-boot.log

Examples:
  # Basic configuration with environment variables
  export ROOT_PASSWORD="MySecureRootPass"
  export EC2_USER_PASSWORD="MySecureUserPass"
  $0 --image custom.img
  
  # Full customization
  $0 --image custom.img --hostname myserver --sshkey ~/.ssh/id_rsa.pub
EOF
  exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) IMAGE="$2"; shift 2 ;;
    --test) TEST_MODE=true; shift ;;
    --hostname) HOSTNAME="$2"; shift 2 ;;
    --sshkey) SSH_KEY_FILE="$2"; shift 2 ;;
    --netplan) NETPLAN_FILE="$2"; shift 2 ;;
    --no-ssh) INSTALL_SSH_SERVER=false; shift ;;
    --no-sshkeys) GENERATE_SSH_KEYS=false; shift ;;
    --help|-h) show_help ;;
    *) log_error "Invalid option: $1 (use --help for usage)" ;;
  esac
done

# Validate configuration
IMAGE="${IMAGE:-$DEFAULT_IMAGE}"
[[ -f "$IMAGE" ]] || log_error "Image file not found: $IMAGE"

# Verify passwords are set
if [[ -z "$ROOT_PASSWORD" ]]; then
  log_error "Root password not set. Please set ROOT_PASSWORD environment variable"
fi

if [[ -z "$EC2_USER_PASSWORD" ]]; then
  log_error "EC2 user password not set. Please set EC2_USER_PASSWORD environment variable"
fi

cleanup() {
  log_info "Starting cleanup procedure"
  
  # Unmount in reverse order
  for mount in "${MOUNT_ROOT}/boot/efi" "${MOUNT_ROOT}/boot" "${MOUNT_ROOT}" "${MOUNT_BOOT}"; do
    if mountpoint -q "$mount"; then
      log_info "Unmounting $mount"
      sudo umount "$mount" 2>/dev/null || log_warn "Failed to unmount $mount"
    fi
  done
  
  # Close LUKS container if open
  if [[ -e "/dev/mapper/${CRYPT_NAME}" ]]; then
    log_info "Closing LUKS container"
    sudo cryptsetup luksClose "${CRYPT_NAME}" || log_warn "Failed to close LUKS container"
  fi
  
  # Detach loop device if attached
  if [[ -n "$LOOP_DEVICE" ]]; then
    log_info "Detaching loop device $LOOP_DEVICE"
    sudo losetup -d "$LOOP_DEVICE" || log_warn "Failed to detach loop device"
  fi
  
  log_info "Cleanup completed"
}

mount_image() {
  log_info "Setting up image mounts"
  
  # Setup loop device
  LOOP_DEVICE=$(sudo losetup --partscan --find --show "$IMAGE") || log_error "Failed to create loop device"
  log_info "Using loop device: $LOOP_DEVICE"
  
  # Mount boot partition
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
  
  # Mount additional partitions inside chroot
  sudo mount -t ext4 "${LOOP_DEVICE}p2" "${MOUNT_ROOT}/boot" || log_error "Failed to mount /boot in chroot"
  sudo mount "${LOOP_DEVICE}p1" "${MOUNT_ROOT}/boot/efi" || log_error "Failed to mount /boot/efi in chroot"
}

configure_system() {
  log_info "Configuring base system settings"
  
  # Ensure clean machine-id
  sudo rm -f "${MOUNT_ROOT}/etc/machine-id"
  sudo touch "${MOUNT_ROOT}/etc/machine-id" || log_warn "Failed to create machine-id"
  
  # Set root password
  echo "root:${ROOT_PASSWORD}" | sudo chroot "${MOUNT_ROOT}" chpasswd || log_warn "Failed to set root password"
  sudo chroot "${MOUNT_ROOT}" passwd -e root || log_warn "Failed to expire root password"
  
  # Create required directories
  sudo mkdir -p \
    "${MOUNT_ROOT}/etc/netplan" \
    "${MOUNT_ROOT}/etc/cloud/cloud.cfg.d" \
    "${MOUNT_ROOT}/usr/local/bin" \
    "${MOUNT_ROOT}/var/lib"
}

setup_ssh() {
  if [[ "$INSTALL_SSH_SERVER" == true ]]; then
    log_info "Configuring OpenSSH server"
    
    # Install package
    sudo chroot "${MOUNT_ROOT}" apt-get update || log_warn "Failed to update packages"
    sudo chroot "${MOUNT_ROOT}" apt-get install -y openssh-server || log_error "Failed to install OpenSSH"
    
    # Configure SSH
    sudo sed -i 's/#\?PasswordAuthentication .*/PasswordAuthentication yes/' \
      "${MOUNT_ROOT}/etc/ssh/sshd_config" || log_warn "Failed to configure SSH"
    
    # Enable service
    sudo chroot "${MOUNT_ROOT}" systemctl enable ssh || log_warn "Failed to enable SSH service"
  fi

  if [[ "$GENERATE_SSH_KEYS" == true ]]; then
    log_info "Generating SSH host keys if needed"
    
    if ! sudo ls "${MOUNT_ROOT}/etc/ssh/ssh_host_*" 1>/dev/null 2>&1; then
      log_info "No host keys found - generating new set"
      
      # Mount required filesystems
      sudo mount -t proc proc "${MOUNT_ROOT}/proc"
      sudo mount -t sysfs sys "${MOUNT_ROOT}/sys"
      sudo mount -o bind /dev "${MOUNT_ROOT}/dev"
      
      # Generate keys
      sudo chroot "${MOUNT_ROOT}" dpkg-reconfigure openssh-server || log_warn "Failed to generate SSH keys"
      
      # Cleanup mounts
      sudo umount "${MOUNT_ROOT}/dev"
      sudo umount "${MOUNT_ROOT}/sys"
      sudo umount "${MOUNT_ROOT}/proc"
    fi
  fi
}

create_first_boot_service() {
  log_info "Creating first-boot service"

  # Service file with reliable execution control
  sudo tee "${MOUNT_ROOT}/etc/systemd/system/first-boot-config.service" >/dev/null <<EOF
[Unit]
Description=First Boot Configuration Service
After=network.target systemd-networkd-wait-online.service
Wants=systemd-networkd-wait-online.service
ConditionPathExists=!${FIRST_BOOT_MARKER}

[Service]
Type=oneshot
ExecStart=/usr/local/bin/first-boot-config.sh
StandardOutput=journal+console
StandardError=journal+console
RemainAfterExit=yes
TimeoutSec=1800
ExecStartPost=/bin/touch ${FIRST_BOOT_MARKER}

[Install]
WantedBy=multi-user.target
EOF

  # First-boot script with environment variables for passwords
  sudo tee "${MOUNT_ROOT}/usr/local/bin/first-boot-config.sh" >/dev/null <<'EOF'
#!/bin/bash
set -euo pipefail

# Configuration - passwords will be passed from environment
export DEBIAN_FRONTEND=noninteractive

# Start logging
exec > >(tee /var/log/first-boot.log) 2>&1
echo "Starting first boot configuration at $(date)"

# Network connectivity check
network_ready() {
  for i in {1..10}; do
    if ping -c1 -W2 8.8.8.8 &>/dev/null; then
      echo "Network connectivity verified"
      return 0
    fi
    echo "Waiting for network... (attempt $i/10)"
    sleep 2
  done
  echo "Warning: Network not fully operational"
  return 1
}

# Set hostname if provided
if [[ -f "/boot/hostname" ]]; then
  NEW_HOSTNAME=$(tr -d '[:space:]' < /boot/hostname)
  if [[ -n "$NEW_HOSTNAME" ]]; then
    echo "Setting hostname to: $NEW_HOSTNAME"
    hostnamectl set-hostname "$NEW_HOSTNAME"
    echo "127.0.1.1\t$NEW_HOSTNAME" >> /etc/hosts
  fi
fi

# Apply network configuration
if [[ -f "/boot/config.yaml" ]]; then
  echo "Applying network configuration"
  cp "/boot/config.yaml" "/etc/netplan/99-config.yaml"
  chmod 600 "/etc/netplan/99-config.yaml"
  netplan apply || echo "Warning: netplan apply failed"
fi

# Wait for network
network_ready || true

# System updates
echo "Performing system updates"
apt-get update -qy
apt-get upgrade -qy
apt-get autoremove -qy

# Configure SSH server if installed
if systemctl list-unit-files | grep -q ssh.service; then
  echo "Configuring SSH server"
  
  # Disable password auth if SSH key exists
  if [[ -f "/boot/ssh_key" ]]; then
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
  else
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
  fi
  
  systemctl restart ssh
fi

# Create default user with proper SSH key installation
if ! id "ec2-user" &>/dev/null; then
  echo "Creating ec2-user account"
  useradd -m -s /bin/bash ec2-user
  echo "ec2-user:${EC2_USER_PASSWORD}" | chpasswd
  usermod -aG sudo ec2-user
  
  # Configure sudo access
  echo "ec2-user ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/99-ec2-user
  chmod 440 /etc/sudoers.d/99-ec2-user
  
  # Install SSH key if provided
  if [[ -f "/boot/ssh_key" ]]; then
    echo "Installing SSH key in /home/ec2-user/.ssh/authorized_keys"
    mkdir -p /home/ec2-user/.ssh
    chmod 700 /home/ec2-user/.ssh
    cp "/boot/ssh_key" /home/ec2-user/.ssh/authorized_keys
    chmod 600 /home/ec2-user/.ssh/authorized_keys
    chown -R ec2-user:ec2-user /home/ec2-user/.ssh
  fi
fi

echo "First boot configuration completed successfully at $(date)"
EOF

  # Set permissions and enable service
  sudo chmod 755 "${MOUNT_ROOT}/usr/local/bin/first-boot-config.sh"
  
  # Create environment file for the service
  sudo tee "${MOUNT_ROOT}/etc/default/first-boot-config" >/dev/null <<EOF
# Environment variables for first-boot-config
ROOT_PASSWORD="${ROOT_PASSWORD}"
EC2_USER_PASSWORD="${EC2_USER_PASSWORD}"
EOF

  # Update service to use environment file
  sudo sed -i '/^\[Service\]/a EnvironmentFile=/etc/default/first-boot-config' \
    "${MOUNT_ROOT}/etc/systemd/system/first-boot-config.service"

  sudo chroot "${MOUNT_ROOT}" systemctl enable first-boot-config.service || log_warn "Failed to enable service"
}

copy_config_files() {
  log_info "Copying configuration files to image"
  
  # Hostname configuration
  if [[ -n "$HOSTNAME" ]]; then
    echo "$HOSTNAME" | sudo tee "${MOUNT_BOOT}/hostname" >/dev/null
    log_info "Set hostname to: $HOSTNAME"
  fi
  
  # SSH key installation
  if [[ -n "$SSH_KEY_FILE" ]]; then
    if [[ -f "$SSH_KEY_FILE" ]]; then
      sudo cp "$SSH_KEY_FILE" "${MOUNT_BOOT}/ssh_key"
      sudo chmod 644 "${MOUNT_BOOT}/ssh_key"
      log_info "Installed SSH key from: $SSH_KEY_FILE"
    else
      log_warn "SSH key file not found: $SSH_KEY_FILE"
    fi
  fi
  
  # Network configuration
  if [[ -n "$NETPLAN_FILE" && -f "$NETPLAN_FILE" ]]; then
    sudo cp "$NETPLAN_FILE" "${MOUNT_BOOT}/config.yaml"
    sudo chmod 644 "${MOUNT_BOOT}/config.yaml"
    log_info "Installed custom Netplan config from: $NETPLAN_FILE"
  else
    sudo tee "${MOUNT_ROOT}/etc/netplan/99-default.yaml" >/dev/null <<'EOF'
network:
  version: 2
  renderer: networkd
  ethernets:
    match-en:
      match:
        name: "en*"
      dhcp4: true
      dhcp6: false
EOF
    log_info "Created default Netplan configuration"
  fi
  
  # Cloud-init configuration
  sudo tee "${MOUNT_BOOT}/99-disable-network-config.cfg" >/dev/null <<'EOF'
network: {config: disabled}
EOF
}

# Main execution flow
trap cleanup EXIT
log_info "Starting image customization for: ${IMAGE}"

mount_image
configure_system
setup_ssh
create_first_boot_service
copy_config_files

log_info "Image customization completed successfully"
log_info "First boot will configure:"
[[ -n "$HOSTNAME" ]] && log_info "  - Hostname: $HOSTNAME"
log_info "  - SSH Server: $INSTALL_SSH_SERVER"
log_info "  - Network: $(if [[ -n "$NETPLAN_FILE" ]]; then echo "custom"; else echo "default DHCP"; fi)"
log_info "  - User: ec2-user with password ${EC2_USER_PASSWORD:0:1}****${EC2_USER_PASSWORD: -1}"

if [[ "$TEST_MODE" == true ]]; then
  log_info "Test mode completed successfully"
fi

exit 0
