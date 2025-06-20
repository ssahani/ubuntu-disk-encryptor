#!/usr/bin/env python3

"""
First Boot Configuration Script (Python Port)

This script prepares a custom Ubuntu image with reliable first-boot configuration.
It handles disk mounting, system configuration, SSH setup, and creates a first-boot
service that runs exactly once to complete system setup.

Key Features:
- Encrypted root partition support (LUKS)
- Automatic SSH server configuration
- Hostname and network configuration
- One-time first boot execution
- Detailed logging
- Safe cleanup of resources

Usage:
1. Set required environment variables:
   export ROOT_PASSWORD="your_root_password"
   export EC2_USER_PASSWORD="your_ec2_user_password"

2. Run the script with desired options:
   sudo python3 first-boot-config.py --image ubuntu.img --hostname myserver \
     --sshkey ~/.ssh/id_rsa.pub --netplan custom-netplan.yaml

Environment Variables:
  ROOT_PASSWORD      Password for root user (required)
  EC2_USER_PASSWORD  Password for ec2-user (required)

Command Line Options:
  --image        Path to disk image file (default: ubuntu-2204-efi-kube-v1.30.1)
  --hostname     Set system hostname
  --sshkey       Path to SSH public key for ec2-user
  --netplan      Custom Netplan configuration file
  --no-ssh       Skip SSH server installation
  --no-sshkeys   Skip SSH host key generation
  --verbose      Enable verbose output
  --help         Show this help message

First Boot Operations:
  - Sets hostname from /boot/hostname if available
  - Applies network configuration from /boot/config.yaml
  - Performs system updates
  - Configures SSH server
  - Creates ec2-user account with sudo access
  - Installs SSH key if provided

Logging:
  - Script outputs INFO, WARN, and ERROR messages to stderr
  - First-boot service logs to /var/log/first-boot.log
  - Verbose mode shows detailed command execution

Example:
  sudo python3 first-boot-config.py --image custom.img --hostname myserver \
    --sshkey ~/.ssh/id_rsa.pub --verbose
"""

import os
import sys
import subprocess
import argparse
import shutil
import logging
from pathlib import Path
from typing import Optional, List

# Constants
DEFAULT_IMAGE = "ubuntu-2204-efi-kube-v1.30.1"
MOUNT_BOOT = "/mnt/boot"
MOUNT_ROOT = "/mnt/root"
CRYPT_NAME = "luks-root"
FIRST_BOOT_MARKER = "/var/lib/first-boot-complete"

# Global variables
LOOP_DEVICE = ""
VERBOSE = False

def setup_logging(verbose: bool = False):
    """Configure logging with different levels for console output."""
    global VERBOSE
    VERBOSE = verbose
    
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format='[%(levelname)s] %(asctime)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stderr)
        ]
    )

def log_debug(message: str):
    """Log debug message if verbose mode is enabled."""
    if VERBOSE:
        logging.debug(message)

def log_info(message: str):
    """Log informational message."""
    logging.info(message)

def log_warn(message: str):
    """Log warning message."""
    logging.warning(message)

def log_error(message: str):
    """Log error message and exit."""
    logging.error(message)
    sys.exit(1)

def run_command(cmd: str, check: bool = True, capture_output: bool = True) -> Optional[str]:
    """
    Execute a shell command with optional output capture.
    
    Args:
        cmd: Command string to execute
        check: Whether to raise exception on failure
        capture_output: Whether to capture and return output
        
    Returns:
        Command output if capture_output=True, None otherwise
    """
    log_debug(f"Executing command: {cmd}")
    
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            check=check,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE,
            text=True,
            executable='/bin/bash'
        )
        
        if VERBOSE and result.stdout:
            log_debug(f"Command output:\n{result.stdout}")
        if result.stderr:
            log_debug(f"Command stderr:\n{result.stderr}")
            
        return result.stdout.strip() if capture_output else None
        
    except subprocess.CalledProcessError as e:
        error_msg = f"Command failed (exit {e.returncode}): {cmd}\nError: {e.stderr}"
        if check:
            log_error(error_msg)
        else:
            log_warn(error_msg)
            return None

def parse_arguments() -> argparse.Namespace:
    """Parse and validate command line arguments."""
    parser = argparse.ArgumentParser(
        description="Prepare a custom Ubuntu image with first-boot configuration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  # Basic configuration with environment variables
  export ROOT_PASSWORD="secure123"
  export EC2_USER_PASSWORD="secure456"
  sudo %(prog)s --image custom.img
  
  # Full customization with verbose output
  sudo %(prog)s --image custom.img --hostname myserver \\
    --sshkey ~/.ssh/id_rsa.pub --netplan config.yaml --verbose
"""
    )
    
    parser.add_argument(
        "--image",
        default=DEFAULT_IMAGE,
        help=f"path to disk image (default: {DEFAULT_IMAGE})"
    )
    parser.add_argument(
        "--hostname",
        help="system hostname to configure"
    )
    parser.add_argument(
        "--sshkey",
        help="path to SSH public key for ec2-user"
    )
    parser.add_argument(
        "--netplan", 
        help="custom Netplan configuration file"
    )
    parser.add_argument(
        "--no-ssh",
        action="store_false",
        dest="install_ssh_server",
        help="skip SSH server installation"
    )
    parser.add_argument(
        "--no-sshkeys",
        action="store_false",
        dest="generate_ssh_keys",
        help="skip SSH host key generation"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="enable verbose output"
    )
    
    return parser.parse_args()

def validate_environment():
    """Validate required environment variables."""
    if not os.getenv("ROOT_PASSWORD"):
        log_error("ROOT_PASSWORD environment variable must be set")
    
    if not os.getenv("EC2_USER_PASSWORD"):
        log_error("EC2_USER_PASSWORD environment variable must be set")

def cleanup():
    """Clean up mounted filesystems and devices."""
    log_info("Starting cleanup procedure")
    
    # Unmount in reverse order
    mounts = [
        f"{MOUNT_ROOT}/boot/efi",
        f"{MOUNT_ROOT}/boot",
        MOUNT_ROOT,
        MOUNT_BOOT
    ]
    
    for mount in mounts:
        if os.path.ismount(mount):
            log_info(f"Unmounting {mount}")
            run_command(f"umount {mount}", check=False)
    
    # Close LUKS container if open
    if Path(f"/dev/mapper/{CRYPT_NAME}").exists():
        log_info(f"Closing LUKS container {CRYPT_NAME}")
        run_command(f"cryptsetup luksClose {CRYPT_NAME}", check=False)
    
    # Detach loop device if attached
    global LOOP_DEVICE
    if LOOP_DEVICE:
        log_info(f"Detaching loop device {LOOP_DEVICE}")
        run_command(f"losetup -d {LOOP_DEVICE}", check=False)
        LOOP_DEVICE = ""

def mount_image(image_path: str):
    """Mount the disk image and its partitions."""
    global LOOP_DEVICE
    
    log_info(f"Mounting image: {image_path}")
    
    # Setup loop device
    LOOP_DEVICE = run_command(f"losetup --partscan --find --show {image_path}")
    log_info(f"Using loop device: {LOOP_DEVICE}")
    
    # Create mount points
    Path(MOUNT_BOOT).mkdir(parents=True, exist_ok=True)
    Path(MOUNT_ROOT).mkdir(parents=True, exist_ok=True)
    
    # Mount boot partition
    run_command(f"mount -t ext4 {LOOP_DEVICE}p2 {MOUNT_BOOT}")
    
    # Verify LUKS key exists
    keyfile = f"{MOUNT_BOOT}/root_crypt.key"
    if not Path(keyfile).exists():
        log_error(f"LUKS keyfile not found: {keyfile}")
    
    # Open LUKS container
    run_command(f"cryptsetup luksOpen --key-file={keyfile} {LOOP_DEVICE}p3 {CRYPT_NAME}")
    
    # Mount root filesystem
    run_command(f"mount /dev/mapper/{CRYPT_NAME} {MOUNT_ROOT}")
    
    # Mount additional partitions
    run_command(f"mount -t ext4 {LOOP_DEVICE}p2 {MOUNT_ROOT}/boot")
    run_command(f"mount {LOOP_DEVICE}p1 {MOUNT_ROOT}/boot/efi")

def configure_system():
    """Configure basic system settings."""
    log_info("Configuring base system")
    
    # Machine ID handling
    machine_id = Path(f"{MOUNT_ROOT}/etc/machine-id")
    if machine_id.exists():
        log_info("Resetting machine-id")
        machine_id.unlink()
    machine_id.touch()
    
    # Set root password
    root_pass = os.getenv("ROOT_PASSWORD")
    run_command(f"echo 'root:{root_pass}' | chroot {MOUNT_ROOT} chpasswd")
    run_command(f"chroot {MOUNT_ROOT} passwd -e root")
    
    # Create required directories
    for directory in [
        f"{MOUNT_ROOT}/etc/netplan",
        f"{MOUNT_ROOT}/etc/cloud/cloud.cfg.d",
        f"{MOUNT_ROOT}/usr/local/bin",
        f"{MOUNT_ROOT}/var/lib"
    ]:
        Path(directory).mkdir(parents=True, exist_ok=True)

def setup_ssh(install: bool, generate_keys: bool):
    """Configure SSH server and keys."""
    if install:
        log_info("Configuring SSH server")
        run_command(f"chroot {MOUNT_ROOT} apt-get update")
        run_command(f"chroot {MOUNT_ROOT} apt-get install -y openssh-server")
        
        # Configure SSH
        sshd_config = Path(f"{MOUNT_ROOT}/etc/ssh/sshd_config")
        content = sshd_config.read_text()
        content = re.sub(
            r'#?\s*PasswordAuthentication\s.*',
            'PasswordAuthentication yes',
            content
        )
        sshd_config.write_text(content)
        
        # Enable service
        run_command(f"chroot {MOUNT_ROOT} systemctl enable ssh")
    
    if generate_keys and not any(Path(f"{MOUNT_ROOT}/etc/ssh").glob("ssh_host_*")):
        log_info("Generating SSH host keys")
        
        # Mount required filesystems
        run_command(f"mount -t proc proc {MOUNT_ROOT}/proc")
        run_command(f"mount -t sysfs sys {MOUNT_ROOT}/sys")
        run_command(f"mount -o bind /dev {MOUNT_ROOT}/dev")
        
        # Generate keys
        run_command(f"chroot {MOUNT_ROOT} dpkg-reconfigure openssh-server")
        
        # Cleanup mounts
        run_command(f"umount {MOUNT_ROOT}/dev")
        run_command(f"umount {MOUNT_ROOT}/sys")
        run_command(f"umount {MOUNT_ROOT}/proc")

def create_first_boot_service():
    """Create first-boot service and configuration."""
    log_info("Creating first-boot service")
    
    # Service file
    service_content = f"""\
[Unit]
Description=First Boot Configuration Service
After=network.target systemd-networkd-wait-online.service
Wants=systemd-networkd-wait-online.service
ConditionPathExists=!{FIRST_BOOT_MARKER}

[Service]
Type=oneshot
ExecStart=/usr/local/bin/first-boot-config.sh
StandardOutput=journal+console
StandardError=journal+console
RemainAfterExit=yes
TimeoutSec=1800
ExecStartPost=/bin/touch {FIRST_BOOT_MARKER}
EnvironmentFile=/etc/default/first-boot-config

[Install]
WantedBy=multi-user.target
"""
    Path(f"{MOUNT_ROOT}/etc/systemd/system/first-boot-config.service").write_text(service_content)
    
    # First-boot script
    script_content = """\
#!/bin/bash
set -euo pipefail

# Start logging
exec > >(tee /var/log/first-boot.log) 2>&1
echo "Starting first boot configuration at $(date)"

# Network check
for i in {1..10}; do
  if ping -c1 -W2 8.8.8.8 &>/dev/null; then
    echo "Network ready"
    break
  fi
  echo "Waiting for network... ($i/10)"
  sleep 2
done

# Hostname configuration
if [[ -f "/boot/hostname" ]]; then
  hostname=$(tr -d '[:space:]' < /boot/hostname)
  if [[ -n "$hostname" ]]; then
    echo "Setting hostname: $hostname"
    hostnamectl set-hostname "$hostname"
    echo "127.0.1.1\\t$hostname" >> /etc/hosts
  fi
fi

# Network configuration
if [[ -f "/boot/config.yaml" ]]; then
  echo "Applying network config"
  cp "/boot/config.yaml" "/etc/netplan/99-config.yaml"
  netplan apply || echo "Warning: netplan apply failed"
fi

# System updates
echo "Running system updates"
apt-get update -qy
apt-get upgrade -qy
apt-get autoremove -qy

# SSH configuration
if [[ -f "/boot/ssh_key" ]]; then
  echo "Configuring SSH key for ec2-user"
  mkdir -p /home/ec2-user/.ssh
  chmod 700 /home/ec2-user/.ssh
  cp "/boot/ssh_key" /home/ec2-user/.ssh/authorized_keys
  chmod 600 /home/ec2-user/.ssh/authorized_keys
  chown -R ec2-user:ec2-user /home/ec2-user/.ssh
fi

echo "First boot configuration completed at $(date)"
"""
    script_path = Path(f"{MOUNT_ROOT}/usr/local/bin/first-boot-config.sh")
    script_path.write_text(script_content)
    script_path.chmod(0o755)
    
    # Environment file
    env_content = f"""\
ROOT_PASSWORD={os.getenv('ROOT_PASSWORD')}
EC2_USER_PASSWORD={os.getenv('EC2_USER_PASSWORD')}
"""
    Path(f"{MOUNT_ROOT}/etc/default/first-boot-config").write_text(env_content)
    
    # Enable service
    run_command(f"chroot {MOUNT_ROOT} systemctl enable first-boot-config.service")

def copy_config_files(args: argparse.Namespace):
    """Copy configuration files to the image."""
    log_info("Copying configuration files")
    
    # Hostname
    if args.hostname:
        Path(f"{MOUNT_BOOT}/hostname").write_text(args.hostname)
        log_info(f"Set hostname: {args.hostname}")
    
    # SSH key
    if args.sshkey and Path(args.sshkey).exists():
        shutil.copy(args.sshkey, f"{MOUNT_BOOT}/ssh_key")
        log_info(f"Copied SSH key: {args.sshkey}")
    
    # Netplan config
    if args.netplan and Path(args.netplan).exists():
        shutil.copy(args.netplan, f"{MOUNT_BOOT}/config.yaml")
        log_info(f"Copied Netplan config: {args.netplan}")
    else:
        Path(f"{MOUNT_ROOT}/etc/netplan/99-default.yaml").write_text("""\
network:
  version: 2
  renderer: networkd
  ethernets:
    match-en:
      match:
        name: "en*"
      dhcp4: true
      dhcp6: false
""")
    
    # Cloud-init config
    Path(f"{MOUNT_BOOT}/99-disable-network-config.cfg").write_text("network: {config: disabled}\n")

def main():
    try:
        # Parse arguments and setup logging
        args = parse_arguments()
        setup_logging(args.verbose)
        
        # Validate environment
        validate_environment()
        
        # Verify image exists
        if not Path(args.image).exists():
            log_error(f"Image file not found: {args.image}")
        
        log_info(f"Starting first-boot configuration for {args.image}")
        
        # Mount image and configure
        mount_image(args.image)
        configure_system()
        setup_ssh(args.install_ssh_server, args.generate_ssh_keys)
        create_first_boot_service()
        copy_config_files(args)
        
        # Summary
        log_info("Configuration completed successfully")
        log_info("First boot will perform:")
        log_info(f"- Hostname: {args.hostname or '(not set)'}")
        log_info(f"- SSH: {'enabled' if args.install_ssh_server else 'disabled'}")
        log_info(f"- SSH keys: {'generated' if args.generate_ssh_keys else 'skipped'}")
        log_info(f"- Network: {'custom' if args.netplan else 'default DHCP'}")
        
    except Exception as e:
        log_error(f"Script failed: {str(e)}")
    finally:
        cleanup()

if __name__ == "__main__":
    main()
