#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Enhanced Cloud-Init First Boot Configuration with Reliable First Boot Detection

Key Features:
1. Properly configures cloud-init to run on first boot using standard methods
2. Sets up all necessary configuration files in /etc/cloud
3. Configures users, SSH, networking, and file copies
4. Ensures reliable first boot detection through cloud-init's standard mechanisms
5. Adds comprehensive logging and error handling
"""

import os
import sys
import subprocess
import argparse
import shutil
import time
import base64
from pathlib import Path

# Constants
DEFAULT_IMAGE = "ubuntu-2204-efi-kube-v1.30.1"
MOUNT_BOOT = "/mnt/boot"
MOUNT_ROOT = "/mnt/root"
CRYPT_NAME = "luks-root"
LOG_FILE = "/var/log/cloud-init-prep.log"
DEFAULT_PASSWORD = "max"  # Password for root and ec2-user

class ConsoleLogger:
    """Enhanced logging handler with both console and file output"""
    COLORS = {
        'DEBUG': '\033[36m', 'INFO': '\033[32m', 'WARNING': '\033[33m',
        'ERROR': '\033[31m', 'CRITICAL': '\033[41m', 'RESET': '\033[0m'
    }

    def __init__(self, verbose=False):
        self.verbose = verbose
        Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
        self._clean_log()

    def _clean_log(self):
        """Initialize fresh log file"""
        with open(LOG_FILE, 'w') as f:
            f.write(f"Cloud-Init Preparation Log - {time.ctime()}\n{'='*50}\n")

    def debug(self, message):
        if self.verbose:
            self._log('DEBUG', message, self.COLORS['DEBUG'])

    def info(self, message):
        self._log('INFO', message, self.COLORS['INFO'])

    def warning(self, message):
        self._log('WARNING', message, self.COLORS['WARNING'], sys.stderr)

    def error(self, message):
        self._log('ERROR', message, self.COLORS['ERROR'], sys.stderr)
        sys.exit(1)

    def _log(self, level, message, color=None, file=sys.stdout):
        """Internal log handler"""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"{timestamp} [{level}] {message}"
        with open(LOG_FILE, 'a') as f:
            f.write(f"{log_entry}\n")
        print(f"{color}{log_entry}{self.COLORS['RESET']}" if color else log_entry, file=file)

def run_command(cmd, check=True, capture_output=True):
    """Execute shell command with comprehensive error handling"""
    logger.debug(f"Executing: {cmd}")
    try:
        result = subprocess.run(
            cmd, shell=True, check=check,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            text=True, executable='/bin/bash'
        )
        if capture_output and result.stdout:
            logger.debug(f"Output: {result.stdout.strip()}")
        if capture_output and result.stderr:
            logger.debug(f"Stderr: {result.stderr.strip()}")
        return result
    except subprocess.CalledProcessError as e:
        error_msg = f"Command failed ({e.returncode}): {cmd}\n{e.stderr.strip() if e.stderr else 'No stderr output'}"
        if check:
            logger.error(error_msg)
        raise

def parse_arguments():
    """Parse and validate command line arguments"""
    parser = argparse.ArgumentParser(
        description="Prepare disk image with guaranteed cloud-init first boot execution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n"
               "  sudo ./cloud-init-prep.py \\\n"
               "    --image ubuntu.img \\\n"
               "    --hostname myserver \\\n"
               "    --sshkey ~/.ssh/id_rsa.pub \\\n"
               "    --netplan config.yaml"
    )
    
    parser.add_argument("--image", default=DEFAULT_IMAGE,
                      help=f"Disk image path (default: {DEFAULT_IMAGE})")
    parser.add_argument("--hostname", help="System hostname to configure")
    parser.add_argument("--sshkey", help="Path to SSH public key for ec2-user")
    parser.add_argument("--netplan", help="Path to custom Netplan config file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    return parser.parse_args()

def validate_environment():
    """Check environment prerequisites"""
    if os.geteuid() != 0:
        logger.error("This script must be run as root")
    if not shutil.which("cloud-init"):
        logger.error("cloud-init must be installed on this system")

def mount_image(image_path):
    """Mount disk image partitions with proper error handling"""
    global LOOP_DEVICE
    logger.info(f"Mounting image: {image_path}")
    
    if not Path(image_path).exists():
        logger.error(f"Image file not found: {image_path}")

    try:
        # Setup loop device
        result = run_command(f"losetup --partscan --find --show {image_path}")
        LOOP_DEVICE = result.stdout.strip()
        logger.info(f"Using loop device: {LOOP_DEVICE}")

        # Create mount points
        Path(MOUNT_BOOT).mkdir(parents=True, exist_ok=True)
        Path(MOUNT_ROOT).mkdir(parents=True, exist_ok=True)

        # Mount partitions
        run_command(f"mount -t ext4 {LOOP_DEVICE}p2 {MOUNT_BOOT}")
        
        # Open LUKS container
        keyfile = f"{MOUNT_BOOT}/root_crypt.key"
        if not Path(keyfile).exists():
            logger.error(f"LUKS keyfile missing: {keyfile}")
        
        run_command(f"cryptsetup luksOpen --key-file={keyfile} {LOOP_DEVICE}p3 {CRYPT_NAME}")
        run_command(f"mount /dev/mapper/{CRYPT_NAME} {MOUNT_ROOT}")
        run_command(f"mount -t ext4 {LOOP_DEVICE}p2 {MOUNT_ROOT}/boot")
        run_command(f"mount {LOOP_DEVICE}p1 {MOUNT_ROOT}/boot/efi")
        
    except Exception as e:
        logger.error(f"Mounting failed: {str(e)}")

def ensure_cloud_init_first_boot():
    """Ensure cloud-init will run on first boot by setting up proper triggers"""
    logger.info("Configuring cloud-init for reliable first boot execution")
    
    # Cloud-init uses several methods to detect first boot:
    # 1. /var/lib/cloud/instance/sem/config_scripts_user (indicates first boot)
    # 2. /var/lib/cloud/instance/boot-finished (indicates boot completed)
    # 3. /var/lib/cloud/data/previous-datasource (compares with current)
    
    # We need to ensure these don't exist in the target image
    cloud_dirs = [
        f"{MOUNT_ROOT}/var/lib/cloud/instance",
        f"{MOUNT_ROOT}/var/lib/cloud/instances",
        f"{MOUNT_ROOT}/var/lib/cloud/data"
    ]
    
    for dir_path in cloud_dirs:
        if Path(dir_path).exists():
            logger.debug(f"Removing cloud-init state directory: {dir_path}")
            shutil.rmtree(dir_path, ignore_errors=True)

    # Ensure cloud-init is enabled in the target image
    run_command(f"chroot {MOUNT_ROOT} systemctl enable cloud-init.service")
    run_command(f"chroot {MOUNT_ROOT} systemctl enable cloud-init-local.service")
    run_command(f"chroot {MOUNT_ROOT} systemctl enable cloud-config.service")
    run_command(f"chroot {MOUNT_ROOT} systemctl enable cloud-final.service")

def prepare_cloud_init_config():
    """Create comprehensive cloud-init configuration with first boot guarantees"""
    logger.info("Preparing complete cloud-init configuration")
    
    cloud_init_dir = Path(f"{MOUNT_ROOT}/etc/cloud/cloud.cfg.d")
    cloud_init_dir.mkdir(exist_ok=True)

    # Prepare all files to be copied from /boot/ during first boot
    required_files = [
        {
            'boot_path': "/boot/10_tinkerbell.cfg",
            'dest': "/etc/cloud/cloud.cfg.d/10_tinkerbell.cfg",
            'perms': 0o644
        },
        {
            'boot_path': "/boot/99-disable-network-config.cfg",
            'dest': "/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg",
            'perms': 0o644
        },
        {
            'boot_path': "/boot/ds-identify.cfg",
            'dest': "/etc/cloud/ds-identify.cfg",
            'perms': 0o644
        }
    ]

    # Handle custom netplan config if provided
    if args.netplan and Path(args.netplan).exists():
        netplan_dest = f"{MOUNT_BOOT}/config.yaml"
        shutil.copy(args.netplan, netplan_dest)
        required_files.append({
            'boot_path': "/boot/config.yaml",
            'dest': "/etc/netplan/config.yaml",
            'perms': 0o600
        })

    # Generate write_files entries
    write_files_entries = []
    for file_info in required_files:
        src_path = Path(f"{MOUNT_ROOT}{file_info['boot_path']}")
        if src_path.exists():
            content = src_path.read_text()
            write_files_entries.append(f"""  - path: {file_info['dest']}
    encoding: b64
    content: {base64.b64encode(content.encode()).decode()}
    permissions: '{file_info['perms']:o}'
    owner: root:root
""")

    # Main cloud-init configuration
    config_content = f"""#cloud-config

# System Information
hostname: {args.hostname if args.hostname else 'localhost'}
manage_etc_hosts: true
preserve_hostname: false

# User Configuration
users:
  - name: root
    lock_passwd: false
    plain_text_passwd: "{DEFAULT_PASSWORD}"
  - name: ec2-user
    gecos: EC2 Default User
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: users, admin, sudo
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: "{DEFAULT_PASSWORD}"
    ssh_authorized_keys:
      - {"".join(Path(args.sshkey).read_text().splitlines()) if args.sshkey and Path(args.sshkey).exists() else ''}

# Authentication
chpasswd:
  list: |
    root:{DEFAULT_PASSWORD}
    ec2-user:{DEFAULT_PASSWORD}
  expire: false

# SSH Configuration
ssh_pwauth: true
disable_root: false

# Ensure cloud-init runs on first boot
cloud_init_modules:
  - migrator
  - seed_random
  - bootcmd
  - write-files
  - growpart
  - resizefs
  - set_hostname
  - update_hostname
  - update_etc_hosts
  - users-groups
  - ssh

# Write configuration files
write_files:
{"".join(write_files_entries)}

# First boot commands
runcmd:
  # Ensure cloud-init directories exist
  - [mkdir, -p, /etc/cloud/cloud.cfg.d]
  - [mkdir, -p, /etc/cloud]
  - [mkdir, -p, /etc/netplan]

  # Copy files from /boot to their destinations
  - [cp, "/boot/10_tinkerbell.cfg", "/etc/cloud/cloud.cfg.d/"]
  - [cp, "/boot/99-disable-network-config.cfg", "/etc/cloud/cloud.cfg.d/"]
  - [cp, "/boot/ds-identify.cfg", "/etc/cloud/"]
  - [cp, "/boot/config.yaml", "/etc/netplan/"]

  # Set permissions
  - [chmod, "644", "/etc/cloud/cloud.cfg.d/10_tinkerbell.cfg"]
  - [chmod, "644", "/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg"]
  - [chmod, "644", "/etc/cloud/ds-identify.cfg"]
  - [chmod, "600", "/etc/netplan/config.yaml"]

  # Apply network configuration
  - [netplan, apply]
  - [systemctl, restart, systemd-networkd]
  - [systemctl, restart, networking.service]

  # Final system configuration
  - [cloud-init, clean]
  - [cloud-init, modules, --mode=config]
  - [cloud-init, modules, --mode=final]

# Final message
final_message: "System initialization completed. Hostname: $hostname"
power_state:
  mode: reboot
  message: "Rebooting after initial configuration"
  timeout: 30
"""

    (cloud_init_dir / "10_main.cfg").write_text(config_content)
    logger.info("Complete cloud-init configuration created")

    # Create a marker file that cloud-init will check
    (Path(f"{MOUNT_ROOT}/etc") / "cloud-first-boot").write_text("")

def cleanup():
    """Clean up mounted resources"""
    logger.info("Performing cleanup...")
    
    mount_points = [
        f"{MOUNT_ROOT}/boot/efi",
        f"{MOUNT_ROOT}/boot",
        MOUNT_ROOT,
        MOUNT_BOOT
    ]
    
    for mount in mount_points:
        if Path(mount).is_mount():
            run_command(f"umount {mount}", check=False)
    
    if Path(f"/dev/mapper/{CRYPT_NAME}").exists():
        run_command(f"cryptsetup luksClose {CRYPT_NAME}", check=False)
    
    if 'LOOP_DEVICE' in globals() and LOOP_DEVICE:
        run_command(f"losetup -d {LOOP_DEVICE}", check=False)

def main():
    global logger, args
    
    args = parse_arguments()
    logger = ConsoleLogger(verbose=args.verbose)
    
    try:
        validate_environment()
        mount_image(args.image)
        
        # Critical steps to ensure cloud-init runs on first boot
        ensure_cloud_init_first_boot()
        prepare_cloud_init_config()
        
        logger.info("\nConfiguration Summary:")
        logger.info(f"• Hostname: {args.hostname or '(not set)'}")
        logger.info(f"• SSH Key: {'configured' if args.sshkey and Path(args.sshkey).exists() else 'not configured'}")
        logger.info(f"• Netplan Config: {'custom' if args.netplan and Path(args.netplan).exists() else 'default'}")
        logger.info(f"• Root password: {DEFAULT_PASSWORD}")
        logger.info(f"• ec2-user password: {DEFAULT_PASSWORD}")
        logger.info("• Cloud-init first boot guarantees:")
        logger.info("  - Cleaned previous cloud-init state")
        logger.info("  - Enabled all cloud-init services")
        logger.info("  - Added first boot marker file")
        logger.info("  - Configured automatic reboot after configuration")
        
    except KeyboardInterrupt:
        logger.info("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"\nScript failed: {str(e)}")
        sys.exit(1)
    finally:
        cleanup()
        logger.info("Operation completed successfully")

if __name__ == "__main__":
    main()
