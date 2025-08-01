#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Complete Cloud-Init First Boot Configuration with Persistent Netplan Application

Key Features:
1. Ensures cloud-init runs reliably on first boot
2. Configures netplan to apply on every boot after network.target
3. Sets up users, SSH, and system configuration
4. Includes comprehensive error handling and logging
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
DEFAULT_PASSWORD = "max"

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
        description="Prepare disk image with complete cloud-init configuration",
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

def mount_image(image_path):
    """Mount disk image partitions"""
    global LOOP_DEVICE
    logger.info(f"Mounting image: {image_path}")
    
    if not Path(image_path).exists():
        logger.error(f"Image file not found: {image_path}")

    try:
        result = run_command(f"losetup --partscan --find --show {image_path}")
        LOOP_DEVICE = result.stdout.strip()
        logger.info(f"Using loop device: {LOOP_DEVICE}")

        Path(MOUNT_BOOT).mkdir(parents=True, exist_ok=True)
        Path(MOUNT_ROOT).mkdir(parents=True, exist_ok=True)

        run_command(f"mount -t ext4 {LOOP_DEVICE}p2 {MOUNT_BOOT}")
        
        keyfile = f"{MOUNT_BOOT}/root_crypt.key"
        if not Path(keyfile).exists():
            logger.error(f"LUKS keyfile missing: {keyfile}")
        
        run_command(f"cryptsetup luksOpen --key-file={keyfile} {LOOP_DEVICE}p3 {CRYPT_NAME}")
        run_command(f"mount /dev/mapper/{CRYPT_NAME} {MOUNT_ROOT}")
        run_command(f"mount -t ext4 {LOOP_DEVICE}p2 {MOUNT_ROOT}/boot")
        run_command(f"mount {LOOP_DEVICE}p1 {MOUNT_ROOT}/boot/efi")
        
    except Exception as e:
        logger.error(f"Mounting failed: {str(e)}")

def prepare_netplan_service():
    """Create and enable systemd service for persistent netplan application"""
    logger.info("Configuring netplan-apply service for every boot")
    
    service_content = """[Unit]
Description=Apply Netplan configuration
After=network.target
Wants=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/netplan apply

[Install]
WantedBy=multi-user.target
"""
    
    service_path = Path(f"{MOUNT_ROOT}/etc/systemd/system/netplan-apply.service")
    service_path.write_text(service_content)
    
    # Enable the service
    run_command(f"chroot {MOUNT_ROOT} systemctl enable netplan-apply.service")
    logger.info("netplan-apply service configured to run on every boot")

def prepare_cloud_init_config():
    """Create comprehensive cloud-init configuration"""
    logger.info("Preparing complete cloud-init configuration")
    
    cloud_init_dir = Path(f"{MOUNT_ROOT}/etc/cloud/cloud.cfg.d")
    cloud_init_dir.mkdir(exist_ok=True)

    # Prepare files to be copied from /boot/
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

    if args.netplan and Path(args.netplan).exists():
        shutil.copy(args.netplan, f"{MOUNT_BOOT}/config.yaml")
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

# Write configuration files
write_files:
{"".join(write_files_entries)}

# First boot commands
runcmd:
  # Ensure directories exist
  - [mkdir, -p, /etc/cloud/cloud.cfg.d]
  - [mkdir, -p, /etc/cloud]
  - [mkdir, -p, /etc/netplan]

  # Copy files from /boot
  - [cp, "/boot/10_tinkerbell.cfg", "/etc/cloud/cloud.cfg.d/"]
  - [cp, "/boot/99-disable-network-config.cfg", "/etc/cloud/cloud.cfg.d/"]
  - [cp, "/boot/ds-identify.cfg", "/etc/cloud/"]
  - [cp, "/boot/config.yaml", "/etc/netplan/"]

  # Set permissions
  - [chmod, "644", "/etc/cloud/cloud.cfg.d/10_tinkerbell.cfg"]
  - [chmod, "644", "/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg"]
  - [chmod, "644", "/etc/cloud/ds-identify.cfg"]
  - [chmod, "600", "/etc/netplan/config.yaml"]

  # Initial network configuration
  - [netplan, apply]
  - [systemctl, restart, systemd-networkd]
  - [systemctl, restart, ssh]

  # Clean cloud-init and mark first boot complete
  - [cloud-init, clean]
  - [rm, -f, /etc/cloud/cloud-init.disabled]

# Final system setup
power_state:
  mode: reboot
  message: "Rebooting after initial configuration"
  timeout: 30
"""

    (cloud_init_dir / "10_main.cfg").write_text(config_content)
    logger.info("Complete cloud-init configuration created")

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
        
        # Prepare the netplan service first
        prepare_netplan_service()
        
        # Then prepare the cloud-init configuration
        prepare_cloud_init_config()
        
        logger.info("\nConfiguration Summary:")
        logger.info(f"• Hostname: {args.hostname or '(not set)'}")
        logger.info(f"• SSH Key: {'configured' if args.sshkey and Path(args.sshkey).exists() else 'not configured'}")
        logger.info(f"• Netplan Config: {'custom' if args.netplan and Path(args.netplan).exists() else 'default'}")
        logger.info(f"• Root password: {DEFAULT_PASSWORD}")
        logger.info(f"• ec2-user password: {DEFAULT_PASSWORD}")
        logger.info("• Netplan persistence: Enabled (runs after network.target on every boot)")
        logger.info("• Cloud-init first boot: Fully configured")
        
    except KeyboardInterrupt:
        logger.info("\nOperation cancelled by use
