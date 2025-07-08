#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import argparse
import shutil
from pathlib import Path
from typing import Optional, List

# Constants
DEFAULT_IMAGE = "ubuntu-2204-efi-kube-v1.30.1"
MOUNT_POINTS = {
    'boot': "/mnt/boot",
    'root': "/mnt/root",
    'efi': "/mnt/root/boot/efi"
}
CRYPT_NAME = "luks-root"
FIRST_BOOT_MARKER = "/var/lib/first-boot-complete"
DEFAULT_PASSWORD = "max"

class ConsoleLogger:
    """Simple logging to console with colors"""
    COLORS = {
        'INFO': '\033[32m',
        'WARNING': '\033[33m',
        'ERROR': '\033[31m',
        'RESET': '\033[0m'
    }

    @staticmethod
    def log(level: str, message: str) -> None:
        """Log message with colored prefix"""
        color = ConsoleLogger.COLORS.get(level, '')
        print(f"{color}[{level}] {message}{ConsoleLogger.COLORS['RESET']}",
              file=sys.stderr if level in ('WARNING', 'ERROR') else sys.stdout)

    @staticmethod
    def info(message: str) -> None:
        """Log info message"""
        ConsoleLogger.log('INFO', message)

    @staticmethod
    def warn(message: str) -> None:
        """Log warning message"""
        ConsoleLogger.log('WARNING', message)

    @staticmethod
    def error(message: str) -> None:
        """Log error message and exit"""
        ConsoleLogger.log('ERROR', message)
        sys.exit(1)

def run_cmd(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run shell command with error handling"""
    try:
        result = subprocess.run(cmd, shell=True, check=check,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              text=True)
        return result
    except subprocess.CalledProcessError as e:
        ConsoleLogger.error(f"Command failed ({e.returncode}): {cmd}\n{e.stderr.strip()}")

def parse_args() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Configure system image for first boot",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument("--image", default=DEFAULT_IMAGE,
                      help="Disk image to configure")
    parser.add_argument("--hostname", help="Set system hostname")
    parser.add_argument("--root-pass", action="store_true",
                      help=f"Set root password to '{DEFAULT_PASSWORD}'")
    parser.add_argument("--ec2-user", action="store_true",
                      help=f"Create ec2-user with password '{DEFAULT_PASSWORD}'")
    parser.add_argument("--ssh-key", help="Install SSH public key for ec2-user")
    parser.add_argument("--netplan", help="Install custom netplan config")
    parser.add_argument("--no-cleanup", action="store_false", dest="cleanup",
                      help="Skip cleanup after configuration")
    
    return parser.parse_args()

def setup_mounts(image: str) -> str:
    """Mount disk image partitions"""
    ConsoleLogger.info(f"Mounting image: {image}")
    
    # Setup loop device
    result = run_cmd(f"losetup --find --show --partscan {image}")
    loop_dev = result.stdout.strip()
    
    # Create mount points
    for path in MOUNT_POINTS.values():
        Path(path).mkdir(parents=True, exist_ok=True)
    
    try:
        # Mount partitions
        run_cmd(f"mount {loop_dev}p2 {MOUNT_POINTS['boot']}")
        
        # Open LUKS container
        keyfile = f"{MOUNT_POINTS['boot']}/root_crypt.key"
        if not Path(keyfile).exists():
            ConsoleLogger.error(f"Missing LUKS keyfile: {keyfile}")
        
        run_cmd(f"cryptsetup luksOpen --key-file={keyfile} {loop_dev}p3 {CRYPT_NAME}")
        run_cmd(f"mount /dev/mapper/{CRYPT_NAME} {MOUNT_POINTS['root']}")
        run_cmd(f"mount {loop_dev}p2 {MOUNT_POINTS['root']}/boot")
        run_cmd(f"mount {loop_dev}p1 {MOUNT_POINTS['efi']}")
        
        return loop_dev
    except Exception:
        run_cmd(f"losetup -d {loop_dev}", check=False)
        raise

def cleanup(loop_dev: Optional[str] = None) -> None:
    """Clean up mounted resources"""
    ConsoleLogger.info("Cleaning up resources...")
    
    # Unmount in reverse order
    for mount in reversed(list(MOUNT_POINTS.values())):
        if Path(mount).is_mount():
            run_cmd(f"umount {mount}", check=False)
    
    # Close LUKS container
    if Path(f"/dev/mapper/{CRYPT_NAME}").exists():
        run_cmd(f"cryptsetup luksClose {CRYPT_NAME}", check=False)
    
    # Release loop device
    if loop_dev:
        run_cmd(f"losetup -d {loop_dev}", check=False)

def configure_hostname(hostname: str) -> None:
    """Configure system hostname"""
    ConsoleLogger.info(f"Setting hostname: {hostname}")
    Path(f"{MOUNT_POINTS['boot']}/hostname").write_text(f"{hostname}\n")

def set_root_password() -> None:
    """Set root password"""
    ConsoleLogger.info("Setting root password")
    run_cmd(f"echo 'root:{DEFAULT_PASSWORD}' | chroot {MOUNT_POINTS['root']} chpasswd")

def setup_ec2_user(ssh_key: Optional[str] = None) -> None:
    """Configure ec2-user account"""
    ConsoleLogger.info("Configuring ec2-user")
    
    # Create user if needed
    run_cmd(f"chroot {MOUNT_POINTS['root']} id -u ec2-user", check=False)
    if run_cmd(f"chroot {MOUNT_POINTS['root']} id -u ec2-user", check=False).returncode != 0:
        run_cmd(f"chroot {MOUNT_POINTS['root']} useradd -m -s /bin/bash ec2-user")
    
    # Set password
    run_cmd(f"echo 'ec2-user:{DEFAULT_PASSWORD}' | chroot {MOUNT_POINTS['root']} chpasswd")
    
    # Install SSH key if provided
    if ssh_key and Path(ssh_key).exists():
        ssh_dir = f"{MOUNT_POINTS['root']}/home/ec2-user/.ssh"
        Path(ssh_dir).mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copy(ssh_key, f"{ssh_dir}/authorized_keys")
        Path(f"{ssh_dir}/authorized_keys").chmod(0o600)
        run_cmd(f"chroot {MOUNT_POINTS['root']} chown -R ec2-user:ec2-user /home/ec2-user/.ssh")

def install_netplan(config: str) -> None:
    """Install custom netplan configuration"""
    if not Path(config).exists():
        ConsoleLogger.error(f"Netplan config not found: {config}")
    
    ConsoleLogger.info("Installing netplan configuration")
    netplan_dir = f"{MOUNT_POINTS['root']}/etc/netplan"
    Path(netplan_dir).mkdir(exist_ok=True)
    shutil.copy(config, f"{netplan_dir}/99-custom.yaml")

def create_firstboot_service() -> None:
    """Create service to complete configuration on first boot"""
    ConsoleLogger.info("Creating first-boot service")
    
    # Service unit file
    service_path = f"{MOUNT_POINTS['root']}/etc/systemd/system/first-boot-config.service"
    Path(service_path).write_text("""\
[Unit]
Description=First Boot Configuration
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/first-boot-config
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
""")
    
    # First-boot script
    script_path = f"{MOUNT_POINTS['root']}/usr/local/bin/first-boot-config"
    Path(script_path).write_text("""\
#!/bin/sh

# Set hostname if configured
if [ -f /boot/hostname ]; then
    hostnamectl set-hostname "$(cat /boot/hostname)"
fi

# Mark first boot complete
touch /var/lib/first-boot-complete
""")
    Path(script_path).chmod(0o755)
    
    # Enable service
    run_cmd(f"chroot {MOUNT_POINTS['root']} systemctl enable first-boot-config.service")

def main() -> None:
    args = parse_args()
    
    if not Path(args.image).exists():
        ConsoleLogger.error(f"Image not found: {args.image}")
    
    loop_dev = None
    try:
        # Mount image
        loop_dev = setup_mounts(args.image)
        
        # Apply requested configurations
        if args.hostname:
            configure_hostname(args.hostname)
        if args.root_pass:
            set_root_password()
        if args.ec2_user:
            setup_ec2_user(args.ssh_key)
        if args.netplan:
            install_netplan(args.netplan)
        
        # Always create first-boot service
        create_firstboot_service()
        
        ConsoleLogger.info("Configuration completed successfully")
        
    except Exception as e:
        ConsoleLogger.error(f"Configuration failed: {str(e)}")
    finally:
        if args.cleanup and loop_dev:
            cleanup(loop_dev)

if __name__ == "__main__":
    main()
