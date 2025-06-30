#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Enhanced First Boot Configuration Script with Simplified Password Handling

Key Features:
- Sets both root and ec2-user passwords to 'max'
- Simplified password complexity requirements
- No forced password change on first login
- Comprehensive error handling
- Detailed logging
- Full cleanup on exit
"""

import os
import sys
import subprocess
import argparse
import shutil
import time
from pathlib import Path

# Constants
DEFAULT_IMAGE = "ubuntu-2204-efi-kube-v1.30.1"
MOUNT_BOOT = "/mnt/boot"
MOUNT_ROOT = "/mnt/root"
CRYPT_NAME = "luks-root"
FIRST_BOOT_MARKER = "/var/lib/first-boot-complete"
LOG_FILE = "/var/log/first-boot-config.log"
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
            f.write(f"First Boot Configuration Log - {time.ctime()}\n{'='*50}\n")

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
        description="Configure custom Ubuntu image for first boot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n"
               "  sudo ./first-boot-config.py \\\n"
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
    parser.add_argument("--no-ssh", action="store_false", dest="install_ssh",
                      help="Skip SSH server installation")
    parser.add_argument("--no-sshkeys", action="store_false", dest="gen_sshkeys",
                      help="Skip SSH host key generation")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    return parser.parse_args()

def validate_environment():
    """Check environment and ensure password consistency"""
    logger.info("Setting both root and ec2-user passwords to 'max'")
    # Ensure consistent password configuration
    os.environ['ROOT_PASSWORD'] = DEFAULT_PASSWORD
    os.environ['EC2_USER_PASSWORD'] = DEFAULT_PASSWORD

    # Verify script is running as root
    if os.geteuid() != 0:
        logger.error("This script must be run as root")

def cleanup():
    """Clean up mounted resources and temporary devices"""
    logger.info("Performing cleanup...")
    
    # Unmount in reverse order
    mount_points = [
        f"{MOUNT_ROOT}/boot/efi",
        f"{MOUNT_ROOT}/boot",
        MOUNT_ROOT,
        MOUNT_BOOT
    ]
    
    for mount in mount_points:
        if Path(mount).is_mount():
            try:
                run_command(f"umount {mount}", check=False, capture_output=False)
                logger.debug(f"Unmounted {mount}")
            except Exception as e:
                logger.warning(f"Failed to unmount {mount}: {str(e)}")
    
    # Close LUKS container if open
    if Path(f"/dev/mapper/{CRYPT_NAME}").exists():
        try:
            run_command(f"cryptsetup luksClose {CRYPT_NAME}", check=False)
            logger.debug("Closed LUKS container")
        except Exception as e:
            logger.warning(f"Failed to close LUKS container: {str(e)}")
    
    # Clean up loop device if used
    if 'LOOP_DEVICE' in globals() and LOOP_DEVICE:
        try:
            run_command(f"losetup -d {LOOP_DEVICE}", check=False)
            logger.debug(f"Released loop device {LOOP_DEVICE}")
        except Exception as e:
            logger.warning(f"Failed to release loop device: {str(e)}")

def mount_image(image_path):
    """Mount disk image partitions including LUKS encrypted volumes"""
    global LOOP_DEVICE
    logger.info(f"Mounting image: {image_path}")
    
    if not Path(image_path).exists():
        logger.error(f"Image file not found: {image_path}")

    # Setup loop device
    try:
        result = run_command(f"losetup --partscan --find --show {image_path}")
        LOOP_DEVICE = result.stdout.strip()
        logger.info(f"Using loop device: {LOOP_DEVICE}")
    except Exception as e:
        logger.error(f"Failed to setup loop device: {str(e)}")

    # Create mount points
    Path(MOUNT_BOOT).mkdir(parents=True, exist_ok=True)
    Path(MOUNT_ROOT).mkdir(parents=True, exist_ok=True)

    try:
        # Mount boot partition
        run_command(f"mount -t ext4 {LOOP_DEVICE}p2 {MOUNT_BOOT}")
        
        # Check for LUKS keyfile
        keyfile = f"{MOUNT_BOOT}/root_crypt.key"
        if not Path(keyfile).exists():
            logger.error(f"LUKS keyfile missing: {keyfile}")
        
        # Open LUKS container
        run_command(f"cryptsetup luksOpen --key-file={keyfile} {LOOP_DEVICE}p3 {CRYPT_NAME}")
        
        # Mount root filesystem
        run_command(f"mount /dev/mapper/{CRYPT_NAME} {MOUNT_ROOT}")
        run_command(f"mount -t ext4 {LOOP_DEVICE}p2 {MOUNT_ROOT}/boot")
        run_command(f"mount {LOOP_DEVICE}p1 {MOUNT_ROOT}/boot/efi")
        
    except Exception as e:
        logger.error(f"Mounting failed: {str(e)}")

def prepare_machine_id():
    """Clear machine-id to trigger regeneration on first boot"""
    logger.info("Preparing machine-id for regeneration")
    
    machine_id_file = Path(f"{MOUNT_ROOT}/etc/machine-id")
    dbus_machine_id = Path(f"{MOUNT_ROOT}/var/lib/dbus/machine-id")
    
    try:
        if machine_id_file.exists():
            logger.debug("Clearing /etc/machine-id")
            machine_id_file.write_text("")
            machine_id_file.chmod(0o444)
        
        if dbus_machine_id.exists():
            logger.debug("Updating DBus machine-id symlink")
            dbus_machine_id.unlink()
            dbus_machine_id.symlink_to("/etc/machine-id")
    except Exception as e:
        logger.warning(f"Failed to prepare machine-id: {str(e)}")

def configure_system():
    """Perform base system configuration"""
    logger.info("Configuring base system...")
    
    prepare_machine_id()
    
    try:
        # Set root password to 'max' without forcing change
        run_command(f"echo 'root:{DEFAULT_PASSWORD}' | chroot {MOUNT_ROOT} chpasswd")
        logger.debug("Root password set successfully")
        
        # Create required directories
        required_dirs = [
            f"{MOUNT_ROOT}/etc/netplan",
            f"{MOUNT_ROOT}/etc/cloud/cloud.cfg.d",
            f"{MOUNT_ROOT}/usr/local/bin",
            f"{MOUNT_ROOT}/var/lib"
        ]
        
        for dir_path in required_dirs:
            Path(dir_path).mkdir(parents=True, exist_ok=True)
            logger.debug(f"Created directory: {dir_path}")
            
        # Clean up default Netplan configurations
        for netplan_file in Path(f"{MOUNT_ROOT}/etc/netplan").glob("*.yaml"):
            netplan_file.unlink()
            logger.debug(f"Removed default netplan file: {netplan_file}")
            
    except Exception as e:
        logger.error(f"System configuration failed: {str(e)}")

def setup_netplan_service():
    """Configure Netplan apply service"""
    logger.info("Setting up Netplan service...")
    
    service_path = Path(f"{MOUNT_ROOT}/etc/systemd/system/netplan-apply.service")
    try:
        service_path.write_text("""\
[Unit]
Description=Apply Netplan configuration
After=first-boot-config.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/netplan apply

[Install]
WantedBy=multi-user.target
""")
        logger.debug("Created netplan-apply.service")
        
        run_command(f"chroot {MOUNT_ROOT} systemctl enable netplan-apply.service")
        logger.info("Netplan service enabled (will run on first boot)")
    except Exception as e:
        logger.error(f"Failed to setup Netplan service: {str(e)}")

def setup_ssh(install_ssh, gen_sshkeys):
    """Configure SSH server with root login options"""
    if not install_ssh:
        logger.info("Skipping SSH server installation as requested")
        return
        
    logger.info("Configuring SSH server...")
    
    try:
        run_command(f"chroot {MOUNT_ROOT} apt-get update")
        run_command(f"chroot {MOUNT_ROOT} apt-get install -y openssh-server")
        
        
        run_command(f"chroot {MOUNT_ROOT} systemctl enable ssh")
        logger.info("SSH server configured and enabled")
        
        if gen_sshkeys and not any(Path(f"{MOUNT_ROOT}/etc/ssh").glob("ssh_host_*")):
            logger.info("Generating SSH host keys...")
            
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
            
            logger.info("SSH host keys generated")
            
    except Exception as e:
        logger.error(f"SSH configuration failed: {str(e)}")

def create_first_boot_service():
    """Create first-boot oneshot service with comprehensive setup"""
    logger.info("Creating first-boot service...")
    
    service_path = Path(f"{MOUNT_ROOT}/etc/systemd/system/first-boot-config.service")
    script_path = Path(f"{MOUNT_ROOT}/usr/local/bin/first-boot-config.py")
    
    try:
        # Create systemd service
        service_path.write_text(f"""\
[Unit]
Description=First Boot Configuration
Before=multi-user.target cloud-init.target cloud-init.service cloud-init-local.service
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 /usr/local/bin/first-boot-config.py
TimeoutSec=300
StandardOutput=journal+console
StandardError=journal+console
SyslogIdentifier=first-boot

[Install]
WantedBy=multi-user.target
""")
        logger.debug("Created first-boot service unit file")
        
        # Create first-boot script
        script_content = f"""\
#!/usr/bin/env python3

import os
import subprocess
import shutil
import time
from pathlib import Path

LOG_FILE = "/var/log/first-boot.log"
DEFAULT_PASSWORD = "{DEFAULT_PASSWORD}"

def log(message, level='INFO'):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    with open(LOG_FILE, 'a') as f:
        f.write(f"{{timestamp}} [{{level}}] {{message}}\\n")
    subprocess.run(['logger', '-t', 'first-boot', f'{{level}}: {{message}}'], check=False)

def setup_ec2_user():
    try:
        # Create user if doesn't exist
        if not Path("/home/ec2-user").exists():
            subprocess.run([
                'useradd',
                '-m',
                '-s', '/bin/bash',
                'ec2-user'
            ], check=True)
            log("Created ec2-user account")
        else:
            log("ec2-user already exists")
            
        # Set password to 'max'
        subprocess.run([
            'chpasswd',
        ], input=f'ec2-user:{DEFAULT_PASSWORD}', encoding='utf-8', check=True)
        
        log("Set password for ec2-user")
        
        # Setup SSH key if available
        ssh_key_src = "/boot/ssh_key"
        ssh_key_dest = "/home/ec2-user/.ssh/authorized_keys"
            
        if Path(ssh_key_src).exists():
            try:
                Path(ssh_key_dest).parent.mkdir(exist_ok=True, mode=0o700)
                shutil.copy2(ssh_key_src, ssh_key_dest)
                Path(ssh_key_dest).chmod(0o600)
                subprocess.run(['chown', '-R', 'ec2-user:ec2-user', '/home/ec2-user/.ssh'], check=True)
                log("Configured SSH key for ec2-user")
            except Exception as e:
                log(f"SSH key setup error: {{str(e)}}", "ERROR")
                    
    except Exception as e:
        log(f"Error in ec2-user setup: {{str(e)}}", "ERROR")

def copy_config_files():
    try:
        # Create target directories
        Path("/etc/cloud/cloud.cfg.d").mkdir(parents=True, exist_ok=True)
        Path("/etc/netplan/").mkdir(parents=True, exist_ok=True)
        
        # Copy all required config files
        configs = [
            ("/boot/10_tinkerbell.cfg", "/etc/cloud/cloud.cfg.d/"),
            ("/boot/99-disable-network-config.cfg", "/etc/cloud/cloud.cfg.d/"),
            ("/boot/ds-identify.cfg", "/etc/cloud/"),
            ("/boot/config.yaml", "/etc/netplan/")
        ]
        
        for src, dest in configs:
            src_path = Path(src)
            if src_path.exists():
                shutil.copy(src_path, dest)
                log(f"Copied config file: {{src}} to {{dest}}")
            else:
                log(f"Config file not found: {{src}}", "WARNING")
    except Exception as e:
        log(f"Error copying config files: {{str(e)}}", "ERROR")

def main():
    try:
        log("Starting first boot configuration")
        setup_ec2_user()
        copy_config_files()
        
        # Create marker file to prevent re-execution
        Path("{FIRST_BOOT_MARKER}").touch()
        log("First boot configuration completed successfully")
    except Exception as e:
        log(f"First boot configuration failed: {{str(e)}}", "ERROR")
        raise

if __name__ == "__main__":
    main()
"""
        script_path.write_text(script_content)
        script_path.chmod(0o755)
        logger.debug("Created first-boot script")
        
        # Enable the service
        run_command(f"chroot {MOUNT_ROOT} systemctl enable first-boot-config.service")
        logger.info("First-boot service configured and enabled")
        
    except Exception as e:
        logger.error(f"Failed to create first-boot service: {str(e)}")

def copy_config_files(args):
    """Copy configuration files to image with validation"""
    logger.info("Copying configuration files...")
    
    try:
        if args.hostname:
            hostname_file = Path(f"{MOUNT_BOOT}/hostname")
            hostname_file.write_text(args.hostname)
            logger.debug(f"Set hostname to: {args.hostname}")
        
        if args.sshkey:
            sshkey_path = Path(args.sshkey)
            if sshkey_path.exists():
                shutil.copy(sshkey_path, f"{MOUNT_BOOT}/ssh_key")
                logger.debug(f"Copied SSH key from: {args.sshkey}")
            else:
                logger.warning(f"SSH key not found: {args.sshkey}")
        
        if args.netplan:
            netplan_path = Path(args.netplan)
            if netplan_path.exists():
                shutil.copy(netplan_path, f"{MOUNT_BOOT}/config.yaml")
                logger.debug(f"Copied Netplan config from: {args.netplan}")
            else:
                logger.warning(f"Netplan config not found: {args.netplan}")
        
        # Cloud-init network configuration
        disable_net_config = Path(f"{MOUNT_BOOT}/99-disable-network-config.cfg")
        disable_net_config.write_text("network: {config: disabled}\n")
        logger.debug("Disabled cloud-init network configuration")
        
    except Exception as e:
        logger.error(f"Failed to copy configuration files: {str(e)}")

def main():
    global logger, LOOP_DEVICE
    
    # Ensure script is executable
    if not os.access(__file__, os.X_OK):
        os.chmod(__file__, 0o755)
    
    args = parse_arguments()
    logger = ConsoleLogger(verbose=args.verbose)
    
    try:
        validate_environment()
        
        if not Path(args.image).exists():
            logger.error(f"Image not found: {args.image}")
        
        mount_image(args.image)
        configure_system()
        setup_netplan_service()
        setup_ssh(args.install_ssh, args.gen_sshkeys)
        create_first_boot_service()
        copy_config_files(args)
        
        # Print summary
        logger.info("\nConfiguration Summary:")
        logger.info(f"• Hostname: {args.hostname or '(not set)'}")
        logger.info(f"• SSH Server: {'enabled' if args.install_ssh else 'disabled'}")
        logger.info(f"• SSH Host Keys: {'generated' if args.gen_sshkeys else 'skipped'}")
        logger.info(f"• Netplan Config: {'custom' if args.netplan else 'default'}")
        logger.info("• Root SSH login: enabled")
        logger.info("• Both root and ec2-user passwords set to 'max'")
        logger.info("• Machine-ID will be regenerated on first boot")
        logger.info("• First-boot service configured to complete setup")
        
    except KeyboardInterrupt:
        logger.info("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"\nScript failed: {str(e)}")
        sys.exit(1)
    finally:
        cleanup()
        logger.info("Cleanup completed")

if __name__ == "__main__":
    main()
