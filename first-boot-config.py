#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Simplified First Boot Configuration Script

Key Features:
- Sets both root and ec2-user passwords to 'max'
- Automatic hostname configuration from /boot/hostname
- Simplified password complexity requirements
- Console output only (no file logging)
- Clean resource management with proper cleanup
- First-boot service for final configuration
"""

import os
import sys
import subprocess
import argparse
import shutil
import time
from pathlib import Path
from typing import Optional

# Constants
DEFAULT_IMAGE = "ubuntu-2204-efi-kube-v1.30.1"
MOUNT_BOOT = "/mnt/boot"
MOUNT_ROOT = "/mnt/root"
CRYPT_NAME = "luks-root"
FIRST_BOOT_MARKER = "/var/lib/first-boot-complete"
DEFAULT_PASSWORD = "max"

class ConsoleOutput:
    """Simple console output handler with colors"""
    COLORS = {
        'DEBUG': '\033[36m', 
        'INFO': '\033[32m', 
        'WARNING': '\033[33m',
        'ERROR': '\033[31m', 
        'CRITICAL': '\033[41m', 
        'RESET': '\033[0m'
    }

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def debug(self, message: str) -> None:
        """Print debug message"""
        if self.verbose:
            self._print('DEBUG', message, self.COLORS['DEBUG'])

    def info(self, message: str) -> None:
        """Print info message"""
        self._print('INFO', message, self.COLORS['INFO'])

    def warning(self, message: str) -> None:
        """Print warning message"""
        self._print('WARNING', message, self.COLORS['WARNING'], sys.stderr)

    def error(self, message: str) -> None:
        """Print error message and exit"""
        self._print('ERROR', message, self.COLORS['ERROR'], sys.stderr)
        sys.exit(1)

    def _print(self, level: str, message: str, color: Optional[str] = None, 
              file=sys.stdout) -> None:
        """Internal print handler"""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        print(f"{color}{timestamp} [{level}] {message}{self.COLORS['RESET']}" 
              if color else f"{timestamp} [{level}] {message}", file=file)

def run_command(cmd: str, check: bool = True, capture_output: bool = True) -> subprocess.CompletedProcess:
    """Execute shell command with error handling"""
    console.debug(f"Executing: {cmd}")
    try:
        result = subprocess.run(
            cmd, shell=True, check=check,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            text=True, executable='/bin/bash'
        )
        if capture_output and result.stdout:
            console.debug(f"Output: {result.stdout.strip()}")
        if capture_output and result.stderr:
            console.debug(f"Stderr: {result.stderr.strip()}")
        return result
    except subprocess.CalledProcessError as e:
        error_msg = f"Command failed ({e.returncode}): {cmd}\n{e.stderr.strip() if e.stderr else 'No stderr output'}"
        if check:
            console.error(error_msg)
        raise

def parse_arguments() -> argparse.Namespace:
    """Parse and validate command line arguments"""
    parser = argparse.ArgumentParser(
        description="Configure custom Ubuntu image for first boot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Example:
  sudo ./first-boot-config.py \\
    --image ubuntu.img \\
    --hostname myserver \\
    --sshkey ~/.ssh/id_rsa.pub \\
    --netplan config.yaml"""
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

def validate_environment() -> None:
    """Check environment and ensure password consistency"""
    console.info("Setting both root and ec2-user passwords to 'max'")
    os.environ['ROOT_PASSWORD'] = DEFAULT_PASSWORD
    os.environ['EC2_USER_PASSWORD'] = DEFAULT_PASSWORD

    if os.geteuid() != 0:
        console.error("This script must be run as root")

def cleanup() -> None:
    """Clean up mounted resources and temporary devices"""
    console.info("Performing cleanup...")
    
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
                console.debug(f"Unmounted {mount}")
            except Exception as e:
                console.warning(f"Failed to unmount {mount}: {str(e)}")
    
    if Path(f"/dev/mapper/{CRYPT_NAME}").exists():
        try:
            run_command(f"cryptsetup luksClose {CRYPT_NAME}", check=False)
            console.debug("Closed LUKS container")
        except Exception as e:
            console.warning(f"Failed to close LUKS container: {str(e)}")
    
    if 'LOOP_DEVICE' in globals() and LOOP_DEVICE:
        try:
            run_command(f"losetup -d {LOOP_DEVICE}", check=False)
            console.debug(f"Released loop device {LOOP_DEVICE}")
        except Exception as e:
            console.warning(f"Failed to release loop device: {str(e)}")

def mount_image(image_path: str) -> None:
    """Mount disk image partitions including LUKS encrypted volumes"""
    global LOOP_DEVICE
    console.info(f"Mounting image: {image_path}")
    
    if not Path(image_path).exists():
        console.error(f"Image file not found: {image_path}")

    try:
        result = run_command(f"losetup --partscan --find --show {image_path}")
        LOOP_DEVICE = result.stdout.strip()
        console.info(f"Using loop device: {LOOP_DEVICE}")
    except Exception as e:
        console.error(f"Failed to setup loop device: {str(e)}")

    Path(MOUNT_BOOT).mkdir(parents=True, exist_ok=True)
    Path(MOUNT_ROOT).mkdir(parents=True, exist_ok=True)

    try:
        run_command(f"mount -t ext4 {LOOP_DEVICE}p2 {MOUNT_BOOT}")
        
        keyfile = f"{MOUNT_BOOT}/root_crypt.key"
        if not Path(keyfile).exists():
            console.error(f"LUKS keyfile missing: {keyfile}")
        
        run_command(f"cryptsetup luksOpen --key-file={keyfile} {LOOP_DEVICE}p3 {CRYPT_NAME}")
        run_command(f"mount /dev/mapper/{CRYPT_NAME} {MOUNT_ROOT}")
        run_command(f"mount -t ext4 {LOOP_DEVICE}p2 {MOUNT_ROOT}/boot")
        run_command(f"mount {LOOP_DEVICE}p1 {MOUNT_ROOT}/boot/efi")
        
    except Exception as e:
        console.error(f"Mounting failed: {str(e)}")

def prepare_machine_id() -> None:
    """Clear machine-id to trigger regeneration on first boot"""
    console.info("Preparing machine-id for regeneration")
    
    machine_id_file = Path(f"{MOUNT_ROOT}/etc/machine-id")
    dbus_machine_id = Path(f"{MOUNT_ROOT}/var/lib/dbus/machine-id")
    
    try:
        if machine_id_file.exists():
            console.debug("Clearing /etc/machine-id")
            machine_id_file.write_text("")
            machine_id_file.chmod(0o444)
        
        if dbus_machine_id.exists():
            console.debug("Updating DBus machine-id symlink")
            dbus_machine_id.unlink()
            dbus_machine_id.symlink_to("/etc/machine-id")
    except Exception as e:
        console.warning(f"Failed to prepare machine-id: {str(e)}")

def configure_system() -> None:
    """Perform base system configuration"""
    console.info("Configuring base system...")
    
    prepare_machine_id()
    
    try:
        run_command(f"echo 'root:{DEFAULT_PASSWORD}' | chroot {MOUNT_ROOT} chpasswd")
        console.debug("Root password set successfully")
        
        required_dirs = [
            f"{MOUNT_ROOT}/etc/netplan",
            f"{MOUNT_ROOT}/etc/cloud/cloud.cfg.d",
            f"{MOUNT_ROOT}/usr/local/bin",
            f"{MOUNT_ROOT}/var/lib"
        ]
        
        for dir_path in required_dirs:
            Path(dir_path).mkdir(parents=True, exist_ok=True)
            console.debug(f"Created directory: {dir_path}")
            
        for netplan_file in Path(f"{MOUNT_ROOT}/etc/netplan").glob("*.yaml"):
            netplan_file.unlink()
            console.debug(f"Removed default netplan file: {netplan_file}")
            
    except Exception as e:
        console.error(f"System configuration failed: {str(e)}")

def setup_netplan_service() -> None:
    """Configure Netplan apply service"""
    console.info("Setting up Netplan service...")
    
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
        console.debug("Created netplan-apply.service")
        
        run_command(f"chroot {MOUNT_ROOT} systemctl enable netplan-apply.service")
        console.info("Netplan service enabled (will run on first boot)")
    except Exception as e:
        console.error(f"Failed to setup Netplan service: {str(e)}")

def setup_ssh(install_ssh: bool, gen_sshkeys: bool) -> None:
    """Configure SSH server with root login options"""
    if not install_ssh:
        console.info("Skipping SSH server installation as requested")
        return
        
    console.info("Configuring SSH server...")
    
    try:
        run_command(f"chroot {MOUNT_ROOT} apt-get update")
        run_command(f"chroot {MOUNT_ROOT} apt-get install -y openssh-server")
        run_command(f"chroot {MOUNT_ROOT} systemctl enable ssh")
        console.info("SSH server configured and enabled")
        
        if gen_sshkeys and not any(Path(f"{MOUNT_ROOT}/etc/ssh").glob("ssh_host_*")):
            console.info("Generating SSH host keys...")
            
            run_command(f"mount -t proc proc {MOUNT_ROOT}/proc")
            run_command(f"mount -t sysfs sys {MOUNT_ROOT}/sys")
            run_command(f"mount -o bind /dev {MOUNT_ROOT}/dev")
            
            run_command(f"chroot {MOUNT_ROOT} dpkg-reconfigure openssh-server")
            
            run_command(f"umount {MOUNT_ROOT}/dev")
            run_command(f"umount {MOUNT_ROOT}/sys")
            run_command(f"umount {MOUNT_ROOT}/proc")
            
            console.info("SSH host keys generated")
            
    except Exception as e:
        console.error(f"SSH configuration failed: {str(e)}")

def create_first_boot_script() -> str:
    """Generate the first-boot script content"""
    return f"""#!/usr/bin/env python3

import os
import subprocess
import shutil
import time
from pathlib import Path

DEFAULT_PASSWORD = "{DEFAULT_PASSWORD}"

def setup_hostname() -> None:
    try:
        hostname_file = Path("/boot/hostname")
        if hostname_file.exists():
            with hostname_file.open() as f:
                new_hostname = f.read().strip()
            
            if new_hostname:
                subprocess.run(['hostnamectl', 'set-hostname', new_hostname], check=True)
                
                with open("/etc/hostname", "w") as f:
                    f.write(f"{{new_hostname}}\\n")
                
                hosts_file = Path("/etc/hosts")
                if hosts_file.exists():
                    hosts_content = hosts_file.read_text()
                    if "127.0.1.1" in hosts_content:
                        new_hosts = []
                        for line in hosts_content.splitlines():
                            if line.startswith("127.0.1.1"):
                                new_hosts.append(f"127.0.1.1\\t{{new_hostname}}")
                            else:
                                new_hosts.append(line)
                        hosts_file.write_text("\\n".join(new_hosts) + "\\n")
                
                print(f"Hostname set to: {{new_hostname}}")
    except Exception as e:
        print(f"Error setting hostname: {{str(e)}}")

def setup_ec2_user() -> None:
    try:
        if not Path("/home/ec2-user").exists():
            subprocess.run([
                'useradd',
                '-m',
                '-s', '/bin/bash',
                'ec2-user'
            ], check=True)
            print("Created ec2-user account")
            
        subprocess.run([
            'chpasswd',
        ], input=f'ec2-user:{DEFAULT_PASSWORD}', encoding='utf-8', check=True)
        
        print("Set password for ec2-user")
        
        ssh_key_src = "/boot/ssh_key"
        ssh_key_dest = "/home/ec2-user/.ssh/authorized_keys"
            
        if Path(ssh_key_src).exists():
            Path(ssh_key_dest).parent.mkdir(exist_ok=True, mode=0o700)
            shutil.copy2(ssh_key_src, ssh_key_dest)
            Path(ssh_key_dest).chmod(0o600)
            subprocess.run(['chown', '-R', 'ec2-user:ec2-user', '/home/ec2-user/.ssh'], check=True)
            print("Configured SSH key for ec2-user")
                    
    except Exception as e:
        print(f"Error in ec2-user setup: {{str(e)}}")

def copy_config_files() -> None:
    try:
        Path("/etc/cloud/cloud.cfg.d").mkdir(parents=True, exist_ok=True)
        Path("/etc/netplan/").mkdir(parents=True, exist_ok=True)
        
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
                print(f"Copied config file: {{src}} to {{dest}}")
    except Exception as e:
        print(f"Error copying config files: {{str(e)}}")

def main() -> None:
    print("Starting first boot configuration")
    setup_hostname()
    setup_ec2_user()
    copy_config_files()
    
    Path("{FIRST_BOOT_MARKER}").touch()
    print("First boot configuration completed successfully")

if __name__ == "__main__":
    main()
"""

def create_first_boot_service() -> None:
    """Create first-boot oneshot service"""
    console.info("Creating first-boot service...")
    
    service_path = Path(f"{MOUNT_ROOT}/etc/systemd/system/first-boot-config.service")
    script_path = Path(f"{MOUNT_ROOT}/usr/local/bin/first-boot-config.py")
    
    try:
        service_path.write_text("""\
[Unit]
Description=First Boot Configuration
After=local-fs.target
Requires=local-fs.target

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
        console.debug("Created first-boot service unit file")
        
        script_content = create_first_boot_script()
        script_path.write_text(script_content)
        script_path.chmod(0o755)
        console.debug("Created first-boot script")
        
        run_command(f"chroot {MOUNT_ROOT} systemctl enable first-boot-config.service")
        console.info("First-boot service configured and enabled")
        
    except Exception as e:
        console.error(f"Failed to create first-boot service: {str(e)}")

def copy_config_files(args: argparse.Namespace) -> None:
    """Copy configuration files to image"""
    console.info("Copying configuration files...")
    
    try:
        if args.hostname:
            hostname_file = Path(f"{MOUNT_BOOT}/hostname")
            hostname_file.write_text(args.hostname)
            console.debug(f"Set hostname to: {args.hostname}")
        
        if args.sshkey:
            sshkey_path = Path(args.sshkey)
            if sshkey_path.exists():
                shutil.copy(sshkey_path, f"{MOUNT_BOOT}/ssh_key")
                console.debug(f"Copied SSH key from: {args.sshkey}")
        
        if args.netplan:
            netplan_path = Path(args.netplan)
            if netplan_path.exists():
                shutil.copy(netplan_path, f"{MOUNT_BOOT}/config.yaml")
                console.debug(f"Copied Netplan config from: {args.netplan}")
        
        disable_net_config = Path(f"{MOUNT_BOOT}/99-disable-network-config.cfg")
        disable_net_config.write_text("network: {config: disabled}\n")
        console.debug("Disabled cloud-init network configuration")
        
    except Exception as e:
        console.error(f"Failed to copy configuration files: {str(e)}")

def print_summary(args: argparse.Namespace) -> None:
    """Print configuration summary"""
    console.info("\nConfiguration Summary:")
    console.info(f"• Hostname: {args.hostname or '(not set)'}")
    console.info(f"• SSH Server: {'enabled' if args.install_ssh else 'disabled'}")
    console.info(f"• SSH Host Keys: {'generated' if args.gen_sshkeys else 'skipped'}")
    console.info(f"• Netplan Config: {'custom' if args.netplan else 'default'}")
    console.info("• Both root and ec2-user passwords set to 'max'")
    console.info("• First-boot service configured to complete setup")

def main() -> None:
    global console, LOOP_DEVICE
    
    if not os.access(__file__, os.X_OK):
        os.chmod(__file__, 0o755)
    
    args = parse_arguments()
    console = ConsoleOutput(verbose=args.verbose)
    
    try:
        validate_environment()
        
        if not Path(args.image).exists():
            console.error(f"Image not found: {args.image}")
        
        mount_image(args.image)
        configure_system()
        setup_netplan_service()
        setup_ssh(args.install_ssh, args.gen_sshkeys)
        create_first_boot_service()
        copy_config_files(args)
        
        print_summary(args)
        
    except KeyboardInterrupt:
        console.info("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        console.error(f"\nScript failed: {str(e)}")
        sys.exit(1)
    finally:
        cleanup()
        console.info("Cleanup completed")

if __name__ == "__main__":
    main()
