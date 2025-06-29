#!/usr/bin/env python3

"""
First Boot Configuration Script

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

class ConsoleLogger:
    """Colorized console logger"""
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'RESET': '\033[0m'      # Reset
    }

    def __init__(self, verbose=False):
        self.verbose = verbose

    def debug(self, message):
        if self.verbose:
            print(f"{self.COLORS['DEBUG']}[DEBUG] {message}{self.COLORS['RESET']}")

    def info(self, message):
        print(f"{self.COLORS['INFO']}[INFO] {message}{self.COLORS['RESET']}")

    def warning(self, message):
        print(f"{self.COLORS['WARNING']}[WARNING] {message}{self.COLORS['RESET']}",
              file=sys.stderr)

    def error(self, message):
        print(f"{self.COLORS['ERROR']}[ERROR] {message}{self.COLORS['RESET']}",
              file=sys.stderr)
        sys.exit(1)

def run_command(cmd, check=True, capture_output=True):
    """Execute shell command with error handling"""
    logger.debug(f"Executing: {cmd}")
    
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
        
        if logger.verbose and result.stdout:
            logger.debug(f"Output:\n{result.stdout}")
        if result.stderr:
            logger.debug(f"Stderr:\n{result.stderr}")
            
        return result.stdout.strip() if capture_output else None
        
    except subprocess.CalledProcessError as e:
        error_msg = f"Command failed ({e.returncode}): {cmd}\n{e.stderr}"
        if check:
            logger.error(error_msg)
        else:
            logger.warning(error_msg)
            return None

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Configure custom Ubuntu image for first boot",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("--image", default=DEFAULT_IMAGE,
                      help=f"Disk image path (default: {DEFAULT_IMAGE})")
    parser.add_argument("--hostname", help="System hostname")
    parser.add_argument("--sshkey", help="SSH public key path for ec2-user")
    parser.add_argument("--netplan", help="Custom Netplan config file")
    parser.add_argument("--no-ssh", action="store_false", dest="install_ssh",
                      help="Skip SSH server installation")
    parser.add_argument("--no-sshkeys", action="store_false", dest="gen_sshkeys",
                      help="Skip SSH host key generation")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    return parser.parse_args()

def validate_environment():
    """Check required environment variables"""
    required_vars = ['ROOT_PASSWORD', 'EC2_USER_PASSWORD']
    missing = [var for var in required_vars if not os.getenv(var)]
    
    if missing:
        logger.error(f"Missing environment variables: {', '.join(missing)}")

def cleanup():
    """Clean up mounted resources"""
    logger.info("Cleaning up resources...")
    
    # Unmount in reverse order
    for mount in [
        f"{MOUNT_ROOT}/boot/efi",
        f"{MOUNT_ROOT}/boot",
        MOUNT_ROOT,
        MOUNT_BOOT
    ]:
        if Path(mount).is_mount():
            run_command(f"umount {mount}", check=False)
    
    # Close LUKS container
    if Path(f"/dev/mapper/{CRYPT_NAME}").exists():
        run_command(f"cryptsetup luksClose {CRYPT_NAME}", check=False)
    
    # Detach loop device
    if 'LOOP_DEVICE' in globals() and LOOP_DEVICE:
        run_command(f"losetup -d {LOOP_DEVICE}", check=False)

def mount_image(image_path):
    """Mount disk image partitions"""
    global LOOP_DEVICE
    
    logger.info(f"Mounting image: {image_path}")
    
    # Setup loop device
    LOOP_DEVICE = run_command(f"losetup --partscan --find --show {image_path}")
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

def configure_system():
    """Basic system configuration"""
    logger.info("Configuring system...")
    
    # Reset machine-id
    machine_id = Path(f"{MOUNT_ROOT}/etc/machine-id")
    if machine_id.exists():
        machine_id.unlink()
    machine_id.touch()
    
    # Set root password
    root_pass = os.getenv("ROOT_PASSWORD")
    run_command(f"echo 'root:{root_pass}' | chroot {MOUNT_ROOT} chpasswd")
    run_command(f"chroot {MOUNT_ROOT} passwd -e root")
    
    # Create required directories
    for dir_path in [
        f"{MOUNT_ROOT}/etc/netplan",
        f"{MOUNT_ROOT}/etc/cloud/cloud.cfg.d",
        f"{MOUNT_ROOT}/usr/local/bin",
        f"{MOUNT_ROOT}/var/lib"
    ]:
        Path(dir_path).mkdir(parents=True, exist_ok=True)

def setup_ssh(install_ssh, gen_sshkeys):
    """Configure SSH server"""
    if install_ssh:
        logger.info("Configuring SSH server...")
        run_command(f"chroot {MOUNT_ROOT} apt-get update")
        run_command(f"chroot {MOUNT_ROOT} apt-get install -y openssh-server")
        
        # Enable password auth
        sshd_config = Path(f"{MOUNT_ROOT}/etc/ssh/sshd_config")
        content = sshd_config.read_text()
        content = content.replace("#PasswordAuthentication yes", "PasswordAuthentication yes")
        sshd_config.write_text(content)
        
        run_command(f"chroot {MOUNT_ROOT} systemctl enable ssh")
    
    if gen_sshkeys and not any(Path(f"{MOUNT_ROOT}/etc/ssh").glob("ssh_host_*")):
        logger.info("Generating SSH host keys...")
        run_command(f"mount -t proc proc {MOUNT_ROOT}/proc")
        run_command(f"mount -t sysfs sys {MOUNT_ROOT}/sys")
        run_command(f"mount -o bind /dev {MOUNT_ROOT}/dev")
        
        run_command(f"chroot {MOUNT_ROOT} dpkg-reconfigure openssh-server")
        
        run_command(f"umount {MOUNT_ROOT}/dev")
        run_command(f"umount {MOUNT_ROOT}/sys")
        run_command(f"umount {MOUNT_ROOT}/proc")

def create_first_boot_service():
    """Create first-boot oneshot service with Python config"""
    logger.info("Creating first-boot service...")
    
    # Service file
    service_path = Path(f"{MOUNT_ROOT}/etc/systemd/system/first-boot-config.service")
    service_path.write_text(f"""\
[Unit]
Description=First Boot Configuration
After=network.target
ConditionPathExists=!{FIRST_BOOT_MARKER}

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/bin/first-boot-config.py
RemainAfterExit=yes
ExecStartPost=/bin/touch {FIRST_BOOT_MARKER}

[Install]
WantedBy=multi-user.target
""")
    
    # Python first-boot script
    script_path = Path(f"{MOUNT_ROOT}/usr/local/bin/first-boot-config.py")
    script_path.write_text("""\
#!/usr/bin/env python3

import os
import subprocess
import time
from pathlib import Path

def log(message):
    with open("/var/log/first-boot.log", "a") as f:
        f.write(f"{time.ctime()}: {message}\\n")

def check_network():
    log("Checking network connectivity...")
    for i in range(1, 11):
        try:
            subprocess.run(["ping", "-c1", "-W2", "8.8.8.8"], 
                          check=True, 
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
            log("Network is ready")
            return True
        except subprocess.CalledProcessError:
            log(f"Waiting for network... ({i}/10)")
            time.sleep(2)
    return False

def set_hostname():
    hostname_file = Path("/boot/hostname")
    if hostname_file.exists():
        hostname = hostname_file.read_text().strip()
        if hostname:
            log(f"Setting hostname: {hostname}")
            subprocess.run(["hostnamectl", "set-hostname", hostname], check=True)
            with open("/etc/hosts", "a") as f:
                f.write(f"127.0.1.1\\t{hostname}\\n")

def configure_network():
    config_file = Path("/boot/config.yaml")
    if config_file.exists():
        log("Applying network configuration")
        dest = Path("/etc/netplan/99-config.yaml")
        dest.write_text(config_file.read_text())
        subprocess.run(["netplan", "apply"], check=False)

def system_updates():
    log("Running system updates")
    subprocess.run(["apt-get", "update", "-qy"], check=True)
    subprocess.run(["apt-get", "upgrade", "-qy"], check=True)

def configure_ssh_key():
    ssh_key = Path("/boot/ssh_key")
    if ssh_key.exists():
        log("Configuring SSH key for ec2-user")
        ssh_dir = Path("/home/ec2-user/.ssh")
        ssh_dir.mkdir(exist_ok=True)
        ssh_key_dest = ssh_dir / "authorized_keys"
        ssh_key_dest.write_text(ssh_key.read_text())
        ssh_dir.chmod(0o700)
        ssh_key_dest.chmod(0o600)
        subprocess.run(["chown", "-R", "ec2-user:ec2-user", str(ssh_dir)], check=True)

def main():
    log("Starting first boot configuration")
    
    check_network()
    set_hostname()
    configure_network()
    system_updates()
    configure_ssh_key()
    
    log("First boot configuration completed")

if __name__ == "__main__":
    main()
""")
    script_path.chmod(0o755)
    
    # Enable service
    run_command(f"chroot {MOUNT_ROOT} systemctl enable first-boot-config.service")

def copy_config_files(args):
    """Copy configuration files to image"""
    logger.info("Copying config files...")
    
    if args.hostname:
        Path(f"{MOUNT_BOOT}/hostname").write_text(args.hostname)
    
    if args.sshkey and Path(args.sshkey).exists():
        shutil.copy(args.sshkey, f"{MOUNT_BOOT}/ssh_key")
    
    if args.netplan and Path(args.netplan).exists():
        shutil.copy(args.netplan, f"{MOUNT_BOOT}/config.yaml")
    else:
        Path(f"{MOUNT_ROOT}/etc/netplan/99-default.yaml").write_text("""\
network:
  version: 2
  renderer: networkd
  ethernets:
    match-en:
      match: {name: "en*"}
      dhcp4: true
""")
    
    # Disable cloud-init network config
    Path(f"{MOUNT_BOOT}/99-disable-network-config.cfg").write_text("network: {config: disabled}\n")

def main():
    global logger, LOOP_DEVICE
    
    args = parse_arguments()
    logger = ConsoleLogger(verbose=args.verbose)
    
    try:
        validate_environment()
        
        if not Path(args.image).exists():
            logger.error(f"Image not found: {args.image}")
        
        logger.info(f"Configuring image: {args.image}")
        mount_image(args.image)
        configure_system()
        setup_ssh(args.install_ssh, args.gen_sshkeys)
        create_first_boot_service()
        copy_config_files(args)
        
        logger.info("\nConfiguration complete. First boot will:")
        logger.info(f"• Set hostname: {args.hostname or '(not set)'}")
        logger.info(f"• SSH server: {'enabled' if args.install_ssh else 'disabled'}")
        logger.info(f"• SSH keys: {'generated' if args.gen_sshkeys else 'skipped'}")
        logger.info(f"• Network: {'custom' if args.netplan else 'default DHCP'}")
        
    except Exception as e:
        logger.error(f"Configuration failed: {str(e)}")
    finally:
        cleanup()

if __name__ == "__main__":
    main()
