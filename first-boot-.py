#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
First Boot Configuration Script with Simplified Password Handling

Key Changes:
- Sets both root and ec2-user passwords to 'max'
- Removes strict password complexity checks
- Doesn't force password change on first login
- Handles all required file copies from /boot to their destinations
- Applies Netplan configuration automatically
- Sets DNS servers in chroot environment
- Improved directory and file creation handling
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

# File copy mappings (source: destination)
FILE_COPIES = {
    "/boot/99-disable-network-config.cfg": "/etc/cloud/cloud.cfg.d/",
    "/boot/ds-identify.cfg": "/etc/cloud/",
    "/boot/10_tinkerbell.cfg": "/etc/cloud/cloud.cfg.d/",
    "/boot/config.yaml": "/etc/netplan/",
    "/boot/ssh_key": "/home/ec2-user/.ssh/authorized_keys"
}

def print_message(level, message):
    """Simple print-based message handler"""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    print(f"{timestamp} [{level}] {message}")
    with open(LOG_FILE, 'a') as f:
        f.write(f"{timestamp} [{level}] {message}\n")

def run_command(cmd, check=True):
    """Execute shell command with comprehensive error handling"""
    print_message("DEBUG", f"Executing: {cmd}")
    try:
        result = subprocess.run(
            cmd, shell=True, check=check,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, executable='/bin/bash'
        )
        if result.stdout:
            print_message("DEBUG", f"Output: {result.stdout}")
        if result.stderr:
            print_message("DEBUG", f"Stderr: {result.stderr}")
        return result
    except subprocess.CalledProcessError as e:
        error_msg = f"Command failed ({e.returncode}): {cmd}\n{e.stderr}"
        if check:
            print_message("ERROR", error_msg)
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
    """Check environment - passwords will be set to 'max' regardless of env vars"""
    print_message("INFO", "Setting both root and ec2-user passwords to 'max'")
    # Override any environment variables that might be set
    os.environ['ROOT_PASSWORD'] = DEFAULT_PASSWORD
    os.environ['EC2_USER_PASSWORD'] = DEFAULT_PASSWORD

def cleanup():
    """Clean up mounted resources and temporary devices"""
    print_message("INFO", "Performing cleanup...")
    
    for mount in [f"{MOUNT_ROOT}/boot/efi", f"{MOUNT_ROOT}/boot", 
                 MOUNT_ROOT, MOUNT_BOOT]:
        if Path(mount).is_mount():
            run_command(f"umount {mount}", check=False)
    
    if Path(f"/dev/mapper/{CRYPT_NAME}").exists():
        run_command(f"cryptsetup luksClose {CRYPT_NAME}", check=False)
    
    if 'LOOP_DEVICE' in globals() and LOOP_DEVICE:
        run_command(f"losetup -d {LOOP_DEVICE}", check=False)

def mount_image(image_path):
    """Mount disk image partitions including LUKS encrypted volumes"""
    global LOOP_DEVICE
    print_message("INFO", f"Mounting image: {image_path}")
    
    if not Path(image_path).exists():
        print_message("ERROR", f"Image file not found: {image_path}")

    # Ensure mount points exist
    Path(MOUNT_BOOT).mkdir(parents=True, exist_ok=True)
    Path(MOUNT_ROOT).mkdir(parents=True, exist_ok=True)

    LOOP_DEVICE = run_command(f"losetup --partscan --find --show {image_path}").stdout.strip()
    print_message("INFO", f"Using loop device: {LOOP_DEVICE}")

    run_command(f"mount -t ext4 {LOOP_DEVICE}p2 {MOUNT_BOOT}")

    keyfile = f"{MOUNT_BOOT}/root_crypt.key"
    if not Path(keyfile).exists():
        print_message("ERROR", f"LUKS keyfile missing: {keyfile}")

    run_command(f"cryptsetup luksOpen --key-file={keyfile} {LOOP_DEVICE}p3 {CRYPT_NAME}")
    run_command(f"mount /dev/mapper/{CRYPT_NAME} {MOUNT_ROOT}")
    run_command(f"mount -t ext4 {LOOP_DEVICE}p2 {MOUNT_ROOT}/boot")
    run_command(f"mount {LOOP_DEVICE}p1 {MOUNT_ROOT}/boot/efi")

def prepare_machine_id():
    """Clear machine-id to trigger regeneration on first boot"""
    print_message("INFO", "Preparing machine-id for regeneration")
    
    machine_id_file = Path(f"{MOUNT_ROOT}/etc/machine-id")
    dbus_machine_id = Path(f"{MOUNT_ROOT}/var/lib/dbus/machine-id")
    
    if machine_id_file.exists():
        print_message("DEBUG", "Clearing /etc/machine-id")
        machine_id_file.write_text("")
        machine_id_file.chmod(0o444)
    
    if dbus_machine_id.exists():
        print_message("DEBUG", "Updating DBus machine-id symlink")
        dbus_machine_id.unlink()
        dbus_machine_id.symlink_to("/etc/machine-id")

def ensure_resolv_conf():
    """Ensure resolv.conf exists with default DNS servers"""
    resolv_conf = Path(f"{MOUNT_ROOT}/etc/resolv.conf")
    resolv_conf.parent.mkdir(parents=True, exist_ok=True)
    
    if not resolv_conf.exists():
        print_message("DEBUG", "Creating /etc/resolv.conf with default DNS servers")
        resolv_conf.write_text("nameserver 8.8.8.8\nnameserver 8.8.4.4\n")
    else:
        print_message("DEBUG", "/etc/resolv.conf already exists")

def configure_system():
    """Perform base system configuration"""
    print_message("INFO", "Configuring base system...")
    
    prepare_machine_id()
    ensure_resolv_conf()  # Ensure resolv.conf exists before chroot operations
    
    # Set root password to 'max' without forcing change
    run_command(f"echo 'root:{DEFAULT_PASSWORD}' | chroot {MOUNT_ROOT} chpasswd")
    
    # Create required directories
    required_dirs = [
        f"{MOUNT_ROOT}/etc/netplan",
        f"{MOUNT_ROOT}/etc/cloud/cloud.cfg.d",
        f"{MOUNT_ROOT}/usr/local/bin",
        f"{MOUNT_ROOT}/var/lib",
        f"{MOUNT_ROOT}/home/ec2-user/.ssh"
    ]
    
    for dir_path in required_dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        print_message("DEBUG", f"Created directory: {dir_path}")

    # Clean up default Netplan configurations
    for netplan_file in Path(f"{MOUNT_ROOT}/etc/netplan").glob("*.yaml"):
        netplan_file.unlink()
        print_message("DEBUG", f"Removed default Netplan file: {netplan_file}")

def setup_netplan_service():
    """Configure Netplan apply service"""
    print_message("INFO", "Setting up Netplan service...")
    
    service_path = Path(f"{MOUNT_ROOT}/etc/systemd/system/netplan-apply.service")
    service_path.write_text("""\
[Unit]
Description=Apply Netplan configuration
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/netplan apply

[Install]
WantedBy=multi-user.target
""")
    
    run_command(f"chroot {MOUNT_ROOT} systemctl enable netplan-apply.service")
    print_message("INFO", "Netplan service enabled (will run on first boot)")

def setup_ssh(install_ssh, gen_sshkeys):
    """Configure SSH server with root login options"""
    if install_ssh:
        print_message("INFO", "Configuring SSH server...")
        
        # Mount required filesystems for chroot
        print_message("DEBUG", "Mounting special filesystems for chroot")
        run_command(f"mount -t proc proc {MOUNT_ROOT}/proc")
        run_command(f"mount -t sysfs sys {MOUNT_ROOT}/sys")
        run_command(f"mount -o bind /dev {MOUNT_ROOT}/dev")
        run_command(f"mount -o bind /dev/pts {MOUNT_ROOT}/dev/pts")
        
        try:
            # First install essential packages for package management
            print_message("DEBUG", "Installing base packages")
            run_command(f"chroot {MOUNT_ROOT} apt-get update --allow-unauthenticated -qq")
            run_command(f"chroot {MOUNT_ROOT} apt-get install -y --allow-unauthenticated gpgv2 apt-utils")
            
            # Now do the regular update and install
            print_message("DEBUG", "Running apt-get update")
            run_command(f"chroot {MOUNT_ROOT} apt-get update")
            print_message("DEBUG", "Installing openssh-server")
            run_command(f"chroot {MOUNT_ROOT} apt-get install -y openssh-server")
            
            # Enable root login and password auth
            sshd_config = Path(f"{MOUNT_ROOT}/etc/ssh/sshd_config")
            if sshd_config.exists():
                content = sshd_config.read_text()
                content = content.replace("#PermitRootLogin", "PermitRootLogin")
                content = content.replace("#PasswordAuthentication", "PasswordAuthentication")
                content = content.replace("PermitRootLogin no", "PermitRootLogin yes")
                content = content.replace("PasswordAuthentication no", "PasswordAuthentication yes")
                sshd_config.write_text(content)
                
                # Backup original config
                sshd_config.with_name("sshd_config.original").write_text(content)
                print_message("DEBUG", "SSH config backup created")
            
            run_command(f"chroot {MOUNT_ROOT} systemctl enable ssh")
            
        finally:
            # Always unmount the special filesystems
            print_message("DEBUG", "Unmounting special filesystems")
            run_command(f"umount {MOUNT_ROOT}/dev/pts", check=False)
            run_command(f"umount {MOUNT_ROOT}/dev", check=False)
            run_command(f"umount {MOUNT_ROOT}/sys", check=False)
            run_command(f"umount {MOUNT_ROOT}/proc", check=False)
    
    if gen_sshkeys and not any(Path(f"{MOUNT_ROOT}/etc/ssh").glob("ssh_host_*")):
        print_message("INFO", "Generating SSH host keys...")
        run_command(f"mount -t proc proc {MOUNT_ROOT}/proc")
        run_command(f"mount -t sysfs sys {MOUNT_ROOT}/sys")
        run_command(f"mount -o bind /dev {MOUNT_ROOT}/dev")
        
        try:
            run_command(f"chroot {MOUNT_ROOT} dpkg-reconfigure openssh-server")
        finally:
            run_command(f"umount {MOUNT_ROOT}/dev", check=False)
            run_command(f"umount {MOUNT_ROOT}/sys", check=False)
            run_command(f"umount {MOUNT_ROOT}/proc", check=False)

def create_first_boot_service():
    """Create first-boot oneshot service with comprehensive setup"""
    print_message("INFO", "Creating first-boot service...")
    
    service_path = Path(f"{MOUNT_ROOT}/etc/systemd/system/first-boot-config.service")
    service_path.write_text(f"""\
[Unit]
Description=First Boot Configuration
After=systemd-journald.service
Before=systemd-networkd.service network-pre.target
Wants=systemd-journald.service
Conflicts=shutdown.target
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 /usr/local/bin/first-boot-config.py
ExecStartPost=/bin/touch {FIRST_BOOT_MARKER}
TimeoutSec=300
StandardOutput=journal
StandardError=journal
SyslogIdentifier=first-boot

[Install]
WantedBy=multi-user.target
""")
    
    script_path = Path(f"{MOUNT_ROOT}/usr/local/bin/first-boot-config.py")
    script_content = f"""#!/usr/bin/env python3

import os
import subprocess
import time
import shutil
from pathlib import Path

DEFAULT_PASSWORD = "{DEFAULT_PASSWORD}"

def log_journal(message, level='info'):
    subprocess.run(['logger', '-t', 'first-boot', '-p', f'user.{{level}}', message], check=False)

def copy_files():
    \"\"\"Handle all required file copies from /boot to their destinations\"\"\"
    file_copies = {{
        "/boot/99-disable-network-config.cfg": "/etc/cloud/cloud.cfg.d/",
        "/boot/ds-identify.cfg": "/etc/cloud/",
        "/boot/10_tinkerbell.cfg": "/etc/cloud/cloud.cfg.d/",
        "/boot/config.yaml": "/etc/netplan/",
        "/boot/ssh_key": "/home/ec2-user/.ssh/authorized_keys"
    }}
    
    for src, dst in file_copies.items():
        try:
            if not Path(src).exists():
                log_journal(f"Source file not found: {{src}}", 'warning')
                continue
                
            # Create destination directory if needed
            if dst.endswith('/'):
                Path(dst).mkdir(parents=True, exist_ok=True)
                full_dst = os.path.join(dst, os.path.basename(src))
            else:
                Path(dst).parent.mkdir(parents=True, exist_ok=True)
                full_dst = dst
                
            shutil.copy2(src, full_dst)
            
            # Special handling for authorized_keys
            if "authorized_keys" in dst:
                Path(full_dst).chmod(0o600)
                subprocess.run(['chown', 'ec2-user:ec2-user', full_dst], check=True)
                
            log_journal(f"Copied {{src}} to {{full_dst}}")
            
        except Exception as e:
            log_journal(f"Failed to copy {{src}} to {{dst}}: {{str(e)}}", 'err')

def apply_netplan():
    \"\"\"Apply the Netplan configuration if available\"\"\"
    netplan_file = "/boot/config.yaml"
    if Path(netplan_file).exists():
        try:
            # Copy to /etc/netplan if it's not already there
            if not Path("/etc/netplan/config.yaml").exists():
                shutil.copy2(netplan_file, "/etc/netplan/config.yaml")
            
            # Apply the configuration
            subprocess.run(['netplan', 'apply'], check=True)
            log_journal("Successfully applied Netplan configuration")
        except Exception as e:
            log_journal(f"Failed to apply Netplan: {{str(e)}}", 'err')

def setup_ec2_user():
    try:
        # Check if ec2-user exists
        result = subprocess.run(['id', 'ec2-user'], 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE)
        
        if result.returncode != 0:
            # Create ec2-user with password 'max'
            subprocess.run([
                'useradd',
                '-m',
                '-s', '/bin/bash',
                'ec2-user'
            ], check=True)
            log_journal("Created ec2-user account")
            
            # Set password to 'max'
            subprocess.run([
                'echo',
                f'ec2-user:{DEFAULT_PASSWORD}',
                '|', 'chpasswd'
            ], check=True)
            log_journal("Set password for ec2-user")
        
        # Ensure .ssh directory exists with correct permissions
        ssh_dir = "/home/ec2-user/.ssh"
        Path(ssh_dir).mkdir(exist_ok=True, mode=0o700)
        subprocess.run(['chown', 'ec2-user:ec2-user', ssh_dir], check=True)
                
    except Exception as e:
        log_journal(f"Error in ec2-user setup: {{str(e)}}", 'err')

def main():
    log_journal("Starting first boot configuration")
    
    # Perform all required operations
    setup_ec2_user()
    copy_files()
    apply_netplan()
    
    log_journal("First boot configuration completed")

if __name__ == "__main__":
    main()
"""
    
    script_path.write_text(script_content)
    script_path.chmod(0o755)
    
    run_command(f"chroot {MOUNT_ROOT} systemctl enable first-boot-config.service")
    print_message("INFO", "First-boot service configured")

def copy_config_files(args):
    """Copy configuration files to image with validation"""
    print_message("INFO", "Copying configuration files...")
    
    if args.hostname:
        Path(f"{MOUNT_BOOT}/hostname").write_text(args.hostname)
        print_message("DEBUG", f"Set hostname to: {args.hostname}")
    
    if args.sshkey:
        if Path(args.sshkey).exists():
            shutil.copy(args.sshkey, f"{MOUNT_BOOT}/ssh_key")
            print_message("DEBUG", f"Copied SSH key from: {args.sshkey}")
        else:
            print_message("WARNING", f"SSH key not found: {args.sshkey}")
    
    if args.netplan:
        if Path(args.netplan).exists():
            shutil.copy(args.netplan, f"{MOUNT_BOOT}/config.yaml")
            print_message("DEBUG", f"Copied Netplan config from: {args.netplan}")
        else:
            print_message("WARNING", f"Netplan config not found: {args.netplan}")
    
    # Cloud-init network configuration
    Path(f"{MOUNT_BOOT}/99-disable-network-config.cfg").write_text(
        "network: {config: disabled}\n")
    print_message("DEBUG", "Disabled cloud-init network configuration")

def main():
    global LOOP_DEVICE
    
    if not os.access(__file__, os.X_OK):
        os.chmod(__file__, 0o755)
    
    args = parse_arguments()
    
    try:
        validate_environment()
        
        if not Path(args.image).exists():
            print_message("ERROR", f"Image not found: {args.image}")
        
        mount_image(args.image)
        configure_system()
        setup_netplan_service()
        setup_ssh(args.install_ssh, args.gen_sshkeys)
        create_first_boot_service()
        copy_config_files(args)
        
        print_message("INFO", "\nConfiguration Summary:")
        print_message("INFO", f"• Hostname: {args.hostname or '(not set)'}")
        print_message("INFO", f"• SSH Server: {'enabled' if args.install_ssh else 'disabled'}")
        print_message("INFO", f"• SSH Host Keys: {'generated' if args.gen_sshkeys else 'skipped'}")
        print_message("INFO", f"• Netplan Config: {'custom' if args.netplan else 'default'}")
        print_message("INFO", "• Root SSH login: enabled")
        print_message("INFO", "• Both root and ec2-user passwords set to 'max'")
        print_message("INFO", "• Machine-ID will be regenerated on first boot")
        print_message("INFO", "• File copies configured:")
        for src, dst in FILE_COPIES.items():
            print_message("INFO", f"  - {src} → {dst}")
        
    except KeyboardInterrupt:
        print_message("INFO", "Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print_message("ERROR", f"Script failed: {str(e)}")
        sys.exit(1)
    finally:
        cleanup()

if __name__ == "__main__":
    main()
