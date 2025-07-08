#!/usr/bin/env python3
import os
import sys
import subprocess
import argparse
import tempfile
import shutil
import logging
from datetime import datetime
import time
import random
import string
import json
import hashlib

# === CONSTANTS ===
MAPPER_NAME = "root_crypt"
KEYFILE_NAME = "root_crypt.key"
KEYFILE_PATH = f"/boot/{KEYFILE_NAME}"
LUKS_HEADER_SIZE = 16 * 1024 * 1024  # 16 MiB for LUKS2
SECTOR_SIZE = 512
ALIGNMENT = 1 * 1024 * 1024  # 1 MiB alignment
DEFAULT_CIPHER = "aes-xts-plain64"
DEFAULT_KEY_SIZE = 512
DEFAULT_ROOT_RESIZE = 2  # Default root expansion in GB (increased from 1GB to 2GB)
DEBUG_LOG = "./encrypt_debug.log"

# === COLOR LOGGING ===
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'

# === LOGGING SYSTEM ===
def setup_logging(debug=False):
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s',
        handlers=[
            logging.FileHandler(DEBUG_LOG),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger()

logger = setup_logging()

def log(message):
    logger.info(f"{Colors.GREEN}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]{Colors.NC} {message}")

def debug(message):
    logger.debug(f"{Colors.CYAN}[DEBUG][{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]{Colors.NC} {message}")

def error(message, exit_code=1):
    logger.error(f"{Colors.RED}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ERROR:{Colors.NC} {message}")
    sys.exit(exit_code)

def warn(message):
    logger.warning(f"{Colors.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} WARN:{Colors.NC} {message}")

# === COMMAND EXECUTION ===
def run_command(cmd, check=True, capture_output=False, input_text=None):
    debug(f"Executing: {cmd}")
    try:
        result = subprocess.run(
            cmd,
            check=check,
            shell=isinstance(cmd, str),
            capture_output=capture_output,
            text=True,
            input=input_text
        )
        return result
    except subprocess.CalledProcessError as e:
        error(f"Command failed: {e.cmd}\nError: {e.stderr}", 1)

def sudo_command(cmd, **kwargs):
    if isinstance(cmd, str):
        cmd = f"sudo {cmd}"
    else:
        cmd = ["sudo"] + cmd
    return run_command(cmd, **kwargs)

# === CLEANUP HANDLING ===
class CleanupManager:
    def __init__(self):
        self.actions = []
        self.temp_files = []
        self.temp_dirs = []
        self.loop_devices = []
        self.mount_points = []
        self.mapped_devices = []
    
    def add_action(self, action):
        self.actions.append(action)
    
    def add_temp_file(self, path):
        self.temp_files.append(path)
    
    def add_temp_dir(self, path):
        self.temp_dirs.append(path)
    
    def add_loop_device(self, device):
        self.loop_devices.append(device)
    
    def add_mount_point(self, path):
        self.mount_points.append(path)
    
    def add_mapped_device(self, device):
        self.mapped_devices.append(device)
    
    def cleanup(self):
        debug("Executing cleanup procedures...")
        
        # Unmount in reverse order
        for mount_point in reversed(self.mount_points):
            debug(f"Unmounting {mount_point}")
            sudo_command(f"umount -R {mount_point}", check=False)
        
        # Close mapped devices
        for device in reversed(self.mapped_devices):
            debug(f"Closing mapped device {device}")
            sudo_command(f"cryptsetup luksClose {device}", check=False)
        
        # Remove loop devices
        for device in reversed(self.loop_devices):
            debug(f"Removing loop device {device}")
            sudo_command(f"losetup -d {device}", check=False)
        
        # Remove temp dirs
        for temp_dir in reversed(self.temp_dirs):
            debug(f"Removing temp dir {temp_dir}")
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception as e:
                debug(f"Failed to remove {temp_dir}: {str(e)}")
        
        # Remove temp files
        for temp_file in reversed(self.temp_files):
            debug(f"Removing temp file {temp_file}")
            try:
                os.unlink(temp_file)
            except Exception as e:
                debug(f"Failed to remove {temp_file}: {str(e)}")
        
        # Execute custom actions
        for action in reversed(self.actions):
            debug(f"Executing cleanup action: {action}")
            try:
                sudo_command(action, check=False)
            except Exception as e:
                debug(f"Failed to execute cleanup action: {str(e)}")

cleanup_manager = CleanupManager()

# === HELP TEXT ===
def show_help():
    help_text = """Encrypt Ubuntu Disk Image Tool (Python Version)

Purpose:
  Transforms an unencrypted Ubuntu 22.04+ raw disk image into an encrypted
  image with LUKS2 encryption on the root partition while preserving the
  EFI and boot partitions.

Features:
  - Creates LUKS2-encrypted root partition
  - Generates secure random key stored in /boot
  - Maintains bootability with GRUB updates
  - Preserves original partition structure
  - Automatically increases root partition by 2GB
  - Comprehensive logging and debugging

Usage:
  encrypt_ubuntu_image.py [OPTIONS] <input_image> <output_image>

Required Arguments:
  input_image    Path to unencrypted raw disk image
  output_image   Path for encrypted output image

Options:
  -c CIPHER      LUKS encryption cipher (default: aes-xts-plain64)
                 Recommended alternatives: aes-cbc-essiv:sha256, serpent-xts-plain64
  -k KEY_SIZE    Key size in bits (default: 512)
                 Common values: 128, 192, 256, 384, 512
  -d             Enable debug output (verbose logging)
  -r ROOT_RESIZE Additional space for root partition in GB (default: 2)
  -h, --help     Show this help message

Key Management:
  - Key file is stored at /boot/root_crypt.key in the output image
  - Backup copy is created in current directory as root_crypt.key.backup
  - Key file contains 4096 bytes of cryptographically secure random data

Security Considerations:
  WARNING: The /boot partition remains unencrypted and contains:
  - The encryption key file
  - Kernel and initramfs
  - GRUB configuration
  Ensure physical security of the /boot partition or use Secure Boot.

Examples:
  1. Basic usage with defaults (2GB root expansion):
     encrypt_ubuntu_image.py ubuntu.raw encrypted_ubuntu.raw

  2. Custom cipher and key size:
     encrypt_ubuntu_image.py -c serpent-xts-plain64 -k 512 ubuntu.raw encrypted_ubuntu.raw

  3. With debug output and 4GB root expansion:
     encrypt_ubuntu_image.py -d -r 4 ubuntu.raw encrypted_ubuntu.raw

Exit Codes:
  0 - Success
  1 - General error
  2 - Invalid arguments
  3 - Missing dependencies
  4 - Filesystem error
  5 - Partitioning error
  6 - Encryption failure

Debugging:
  - Full debug log is written to: ./encrypt_debug.log
  - Use -d option for real-time debug output
"""
    print(help_text)
    sys.exit(0)

# === DEPENDENCY CHECK ===
def check_dependencies():
    debug("Verifying system dependencies...")
    
    required_tools = [
        "jq", "qemu-img", "cryptsetup", "partx",
        "blkid", "parted", "grub-install", "rsync",
        "losetup", "mkfs.ext4", "mkfs.vfat", "awk"
    ]
    
    missing = []
    
    for tool in required_tools:
        if not shutil.which(tool):
            missing.append(tool)
    
    if missing:
        error(f"Missing required tools: {', '.join(missing)}", 3)

# === IMAGE VALIDATION ===
def validate_input_image(loop_device):
    debug("Validating input image structure...")
    
    # Verify partitions exist
    for part_num in [1, 2, 3]:
        part_device = f"{loop_device}p{part_num}"
        if not os.path.exists(part_device):
            error(f"Missing partition in input image: {part_device}", 5)
    
    # Verify filesystem types
    result = sudo_command(["parted", "-s", loop_device, "print"])
    efi_type = None
    for line in result.stdout.splitlines():
        if line.startswith(" 1"):
            efi_type = line.split()[4]
            break
    
    if efi_type != "fat32":
        error("EFI partition is not FAT32", 4)
    
    result = sudo_command(["blkid", "-s", "TYPE", "-o", "value", f"{loop_device}p3"])
    root_type = result.stdout.strip()
    if root_type != "ext4":
        error("Root partition is not ext4", 4)

# === SIZE CALCULATIONS ===
def calculate_sizes(loop_device, root_resize_gb):
    debug("Calculating partition sizes...")
    
    # Get current partition sizes
    efi_size = int(sudo_command(["blockdev", "--getsize64", f"{loop_device}p1"]).stdout)
    boot_size = int(sudo_command(["blockdev", "--getsize64", f"{loop_device}p2"]).stdout)
    root_size = int(sudo_command(["blockdev", "--getsize64", f"{loop_device}p3"]).stdout)
    
    # Apply root resize (now defaults to 2GB)
    root_size += root_resize_gb * 1024 * 1024 * 1024
    
    # Align sizes to 1MiB
    def align_size(size):
        return ((size + ALIGNMENT - 1) // ALIGNMENT) * ALIGNMENT
    
    efi_size = align_size(efi_size)
    boot_size = align_size(boot_size)
    root_size = align_size(root_size)
    
    total_size = ALIGNMENT + efi_size + boot_size + root_size + LUKS_HEADER_SIZE + ALIGNMENT
    
    debug("Calculated sizes:")
    debug(f"  EFI:  {efi_size//1024//1024} MiB")
    debug(f"  Boot: {boot_size//1024//1024} MiB")
    debug(f"  Root: {root_size//1024//1024} MiB (including +{root_resize_gb}GB)")
    debug(f"  LUKS Header: {LUKS_HEADER_SIZE//1024//1024} MiB")
    debug(f"  Total: {total_size//1024//1024//1024} GiB")
    
    # Verify disk space
    output_dir = os.path.dirname(os.path.abspath(args.output_image))
    statvfs = os.statvfs(output_dir)
    free_space = statvfs.f_frsize * statvfs.f_bavail
    
    if free_space < total_size:
        error(f"Insufficient disk space. Need {total_size//1024//1024} MiB, available {free_space//1024//1024} MiB", 5)
    
    return {
        "efi_size": efi_size,
        "boot_size": boot_size,
        "root_size": root_size,
        "total_size": total_size
    }

# === IMAGE CREATION ===
def create_encrypted_image(output_path, sizes):
    log("Creating encrypted disk image...")
    
    # Create blank image
    run_command(["qemu-img", "create", "-f", "raw", output_path, str(sizes["total_size"])])
    
    # Setup loop device
    loop_output = sudo_command(["losetup", "--show", "--find", output_path]).stdout.strip()
    cleanup_manager.add_loop_device(loop_output)
    debug(f"Output loop device: {loop_output}")
    
    # Create partition table with proper alignment
    efi_start = ALIGNMENT // SECTOR_SIZE
    efi_end = efi_start + sizes["efi_size"] // SECTOR_SIZE - 1
    boot_start = efi_end + 1
    boot_end = boot_start + sizes["boot_size"] // SECTOR_SIZE - 1
    root_start = boot_end + 1
    root_end = root_start + (sizes["root_size"] + LUKS_HEADER_SIZE) // SECTOR_SIZE - 1
    
    debug("Partition layout:")
    debug(f"  EFI:  {efi_start}s-{efi_end}s")
    debug(f"  Boot: {boot_start}s-{boot_end}s")
    debug(f"  Root: {root_start}s-{root_end}s")
    
    # Create partitions
    sudo_command([
        "parted", "-s", loop_output, "--",
        "mklabel", "gpt",
        "mkpart", "EFI", "fat32", f"{efi_start}s", f"{efi_end}s",
        "set", "1", "esp", "on",
        "set", "1", "boot", "on",
        "mkpart", "boot", "ext4", f"{boot_start}s", f"{boot_end}s",
        "mkpart", "root", "ext4", f"{root_start}s", f"{root_end}s"
    ])
    
    sudo_command(["partx", "-u", loop_output])
    
    return {
        "loop_device": loop_output,
        "efi_part": f"{loop_output}p1",
        "boot_part": f"{loop_output}p2",
        "root_part": f"{loop_output}p3"
    }

# === COPY AND ENCRYPT ===
def copy_and_encrypt(input_loop, output_parts, cipher, key_size):
    log("Copying and encrypting partitions...")
    
    # Copy EFI and boot partitions
    debug("Copying EFI partition...")
    sudo_command(f"dd if={input_loop}p1 of={output_parts['efi_part']} bs=4M status=progress conv=fsync")
    
    debug("Copying boot partition...")
    sudo_command(f"dd if={input_loop}p2 of={output_parts['boot_part']} bs=4M status=progress conv=fsync")
    
    # Generate encryption key
    log("Generating LUKS encryption key...")
    temp_keyfile = tempfile.mktemp()
    cleanup_manager.add_temp_file(temp_keyfile)
    debug(f"Key file temp path: {temp_keyfile}")
    
    sudo_command(f"dd if=/dev/urandom of={temp_keyfile} bs=1024 count=4")
    sudo_command(f"chmod 0400 {temp_keyfile}")
    
    # Create key backup
    backup_keyfile = f"./{KEYFILE_NAME}.backup"
    sudo_command(f"cp {temp_keyfile} {backup_keyfile}")
    sudo_command(f"chmod 0400 {backup_keyfile}")
    log(f"Key backup created: {backup_keyfile}")
    
    # Get key fingerprint
    result = sudo_command(f"sha256sum {backup_keyfile}")
    debug(f"Key fingerprint: {result.stdout.strip()}")
    
    # Encrypt root partition
    log("Encrypting root partition with LUKS2...")
    debug(f"Using cipher: {cipher} with {key_size}-bit key")
    
    sudo_command([
        "cryptsetup", "luksFormat",
        "--type", "luks2",
        "--cipher", cipher,
        "--key-size", str(key_size),
        "--batch-mode", output_parts["root_part"], temp_keyfile
    ])
    
    # Open encrypted volume
    sudo_command(["cryptsetup", "luksOpen", output_parts["root_part"], MAPPER_NAME, "--key-file", temp_keyfile])
    cleanup_manager.add_mapped_device(MAPPER_NAME)
    
    # Copy root filesystem
    log("Copying root filesystem to encrypted partition...")
    temp_root_mount = tempfile.mkdtemp()
    cleanup_manager.add_temp_dir(temp_root_mount)
    debug(f"Mounting source root at {temp_root_mount}")
    sudo_command(["mount", f"{input_loop}p3", temp_root_mount])
    cleanup_manager.add_mount_point(temp_root_mount)
    
    temp_mount = tempfile.mkdtemp()
    cleanup_manager.add_temp_dir(temp_mount)
    debug(f"Formatting encrypted partition as ext4")
    sudo_command(["mkfs.ext4", f"/dev/mapper/{MAPPER_NAME}"])
    
    debug(f"Mounting encrypted partition at {temp_mount}")
    sudo_command(["mount", f"/dev/mapper/{MAPPER_NAME}", temp_mount])
    cleanup_manager.add_mount_point(temp_mount)
    
    debug("Copying files with rsync...")
    sudo_command([
        "rsync", "-aAX",
        "--exclude=/dev/*", "--exclude=/proc/*", "--exclude=/sys/*",
        "--exclude=/tmp/*", "--exclude=/run/*", "--exclude=/mnt/*",
        "--exclude=/media/*", "--exclude=/lost+found",
        f"{temp_root_mount}/", f"{temp_mount}/"
    ])
    
    return {
        "temp_keyfile": temp_keyfile,
        "backup_keyfile": backup_keyfile,
        "temp_root_mount": temp_root_mount,
        "temp_mount": temp_mount
    }

# === SYSTEM CONFIGURATION ===
def configure_system(output_parts, mounts):
    log("Configuring encrypted system...")
    
    # Mount target boot partition
    temp_boot_mount = tempfile.mkdtemp()
    cleanup_manager.add_temp_dir(temp_boot_mount)
    debug(f"Mounting target boot at {temp_boot_mount}")
    sudo_command(["mount", output_parts["boot_part"], temp_boot_mount])
    cleanup_manager.add_mount_point(temp_boot_mount)
    
    # Install key file
    target_keyfile = os.path.join(temp_boot_mount, KEYFILE_NAME)
    debug(f"Installing key file to {target_keyfile}")
    sudo_command(f"cp {mounts['temp_keyfile']} {target_keyfile}")
    sudo_command(f"chmod 0400 {target_keyfile}")
    os.unlink(mounts["temp_keyfile"])
    
    # Bind mount boot
    debug(f"Bind mounting boot to {mounts['temp_mount']}/boot")
    os.makedirs(os.path.join(mounts["temp_mount"], "boot"), exist_ok=True)
    sudo_command(["mount", "--bind", temp_boot_mount, os.path.join(mounts["temp_mount"], "boot")])
    cleanup_manager.add_mount_point(os.path.join(mounts["temp_mount"], "boot"))
    
    # Get root UUID
    result = sudo_command(["blkid", "-s", "UUID", "-o", "value", output_parts["root_part"]])
    root_uuid = result.stdout.strip()
    debug(f"Updating crypttab with UUID {root_uuid}")
    
    # Update crypttab
    crypttab_path = os.path.join(mounts["temp_mount"], "etc/crypttab")
    with open(crypttab_path, "w") as f:
        f.write(f"{MAPPER_NAME} UUID={root_uuid} {KEYFILE_PATH} luks,discard\n")
    
    # Get boot UUID
    result = sudo_command(["blkid", "-s", "UUID", "-o", "value", output_parts["boot_part"]])
    boot_uuid = result.stdout.strip()
    root_mapper = f"/dev/mapper/{MAPPER_NAME}"
    
    log("Updating /etc/fstab with proper entries...")
    temp_fstab = tempfile.mktemp()
    cleanup_manager.add_temp_file(temp_fstab)
    
    # Process existing fstab
    original_fstab = os.path.join(mounts["temp_mount"], "etc/fstab")
    with open(original_fstab, "r") as f:
        original_lines = f.readlines()
    
    # Process fstab lines
    new_lines = []
    for line in original_lines:
        line = line.strip()
        if not line or line.startswith("#"):
            new_lines.append(line)
            continue
        
        parts = line.split()
        if len(parts) < 2:
            new_lines.append(line)
            continue
        
        mount_point = parts[1]
        device = parts[0]
        
        # Skip existing /boot or / entries
        if mount_point in ("/boot", "/boot/", "/", "/ "):
            new_lines.append(f"# {line} (commented out during encryption)")
        elif device == root_mapper:
            new_lines.append(f"# {line} (commented out during encryption)")
        else:
            new_lines.append(line)
    
    # Add new entries
    new_lines.extend([
        f"# /boot was on {output_parts['boot_part']} during encryption",
        f"UUID={boot_uuid} /boot ext4 defaults 0 2",
        f"# / was on {output_parts['root_part']} during encryption",
        f"{root_mapper} / ext4 defaults 0 1"
    ])
    
    # Write new fstab
    with open(temp_fstab, "w") as f:
        f.write("\n".join(new_lines) + "\n")
    
    debug("New fstab contents:")
    with open(temp_fstab, "r") as f:
        debug(f.read())
    
    sudo_command(f"cp {temp_fstab} {original_fstab}")
    sudo_command(f"chmod 644 {original_fstab}")
    
    # Prepare chroot environment
    log("Preparing chroot environment...")
    debug("Mounting special filesystems")
    sudo_command(["mount", "--bind", "/dev", os.path.join(mounts["temp_mount"], "dev")])
    cleanup_manager.add_mount_point(os.path.join(mounts["temp_mount"], "dev"))
    sudo_command(["mount", "--bind", "/sys", os.path.join(mounts["temp_mount"], "sys")])
    cleanup_manager.add_mount_point(os.path.join(mounts["temp_mount"], "sys"))
    sudo_command(["mount", "--bind", "/proc", os.path.join(mounts["temp_mount"], "proc")])
    cleanup_manager.add_mount_point(os.path.join(mounts["temp_mount"], "proc"))
    
    # Configure cryptsetup initramfs hook
    conf_hook_dir = os.path.join(mounts["temp_mount"], "etc/cryptsetup-initramfs")
    os.makedirs(conf_hook_dir, exist_ok=True)
    with open(os.path.join(conf_hook_dir, "conf-hook"), "w") as f:
        f.write("CRYPTSETUP=y\n")
        f.write("KEYFILE_PATTERN=/boot/*.key\n")
    
    # Configure GRUB
    grub_dir = os.path.join(mounts["temp_mount"], "etc/default/grub.d")
    os.makedirs(grub_dir, exist_ok=True)
    with open(os.path.join(grub_dir, "99-crypt.cfg"), "w") as f:
        f.write("GRUB_ENABLE_CRYPTODISK=y\n")
    
    grub_cmdline = f"cryptdevice=UUID={root_uuid}:{MAPPER_NAME} root={root_mapper}"
    grub_file = os.path.join(mounts["temp_mount"], "etc/default/grub")
    
    debug("Updating GRUB_CMDLINE_LINUX_DEFAULT")
    grub_lines = []
    found = False
    with open(grub_file, "r") as f:
        for line in f:
            if line.startswith("GRUB_CMDLINE_LINUX_DEFAULT="):
                grub_lines.append(f'GRUB_CMDLINE_LINUX_DEFAULT="{grub_cmdline}"\n')
                found = True
            else:
                grub_lines.append(line)
    
    if not found:
        grub_lines.append(f'GRUB_CMDLINE_LINUX_DEFAULT="{grub_cmdline}"\n')
    
    with open(grub_file, "w") as f:
        f.writelines(grub_lines)
    
    # Update initramfs
    log("Updating initramfs...")
    sudo_command(["chroot", mounts["temp_mount"], "update-initramfs", "-u", "-k", "all"])
    
    # Verify key in initramfs
    log("Verifying key in initramfs...")
    result = sudo_command(["chroot", mounts["temp_mount"], "ls", "/boot"])
    kernel_versions = [line.split("-")[-1] for line in result.stdout.splitlines() 
                     if line.startswith("initrd.img-")]
    
    if kernel_versions:
        kernel_version = kernel_versions[0]
        initrd_path = os.path.join(mounts["temp_mount"], "boot", f"initrd.img-{kernel_version}")
        result = sudo_command(f"lsinitramfs {initrd_path} | grep {KEYFILE_NAME}", check=False)
        if result.returncode == 0:
            debug("Key file verified in initramfs")
        else:
            warn("Key file not found in initramfs!")
    else:
        warn("Could not verify key in initramfs - kernel version not found")
    
    # Update GRUB
    log("Updating GRUB configuration...")
    sudo_command(["chroot", mounts["temp_mount"], "update-grub"])

# === MAIN SCRIPT ===
def main():
    global args
    
    parser = argparse.ArgumentParser(description="Encrypt Ubuntu disk image", add_help=False)
    parser.add_argument("-c", "--cipher", default=DEFAULT_CIPHER, 
                      help=f"LUKS encryption cipher (default: {DEFAULT_CIPHER})")
    parser.add_argument("-k", "--key-size", type=int, default=DEFAULT_KEY_SIZE,
                      help=f"Key size in bits (default: {DEFAULT_KEY_SIZE})")
    parser.add_argument("-r", "--root-resize", type=int, default=DEFAULT_ROOT_RESIZE,
                      help=f"Additional space for root partition in GB (default: {DEFAULT_ROOT_RESIZE})")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    parser.add_argument("-h", "--help", action="store_true", help="Show help message")
    parser.add_argument("input_image", nargs="?", help="Path to unencrypted raw disk image")
    parser.add_argument("output_image", nargs="?", help="Path for encrypted output image")
    
    args = parser.parse_args()
    
    if args.help or not args.input_image or not args.output_image:
        show_help()
    
    # Reconfigure logging with debug if needed
    global logger
    logger = setup_logging(args.debug)
    log("Starting Ubuntu disk image encryption (Python version)")
    debug(f"Command line: {' '.join(sys.argv)}")
    
    try:
        # Check dependencies
        check_dependencies()
        
        # Setup input loop device
        log("Setting up input image...")
        loop_input = sudo_command(["losetup", "--show", "--find", "--partscan", args.input_image]).stdout.strip()
        cleanup_manager.add_loop_device(loop_input)
        debug(f"Input loop device: {loop_input}")
        sudo_command(["partx", "-u", loop_input])
        
        # Validate input image structure
        validate_input_image(loop_input)
        
        # Calculate partition sizes (now with 2GB default increase)
        sizes = calculate_sizes(loop_input, args.root_resize)
        
        # Create and partition output image
        output_parts = create_encrypted_image(args.output_image, sizes)
        
        # Copy data and encrypt
        mounts = copy_and_encrypt(loop_input, output_parts, args.cipher, args.key_size)
        
        # Configure the encrypted system
        configure_system(output_parts, mounts)
        
        # Cleanup
        cleanup_manager.cleanup()
        
        # Final output
        log("Encryption process completed successfully")
        log(f"Output image: {args.output_image}")
        log(f"Key backup: {mounts['backup_keyfile']}")
        log(f"Debug log: {DEBUG_LOG}")
        print(f"{Colors.YELLOW}WARNING: The encryption key is stored in unencrypted /boot partition.")
        print(f"Ensure physical security or use Secure Boot to protect this key.{Colors.NC}")
        
    except Exception as e:
        error(f"Unexpected error: {str(e)}", 1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        error("Operation cancelled by user", 1)
