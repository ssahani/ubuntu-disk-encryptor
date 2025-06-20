#!/usr/bin/env python3

import os
import subprocess
import argparse
import sys
import secrets
import string
from pathlib import Path

class Colors:
    DEBUG = '\033[94m'
    INFO = '\033[92m'
    WARNING = '\033[93m'
    ERROR = '\033[91m'
    END = '\033[0m'

def print_debug(message, verbose=False):
    if verbose:
        print(f"{Colors.DEBUG}[DEBUG] {message}{Colors.END}")

def print_info(message):
    print(f"{Colors.INFO}[INFO] {message}{Colors.END}")

def print_warning(message):
    print(f"{Colors.WARNING}[WARNING] {message}{Colors.END}")

def print_error(message):
    print(f"{Colors.ERROR}[ERROR] {message}{Colors.END}", file=sys.stderr)

def run_command(cmd, check=True, verbose=False):
    """Run a shell command with optional verbosity."""
    print_debug(f"Executing: {cmd}", verbose)
    try:
        result = subprocess.run(cmd, check=check, shell=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, executable='/bin/bash')
        if verbose and result.stdout:
            print_debug(f"Output: {result.stdout}", verbose)
        if verbose and result.stderr:
            print_debug(f"Stderr: {result.stderr}", verbose)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print_error(f"Command failed: {cmd}")
        print_error(f"Error: {e.stderr}")
        sys.exit(1)

def detect_package_manager():
    """Detect the system's package manager."""
    if Path("/usr/bin/apt").exists():
        return "apt"
    elif Path("/usr/bin/dnf").exists():
        return "dnf"
    elif Path("/usr/bin/yum").exists():
        return "yum"
    elif Path("/usr/bin/pacman").exists():
        return "pacman"
    elif Path("/usr/bin/zypper").exists():
        return "zypper"
    return None

def install_packages(packages, verbose=False):
    """Install required packages."""
    pkg_manager = detect_package_manager()
    if not pkg_manager:
        print_error("Could not detect package manager")
        sys.exit(1)

    print_info(f"Installing packages using {pkg_manager}: {', '.join(packages)}")

    if pkg_manager == "apt":
        cmd = f"apt-get update && apt-get install -y {' '.join(packages)}"
    elif pkg_manager in ["dnf", "yum"]:
        cmd = f"{pkg_manager} install -y {' '.join(packages)}"
    elif pkg_manager == "pacman":
        cmd = f"pacman -Sy --noconfirm {' '.join(packages)}"
    elif pkg_manager == "zypper":
        cmd = f"zypper --non-interactive install {' '.join(packages)}"

    run_command(cmd, verbose=verbose)

def check_dependencies(verbose=False):
    """Check and install required dependencies."""
    required_packages = {
        "systemd": ["systemd", "systemd-cryptsetup"],
        "tpm2": ["tpm2-tools", "tpm2-tss"],
        "cryptsetup": ["cryptsetup"],
        "grub": ["grub2-common"]  # For kernel cmdline updates
    }

    # Check what's installed and what's missing
    missing_packages = []
    for category, packages in required_packages.items():
        for pkg in packages:
            if not run_command(f"command -v {pkg.split('-')[0]}", check=False, verbose=verbose):
                missing_packages.append(pkg)

    if missing_packages:
        print_warning(f"Missing packages: {', '.join(missing_packages)}")
        install_packages(missing_packages, verbose=verbose)

    # Verify systemd version
    try:
        version = run_command("systemd-cryptenroll --version", verbose=verbose)
        if int(version.split('.')[0]) < 247:
            print_error("systemd version too old (need 247+ for TPM2 support)")
            sys.exit(1)
    except:
        print_error("systemd-cryptenroll not available after installation")
        sys.exit(1)

def check_root():
    """Check if running as root."""
    if os.geteuid() != 0:
        print_error("This script must be run as root")
        sys.exit(1)

def generate_random_password(length=32):
    """Generate a random password."""
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

def setup_luks_with_tpm(device, partition, kernel_cmdline=True, initramfs=True, verbose=False):
    """Setup LUKS encryption with TPM2 using systemd-cryptenroll."""
    device_path = f"{device}{partition}"
    print_info(f"Setting up LUKS with TPM2 for {device_path}")

    # Check if the device exists
    if not Path(device_path).exists():
        print_error(f"Device {device_path} does not exist")
        sys.exit(1)

    # Check if the partition is already encrypted
    result = run_command(f"blkid -o value -s TYPE {device_path}", check=False, verbose=verbose)
    if result == "crypto_LUKS":
        print_warning(f"{device_path} is already encrypted with LUKS")
        response = input("Do you want to continue and add TPM2 unlocking? (y/N): ").lower()
        if response != 'y':
            sys.exit(0)
    else:
        # Generate a random password
        password = generate_random_password()
        print_debug("Generated LUKS password", verbose)

        # Encrypt the partition
        print_info(f"Encrypting {device_path} with LUKS")
        run_command(f"echo -n '{password}' | cryptsetup luksFormat --type luks2 {device_path} -",
                   verbose=verbose)

        # Add the primary key to slot 0
        print_info("Adding primary key to slot 0")
        run_command(f"echo -n '{password}' | cryptsetup luksAddKey {device_path} -",
                   verbose=verbose)

    # Get the LUKS UUID
    luks_uuid = run_command(f"cryptsetup luksUUID {device_path}", verbose=verbose)
    print_info(f"LUKS UUID: {luks_uuid}")

    # Add TPM2 enrollment
    print_info("Enrolling TPM2 with systemd-cryptenroll")
    run_command(f"systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0,7 {device_path}",
               verbose=verbose)

    # Verify the enrollment
    print_info("Verifying TPM2 enrollment")
    enrollments = run_command(f"systemd-cryptenroll --list {device_path}", verbose=verbose)
    if "TPM2" not in enrollments:
        print_error("Failed to enroll TPM2")
        sys.exit(1)

    # Update crypttab
    print_info("Updating /etc/crypttab")
    crypttab_entry = f"luks-{luks_uuid} UUID={luks_uuid} none tpm2-device=auto"

    crypttab_path = Path("/etc/crypttab")
    if crypttab_path.exists():
        with open(crypttab_path, 'r') as f:
            crypttab = f.read()
    else:
        crypttab = ""

    if f"luks-{luks_uuid}" not in crypttab:
        with open(crypttab_path, 'a') as f:
            f.write(f"\n{crypttab_entry}\n")

    # Update kernel cmdline if requested
    if kernel_cmdline:
        print_info("Updating kernel command line")
        run_command(f"grubby --update-kernel=ALL --args='rd.luks.uuid={luks_uuid}'",
                   verbose=verbose)

    # Update initramfs if requested
    if initramfs:
        print_info("Updating initramfs")
        distro = run_command("grep '^ID=' /etc/os-release | cut -d= -f2", verbose=verbose).strip('"').lower()

        if distro in ["debian", "ubuntu"]:
            run_command("update-initramfs -u -k all", verbose=verbose)
        elif distro in ["fedora", "centos", "rhel"]:
            run_command("dracut -f", verbose=verbose)
        else:
            print_warning(f"Unsupported distribution '{distro}', initramfs not updated")

    print_info("TPM2 LUKS setup completed successfully")

def main():
    parser = argparse.ArgumentParser(description="Setup LUKS encryption with TPM2 unlocking using systemd-cryptenroll")
    parser.add_argument("device", help="The block device (e.g., /dev/nvme0n1)")
    parser.add_argument("partition", help="The partition number (e.g., 1 for /dev/nvme0n1p1)")
    parser.add_argument("--no-kernel-cmdline", action="store_false", dest="kernel_cmdline",
                       help="Don't update kernel command line")
    parser.add_argument("--no-initramfs", action="store_false", dest="initramfs",
                       help="Don't update initramfs")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Enable verbose output")

    args = parser.parse_args()

    check_root()
    check_dependencies(verbose=args.verbose)

    setup_luks_with_tpm(
        args.device,
        args.partition,
        kernel_cmdline=args.kernel_cmdline,
        initramfs=args.initramfs,
        verbose=args.verbose
    )

if __name__ == "__main__":
    main()
