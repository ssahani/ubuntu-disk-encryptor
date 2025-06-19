
# Ubuntu Image Customization [Script](https://github.com/ssahani/disk/blob/main/first-boot-config.sh)

## Overview

This script prepares a custom Ubuntu image with reliable first-boot configuration, including system setup, user creation, SSH configuration, and network setup. It's designed for creating cloud-ready images with secure defaults and customizable options.

## Features

- **First-boot configuration** with guaranteed one-time execution
- **Secure defaults** with encrypted root filesystem (LUKS)
- **Flexible configuration** via command-line arguments or environment variables
- **Comprehensive logging** of first-boot operations
- **Network configuration** support (Netplan)
- **SSH key installation** for the default user
- **Hostname configuration**
- **System updates** on first boot
- **Clean machine ID** generation

## Requirements

- Ubuntu 22.04 host system (for running the script)
- Root/sudo privileges
- `cryptsetup` for LUKS operations
- `losetup` for image mounting
- Basic Linux utilities (bash, coreutils, etc.)

## Usage

### Basic Command

```bash
sudo ./customize_image.sh --image /path/to/image.img
```

### Full Options

```bash
sudo ./customize_image.sh \
  --image /path/to/image.img \
  --hostname my-server \
  --sshkey ~/.ssh/id_rsa.pub \
  --netplan /path/to/netplan.yaml \
  --no-ssh \
  --no-sshkeys
```

### Environment Variables

```bash
export ROOT_PASSWORD="SecureRootPass123"
export EC2_USER_PASSWORD="SecureUserPass123"
sudo ./customize_image.sh --image /path/to/image.img
```

### Script Parameters

| Parameter        | Description                                | Default Value                     |
|------------------|--------------------------------------------|-----------------------------------|
| `--image`        | Path to the image file                     | `ubuntu-2204-efi-kube-v1.30.1`    |
| `--test`         | Verify configurations without making changes| `false`                           |
| `--hostname`     | Set instance hostname                      | (none)                            |
| `--sshkey`       | Path to SSH public key for ec2-user        | (none)                            |
| `--netplan`      | Custom Netplan configuration file          | (none)                            |
| `--no-ssh`       | Skip SSH server installation               | `false`                           |
| `--no-sshkeys`   | Skip SSH host key generation               | `false`                           |
| `--help` or `-h` | Show help message                          | (none)                            |

### Environment Variables

| Variable         | Description                                | Default Value                     |
|------------------|--------------------------------------------|-----------------------------------|
| `ROOT_PASSWORD`  | Password for root user                     | `max`                             |
| `EC2_USER_PASSWORD` | Password for ec2-user                    | `max`                             |

## First Boot Process

The script creates a systemd service that runs on first boot and performs:

- Network configuration (if provided)
- System updates (`apt-get update/upgrade`)
- User creation (ec2-user with sudo privileges)
- SSH configuration (key installation and service setup)
- Hostname setting (if provided)
- Cleanup and marker creation to prevent re-execution

The service creates a marker file (`/var/lib/first-boot-complete`) after successful execution to prevent running again.

## Detailed Script Functions

1. **Image Mounting**
   - Sets up loop device for the image
   - Mounts boot partition
   - Opens LUKS encrypted root partition
   - Mounts root filesystem and nested partitions (`/boot`, `/boot/efi`)

2. **System Configuration**
   - Resets machine-id for unique instance identification
   - Sets root password
   - Creates necessary directories
   - Configures default Netplan if none provided

3. **SSH Setup**

   Optionally:
   - Installs OpenSSH server
   - Configures password authentication
   - Generates SSH host keys if missing
   - Enables SSH service

4. **First-Boot Service Creation**

   Creates a systemd service that:
   - Runs only once (checks for marker file)
   - Configures network if custom config provided
   - Sets hostname if specified
   - Creates ec2-user with SSH key if provided
   - Performs system updates
   - Configures SSH server
   - Creates completion marker

5. **Configuration File Handling**

   Copies to `/boot` in the image:
   - Hostname file (if specified)
   - SSH public key (if provided)
   - Netplan configuration (if provided)
   - Cloud-init network disable config

6. **Error Handling**

   The script includes comprehensive error handling:
   - Input validation
   - Mount point verification
   - Cleanup on exit (unmounting, LUKS closure)
   - Logging of all operations
   - Exit on critical errors

7. **Logging**

   All first-boot operations are logged to:
   - Systemd journal
   - `/var/log/first-boot.log`

8. **Cleanup**

   The script includes a cleanup function that:
   - Unmounts all mounted partitions
   - Closes LUKS container
   - Detaches loop device
   - Runs automatically on exit (success or failure)

9. **Example Configurations**

   - **Basic DHCP Configuration**

     ```bash
     sudo ./customize_image.sh --image base.img
     ```

   - **Custom Network Configuration**

     ```bash
     sudo ./customize_image.sh \
       --image base.img \
       --netplan custom-netplan.yaml \
       --hostname prod-web-01
     ```

   - **SSH Key Only Setup**

     ```bash
     sudo ./customize_image.sh \
       --image base.img \
       --sshkey ~/.ssh/id_rsa.pub \
       --no-sshkeys
     ```

10. **Security Considerations**

   - Passwords are set via environment variables (not command line)
   - SSH password authentication can be disabled when using keys
   - LUKS encryption is used for the root filesystem
   - First-boot script includes secure defaults
   - Sensitive operations require root privileges

11. **Limitations**

   - Designed specifically for Ubuntu 22.04 with LUKS encryption
   - Requires specific partition layout:
     - `p1`: EFI system partition
     - `p2`: `/boot` partition
     - `p3`: LUKS-encrypted root partition
   - Tested on x86_64 architecture
