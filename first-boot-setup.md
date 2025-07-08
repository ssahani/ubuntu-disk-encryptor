# First Boot Configuration Script

A modular Python script to configure Ubuntu disk images with selective first-boot settings.

## Features

- **Selective Configuration**: Only applies requested changes
- **Supported Configurations**:
  - Hostname setting
  - Root password configuration
  - EC2-user creation with SSH key
  - Custom Netplan installation
- **Atomic Operations**: Each task is self-contained
- **Clean Resource Management**: Proper mount/unmount handling
- **First-Boot Service**: Completes configuration on first system start

## Requirements

- Python 3.6+
- Linux system with:
  - `losetup`
  - `cryptsetup`
  - `mount`/`umount`
  - `chroot` capability
- Root privileges

## Installation

```bash
chmod +x first-boot-config.py
sudo cp first-boot-config.py /usr/local/bin/
```

## Usage

```bash
sudo ./first-boot-config.py [OPTIONS]
```

### Basic Options

| Option          | Description                          | Default               |
|-----------------|--------------------------------------|-----------------------|
| `--image`       | Disk image to configure              | `ubuntu-2204-efi-kube-v1.30.1` |
| `--hostname`    | Set system hostname                  | (none)               |
| `--root-pass`   | Set root password to 'max'           | Disabled             |
| `--ec2-user`    | Create ec2-user with password 'max'  | Disabled             |
| `--ssh-key`     | SSH public key for ec2-user          | (none)               |
| `--netplan`     | Custom Netplan config file           | (none)               |
| `--no-cleanup`  | Skip cleanup after configuration     | Cleanup enabled      |

### Common Examples

1. **Set only hostname**:
   ```bash
   sudo ./first-boot-config.py --image ubuntu.img --hostname myserver
   ```

2. **Full configuration**:
   ```bash
   sudo ./first-boot-config.py \
     --image ubuntu.img \
     --hostname prod-server \
     --root-pass \
     --ec2-user \
     --ssh-key ~/.ssh/id_rsa.pub \
     --netplan 99-custom.yaml
   ```

3. **Debug mode (no cleanup)**:
   ```bash
   sudo ./first-boot-config.py --image ubuntu.img --hostname test --no-cleanup
   ```

## Configuration Workflow

1. Mounts the disk image
2. Applies requested configurations:
   - Writes hostname to `/boot/hostname`
   - Sets passwords in `/etc/shadow`
   - Installs SSH keys
   - Copies Netplan configs
3. Creates first-boot service
4. Unmounts and cleans up (unless disabled)

The first-boot service completes these tasks on first system startup:
- Applies the hostname using `hostnamectl`
- Creates completion marker file

## Technical Details

- **Image Requirements**:
  - Must have LUKS-encrypted root partition
  - Requires `/boot/root_crypt.key` for decryption
- **Password Security**:
  - Both root and ec2-user are set to password 'max'
  - Consider changing after first login
- **Netplan**:
  - Existing Netplan configs are removed
  - Custom config installed as `/etc/netplan/99-custom.yaml`

## Troubleshooting

**Error: "Missing LUKS keyfile"**
- Ensure your image has `/boot/root_crypt.key`

**Error: Mount failures**
- Try with `--no-cleanup` and manually check mounts:
  ```bash
  mount | grep /mnt
  ```

**Debugging first-boot**:
- Check journal logs:
  ```bash
  journalctl -u first-boot-config
  ```

## License

MIT License - Free for modification and redistribution
