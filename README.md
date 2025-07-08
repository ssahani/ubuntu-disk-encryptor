# 🔐 encrypt\_ubuntu\_image.sh – Ubuntu Full Disk Encryption Tool (LUKS2)

## Description

`encrypt_ubuntu_image.sh` is a robust Bash script that converts an **unencrypted Ubuntu raw disk image** into a **LUKS2-encrypted image**, preserving EFI and `/boot` partitions while encrypting the root (`/`) filesystem. Ideal for bare metal provisioning, secure edge deployments, and cloud image customization.

---

## 🛠️ Features

* 📂 **Preserves original partitions**: EFI and `/boot` untouched
* 🔐 **Encrypts root partition** with **LUKS2**
* 🔑 **Auto-generates key file** stored in `/boot/root_crypt.key`
* 🖫️ **Key backup** saved as `./root_crypt.key.backup`
* 📊 **Extensible and modular**: clean, traceable code with verbose logging
* ⚙️ **GRUB + initramfs** configured for bootable encryption
* 📊 **Increases root partition size by default (2GB)**
* 📋 **Extensive logging** to `encrypt_debug.log`

---

## 🧪 Requirements

Ensure the following tools are installed:

```bash
jq qemu-img cryptsetup partx blkid parted grub-install rsync losetup mkfs.ext4 mkfs.vfat awk
```

---

## 🗽 Usage

```bash
./encrypt_ubuntu_image.sh [OPTIONS] <input_image.raw> <output_image.raw>
```

### Required Arguments:

* `input_image.raw`: Path to original unencrypted Ubuntu raw disk image
* `output_image.raw`: Output path for new encrypted image

### Options:

| Option      | Description                                     | Default           |
| ----------- | ----------------------------------------------- | ----------------- |
| `-c CIPHER` | Set LUKS cipher (e.g. `aes-xts-plain64`)        | `aes-xts-plain64` |
| `-k BITS`   | Set key size in bits                            | `512`             |
| `-r GB`     | Additional size (in GB) added to root partition | `2`               |
| `-d`        | Enable debug logging (live + file)              | Off               |
| `-h`        | Show help and exit                              | —                 |

---

## 📆 Example Commands

1. **Basic usage**:

```bash
./encrypt_ubuntu_image.sh ubuntu.raw ubuntu-encrypted.raw
```

2. **Custom cipher and key size**:

```bash
./encrypt_ubuntu_image.sh -c serpent-xts-plain64 -k 512 ubuntu.raw secure.raw
```

3. **Debug mode and 4GB root increase**:

```bash
./encrypt_ubuntu_image.sh -d -r 4 ubuntu.raw ubuntu-secure.raw
```

---

## 🔐 Security Warning

The `/boot` partition is **unencrypted** and contains:

* `root_crypt.key` (used to unlock the encrypted root)
* Kernel and initramfs
* GRUB configuration

**Secure Boot** or physical disk protection is **strongly recommended**.

---

## 📁 Output Artifacts

* `encrypted_ubuntu.raw`: Final LUKS2-encrypted image
* `root_crypt.key.backup`: Local backup of encryption key
* `encrypt_debug.log`: Detailed log of all operations

---

## 📌 Changelog

* **v2.2.0**:

  * Default root resize increased to 2GB
  * Full `/etc/fstab` and `/etc/crypttab` updates
  * Auto detection of kernel version for `initramfs`
  * Keyfile verification in `initrd.img`
  * Enhanced GRUB and cryptsetup integration

---

## 🩺 Cleanup

All temporary mounts and devices are automatically cleaned on script exit.

---
