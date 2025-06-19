# TPM2-LUKS tpm2-luks-setup

![Shell Script](https://img.shields.io/badge/Shell_Script-5.0-green.svg)
![TPM2](https://img.shields.io/badge/TPM2-2.0-blue.svg)
![LUKS](https://img.shields.io/badge/LUKS-2.0-yellow.svg)

A robust Bash script for automating TPM2-bound LUKS encryption setup, including disk partitioning, encryption, and auto-unlock configuration.

---

## Features

- 🛡️ End-to-end encrypted disk setup  
- 🔐 TPM2 auto-unlock binding  
- 💽 Disk partitioning (GPT)  
- 🔧 Multiple filesystem support (ext4/xfs/btrfs)  
- ⚡ Automatic `crypttab`/`fstab` configuration  
- 📋 Detailed logging and backups  
- 🔄 TPM2 binding removal  
- 🧩 PCR policy customization  

---

## Installation

```bash
sudo curl -L https://raw.githubusercontent.com/ssahani/disk/refs/heads/main/tpm2-luks-setup.sh -o /usr/local/bin/tpm2-luks-setup.sh 
sudo chmod +x /usr/local/bin/tpm2-luks-setup.sh
```

---

## Usage

### Basic TPM2 binding for existing LUKS:

```bash
sudo tpm2-luks-setup.sh --device /dev/sda1 --pcrs 7
```

### Full disk setup (partition + encrypt + TPM):

```bash
sudo tpm2-luks-setup.sh  \
  --device /dev/sdb \
  --partition \
  --filesystem ext4 \
  --mountpoint /secure \
  --label secure_data \
  --pcrs 0,7
```

### Remove TPM binding:

```bash
sudo tpm2-luks-setup.sh --device /dev/sda1 --remove
```

---

## Options

| Option         | Description                                 | Default       |
|----------------|---------------------------------------------|---------------|
| `--device`     | Block device to use (required)              | -             |
| `--pcrs`       | PCR banks to use (comma-separated)          | 7             |
| `--partition`  | Create partition and encrypt                | false         |
| `--filesystem` | Filesystem type (ext4/xfs/btrfs)            | ext4          |
| `--mountpoint` | Mountpoint path                             | -             |
| `--label`      | Partition/LUKS label                        | "encrypted"   |
| `--size`       | Partition size (e.g., 10G, 100%)            | 100%          |
| `--remove`     | Remove TPM2 binding                         | false         |
| `--force`      | Skip confirmations                          | false         |
| `--help`       | Show help message                           | -             |

---

## Requirements

- Linux kernel 5.4+  
- systemd 247+  
- cryptsetup 2.3+  
- tpm2-tools 4.0+  
- parted  
- e2fsprogs (for ext4) / xfsprogs / btrfs-progs  

---

## Recovery

Recovery keys are stored in:

```
/etc/luks-keys/<device>.key
```

### Example manual unlock:

```bash
sudo cryptsetup open /dev/sda1 crypt_sda1 --key-file /etc/luks-keys/sda1.key
```

---

## Security Considerations

- **Backup recovery keys** – Store copies in secure offline locations  
- **PCR policies** – Understand PCR 0/7 implications for system updates  
- **Secure deletion** – Use `wipefs` before repurposing disks  
- **Audit logs** – Check `/var/log/tpm2-luks-manager-*.log`  

---

## License

MIT License – See `LICENSE` for details.

---

## This README includes

1. **Badges** – Visual indicators for version/compatibility  
2. **Feature Highlights** – Quick visual overview  
3. **Installation** – One-line install method  
4. **Usage Examples** – Common scenarios  
5. **Option Reference** – Complete parameter documentation  
6. **Requirements** – Software prerequisites  
7. **Recovery** – Emergency access instructions  
8. **Security Notes** – Important operational considerations  

---
