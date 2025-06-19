# TPM2 LUKS Auto-Unlock Configuration

![TPM2 Security Chip](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html)  
*Automate LUKS decryption using TPM2 security chip*
[tpm-auto-decrypt-systemd.sh](https://github.com/ssahani/disk/blob/main/tpm-auto-decrypt-systemd.sh)
## 📖 Table of Contents
- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Usage](#-usage)
- [Configuration Options](#-configuration-options)
- [PCR Selection Guide](#-pcr-selection-guide)
- [Operation Details](#-operation-details)
- [Troubleshooting](#-troubleshooting)
- [Security Considerations](#-security-considerations)
- [License](#-license)

## ✨ Features

- 🔒 Automatic LUKS decryption during boot using TPM2
- 📝 Comprehensive logging of all operations
- ⏮️ Configuration file backups before modifications
- 🔍 Pre-operation system validation checks
- 🎨 Color-coded status output
- 📦 Automatic dependency installation
- 🔄 Support for both setup and removal operations
- 🧩 Flexible PCR configurations

## 🧰 Prerequisites

- Linux system with UEFI Secure Boot
- TPM2.0 chip enabled in BIOS
- LUKS-encrypted partition
- Systemd ≥ 247 (Ubuntu 20.04+ recommended)
- Root privileges

## 📥 Installation

```bash
curl -O https://github.com/ssahani/disk/blob/main/tpm-auto-decrypt-systemd.sh
chmod +x tpm2-luks-config.sh
sudo mv tpm2-luks-config.sh /usr/local/bin/
```

🚀 Usage
Basic Setup (default PCR7)
```bash

sudo tpm2-luks-config.sh --device /dev/sda1
```
Custom PCR Configuration
```bash

sudo tpm2-luks-config.sh --device /dev/nvme0n1p3 --pcrs 0,4,7
```
Remove TPM2 Binding
```bash

sudo tpm2-luks-config.sh --device /dev/sda1 --remove
```
⚙️ Configuration Options
Option	Description	Default
--device	LUKS encrypted device (required)	-
--pcrs	PCR banks to use (comma-separated)	7
--remove	Remove TPM2 binding	false
--force	Skip confirmation prompts	false
--help	Show help message	-
🔬 PCR Selection Guide
PCR	Measurement	Recommended
0	Core system firmware executable code	✅
4	Boot Manager	✅
7	Secure Boot state	✅✅
2	Extended PCR	⚠️ Special cases

Recommendation: Start with PCR7 only for Secure Boot systems. Combine with PCR0/PCR4 for stricter policies.
🔧 Operation Details
What the Script Does:

    Validation Phase:

        Verifies TPM2 chip is present and accessible

        Checks LUKS partition validity

        Ensures system requirements are met

    Backup Phase:

        Creates backups of:

            /etc/crypttab

            /etc/fstab

            /etc/default/grub

        Stores in /etc/backups with timestamp

    Configuration Phase:

        Adds/removes TPM2 key slot

        Updates crypttab with proper options

        Regenerates initramfs

    Verification Phase:

        Displays final configuration

        Provides next steps

File Modifications:
File	Modification
/etc/crypttab	Adds/updates LUKS entry with TPM2 options
Initramfs	Regenerated to include TPM2 modules
🐛 Troubleshooting
Common Issues:

    TPM Device Not Found:
```bash

sudo dmesg | grep -i tpm
sudo systemctl status tpm2-abrmd
```
Binding Fails:
```bash

sudo cryptsetup luksDump /dev/sda1 | grep -i tpm
sudo journalctl -xe
```
Boot Failures:

    Use recovery key to unlock

    Check logs:
   ``` bash

        sudo journalctl -b -p err
```
Log Files:
```
    Script log: /tmp/tpm2-luks-config-*.log

    System logs: journalctl -xe
```
🔒 Security Considerations

    Always maintain a backup of your LUKS recovery key

    TPM binding is not a replacement for strong passphrases

    PCR changes (like BIOS updates) may prevent unlocking

    Regularly test recovery process

    Consider combining with:

        Secure Boot

        BIOS password

        Encrypted /boot partition

📜 License

MIT License - Free for personal and commercial use
