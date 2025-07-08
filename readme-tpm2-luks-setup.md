# Ubuntu Disk Encryptor with TPM2

![TPM2 + LUKS Encryption Diagram](assets/tpm2-luks-diagram.png)  
*Diagram showing TPM2-backed LUKS disk encryption workflow*

A Bash script to automate LUKS disk encryption with TPM2 binding on Ubuntu systems.

## Description

This script simplifies the process of setting up LUKS disk encryption while binding the decryption key to the system's TPM2 chip. This provides both security (full disk encryption) and convenience (automatic decryption at boot when the system integrity is intact).

## Features

- 🔒 Automates LUKS encryption setup for Ubuntu systems
- 🔑 Binds LUKS decryption to TPM2 chip
- 💻 Supports both BIOS and UEFI systems
- 🚀 Configures initramfs for TPM2-backed automatic decryption
- 🛡️ Includes recovery options and safety checks

## Prerequisites

- Ubuntu 20.04 LTS or newer (recommended)
- System with TPM2 chip (most modern systems)
- Root access
- `tpm2-tools` package installed (will be installed automatically if missing)

## Installation & Usage

```bash
# Clone repository
git clone https://github.com/ssahani/ubuntu-disk-encryptor.git
cd ubuntu-disk-encryptor

# Make script executable
chmod +x tpm2-luks-setup.sh

# Run with options
sudo ./tpm2-luks-setup.sh -d /dev/nvme0n1 -p "your_recovery_passphrase"
```

## Workflow Overview

1. **Initialization**: Checks system requirements and TPM2 availability
2. **Encryption**: Sets up LUKS encryption on target disk
3. **Key Binding**: Creates TPM2-bound decryption key
4. **Configuration**: Updates initramfs and boot components
5. **Recovery**: Generates fallback mechanisms

## Recovery Options

If automatic decryption fails:
1. Use the recovery passphrase set during installation
2. Use the recovery keyfile saved to `/etc/tpm2-luks/`

## Security Considerations

![Security Warning](assets/warning-icon.png) **Important Warnings**:
- This will encrypt your disk - ensure you have backups
- The recovery passphrase is crucial - don't lose it
- Test in a non-production environment first
- TPM2 binding means the disk won't unlock if hardware changes

## Contributing

Pull requests are welcome. For major changes, please open an issue first.

## License

[MIT](https://choosealicense.com/licenses/mit/)
