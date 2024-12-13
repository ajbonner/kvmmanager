# VM Manager

A Python-based command-line tool for managing KVM virtual machines. This tool automates the creation, monitoring, and cleanup of virtual machines using libvirt.

## Features

- Generate random, unique hostnames using Australian animals and descriptive adjectives
- Create multiple VMs concurrently using async/await
- Automatic IP address detection and monitoring
- Bridge network support (br0)
- Complete VM cleanup functionality
- VM status monitoring

## Prerequisites

- Python 3.7+
- KVM/QEMU
- libvirt
- Bridge networking configured (br0)
- AlmaLinux 9 ISO image

### Required Python Packages

- PyYAML
- asyncio
- typing

### System Requirements

- Configured bridge interface (br0)
- Sufficient disk space for VM creation
- Root/sudo privileges for VM management

## Installation

1. Clone the repository
2. Ensure the script is executable:
   ```bash
   chmod +x vmmanger.py
   ```
4. [Download](https://mirror.server.net/almalinux/9.5/isos/x86_64/) an AlmaLinux 9 Installation ISO
5. Place the AlmaLinux ISO in the `media/` directory
6. Ensure configuration files exist in `conf/` directory:
   - `active-adjectives.yml`
   - `australian-animals.yml`

## Usage

```bash
./vmmanger.py [command] [options]
```

### Available Commands

1. Create VMs:
   ```bash
   ./vmmanger.py create <number_of_vms>
   ```

2. Destroy all VMs:
   ```bash
   ./vmmanger.py destroy
   ```

3. Check VM Status:
   ```bash
   ./vmmanger.py status
   ```

## VM Configuration

Each VM is created with:
- 2048MB RAM
- 2 vCPUs
- 20GB disk space
- Bridge networking (br0)
- AlmaLinux 9 minimal installation
- Serial console access

## Network Configuration

- Uses bridge networking (br0)
- Automatically assigns IP addresses via DHCP
- Supports MAC address to IP mapping
- Monitors VM IP assignment

## Cleanup

The destroy command performs complete cleanup:
- Removes managed saves
- Destroys running VMs
- Undefines VM configurations
- Deletes associated storage volumes

## Error Handling

- Provides detailed error messages
- Captures both stdout and stderr
- Includes execution time tracking
- Handles concurrent operations safely

## Notes

- Requires root/sudo privileges for most operations
- Assumes AlmaLinux 9 ISO is available in the media directory
- Expects bridge interface br0 to be configured
- Uses Kickstart configuration for automated installation

## License
MIT