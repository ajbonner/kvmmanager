#!/usr/bin/env python3
import subprocess


def run_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing command {' '.join(command)}: {e}")
        return ""


def get_domain_list():
    """Get list of all virtual machine domains"""
    output = run_command(["virsh", "-q", "list", "--all"])
    return [line.split()[1] for line in output.splitlines() if line.strip()]


def get_volume_list():
    """Get list of all storage volumes in default pool"""
    output = run_command(["virsh", "-q", "vol-list", "default"])
    return [line.split()[1] for line in output.splitlines() if line.strip()]


def cleanup_domains():
    """Stop and undefine all virtual machine domains"""
    domains = get_domain_list()
    for domain in domains:
        print(f"Cleaning up domain: {domain}")
        run_command(["virsh", "destroy", domain])
        run_command(["virsh", "undefine", domain])


def cleanup_volumes():
    """Delete all volumes in the default storage pool"""
    volumes = get_volume_list()
    for volume in volumes:
        print(f"Deleting volume: {volume}")
        run_command(["virsh", "vol-delete", volume])


def main():
    print("Starting virtual machine cleanup...")
    cleanup_domains()
    cleanup_volumes()
    print("Cleanup complete!")


if __name__ == "__main__":
    main()
