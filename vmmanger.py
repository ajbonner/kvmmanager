#!/usr/bin/env python3

import asyncio
import random
import re
import subprocess
import sys
import time
from typing import AsyncIterator
import yaml


def read_yaml(yaml_path):
    with open(yaml_path, 'r', encoding='utf8') as stream:
        contents = yaml.safe_load(stream)
    return contents


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


def cleanup_managedsaves():
    domains = get_domain_list()
    for domain in domains:
         print(f"Removing managed save for {domain}")
         run_command(["virsh", "managedsave-remove", domain])


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


def delete_vms():
    print("Starting virtual machine cleanup...")
    cleanup_managedsaves()
    cleanup_domains()
    cleanup_volumes()
    print("Cleanup complete!")


def generate_hostname():
    """
    Generate a random hostname with format 'mns-(adjective)-(australian-mammal)'
    """
    adjectives = read_yaml('conf/active-adjectives.yml')
    mascots = read_yaml('conf/australian-animals.yml')

    adjective = random.choices(adjectives, k=1)[0]
    mascot = random.choices(mascots, k=1)[0]

    return f"mns-{adjective}-{mascot}"


async def read_stream(stream: asyncio.StreamReader, prefix: str = "") -> AsyncIterator[str]:
    """
    Read from a StreamReader line by line.
    """
    while True:
        line = await stream.readline()
        if not line:
            break
        line = line.decode().rstrip()
        yield line


async def create_vm(hostname):
    start_time = time.time()
    image = 'media/AlmaLinux-9-latest-x86_64-minimal.iso'
    cmd = [
        'virt-install',
        '--name', hostname,
        '--ram', '2048',
        '--vcpus', '2',
        '--disk', f'size=20',
        '--os-variant', 'almalinux9',
        # '--location', 'https://mirror.rackspace.com/almalinux/9/BaseOS/x86_64/os/',
        '--location', image,
        '--network', 'bridge=br0,model=virtio',
        '--graphics', 'none',
        '--extra-args', 'console=ttyS0 inst.text inst.ks=file:/ks.cfg ip=dhcp',
        '--initrd-inject=ks.cfg',
        '--noautoconsole',
        '--wait=-1'
    ]

    process = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Create prefix for this command's output
    prefix = f"[{hostname}] "
    captured_stdout = []
    captured_stderr = []

    # Process stdout and stderr concurrently
    async def handle_stream(stream: asyncio.StreamReader, is_stderr: bool):
        async for line in read_stream(stream):
            # Store in appropriate list
            if is_stderr:
                captured_stderr.append(line)
                print(f"{prefix}ERR> {line}", file=sys.stderr, flush=True)
            else:
                captured_stdout.append(line)
                print(f"{prefix}OUT> {line}", flush=True)

    # Create tasks for handling both streams
    stdout_task = asyncio.create_task(handle_stream(process.stdout, False))
    stderr_task = asyncio.create_task(handle_stream(process.stderr, True))

    # Wait for the process to complete and streams to be fully read
    await asyncio.gather(stdout_task, stderr_task)
    await process.wait()

    # stdout, stderr = await process.communicate()
    return {
        'hostname': hostname,
        'command': ' '.join(cmd),
        'stdout': '\n'.join(captured_stdout),
        'stderr': '\n'.join(captured_stderr),
        'return_code': process.returncode,
        'execution_time': time.time() - start_time
    }


def get_vm_mac(hostname):
    """Get MAC address of VM using virsh domiflist"""
    try:
        result = run_command(['virsh', 'domiflist', hostname])

        # Parse the output to get MAC address
        for line in result.split('\n'):
            if 'br0' in line:
                return line.split()[4]  # MAC address field
        return None
    except subprocess.CalledProcessError as e:
        print(f"Error getting MAC: {str(e)}")
        return None


    """Get IP address using virsh domipaddr with arp source"""
    try:
        result = run_command(['virsh', '-q', 'domifaddr', hostname, '--source', 'agent'])
        for row in result.split("\n"): 
            if "enp" in row and "ipv4" in row:
                parts = list(filter(None, map(lambda x: x.strip(), row.split(" "))))
                ip_address = parts[3] if len(parts) >= 4 else None
                return ip_address.partition('/')[0] if ip_address else None

    except subprocess.CalledProcessError as e:
        print(f"Error getting IP Address: {str(e)}")

    return None


def get_ip_from_mac(mac):
    """Get IP address by scanning the network for the MAC address"""
    try:
        # Get the br0 interface subnet
        result = run_command(['ip', 'addr', 'show', 'br0'])
        
        # Extract IP/subnet using regex
        match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', result)
        if not match:
            return "Bridge IP not found"
            
        network = match.group(1)
        network_prefix = '.'.join(network.split('.')[:-1])  # Get first three octets
        
        # Try nmap first (commonly available on Arch)
        try:
            scan_result = run_command(['nmap', '-sn', f'{network_prefix}.0/24'])
            # Update ARP cache
            subprocess.run(['sudo', 'ip', 'neigh', 'flush', 'all'], check=True)
        except subprocess.CalledProcessError:
            pass  # Continue to arp cache check if nmap fails
        
        # Check arp cache
        arp_result = run_command(['ip', 'neigh', 'show'])
        
        # Find the IP address matching our MAC
        for line in arp_result.split('\n'):
            if mac.lower() in line.lower():
                return line.split()[0]  # IP address field
        
        return "IP not found"
    except subprocess.CalledProcessError as e:
        return f"Error scanning network: {str(e)}"
    

def wait_for_ips(hostnames, timeout=120):
    print("\nWaiting for VMs to boot and obtain IP addresses...")
    time_taken = 0
    ips_found = {}
    
    while len(ips_found.keys()) < 3 and time_taken < timeout:
        time.sleep(5) 
        time_taken += 5
        for hostname in hostnames:
            ip = get_ip_for_host(hostname)
            ips_found[ip] = True


def display_summary(hostnames):
    print("\nVM Information:")
    print("-" * 50)
    for hostname in hostnames:
        mac = get_vm_mac(hostname)
        if mac:
            ip = get_ip_for_host(hostname)
            print(f"Hostname: {hostname}")
            print(f"MAC Address: {mac}")
            print(f"IP Address: {ip}")
        else:
            print(f"Hostname: {hostname}")
            print("Could not retrieve MAC address")
        print("-" * 50)


async def create_vms(num_vms_required: int):
    # Check if br0 exists
    try:
        subprocess.run(['ip', 'link', 'show', 'br0'], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        print("Error: br0 bridge interface not found. Please ensure it's created first.")
        return

    jobs = []
    for _ in range(num_vms_required):
        hostname = generate_hostname()
        print(f"Creating VM: {hostname}")
        jobs.append(create_vm(hostname))
        
    results = await asyncio.gather(*jobs, return_exceptions=True)
    vms = []
    for result in results:
        if isinstance(result, Exception):
            print(f"An exception was thrown while creating VM: {result}")
            continue
        elif isinstance(result, dict):
            if result['return_code'] == 0:
                print(f"Successfully created VM: {result['hostname']} in {result['execution_time']:.2f} seconds")
                vms.append((result['hostname'], result))
            else:
                print(f"Error creating VM: {result['hostname']} with error: {result['stderr']}")
        else:
            raise RuntimeError(f"Unexpected result: {result}")

    new_hostnames = list(map(lambda x: x[0], vms))
    wait_for_ips(new_hostnames)
    display_summary(new_hostnames)


def print_help_and_die():
    print(f"Usage {sys.argv[0]} (create <num vms>) | status [vm name] | destroy")
    sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_help_and_die()
        
    command = sys.argv[1]

    if command == 'create':
        asyncio.run(create_vms(int(sys.argv[2])))
    elif command == 'destroy':
        delete_vms()
    elif command == 'status':
        display_summary()
    else:
        print_help_and_die()
