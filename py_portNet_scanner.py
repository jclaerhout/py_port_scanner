import argparse
import socket
import subprocess
import sys

from datetime import datetime
from ipaddress import ip_address, ip_network
from concurrent.futures import ThreadPoolExecutor


def banner(target, state="begin", start_time=None):
    """
    Displays a banner indicating the start or end of the scan.

    Args:
        target (str): The target being scanned (IP address or network).
        state (str): Indicates whether it's the start ('begin')
                     or the end ('end') of the scan.
        start_time (datetime, optional): The time when the scan started,
                                         used to calculate and display
                                         the elapsed time.
    """
    if state == "begin":
        print("#" * 50)
        print(f"Scanning Target: {target}")
        print(f"Scanning started at: "
              f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 50 + "\n")
    elif state == "end" and start_time is not None:
        end_time = datetime.now()
        elapsed_time = end_time - start_time
        seconds = elapsed_time.total_seconds()
        formatted_time = "{:.0f}m {:.3f}s".format(seconds // 60, seconds % 60)
        print("\n" + "-" * 50)
        print(f"Scanning finished at: "
              f"{end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Elapsed time: {formatted_time}")
        print("#" * 50)


def check_ip(ip):
    """
    Validates the provided IP address.

    Args:
        ip (str): The IP address to validate.
    Returns:
        str: The valid IP address.
    Raises:
        ValueError: If the IP address format is invalid.
    """
    try:
        ip_address(ip)
        return ip
    except ValueError:
        print("Invalid IP address format.")
        sys.exit()


def check_network(network):
    """
    Validates the provided network address.

    Args:
        network (str): The network address to validate.
    Returns:
        str: The valid network address.
    Raises:
        ValueError: If the network address format is invalid.
    """
    try:
        ip_network(network)
        return network
    except ValueError:
        print("Invalid network format.")
        sys.exit()


def scan_port(target, port, open_ports):
    """
    Attempts to connect to a specific port on the target machine.

    Args:
        target (str): The IP address of the target machine.
        port (int): The port number to scan.
        open_ports (list): A list that stores the open ports.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)  # Timeout shortened to speed up scanning
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"Port {port} is open")
            open_ports.append(port)


def scan_ports(target, max_workers=100):
    """
    Scans all ports (1-65535) on the target machine and lists open ports.

    Args:
        target (str): The IP address of the target machine.
        max_workers (int, optional): The maximum number of threads to use
                                     for concurrent scanning. Defaults to 100.
    Prints:
        - A message indicating no open ports were found if none are open.
        - The total number of open ports if any are found.
    """
    open_ports = []
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for port in range(1, 65535):
                executor.submit(scan_port, target, port, open_ports)
    except KeyboardInterrupt:
        print("\n Exiting Program!")
        sys.exit()

    if not open_ports:
        print("No open ports found.")
    else:
        print(f"Total open ports found: {len(open_ports)}")


def ping_host(ip, active_hosts):
    """
    Sends a ping request to the specified IP address.

    Args:
        ip (str): The IP address of the host to ping.
        active_hosts (list): A list that stores the active hosts
                             that respond to the ping.
    """
    result = subprocess.run(
        ['ping', '-c', '1', '-W', '1', str(ip)],
        stdout=subprocess.DEVNULL  # Suppresses the output of the ping command
    )
    if result.returncode == 0:
        print(f"Host {ip} is active")
        active_hosts.append(ip)


def scan_network(network, max_workers=100):
    """
    Scans a network to identify active hosts by sending ping requests
    to each IP address in the network.

    Args:
        network (str): The network address to scan (e.g., '192.168.1.0/24').
        max_workers (int, optional): The maximum number of threads to use
                                     for concurrent scanning. Defaults to 100.
    Prints:
        - A message indicating no active hosts were found if none respond.
        - The total number of active hosts if any are found.
    """
    active_hosts = []
    print(f"Scanning network: {network}")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for ip in ip_network(network).hosts():
            executor.submit(ping_host, ip, active_hosts)

    if not active_hosts:
        print("No active hosts found.")
    else:
        print(f"Total active hosts found: {len(active_hosts)}")


def execute_scan(mode, target):
    """
    Executes the scan based on the mode (host or network)
    and displays the start and end banners.

    Args:
        mode (str): The scan mode, either 'host' to scan ports or 'network'
                    to scan active hosts in a network.
        target (str): The target IP address or network to scan.
    """
    start_time = datetime.now()
    banner(target, state="begin", start_time=start_time)

    if mode == "host":
        scan_ports(target)
    elif mode == "network":
        scan_network(target)

    banner(target, state="end", start_time=start_time)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Welcome to Py Port Scanner")
    parser.add_argument(
        "mode", choices=["host", "network"],
        help="Choose scan mode: 'host' or 'network'"
    )
    parser.add_argument(
        "target",
        help=("IP address or network to scan. Example: 192.168.1.1 or "
              "192.168.1.0/24")
    )

    args = parser.parse_args()

    if args.mode == "host":
        target = check_ip(args.target)
    elif args.mode == "network":
        target = check_network(args.target)

    execute_scan(args.mode, target)
