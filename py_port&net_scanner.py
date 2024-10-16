import socket
import argparse
from datetime import datetime
from ipaddress import ip_address, ip_network
from concurrent.futures import ThreadPoolExecutor
import subprocess
import sys


def banner(target, state="begin", start_time=None):
    if state == "begin":
        print("-" * 50)
        print(f"Scanning Target: {target}")
        print(f"Scanning started at: "
              f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 50)
    elif state == "end" and start_time is not None:
        end_time = datetime.now()
        elapsed_time = end_time - start_time
        seconds = elapsed_time.total_seconds()
        formatted_time = "{:.0f}m {:.3f}s".format(seconds // 60, seconds % 60)
        print("-" * 50)
        print(f"Scanning finished at: "
              f"{end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Elapsed time: {formatted_time}")
        print("-" * 50)


def check_ip(ip):
    try:
        ip_address(ip)
        return ip
    except ValueError:
        print("Invalid IP address format.")
        sys.exit()


def check_network(network):
    try:
        ip_network(network)
        return network
    except ValueError:
        print("Invalid network format.")
        sys.exit()


def scan_port(target, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)  # Timeout shortened to speed up scanning
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"Port {port} is open")


def scan_ports(target, max_workers=100):
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for port in range(1, 65535):
                executor.submit(scan_port, target, port)
    except KeyboardInterrupt:
        print("\n Exiting Program!")
        sys.exit()


def ping_host(ip):
    result = subprocess.run(
        ['ping', '-c', '1', '-W', '1', str(ip)],
        stdout=subprocess.DEVNULL
    )
    if result.returncode == 0:
        print(f"Host {ip} is active")


def scan_network(network, max_workers=100):
    print(f"Scanning network: {network}")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for ip in ip_network(network).hosts():
            executor.submit(ping_host, ip)


def execute_scan(mode, target):
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
