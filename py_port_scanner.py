import socket
import argparse
from datetime import datetime
from ipaddress import ip_address
from concurrent.futures import ThreadPoolExecutor
import sys


def banner(target, state="begin", start_time=None):
    if state == "begin":
        print("-" * 50)
        print(f"Scanning target: {target}")
        print(
            (
                f"Scanning started at: "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
        )
        print("-" * 50)
    elif state == "end" and start_time is not None:
        end_time = datetime.now()
        elapsed_time = end_time - start_time
        seconds = elapsed_time.total_seconds()
        formatted_time = "{:.0f}m {:.3f}s".format(
            seconds // 60, seconds % 60
        )
        print("-" * 50)
        print(
            f"Scanning finished at: "
            f"{end_time.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        print(f"Elapsed time: {formatted_time}")
        print("-" * 50)


def check_ip(ip):
    try:
        ip_address(ip)
        return ip
    except ValueError:
        print("Invalid IP address format.")
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Welcome to Py Port Scanner")
    parser.add_argument(
        "target", help="IP address to scan. Example: 192.168.1.1"
    )
    args = parser.parse_args()

    target = check_ip(args.target)
    start_time = datetime.now()
    banner(target, state="begin")
    scan_ports(target)
    banner(target, state="end", start_time=start_time)
