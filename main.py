import socket
import sys
import argparse
import re
from datetime import datetime
from ipaddress import ip_network
import subprocess


def banner(target):
    print("-" * 50)
    print("Scanning Target: " + target)
    print("Scanning started at: " + str(datetime.now()))
    print("-" * 50)


def check_ip(ip):
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        parts = ip.split(".")
        for part in parts:
            if int(part) < 0 or int(part) > 255:
                print("Invalid IP address format.")
                sys.exit()
        return ip
    else:
        print("Invalid IP address format.")
        sys.exit()


def check_network(network):
    try:
        ip_network(network)
        return network
    except ValueError:
        print("Invalid network format.")
        sys.exit()


def scan_ports(target):
    try:
        # will scan ports between 1 to 65,535
        for port in range(1, 65535):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)

            # returns an error indicator
            result = s.connect_ex((target, port))
            if result == 0:
                print("Port {} is open".format(port))
            s.close()

    except KeyboardInterrupt:
        print("\n Exiting Program !!!!")
        sys.exit()
    except socket.gaierror:
        print("\n Hostname Could Not Be Resolved !!!!")
        sys.exit()
    except socket.error:
        print("\n Server not responding !!!!")
        sys.exit()


def scan_network(network):
    print(f"Scanning network: {network}")
    for ip in ip_network(network).hosts():
        ip_str = str(ip)
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '1', ip_str], stdout=subprocess.DEVNULL)
        if result.returncode == 0:
            print(f"Host {ip_str} is active")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Welcome to Py Port Scanner")
    parser.add_argument(
        "mode",
        choices=["host", "network"],
        help="""
            Choose scan mode: 'host' for scanning a single host,
             'network' for scanning a local network
            """
    )
    parser.add_argument(
        "target",
        help="""
            IP address to scan (for 'host' mode) or network to scan (for
             'network' mode). For example: 192.168.1.1 or 192.168.1.0/24"""
    )
    args = parser.parse_args()

    if args.mode == "host":
        target = check_ip(args.target)
        scan_ports(target)
    elif args.mode == "network":
        target = check_network(args.target)
        scan_network(target)