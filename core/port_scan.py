# Project: ErisLITE
# Module: port_scan.py
# Author: Liam Piper-Brandon
# Version: 1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-04-05
# Description: TCP port scanner: scans common ports, identifies services, generates reports.

import socket

# Define common ports and their associated services for identification
COMMON_PORTS = {
    20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS"
}

# Extended port list for more comprehensive scanning
EXTENDED_PORTS = {
    3306: "MySQL", 3389: "RDP", 5900: "VNC",
    6379: "Redis", 8080: "HTTP Proxy"
}

# Function to scan a single port on the target
def scan_port(target, port):
    """Scan a single port on the target."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                return True
    except Exception as e:
        print(f"Error scanning port {port} on {target}: {e}")
    return False

# Note: Scanning all 65535 ports can be time-consuming, so we focus on common ports for efficiency.
def scan_common_ports(target):
    """Scan common ports on the target."""
    open_ports = []
    for port in range(1, 1025):
        if scan_port(target, port):
            open_ports.append(port)
    return open_ports

# Service identification based on open ports
def identify_services(ports):
    """Identify services based on open ports."""
    from .network_tools import COMMON_PORTS, EXTENDED_PORTS
    services = {}
    for port in ports:
        service = COMMON_PORTS.get(port) or EXTENDED_PORTS.get(port) or "Unknown"
        services[port] = service
    return services

# Report generation for identified services
def generate_report(target, services):
    """Generate a report of open ports and identified services."""
    report = f"Port Scan Report for {target}\n"
    report += "=" * 40 + "\n"
    for port, service in services.items():
        report += f"Port {port}: {service}\n"
    return report

if __name__ == "__main__":
    target = input("Enter the target IP address or hostname: ")
    print(f"Scanning {target} for common ports...")
    open_ports = scan_common_ports(target)
    if open_ports:
        print(f"Open ports found: {open_ports}")
        services = identify_services(open_ports)
        report = generate_report(target, services)
        print(report)
    else:
        print("No open ports found.")