# Project: ErisLITE
# Module: network_tools.py
# Author: Liam Piper-Brandon
# Version: 0.7
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-29
# Description: Network utility tools: IPs, gateway, DNS, ping, traceroute, WHOIS, connections.

import psutil, socket, platform, subprocess, os, re

from datetime import datetime

from rich.table import Table
from rich.console import Console
from rich.prompt import Prompt
from rich.markdown import Markdown
from rich.panel import Panel

from ui.utils import clear_screen, show_header, pause_return


console = Console()

# Commonly used ports for basic service identification
COMMON_PORTS = {
    22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL",
}

# Extended known ports for more detailed service identification
EXTENDED_PORTS = {
    21: "FTP", 135: "RPC", 139: "NetBIOS", 445: "SMB",
    1433: "SQL Server", 1521: "Oracle DB", 3389: "RDP", 5432: "PostgreSQL",
    9000: "Web UI"
}

# Combine known ports for lookup
KNOWN_PORTS = {**COMMON_PORTS, **EXTENDED_PORTS}

# Additional utility functions for network tools. These include parsing and classifying network listeners, extracting process information, and formatting results for display or API output. They help provide more context and risk assessment for the network-related findings in the Basalt agent.
def show_ips():
    clear_screen()
    show_header("NETWORK INTERFACES")

    table = Table(title="Active Interfaces", show_lines=True)
    table.add_column("Interface", style="cyan", no_wrap=True)
    table.add_column("Address Family", style="white")
    table.add_column("IP Address", style="green")

    interfaces = psutil.net_if_addrs()

    for iface, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                family = "IPv4"
            elif addr.family == socket.AF_INET6:
                family = "IPv6"
            else:
                continue  # Skip MAC, loopback, etc.

            table.add_row(iface, family, addr.address)

    if table.row_count == 0:
        from rich.console import Console
        console = Console()
        console.print("[yellow]No active IP addresses found.[/]")
    else:
        from rich.console import Console
        console = Console()
        console.print(table)

    pause_return()

# Show default gateway information by parsing the output of 'ip route' on Linux. This provides details about the default gateway IP and the associated network interface.
def show_gateway():
    clear_screen()
    show_header("DEFAULT GATEWAY")

    system = platform.system()

    try:
        if system == "Linux":
            result = subprocess.run(["ip", "route"], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if line.startswith("default"):
                    parts = line.split()
                    gateway = parts[2]
                    interface = parts[4] if len(parts) > 4 else "unknown"
                    console.print(f"[bold white]Gateway:[/] {gateway}")
                    console.print(f"[bold white]Interface:[/] {interface}")
                    break
            else:
                console.print("[yellow]No default gateway found.[/]")
        else:
            console.print(f"[red]Unsupported OS:[/] {system}")
    except Exception as e:
        console.print(f"[red]Error fetching gateway info:[/] {e}")

    pause_return()

# Show configured DNS servers by reading /etc/resolv.conf on Linux. This lists the nameservers that the system is configured to use for DNS resolution.
def show_dns():
    clear_screen()
    show_header("DNS SERVERS")

    try:
        nameservers = []

        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) > 1:
                        nameservers.append(parts[1])

        if nameservers:
            console.print("[bold]Configured DNS Servers:[/]\n", style="cyan")
            for ns in nameservers:
                console.print(f"• [green]{ns}[/]")
        else:
            console.print("[yellow]No DNS servers found in /etc/resolv.conf[/]")

    except Exception as e:
        console.print(f"[red]Error reading DNS info:[/] {e}")

    pause_return()

# Ping a host using the system's ping utility. This allows the user to check connectivity to a specific IP address or hostname and see the results in a formatted way.
def ping_host():
    clear_screen()
    show_header("PING A HOST")

    target = Prompt.ask("Enter IP or hostname to ping", default="8.8.8.8")

    try:
        system = platform.system()

        if system == "Windows":
            cmd = ["ping", "-n", "4", target]
        else:
            cmd = ["ping", "-c", "4", target]

        console.print(f"\n[bold]Pinging:[/] {target}...\n", style="cyan")
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            console.print(result.stdout, style="green")
        else:
            console.print("[red]Ping failed.[/]")
            console.print(result.stdout or result.stderr)

    except KeyboardInterrupt:
        console.print("\n[red]Ping canceled by user.[/]")
    except Exception as e:
        console.print(f"[red]Error running ping:[/] {e}")

    pause_return()

# Show active network connections by parsing the output of 'ss -tunp' on Linux. This provides a table of active TCP and UDP connections, including local and remote addresses, connection state, and associated processes when available.
def show_active_connections():
    clear_screen()
    show_header("ACTIVE CONNECTIONS")

    try:
        # Run ss
        result = subprocess.run(
            ["ss", "-tunp"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        lines = result.stdout.strip().splitlines()
        if not lines or len(lines) < 2:
            console.print("[yellow]No active connections found.[/]")
            pause_return()
            return

        # Prepare Rich table
        table = Table(show_header=True, header_style="bold magenta", box=None)
        table.add_column("Proto", style="cyan", no_wrap=True)
        table.add_column("Local Addr", style="white", no_wrap=False, min_width=22, overflow="fold")
        table.add_column("L-Port", style="white", no_wrap=True)
        table.add_column("Remote Addr", style="white", no_wrap=False, min_width=20, overflow="fold")
        table.add_column("R-Port", style="white", no_wrap=True)
        table.add_column("State", style="green", no_wrap=True)
        table.add_column("PID", style="yellow", no_wrap=True)

        total_connections = 0
        unique_remotes = set()

        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 6:
                continue

            proto = parts[0]
            state = parts[1]
            local_raw = parts[4]
            remote_raw = parts[5]

            if ":" in local_raw:
                l_addr, l_port = ":".join(local_raw.split(":")[:-1]), local_raw.split(":")[-1]
            else:
                l_addr, l_port = local_raw, "-"

            if ":" in remote_raw:
                r_addr, r_port = ":".join(remote_raw.split(":")[:-1]), remote_raw.split(":")[-1]
            else:
                r_addr, r_port = remote_raw, "-"

            if r_addr != "*" and r_addr != "0.0.0.0":
                unique_remotes.add(r_addr)

            pid = "-"
            if "users:(" in line:
                proc_info = line.split("users:(")[-1]
                proc_info = proc_info.rstrip(")")
                proc_parts = proc_info.split(",")
                for p in proc_parts:
                    if "pid=" in p:
                        pid = p.split("=")[-1]

            table.add_row(proto, l_addr, l_port, r_addr, r_port, state, pid)
            total_connections += 1

        if table.row_count == 0:
            console.print("[yellow]No active connections found.[/]")
        else:
            console.print(table)
            console.print(
                f"\n[green]Total Connections:[/] {total_connections}    "
                f"[cyan]Unique Remote Hosts:[/] {len(unique_remotes)}"
            )

            # Prompt to save snapshot
            save = Prompt.ask(
                "\n[bold cyan]Save this snapshot to a log file?[/] (y/n)",
                choices=["y", "n"],
                default="n"
            )
            if save == "y":
                # Ensure the directory exists
                log_dir = "data/logs/network_connections"
                os.makedirs(log_dir, exist_ok=True)

                # Build the filename
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = os.path.join(log_dir, f"network_connections_{timestamp}.log")

                # Save the raw ss output
                with open(filename, "w") as f:
                    f.write(result.stdout)

                console.print(f"[green]Snapshot saved to:[/] {filename}")

    except Exception as e:
        console.print(f"[red]Error retrieving connections:[/] {e}")

    pause_return()

# Show the external IP address by querying an external service. This allows the user to see the public IP address of the system as seen from the internet, which can be useful for various network diagnostics and awareness.
def show_external_ip():
    clear_screen()
    show_header("EXTERNAL IP ADDRESS")

    try:
        result = subprocess.run(
            ["curl", "-s", "https://ifconfig.me"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        ip = result.stdout.strip()
        if ip:
            console.print(f"[bold green]Your public IP:[/] {ip}")
        else:
            console.print("[yellow]Could not retrieve external IP.[/]")
    except Exception as e:
        console.print(f"[red]Error retrieving external IP:[/] {e}")

    pause_return()

# Trace route to a host using the system's tracepath utility. This allows the user to see the network path taken to reach a specific IP address or hostname, which can help identify network issues or understand the route traffic takes from the system to the target.
def trace_route():
    clear_screen()
    show_header("TRACE ROUTE")

    host = Prompt.ask("Enter a host to trace route to", default="google.com")

    console.print(f"\n[cyan]Tracing route to:[/] {host}\n")

    try:
        result = subprocess.run(
            ["tracepath", host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20
        )
        console.print(result.stdout)
    except subprocess.TimeoutExpired:
        console.print("[yellow]Tracepath timed out after 20 seconds.[/]")
    except KeyboardInterrupt:
        console.print("\n[red]Tracepath interrupted by user.[/]")
    except Exception as e:
        console.print(f"[red]Error running tracepath:[/] {e}")

    pause_return()

# WHOIS lookup for a domain or IP address. This allows the user to retrieve registration and ownership information about a specific domain or IP, which can be useful for reconnaissance and understanding the entities behind network resources.
def whois_lookup():
    clear_screen()
    show_header("WHOIS LOOKUP")

    target = Prompt.ask("Enter a domain or IP for WHOIS lookup", default="example.com")
    console.print(f"\n[cyan]WHOIS Lookup for:[/] {target}\n")

    try:
        result = subprocess.run(
            ["whois", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        output = result.stdout

        # Define regex fields to extract
        summary_fields = {
            "Domain": r"Domain Name:\s*(.+)",
            "Registrar": r"Registrar:\s*(.+)",
            "Created": r"Creation Date:\s*(.+)",
            "Updated": r"Updated Date:\s*(.+)",
            "Expires": r"Expiry Date:\s*(.+)|Registry Expiry Date:\s*(.+)",
            "DNSSEC": r"DNSSEC:\s*(.+)",
        }

        parsed_summary = {}
        for label, pattern in summary_fields.items():
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                # Group 1 is the first match, fallback to group 2 if available
                value = match.group(1) or match.group(2)
                value = value.strip()

                # Color DNSSEC status
                if label == "DNSSEC":
                    if value.lower() == "signed":
                        value = f"[green]{value}[/]"
                    else:
                        value = f"[red]{value}[/]"

                # Color expiration if within 30 days
                if label == "Expires":
                    try:
                        expiry = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
                        days_left = (expiry - datetime.utcnow()).days
                        if days_left < 30:
                            value = f"[red]{value}[/] [bold red](Expiring Soon)[/]"
                        else:
                            value = f"[green]{value}[/]"
                    except Exception:
                        pass

                parsed_summary[label] = value

        if parsed_summary:
            lines = [f"[bold]{k}:[/] {v}" for k, v in parsed_summary.items()]
            summary_panel = Panel("\n".join(lines), title=f"[green]WHOIS Summary", border_style="cyan")
            console.print(summary_panel)
        else:
            console.print("[dim]No summary fields extracted from WHOIS data.[/]")

    except FileNotFoundError:
        console.print("[red]The 'whois' utility is not installed. Please install it with your package manager.[/]")
    except Exception as e:
        console.print(f"[red]Error performing WHOIS lookup:[/] {e}")

    pause_return()
