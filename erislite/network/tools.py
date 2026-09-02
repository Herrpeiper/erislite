# Project: ErisLITE
# Module: tools.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: Network utilities: addressing, DNS, diagnostics, WHOIS, and connections.

import os, platform, psutil, re, socket, subprocess

from datetime import datetime

from rich import box
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION, NETWORK_LOG_DIR
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, pause_return


COMMON_PORTS = {
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
}

EXTENDED_PORTS = {
    21: "FTP",
    135: "RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "SQL Server",
    1521: "Oracle DB",
    3389: "RDP",
    5432: "PostgreSQL",
    9000: "Web UI",
}

KNOWN_PORTS = {**COMMON_PORTS, **EXTENDED_PORTS}


def show_network_header(title: str) -> None:
    header = Panel(
        Text.from_markup("[dim]Network utility[/]   [dim]Module:[/] [white]EL-NET[/]"),
        title=f"[bold cyan]{title}[/]",
        subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
        border_style="cyan",
        box=box.SQUARE,
        padding=(0, 1),
    )
    console.print(header)
    console.print()


def show_ips() -> None:
    clear_screen()
    show_network_header("NETWORK INTERFACES")

    table = Table(
        title="[italic cyan]Active Interfaces[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )
    table.add_column("Interface", style="cyan", no_wrap=True)
    table.add_column("Family", style="white")
    table.add_column("IP Address", style="white")

    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                family = "IPv4"
            elif addr.family == socket.AF_INET6:
                family = "IPv6"
            else:
                continue

            table.add_row(iface, family, addr.address)

    console.print(
        table if table.row_count else "[yellow]No active IP addresses found.[/]"
    )
    pause_return()


def show_gateway() -> None:
    clear_screen()
    show_network_header("DEFAULT GATEWAY")

    try:
        if platform.system() != "Linux":
            console.print(f"[red]Unsupported OS:[/] {platform.system()}")
            pause_return()
            return

        result = subprocess.run(["ip", "route"], capture_output=True, text=True)

        for line in result.stdout.splitlines():
            if not line.startswith("default"):
                continue

            parts = line.split()
            gateway = parts[2]
            interface = parts[4] if len(parts) > 4 else "unknown"

            console.print(f"[cyan]Gateway:[/]   [white]{gateway}[/]")
            console.print(f"[cyan]Interface:[/] [white]{interface}[/]")
            break
        else:
            console.print("[yellow]No default gateway found.[/]")

    except Exception as e:
        console.print(f"[red]Error fetching gateway info:[/] {e}")

    pause_return()


def show_dns() -> None:
    clear_screen()
    show_network_header("DNS SERVERS")

    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8") as file:
            nameservers = [
                line.split()[1]
                for line in file
                if line.strip().startswith("nameserver") and len(line.split()) > 1
            ]

        if nameservers:
            console.print("[bold cyan]Configured DNS Servers[/]")
            for nameserver in nameservers:
                console.print(f"  [white]{nameserver}[/]")
        else:
            console.print("[yellow]No DNS servers found in /etc/resolv.conf[/]")

    except Exception as e:
        console.print(f"[red]Error reading DNS info:[/] {e}")

    pause_return()


def ping_host() -> None:
    clear_screen()
    show_network_header("PING HOST")

    target = Prompt.ask("[cyan]Target[/]", default="8.8.8.8")

    try:
        cmd = (
            ["ping", "-n", "4", target]
            if platform.system() == "Windows"
            else ["ping", "-c", "4", target]
        )
        console.print(f"\n[cyan]Pinging[/] [white]{target}[/]\n")

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            console.print(result.stdout)
        else:
            console.print("[red]Ping failed.[/]")
            console.print(result.stdout or result.stderr)

    except KeyboardInterrupt:
        console.print("\n[yellow]Ping canceled.[/]")
    except Exception as e:
        console.print(f"[red]Error running ping:[/] {e}")

    pause_return()


def show_active_connections() -> None:
    clear_screen()
    show_network_header("ACTIVE CONNECTIONS")

    try:
        result = subprocess.run(["ss", "-tunp"], capture_output=True, text=True)
        lines = result.stdout.strip().splitlines()

        if len(lines) < 2:
            console.print("[yellow]No active connections found.[/]")
            pause_return()
            return

        table = Table(
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            show_edge=False,
            padding=(0, 1),
        )
        table.add_column("Proto", style="cyan", no_wrap=True)
        table.add_column("Local Addr", style="white", min_width=18, overflow="fold")
        table.add_column("L-Port", style="white", no_wrap=True)
        table.add_column("Remote Addr", style="white", min_width=18, overflow="fold")
        table.add_column("R-Port", style="white", no_wrap=True)
        table.add_column("State", style="green", no_wrap=True)
        table.add_column("PID", style="yellow", no_wrap=True)

        total_connections = 0
        unique_remotes = set()

        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 6:
                continue

            proto, state = parts[0], parts[1]
            local_raw, remote_raw = parts[4], parts[5]

            l_addr, l_port = (
                (":".join(local_raw.split(":")[:-1]), local_raw.split(":")[-1])
                if ":" in local_raw
                else (local_raw, "-")
            )
            r_addr, r_port = (
                (":".join(remote_raw.split(":")[:-1]), remote_raw.split(":")[-1])
                if ":" in remote_raw
                else (remote_raw, "-")
            )

            if r_addr not in {"*", "0.0.0.0"}:
                unique_remotes.add(r_addr)

            pid = "-"
            if "users:(" in line:
                for part in line.split("users:(")[-1].rstrip(")").split(","):
                    if "pid=" in part:
                        pid = part.split("=")[-1]

            table.add_row(proto, l_addr, l_port, r_addr, r_port, state, pid)
            total_connections += 1

        if table.row_count == 0:
            console.print("[yellow]No active connections found.[/]")
            pause_return()
            return

        console.print(table)
        console.print(
            f"\n[cyan]Connections:[/] [white]{total_connections}[/]   "
            f"[cyan]Remote Hosts:[/] [white]{len(unique_remotes)}[/]"
        )

        save = Prompt.ask(
            "\n[cyan]Save snapshot?[/]",
            choices=["y", "n"],
            default="n",
        )

        if save == "y":
            log_dir = NETWORK_LOG_DIR
            os.makedirs(log_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(log_dir, f"network_connections_{timestamp}.log")

            with open(filename, "w", encoding="utf-8") as file:
                file.write(result.stdout)

            console.print(f"[green]Snapshot saved:[/] {filename}")

    except Exception as e:
        console.print(f"[red]Error retrieving connections:[/] {e}")

    pause_return()


def show_external_ip() -> None:
    clear_screen()
    show_network_header("EXTERNAL IP ADDRESS")

    try:
        result = subprocess.run(
            ["curl", "-s", "https://ifconfig.me"],
            capture_output=True,
            text=True,
        )

        ip = result.stdout.strip()

        if ip:
            console.print(f"[cyan]Public IP:[/] [white]{ip}[/]")
        else:
            console.print("[yellow]Could not retrieve external IP.[/]")

    except Exception as e:
        console.print(f"[red]Error retrieving external IP:[/] {e}")

    pause_return()


def trace_route() -> None:
    clear_screen()
    show_network_header("TRACE ROUTE")

    host = Prompt.ask("[cyan]Target[/]", default="google.com")
    console.print(f"\n[cyan]Tracing route to[/] [white]{host}[/]\n")

    try:
        result = subprocess.run(
            ["tracepath", host],
            capture_output=True,
            text=True,
            timeout=20,
        )
        console.print(result.stdout)

    except subprocess.TimeoutExpired:
        console.print("[yellow]Tracepath timed out after 20 seconds.[/]")
    except KeyboardInterrupt:
        console.print("\n[yellow]Tracepath interrupted.[/]")
    except Exception as e:
        console.print(f"[red]Error running tracepath:[/] {e}")

    pause_return()


def whois_lookup() -> None:
    clear_screen()
    show_network_header("WHOIS LOOKUP")

    target = Prompt.ask("[cyan]Domain or IP[/]", default="example.com")

    try:
        result = subprocess.run(["whois", target], capture_output=True, text=True)
        output = result.stdout

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
            if not match:
                continue

            value = (match.group(1) or match.group(2)).strip()

            if label == "DNSSEC":
                value = (
                    f"[green]{value}[/]"
                    if value.lower() == "signed"
                    else f"[red]{value}[/]"
                )

            elif label == "Expires":
                try:
                    expiry = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
                    days_left = (expiry - datetime.utcnow()).days
                    value = (
                        f"[red]{value}[/] [bold red](Expiring Soon)[/]"
                        if days_left < 30
                        else f"[green]{value}[/]"
                    )
                except Exception:
                    pass

            parsed_summary[label] = value

        if parsed_summary:
            lines = [
                f"[cyan]{key}:[/] {value}" for key, value in parsed_summary.items()
            ]
            console.print(
                Panel(
                    "\n".join(lines),
                    title="[bold cyan]WHOIS Summary[/]",
                    border_style="cyan",
                    box=box.ROUNDED,
                )
            )
        else:
            console.print("[dim]No summary fields extracted from WHOIS data.[/]")

    except FileNotFoundError:
        console.print("[red]The 'whois' utility is not installed.[/]")
    except Exception as e:
        console.print(f"[red]Error performing WHOIS lookup:[/] {e}")

    pause_return()
