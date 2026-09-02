# Project: ErisLITE
# Module: hosts.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: /etc/hosts inspection for suspicious redirects and tampering.

import ipaddress
import re

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, get_os, pause_return

HOSTS_PATH = "/etc/hosts"


CRITICAL_DOMAINS = {
    "security.ubuntu.com",
    "archive.ubuntu.com",
    "packages.debian.org",
    "deb.debian.org",
    "dl.fedoraproject.org",
    "mirrors.fedoraproject.org",
    "ocsp.digicert.com",
    "crl.globalsign.com",
    "ocsp.globalsign.com",
    "ocsp.pki.goog",
    "pki.goog",
    "telemetry.microsoft.com",
    "update.microsoft.com",
    "safebrowsing.googleapis.com",
    "safebrowsing.google.com",
    "windowsupdate.com",
    "microsoftupdate.com",
}


LOOPBACK_IPS = {
    "127.0.0.1",
    "127.0.0.2",
    "0.0.0.0",
    "::1",
}


LOCAL_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
}


WHITELIST_ENTRIES = {
    ("127.0.0.1", "localhost"),
    ("127.0.1.1", "localhost"),
    ("::1", "localhost"),
    ("::1", "ip6-localhost"),
    ("::1", "ip6-loopback"),
    ("fe00::0", "ip6-localnet"),
    ("ff00::0", "ip6-mcastprefix"),
    ("ff02::1", "ip6-allnodes"),
    ("ff02::2", "ip6-allrouters"),
}


BASE64_HOSTNAME = re.compile(
    r"^[A-Za-z0-9+/]{24,}={0,2}$"
)

VERY_LONG_HOSTNAME = re.compile(
    r"^\S{80,}$"
)


def _header() -> None:
    console.print(
        Panel(
            Text.from_markup(
                "[dim]Inspect /etc/hosts for suspicious redirects, duplicate mappings, and tampering[/]"
            ),
            title="[bold cyan]HOSTS TAMPER CHECK[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )
    console.print()


def parse_hosts():
    """
    Return:
        entries:
            list[(ip, hostname, raw_line, lineno)]

        error:
            str | None
    """
    entries = []

    try:
        with open(
            HOSTS_PATH,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:
            for lineno, raw_line in enumerate(file, 1):
                stripped = raw_line.strip()

                if not stripped or stripped.startswith("#"):
                    continue

                stripped = stripped.split("#", 1)[0].strip()

                if not stripped:
                    continue

                parts = stripped.split()

                if len(parts) < 2:
                    continue

                ip = parts[0]

                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue

                for hostname in parts[1:]:
                    entries.append(
                        (
                            ip,
                            hostname.lower(),
                            raw_line.rstrip(),
                            lineno,
                        )
                    )

    except (FileNotFoundError, PermissionError) as exc:
        return [], str(exc)

    except Exception as exc:
        return [], str(exc)

    return entries, None


def _is_critical_domain(hostname: str) -> bool:
    return any(
        hostname == domain
        or hostname.endswith("." + domain)
        for domain in CRITICAL_DOMAINS
    )


def _looks_external(hostname: str) -> bool:
    """
    Roughly distinguish external-looking FQDNs from common local aliases.
    """
    if hostname in LOCAL_HOSTNAMES:
        return False

    if hostname.endswith(
        (
            ".localhost",
            ".local",
            ".internal",
        )
    ):
        return False

    return "." in hostname


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except ValueError:
        return False


def scan_hosts():
    entries, error = parse_hosts()

    if error:
        return (
            [],
            [f"Could not read {HOSTS_PATH}: {error}"],
            ["hosts_unreadable"],
        )

    flagged = []

    for ip, hostname, raw_line, lineno in entries:
        if (ip, hostname) in WHITELIST_ENTRIES:
            continue

        reasons = []
        tags = set()

        critical = _is_critical_domain(hostname)

        # High-confidence: security/update infrastructure redirected.
        if critical:
            reasons.append(
                f"Critical domain redirected to {ip}"
            )
            tags.add("hosts_critical_redirect")

        # Loopback redirects are only interesting for external-looking names.
        # Local aliases are common and should not automatically trigger.
        if (
            ip in LOOPBACK_IPS
            and _looks_external(hostname)
            and not critical
        ):
            reasons.append(
                "External-looking hostname redirected to loopback"
            )
            tags.add("hosts_loopback_redirect")

        if VERY_LONG_HOSTNAME.search(hostname):
            reasons.append(
                "Unusually long hostname"
            )
            tags.add("hosts_suspicious_entry")

        if BASE64_HOSTNAME.fullmatch(hostname):
            reasons.append(
                "Hostname resembles encoded data"
            )
            tags.add("hosts_suspicious_entry")

        # A public-looking hostname forced to RFC1918 space may warrant review.
        if (
            _is_private_ip(ip)
            and _looks_external(hostname)
            and not ipaddress.ip_address(ip).is_loopback
        ):
            reasons.append(
                "External-looking hostname mapped to private address"
            )
            tags.add("hosts_private_redirect")

        if reasons:
            flagged.append(
                {
                    "lineno": lineno,
                    "ip": ip,
                    "hostname": hostname,
                    "raw": raw_line,
                    "reasons": reasons,
                    "tags": sorted(tags),
                }
            )

    # Duplicate hostname mappings.
    #
    # Only flag when the same hostname maps to multiple distinct,
    # non-loopback addresses. Local aliases often legitimately appear
    # across loopback/IPv4/IPv6 mappings.
    seen = {}

    for ip, hostname, raw_line, lineno in entries:
        seen.setdefault(hostname, set()).add(ip)

    for hostname, addresses in seen.items():
        if len(addresses) <= 1:
            continue

        non_loopback = {
            ip
            for ip in addresses
            if not ipaddress.ip_address(ip).is_loopback
        }

        if len(non_loopback) <= 1:
            continue

        already_flagged = any(
            finding["hostname"] == hostname
            and "hosts_duplicate_mapping" in finding["tags"]
            for finding in flagged
        )

        if already_flagged:
            continue

        flagged.append(
            {
                "lineno": "-",
                "ip": ", ".join(sorted(addresses)),
                "hostname": hostname,
                "raw": "",
                "reasons": [
                    "Hostname maps to multiple distinct addresses"
                ],
                "tags": ["hosts_duplicate_mapping"],
            }
        )

    return flagged, [], []


def run_hosts_check(silent: bool = False) -> dict:
    if get_os() != "Linux":
        if not silent:
            clear_screen()
            _header()

            console.print(
                Panel.fit(
                    "[yellow]Hosts Tamper Check is only supported on Linux.[/]",
                    border_style="yellow",
                    box=box.ROUNDED,
                )
            )

            pause_return()

        return {
            "status": "unsupported",
            "details": [],
            "tags": [],
        }

    flagged, errors, error_tags = scan_hosts()

    if errors:
        result = {
            "status": "error",
            "details": errors,
            "tags": error_tags,
        }

        if silent:
            return result

        clear_screen()
        _header()

        console.print(
            Panel.fit(
                "\n".join(
                    f"[yellow]{error}[/]"
                    for error in errors
                ),
                title="[bold yellow]UNAVAILABLE[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

        pause_return()
        return result

    all_tags = set()

    for finding in flagged:
        all_tags.update(finding["tags"])

    details = []

    for finding in flagged:
        for reason in finding["reasons"]:
            details.append(
                f"[line {finding['lineno']}] "
                f"{finding['hostname']} — {reason}"
            )

    result = {
        "status": "warning" if flagged else "ok",
        "details": details[:10] if silent else details,
        "tags": sorted(all_tags),
    }

    if silent:
        return result

    clear_screen()
    _header()

    console.print(
        Panel.fit(
            f"[dim]File:[/] [white]{HOSTS_PATH}[/]   "
            f"[dim]Findings:[/] "
            f"[{'yellow' if flagged else 'green'}]{len(flagged)}[/]",
            title="[bold cyan]SUMMARY[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    if flagged:
        table = Table(
            title="[italic cyan]Hosts File Findings[/]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            show_edge=False,
            padding=(0, 1),
        )

        table.add_column(
            "Line",
            style="cyan",
            no_wrap=True,
        )
        table.add_column(
            "Address",
            style="white",
            no_wrap=True,
        )
        table.add_column(
            "Hostname",
            style="white",
        )
        table.add_column(
            "Signal",
            style="yellow",
        )

        for finding in flagged:
            table.add_row(
                str(finding["lineno"]),
                finding["ip"],
                finding["hostname"],
                ", ".join(finding["tags"]),
            )

        console.print(table)
        console.print()

        console.print(
            Panel.fit(
                f"[yellow]{len(flagged)} /etc/hosts entry(ies) require review.[/]\n"
                "[dim]Validate unexpected redirects, private mappings, and duplicate hostname resolution.[/]",
                title="[bold yellow]REVIEW REQUIRED[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    else:
        console.print(
            Panel.fit(
                "[green]No suspicious /etc/hosts entries detected.[/]\n"
                "[dim]No critical redirects or high-signal hostname anomalies were identified.[/]",
                title="[bold green]STATUS: OK[/]",
                border_style="green",
                box=box.ROUNDED,
            )
        )

    pause_return()
    return result