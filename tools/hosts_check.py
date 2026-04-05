# Project: ErisLITE
# Module: hosts_check.py
# Author: Liam Piper-Brandon
# Version: 1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-04-05
# Description: /etc/hosts entries that redirect critical domains or look malicious.

import re

from rich.console import Console
from rich.table import Table
from rich.align import Align

from ui.utils import clear_screen, show_header, pause_return, get_os

console = Console()

HOSTS_PATH = "/etc/hosts"

# ── Heuristics ────────────────────────────────────────────────────────────────

# Domains that should never be redirected in a legitimate hosts file.
# Redirection of these is a strong indicator of DNS hijacking or C2 activity.
CRITICAL_DOMAINS = {
    # Package managers / update infrastructure
    "security.ubuntu.com", "archive.ubuntu.com", "packages.debian.org",
    "deb.debian.org", "dl.fedoraproject.org", "mirrors.fedoraproject.org",
    "yum.repos.d", "rpm.repos",

    # Certificate authorities
    "ocsp.digicert.com", "crl.globalsign.com", "ocsp.globalsign.com",
    "ocsp.pki.goog", "pki.goog",

    # Common telemetry / update targets attackers redirect to block detection
    "telemetry.microsoft.com", "update.microsoft.com",
    "safebrowsing.googleapis.com", "safebrowsing.google.com",

    # Common C2 callback domains seen in commodity malware
    "windowsupdate.com", "microsoftupdate.com",
}

# IPs that are suspicious destinations in a hosts file.
# Loopback redirects of non-local services can be used to block security tools.
LOOPBACK_IPS = {"127.0.0.1", "127.0.0.2", "0.0.0.0", "::1"}

# Patterns that suggest the entry is trying to hide itself or is malformed.
SUSPICIOUS_PATTERNS = [
    # Very long hostname (unusual for legitimate entries)
    re.compile(r"\S{80,}"),
    # IP that looks like an internal RFC1918 range pointing to an unusual domain
    re.compile(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)"),
    # Base64-looking hostname (encoded C2 domain)
    re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$"),
]

# Legitimate standard entries — ignore these completely.
WHITELIST_ENTRIES = {
    ("127.0.0.1",   "localhost"),
    ("127.0.1.1",   "localhost"),
    ("::1",         "localhost"),
    ("::1",         "ip6-localhost"),
    ("::1",         "ip6-loopback"),
    ("fe00::0",     "ip6-localnet"),
    ("ff00::0",     "ip6-mcastprefix"),
    ("ff02::1",     "ip6-allnodes"),
    ("ff02::2",     "ip6-allrouters"),
}


# ── Parser ────────────────────────────────────────────────────────────────────

def parse_hosts():
    """
    Parse /etc/hosts and return a list of (ip, hostname, raw_line, lineno).
    Skips comments and blank lines.
    """
    entries = []
    try:
        with open(HOSTS_PATH, "r", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                # Strip inline comments
                stripped = stripped.split("#")[0].strip()
                parts = stripped.split()
                if len(parts) < 2:
                    continue
                ip = parts[0]
                for hostname in parts[1:]:
                    entries.append((ip, hostname.lower(), line.rstrip(), lineno))
    except (FileNotFoundError, PermissionError) as e:
        return [], str(e)
    return entries, None


# ── Detection ─────────────────────────────────────────────────────────────────

def scan_hosts():
    """
    Analyse /etc/hosts entries and return a list of suspicious findings.
    Each finding: {lineno, ip, hostname, reason, tag}
    """
    entries, err = parse_hosts()
    if err:
        return [], [f"Could not read {HOSTS_PATH}: {err}"], ["hosts_unreadable"]

    flagged = []

    for ip, hostname, raw_line, lineno in entries:
        # Skip known-good standard entries
        if (ip, hostname) in WHITELIST_ENTRIES:
            continue

        reasons = []
        tags    = set()

        # ── Check 1: critical domain redirected ───────────────────────────────
        for domain in CRITICAL_DOMAINS:
            if hostname == domain or hostname.endswith("." + domain):
                reasons.append(f"Critical domain redirected: {hostname} -> {ip}")
                tags.add("hosts_critical_redirect")
                break

        # ── Check 2: loopback redirect of non-localhost hostname ──────────────
        if ip in LOOPBACK_IPS and hostname not in ("localhost", "ip6-localhost", "ip6-loopback"):
            # Redirecting to loopback can block security/update tools
            reasons.append(f"Non-localhost hostname points to loopback: {hostname} -> {ip}")
            tags.add("hosts_loopback_redirect")

        # ── Check 3: suspicious hostname pattern ──────────────────────────────
        for pat in SUSPICIOUS_PATTERNS:
            if pat.search(hostname):
                reasons.append(f"Suspicious hostname pattern: {hostname}")
                tags.add("hosts_suspicious_entry")
                break

        # ── Check 4: duplicate hostname with different IP ─────────────────────
        # (checked post-loop below)

        if reasons:
            flagged.append({
                "lineno":   lineno,
                "ip":       ip,
                "hostname": hostname,
                "raw":      raw_line,
                "reasons":  reasons,
                "tags":     sorted(tags),
            })

    # ── Check 4: detect duplicate hostnames pointing to different IPs ─────────
    seen: dict = {}
    for ip, hostname, raw_line, lineno in entries:
        if hostname in seen and seen[hostname] != ip:
            flagged.append({
                "lineno":   lineno,
                "ip":       ip,
                "hostname": hostname,
                "raw":      raw_line,
                "reasons":  [f"Hostname {hostname} mapped to multiple IPs ({seen[hostname]} and {ip})"],
                "tags":     ["hosts_duplicate_mapping"],
            })
        else:
            seen[hostname] = ip

    return flagged, [], []


# ── Main entry point ──────────────────────────────────────────────────────────

def run_hosts_check(silent: bool = False) -> dict:
    os_type = get_os()

    if os_type != "Linux":
        if not silent:
            clear_screen()
            show_header("/etc/hosts CHECK")
            console.print("[yellow]This module is only supported on Linux.[/]")
            pause_return()
        return {"status": "unsupported", "details": [], "tags": []}

    flagged, errors, error_tags = scan_hosts()

    if errors:
        if not silent:
            clear_screen()
            show_header("/etc/hosts CHECK")
            for e in errors:
                console.print(f"[red]{e}[/]")
            pause_return()
        return {"status": "error", "details": errors, "tags": error_tags}

    all_tags: set = set()
    for f in flagged:
        all_tags.update(f["tags"])

    # ── Silent mode ───────────────────────────────────────────────────────────
    if silent:
        if not flagged:
            return {"status": "ok", "details": [], "tags": []}

        details = []
        for f in flagged:
            for reason in f["reasons"]:
                details.append(f"[line {f['lineno']}] {f['hostname']} — {reason}")

        return {
            "status": "warning",
            "details": details[:10],
            "tags":    sorted(all_tags),
        }

    # ── Interactive mode ──────────────────────────────────────────────────────
    clear_screen()
    show_header("/etc/hosts TAMPER CHECK")

    if not flagged:
        console.print("[green]No suspicious /etc/hosts entries detected.[/]")
        pause_return()
        return {"status": "ok", "details": [], "tags": []}

    table = Table(title=f"Suspicious /etc/hosts Entries ({len(flagged)} found)",
                  show_lines=True)
    table.add_column("Line",     style="cyan",    no_wrap=True)
    table.add_column("IP",       style="yellow",  no_wrap=True)
    table.add_column("Hostname", style="magenta", no_wrap=True)
    table.add_column("Reason",   style="white")

    for f in flagged:
        table.add_row(
            str(f["lineno"]),
            f["ip"],
            f["hostname"],
            "\n".join(f["reasons"]),
        )

    console.print(Align.center(table))
    console.print(f"\n[bold red]⚠  {len(flagged)} suspicious entry(ies) detected in /etc/hosts.[/]")
    pause_return()

    details = []
    for f in flagged:
        for reason in f["reasons"]:
            details.append(f"[line {f['lineno']}] {f['hostname']} — {reason}")

    return {
        "status": "warning",
        "details": details,
        "tags":    sorted(all_tags),
    }