# Project: ErisLITE
# Module: network_scan.py
# Author: Liam Piper-Brandon
# Version: 0.7
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-29
# Description: Network listener scan using 'ss'; risk classification by port and process.

from __future__ import annotations

import platform
import re
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# A mapping of common ports to their typical services. This is used for basic risk classification of listeners based on the port they are using. If a listener is on a well-known port, it may be considered lower risk than an unknown service on a non-standard port.
KNOWN_PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 514: "syslog", 587: "submission",
    631: "ipp", 636: "ldaps", 853: "dns-over-tls", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker", 2376: "docker-tls",
    3000: "dev-web", 3306: "mysql", 3389: "rdp", 5000: "upnp/app", 5432: "postgresql",
    5900: "vnc", 5985: "winrm-http", 5986: "winrm-https", 6379: "redis", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 9000: "app", 9090: "app",
    9200: "elasticsearch", 9418: "git", 27017: "mongodb",
}

# Utility functions for parsing and classifying network listeners. These help extract structured information from the raw output of 'ss' and apply basic risk tagging based on known ports and other heuristics.
def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# Splits a string like "0.0.0.0:22" into host and port components
def _split_host_port(value: str) -> tuple[str, Optional[int]]:
    """
    Handles examples like:
    0.0.0.0:22
    [::]:80
    127.0.0.1:5432
    *:68
    """
    value = value.strip()

    if not value:
        return "-", None

    # IPv6 in brackets: [::]:80
    if value.startswith("["):
        match = re.match(r"^\[(.+)\]:(\d+|\*)$", value)
        if match:
            host = match.group(1)
            port_raw = match.group(2)
            return host, int(port_raw) if port_raw.isdigit() else None

    # Generic last-colon split
    if ":" in value:
        host, port_raw = value.rsplit(":", 1)
        return host, int(port_raw) if port_raw.isdigit() else None

    return value, None

# Parses the process information block from the 'ss' output to extract the process name, PID, and user details when available. This is used to provide more context about which processes are associated with each listener.
def _parse_process_block(raw_line: str) -> tuple[Optional[str], Optional[int], Optional[str]]:
    """
    Pulls process_name / pid / user-ish details from ss output when possible.
    Example fragments:
      users:(("sshd",pid=812,fd=3))
      users:(("python3",pid=2214,fd=5))
    """
    proc_name = None
    pid = None
    user_name = None  # ss usually won't provide this directly

    name_match = re.search(r'users:\(\("([^"]+)"', raw_line)
    if name_match:
        proc_name = name_match.group(1)

    pid_match = re.search(r"pid=(\d+)", raw_line)
    if pid_match:
        pid = int(pid_match.group(1))

    return proc_name, pid, user_name

# Classifies the risk level of a network listener based on its protocol, local address, port, and associated process. It uses known port mappings and heuristics to assign a risk level and reason for that classification.
def _classify_listener(
    protocol: str,
    local_address: str,
    port: Optional[int],
    process_name: Optional[str],
) -> tuple[str, str, Optional[str]]:
    """
    Conservative first-pass risk tagging.
    Returns: (risk, reason, known_service)
    """
    known_service = KNOWN_PORTS.get(port) if port is not None else None

    if port is None:
        return "unknown", "Port could not be parsed", known_service

    if known_service and process_name:
        return "low", f"Known service port ({known_service})", known_service

    if known_service and not process_name:
        return "low", f"Known service port ({known_service}); process unavailable", known_service

    if port < 1024:
        return "medium", "Privileged port with unknown service mapping", known_service

    if local_address in ("0.0.0.0", "::", "*"):
        return "medium", "Wildcard bind on uncommon port", known_service

    return "medium", "Unknown listener on uncommon port", known_service

# Main function to get network listeners data. This is the entry point for the Basalt agent when executing the "network.listeners" module. It runs the 'ss' command, parses the output, and returns a structured result with risk classifications.
def get_network_listeners_data() -> Dict[str, Any]:
    """
    Headless listener scan for Linux.
    Returns structured, JSON-safe results for Basalt agent or ErisLite CLI wrappers.
    """
    system = platform.system()

    response: Dict[str, Any] = {
        "module": "network.listeners",
        "status": "success",
        "hostname": platform.node(),
        "platform": system,
        "collected_at": _utc_now_iso(),
        "summary": {
            "total_listeners": 0,
            "tcp_listeners": 0,
            "udp_listeners": 0,
            "flagged": 0,
        },
        "results": [],
        "errors": [],
        "command": None,
    }

    if system != "Linux":
        response["status"] = "error"
        response["errors"].append(f"Unsupported OS for this module: {system}")
        return response

    cmd = ["ss", "-lntup"]
    response["command"] = " ".join(cmd)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    except FileNotFoundError:
        response["status"] = "error"
        response["errors"].append("The 'ss' utility was not found on this system.")
        return response
    except subprocess.TimeoutExpired:
        response["status"] = "error"
        response["errors"].append("Listener scan timed out after 15 seconds.")
        return response
    except Exception as exc:
        response["status"] = "error"
        response["errors"].append(f"Unexpected error running ss: {exc}")
        return response

    if proc.returncode != 0:
        response["status"] = "error"
        stderr = (proc.stderr or "").strip() or "Unknown error from ss"
        response["errors"].append(stderr)
        return response

    lines = (proc.stdout or "").splitlines()
    if not lines:
        return response

    # Skip header row
    for raw_line in lines[1:]:
        line = raw_line.strip()
        if not line:
            continue

        parts = re.split(r"\s+", line)
        if len(parts) < 5:
            response["errors"].append(f"Skipped unparsable line: {raw_line}")
            continue

        # Typical columns:
        # Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
        protocol = parts[0].lower()
        state = parts[1]
        local_raw = parts[4]
        peer_raw = parts[5] if len(parts) > 5 else "*:*"

        local_address, local_port = _split_host_port(local_raw)
        peer_address, peer_port = _split_host_port(peer_raw)
        process_name, pid, user_name = _parse_process_block(raw_line)
        risk, reason, known_service = _classify_listener(
            protocol=protocol,
            local_address=local_address,
            port=local_port,
            process_name=process_name,
        )

        entry: Dict[str, Any] = {
            "protocol": protocol,
            "state": state,
            "local_address": local_address,
            "local_port": local_port,
            "peer_address": peer_address,
            "peer_port": peer_port,
            "pid": pid,
            "process_name": process_name,
            "user": user_name,
            "known_service": known_service,
            "risk": risk,
            "reason": reason,
        }

        response["results"].append(entry)
        response["summary"]["total_listeners"] += 1

        if protocol.startswith("tcp"):
            response["summary"]["tcp_listeners"] += 1
        elif protocol.startswith("udp"):
            response["summary"]["udp_listeners"] += 1

        if risk in ("medium", "high"):
            response["summary"]["flagged"] += 1

    return response