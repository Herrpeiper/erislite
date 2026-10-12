# Project: ErisLITE
# Module: triage.py
# Author: Liam Piper-Brandon
# Version: 1.5.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-10-12
# Description: Rapid Response triage and host assessment routines.

from __future__ import annotations

import ipaddress
import os
import pwd
import re
import stat
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import psutil

# Login shells that give an account an interactive session.
INTERACTIVE_SHELLS = {
    "/bin/bash",
    "/usr/bin/bash",
    "/bin/sh",
    "/usr/bin/sh",
    "/bin/dash",
    "/usr/bin/dash",
    "/bin/zsh",
    "/usr/bin/zsh",
    "/bin/fish",
    "/usr/bin/fish",
}

CRON_DIRS = (
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
)

SUSPICIOUS_EXEC_PREFIXES = ("/tmp/", "/dev/shm/", "/var/tmp/")

COMMON_PORTS = {80, 443, 53, 123, 465, 587, 993, 995}

# Process names are compared exactly. Substring matching flagged sshd,
# rsync and php-fpm as shells and netcat.
SUSPICIOUS_PROCESS_NAMES = {
    "bash",
    "sh",
    "dash",
    "zsh",
    "nc",
    "ncat",
    "netcat",
    "nc.openbsd",
    "nc.traditional",
    "socat",
}

# Interpreters are often installed with a version suffix (perl5.36, php8.2).
_SUSPICIOUS_INTERPRETER = re.compile(r"^(perl|ruby|lua|php)[0-9.]*$")
_PYTHON_PROCESS = re.compile(r"^python(?:[0-9]+(?:\.[0-9]+)*)?$")


def is_suspicious_python_command(name: str, cmdline: str) -> bool:
    """Return True for Python command lines that resemble a reverse shell."""

    name = (name or "").strip().lower()
    cmdline = (cmdline or "").lower()

    if not _PYTHON_PROCESS.match(name):
        return False

    network_indicator = "socket.socket" in cmdline and (
        ".connect(" in cmdline or "connect_ex(" in cmdline
    )

    shell_indicator = any(
        marker in cmdline
        for marker in (
            "os.dup2",
            "pty.spawn",
            "/bin/sh",
            "/bin/bash",
            "subprocess",
        )
    )

    return network_indicator and shell_indicator


SSHD_PROCESS_NAMES = {"sshd", "sshd-session"}


def is_suspicious_process_name(name: str) -> bool:
    """Return True when a process name is a shell, netcat or script interpreter."""

    name = (name or "").strip().lower()

    if not name:
        return False

    return name in SUSPICIOUS_PROCESS_NAMES or bool(_SUSPICIOUS_INTERPRETER.match(name))


def is_internal_address(ip: str) -> bool:
    """Return True for private, loopback, link-local and unspecified addresses."""

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False

    mapped = getattr(address, "ipv4_mapped", None)

    if mapped is not None:
        address = mapped

    return (
        address.is_private or address.is_loopback or address.is_link_local or address.is_unspecified
    )


def is_loopback_address(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False

    mapped = getattr(address, "ipv4_mapped", None)
    return (mapped or address).is_loopback


def _login_uid_min(path: str = "/etc/login.defs") -> int:
    """Return UID_MIN from login.defs, or 1000 when it cannot be read."""

    try:
        with open(path, encoding="utf-8", errors="replace") as file:
            for line in file:
                parts = line.split()

                if len(parts) >= 2 and parts[0] == "UID_MIN" and parts[1].isdigit():
                    return int(parts[1])
    except OSError:
        pass

    return 1000


def flagged_users(
    accounts: Optional[Iterable[Any]] = None,
    uid_min: Optional[int] = None,
) -> Tuple[List[str], List[str], Optional[str]]:
    """Return (contain, review, error).

    contain: non-root accounts with UID 0. These are high-confidence and are
    offered as containment actions.

    review: system accounts with an interactive shell. Debian ships postgres
    and similar service accounts with /bin/bash, so these are shown for the
    analyst to review and never offered as automatic lock actions.
    """

    if uid_min is None:
        uid_min = _login_uid_min()

    if accounts is None:
        try:
            accounts = pwd.getpwall()
        except Exception as exc:
            return [], [], f"Could not enumerate local users: {exc}"

    contain = set()
    review = set()

    for user in accounts:
        if user.pw_name == "root":
            continue

        if user.pw_uid == 0:
            contain.add(user.pw_name)
        elif user.pw_uid < uid_min and user.pw_shell in INTERACTIVE_SHELLS:
            review.add(user.pw_name)

    return sorted(contain), sorted(review), None


def writable_crons(cron_dirs: Iterable[str] = CRON_DIRS) -> Tuple[List[str], List[str]]:
    """Return regular cron files that any user can write, plus collection errors.

    Symlinks are skipped: lstat reports 0777 for every symlink, which flagged
    them all as world-writable.
    """

    flagged = []
    errors = []

    for directory in cron_dirs:
        if not os.path.isdir(directory):
            continue

        try:
            entries = os.scandir(directory)
        except OSError as exc:
            errors.append(f"{directory}: could not enumerate cron directory: {exc}")
            continue

        with entries:
            for entry in entries:
                try:
                    info = os.lstat(entry.path)
                except OSError:
                    continue

                if stat.S_ISREG(info.st_mode) and info.st_mode & stat.S_IWOTH:
                    flagged.append(entry.path)

    return sorted(flagged), errors


def suspicious_processes() -> List[Dict[str, Any]]:
    found = []

    for proc in psutil.process_iter(["pid", "name", "uids", "cmdline", "create_time"]):
        try:
            exe = proc.exe()
            uids = proc.info.get("uids")
            uid = uids.real if uids else -1

            if exe and exe.startswith(SUSPICIOUS_EXEC_PREFIXES):
                found.append(
                    {
                        "pid": proc.info["pid"],
                        "name": proc.info["name"],
                        "exe": exe,
                        "uid": uid,
                        "create_time": proc.info.get("create_time"),
                        "cmdline": " ".join(proc.info.get("cmdline") or [])[:80],
                    }
                )

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return found


def operator_source_ips() -> Set[str]:
    """Return remote IPs of the SSH session ErisLITE is running under.

    Walks the process ancestry to the sshd session process and collects its
    peer addresses so Rapid Response never proposes blocking the operator.
    """

    ips: Set[str] = set()

    try:
        ancestors = psutil.Process().parents()
    except (psutil.Error, OSError):
        return ips

    for parent in ancestors:
        try:
            if parent.name() not in SSHD_PROCESS_NAMES:
                continue

            connections = (
                parent.net_connections(kind="inet")
                if hasattr(parent, "net_connections")
                else parent.connections(kind="inet")
            )

            for conn in connections:
                if conn.raddr:
                    ips.add(conn.raddr.ip)
        except (psutil.Error, OSError):
            continue

    return ips


def _process_cmdline(pid: Optional[int]) -> str:
    if not pid:
        return ""

    try:
        return " ".join(psutil.Process(pid).cmdline())
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
        return ""


def _process_name(pid: Optional[int]) -> str:
    if not pid:
        return ""

    try:
        return psutil.Process(pid).name().lower()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
        return ""


def classify_connections(
    connections: Iterable[Any],
    name_for_pid=_process_name,
    cmdline_for_pid=_process_cmdline,
    protected_ips: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    """Return suspicious established connections from psutil connection records.

    Inbound connections to a local listening port (an SSH login, a scored web
    request) are only reported when the owning process is a shell or netcat.
    An inbound connection's remote port is ephemeral, so the old
    "non-standard port" rule flagged every SSH session, including the
    operator's own.

    A shell or netcat holding a connection is reported for any non-loopback
    peer, because competition red teams usually sit on private ranges. The
    non-standard port rule only applies to public addresses, where it is
    less noisy.
    """

    protected_ips = protected_ips or set()
    connections = list(connections)

    listening_ports = {
        conn.laddr.port for conn in connections if conn.status == "LISTEN" and conn.laddr
    }

    found = []

    for conn in connections:
        if conn.status != "ESTABLISHED" or not conn.raddr:
            continue

        ip, port = conn.raddr.ip, conn.raddr.port

        if ip in protected_ips or is_loopback_address(ip):
            continue

        proc_name = name_for_pid(conn.pid)
        proc_cmdline = cmdline_for_pid(conn.pid)
        inbound = bool(conn.laddr) and conn.laddr.port in listening_ports
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—"

        record = {
            "pid": conn.pid,
            "proc": proc_name or "unknown",
            "laddr": laddr,
            "raddr": f"{ip}:{port}",
            "remote_ip": ip,
            "direction": "inbound" if inbound else "outbound",
        }

        if is_suspicious_process_name(proc_name) or is_suspicious_python_command(
            proc_name, proc_cmdline
        ):
            record["reason"] = f"{proc_name} holds a {record['direction']} connection"
            found.append(record)
            continue

        if inbound or is_internal_address(ip):
            continue

        if port not in COMMON_PORTS:
            record["reason"] = f"outbound to non-standard port {port} on a public IP"
            found.append(record)

    return found


def suspicious_connections(
    protected_ips: Optional[Set[str]] = None,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    if protected_ips is None:
        protected_ips = operator_source_ips()

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.Error, OSError) as exc:
        return [], f"Could not enumerate network connections: {exc}"

    return classify_connections(connections, protected_ips=protected_ips), None
