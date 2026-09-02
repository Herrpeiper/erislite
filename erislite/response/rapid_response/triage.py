# Project: ErisLITE
# Module: triage.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: Rapid Response triage and host assessment routines.

from __future__ import annotations

import os, pwd
from typing import Any, Dict, List

import psutil


def suspicious_processes() -> List[Dict[str, Any]]:
    suspicious_paths = ("/tmp/", "/dev/shm/", "/var/tmp/")
    found = []

    for proc in psutil.process_iter(["pid", "name", "uids", "cmdline"]):
        try:
            exe = proc.exe()
            uids = proc.info.get("uids")
            uid = uids.real if uids else -1

            if exe and any(exe.startswith(path) for path in suspicious_paths):
                found.append(
                    {
                        "pid": proc.info["pid"],
                        "name": proc.info["name"],
                        "exe": exe,
                        "uid": uid,
                        "cmdline": " ".join(proc.info.get("cmdline") or [])[:80],
                    }
                )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return found


def suspicious_connections() -> List[Dict[str, Any]]:
    private_prefixes = (
        "10.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",
        "192.168.",
        "127.",
        "::1",
        "::ffff:127.",
    )

    common_ports = {80, 443, 53, 123, 465, 587, 993, 995}

    trusted_procs = {
        "firefox",
        "chrome",
        "chromium",
        "brave",
        "curl",
        "wget",
        "apt",
        "apt-get",
        "python3",
        "python",
        "snap",
        "snapd",
        "update-manager",
        "packagekitd",
        "systemd",
        "NetworkManager",
        "ssh",
        "git",
        "code",
        "node",
        "npm",
    }

    suspicious_procs = {
        "bash",
        "sh",
        "dash",
        "zsh",
        "nc",
        "ncat",
        "netcat",
        "socat",
        "perl",
        "ruby",
        "lua",
        "php",
    }

    found = []

    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status != "ESTABLISHED" or not conn.raddr:
                continue

            ip, port = conn.raddr.ip, conn.raddr.port

            if any(ip.startswith(prefix) for prefix in private_prefixes):
                continue

            proc_name = ""

            if conn.pid:
                try:
                    proc_name = psutil.Process(conn.pid).name().lower()
                except Exception:
                    pass

            if proc_name and any(name in proc_name for name in suspicious_procs):
                found.append(
                    {
                        "pid": conn.pid,
                        "proc": proc_name,
                        "laddr": f"{conn.laddr.ip}:{conn.laddr.port}"
                        if conn.laddr
                        else "—",
                        "raddr": f"{ip}:{port}",
                        "remote_ip": ip,
                        "reason": f"suspicious process ({proc_name}) with outbound connection",
                    }
                )
                continue

            if port in common_ports and proc_name in trusted_procs:
                continue

            if port not in common_ports:
                found.append(
                    {
                        "pid": conn.pid,
                        "proc": proc_name or "unknown",
                        "laddr": f"{conn.laddr.ip}:{conn.laddr.port}"
                        if conn.laddr
                        else "—",
                        "raddr": f"{ip}:{port}",
                        "remote_ip": ip,
                        "reason": f"non-standard port {port} to public IP",
                    }
                )

    except Exception:
        pass

    return found


def flagged_users() -> List[str]:
    interactive = {"/bin/bash", "/bin/sh", "/usr/bin/zsh", "/usr/bin/fish"}
    flagged = []

    try:
        for user in pwd.getpwall():
            if user.pw_uid == 0 and user.pw_name != "root":
                flagged.append(user.pw_name)
            elif (
                user.pw_uid < 1000
                and user.pw_shell in interactive
                and user.pw_name != "root"
            ):
                flagged.append(user.pw_name)
    except Exception:
        pass

    return list(set(flagged))


def writable_crons() -> List[str]:
    cron_dirs = [
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ]

    flagged = []

    for directory in cron_dirs:
        if not os.path.isdir(directory):
            continue

        for entry in os.scandir(directory):
            try:
                if os.lstat(entry.path).st_mode & 0o002:
                    flagged.append(entry.path)
            except Exception:
                continue

    return flagged
