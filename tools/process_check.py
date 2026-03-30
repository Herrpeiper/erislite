# Project: ErisLITE
# Module: process_check.py
# Author: Liam Piper-Brandon
# Version: 0.7
# License: MIT
# Created: 2026-03-29
# Last Updated: 2026-03-29
# Description: Process anomaly scan: flags suspicious processes running as root,
#   spawned from unusual paths, using interpreter names, or with hidden/deleted
#   executables. Compatible with silent=True for Threat Sweep integration.

import os
import re

import psutil

from rich.console import Console
from rich.table import Table
from rich.align import Align

from ui.utils import clear_screen, show_header, pause_return, get_os

console = Console()

# ── Heuristics ────────────────────────────────────────────────────────────────

# Paths that are high-risk spawn locations for processes.
# A process whose exe resolves to or was launched from one of these is suspicious.
SUSPICIOUS_SPAWN_PATHS = (
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "/run/user/",
    "/home/",       # scripts running directly from home dirs as root
)

# Interpreter names that should rarely appear as standalone root processes.
# Legitimate interpreters are usually wrapped by a named service.
SUSPICIOUS_INTERPRETERS = {
    "python", "python3", "python2",
    "perl", "ruby", "lua",
    "bash", "sh", "dash", "zsh", "ksh",
    "nc", "ncat", "netcat",
    "socat",
}

# Process names that are known red-team / post-exploitation tools.
KNOWN_BAD_NAMES = {
    "mimikatz", "meterpreter", "metasploit",
    "empire", "covenant", "sliver", "havoc",
    "fscan", "ladon", "linpeas", "pspy",
}

# Legitimate root processes that are noisy if flagged — keep this tight.
# Only add entries you are certain are safe on every deployment.
WHITELISTED_ROOT_PROCS = {
    "systemd", "kthreadd", "rcu_sched", "migration", "watchdog",
    "kworker", "ksoftirqd", "kdevtmpfs", "kauditd", "khungtaskd",
    "kswapd", "vmstat", "jbd2", "ext4-rsv-conver",
    "sshd", "cron", "atd", "rsyslogd", "dbus-daemon",
    "NetworkManager", "wpa_supplicant", "dockerd", "containerd",
    "udevd", "systemd-udevd", "systemd-journald", "systemd-logind",
    "systemd-resolved", "systemd-networkd", "systemd-timesyncd",
    "polkitd", "accounts-daemon", "udisksd", "packagekitd",
    "thermald", "irqbalance", "auditd", "agetty",
    "python3",   # remove if you want python3 root processes flagged
}


# ── Detection functions ───────────────────────────────────────────────────────

def _get_exe_path(proc) -> str:
    """Return the resolved executable path, or '' on access error."""
    try:
        return proc.exe() or ""
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return ""


def _is_deleted(proc) -> bool:
    """True if the process executable has been deleted from disk (common rootkit trick)."""
    try:
        exe = proc.exe()
        return exe.endswith(" (deleted)") or (exe and not os.path.exists(exe))
    except Exception:
        return False


def _is_kernel_thread(proc) -> bool:
    """
    Kernel threads have no executable path and an empty cmdline.
    They are not suspicious — skip them entirely.
    """
    try:
        cmdline = proc.cmdline()
        exe     = proc.exe()
        return not cmdline and not exe
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        # If we can't read either, assume kernel thread and skip
        return True
    except Exception:
        return False
    try:
        parts = proc.cmdline()
        return " ".join(parts) if parts else proc.name()
    except Exception:
        return proc.name()


def scan_processes():
    """
    Walk all running processes and collect suspicious findings.
    Returns a list of dicts: {pid, name, exe, user, reason, tag}
    """
    flagged = []

    for proc in psutil.process_iter(["pid", "name", "uids", "cmdline", "ppid"]):
        try:
            info   = proc.info
            pid    = info["pid"]
            name   = (info["name"] or "").strip()
            uids   = info.get("uids")
            uid    = uids.real if uids else -1
            cmdline = _cmdline_str(proc)
            # Fetch exe lazily — process_iter won't catch AccessDenied for exe on all kernels
            exe       = _get_exe_path(proc)
            base_name = os.path.basename(exe or name).lower().split()[0]

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue

        # Skip kernel threads — they have no exe or cmdline by design
        if _is_kernel_thread(proc):
            continue

        reasons = []
        tags    = set()

        # ── Check 1: root process from a suspicious spawn path ────────────────
        if uid == 0 and exe:
            for bad_path in SUSPICIOUS_SPAWN_PATHS:
                if exe.startswith(bad_path):
                    reasons.append(f"Root process spawned from {bad_path}")
                    tags.add("proc_root_suspicious_path")
                    break

        # ── Check 2: deleted executable ───────────────────────────────────────
        if _is_deleted(proc):
            reasons.append("Executable deleted from disk (process still running)")
            tags.add("proc_deleted_exe")

        # ── Check 3: known bad name ───────────────────────────────────────────
        for bad in KNOWN_BAD_NAMES:
            if bad in base_name or bad in cmdline.lower():
                reasons.append(f"Matches known offensive tool name: {bad}")
                tags.add("proc_known_bad")
                break

        # ── Check 4: interpreter running as root (not whitelisted) ───────────
        if uid == 0 and base_name in SUSPICIOUS_INTERPRETERS:
            if name not in WHITELISTED_ROOT_PROCS and base_name not in WHITELISTED_ROOT_PROCS:
                reasons.append(f"Interpreter running as root: {base_name}")
                tags.add("proc_root_interpreter")

        # ── Check 5: process name looks like a hidden process (leading dot) ───
        if name.startswith("."):
            reasons.append(f"Process name starts with dot (hidden): {name}")
            tags.add("proc_hidden_name")

        # ── Check 6: no exe path resolved but process is running as root ──────
        if uid == 0 and not exe and name not in WHITELISTED_ROOT_PROCS:
            reasons.append("Root process with no resolvable executable path")
            tags.add("proc_no_exe")

        if reasons:
            flagged.append({
                "pid":     pid,
                "name":    name,
                "exe":     exe or "(unknown)",
                "user":    _get_username(uid),
                "cmdline": cmdline[:80],
                "reasons": reasons,
                "tags":    sorted(tags),
            })

    return flagged


def _get_username(uid: int) -> str:
    """Resolve UID to username, fallback to UID string."""
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


# ── Main entry point ──────────────────────────────────────────────────────────

def run_process_scan(silent: bool = False) -> dict:
    os_type = get_os()

    if os_type != "Linux":
        if not silent:
            clear_screen()
            show_header("PROCESS ANOMALY SCAN")
            console.print("[yellow]This module is only supported on Linux.[/]")
            pause_return()
        return {"status": "unsupported", "details": [], "tags": []}

    flagged = scan_processes()

    # Aggregate tags across all findings
    all_tags: set = set()
    for f in flagged:
        all_tags.update(f["tags"])

    # ── Silent mode (Threat Sweep) ────────────────────────────────────────────
    if silent:
        if not flagged:
            return {"status": "ok", "details": [], "tags": []}

        details = []
        for f in flagged:
            for reason in f["reasons"]:
                details.append(f"[PID {f['pid']}] {f['name']} — {reason}")

        return {
            "status": "warning",
            "details": details[:10],   # cap at 10 for sweep summary readability
            "tags": sorted(all_tags),
        }

    # ── Interactive mode ──────────────────────────────────────────────────────
    clear_screen()
    show_header("PROCESS ANOMALY SCAN")

    if not flagged:
        console.print("[green]No suspicious processes detected.[/]")
        pause_return()
        return {"status": "ok", "details": [], "tags": []}

    table = Table(title=f"Suspicious Processes ({len(flagged)} found)", show_lines=True)
    table.add_column("PID",     style="cyan",    no_wrap=True)
    table.add_column("Name",    style="magenta", no_wrap=True)
    table.add_column("User",    style="yellow",  no_wrap=True)
    table.add_column("Reason",  style="white")
    table.add_column("Cmdline", style="dim",     overflow="fold")

    for f in flagged:
        reason_str = "\n".join(f["reasons"])
        table.add_row(
            str(f["pid"]),
            f["name"],
            f["user"],
            reason_str,
            f["cmdline"],
        )

    console.print(Align.center(table))
    console.print(f"\n[bold red]⚠  {len(flagged)} suspicious process(es) detected.[/]")
    pause_return()

    details = []
    for f in flagged:
        for reason in f["reasons"]:
            details.append(f"[PID {f['pid']}] {f['name']} — {reason}")

    return {
        "status": "warning",
        "details": details,
        "tags": sorted(all_tags),
    }