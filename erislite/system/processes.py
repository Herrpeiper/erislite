# Project: ErisLITE
# Module: processes.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: Process anomaly inspection for suspicious paths and execution context.

import os, pwd

import psutil

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, get_os, pause_return


SUSPICIOUS_SPAWN_PATHS = (
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "/run/user/",
    "/home/",
)

SUSPICIOUS_INTERPRETERS = {
    "python",
    "python3",
    "python2",
    "perl",
    "ruby",
    "lua",
    "bash",
    "sh",
    "dash",
    "zsh",
    "ksh",
    "nc",
    "ncat",
    "netcat",
    "socat",
}

KNOWN_BAD_NAMES = {
    "mimikatz",
    "meterpreter",
    "metasploit",
    "empire",
    "covenant",
    "sliver",
    "havoc",
    "fscan",
    "ladon",
    "linpeas",
    "pspy",
}

WHITELISTED_ROOT_PROCS = {
    "systemd",
    "kthreadd",
    "rcu_sched",
    "migration",
    "watchdog",
    "kworker",
    "ksoftirqd",
    "kdevtmpfs",
    "kauditd",
    "khungtaskd",
    "kswapd",
    "vmstat",
    "jbd2",
    "ext4-rsv-conver",
    "sshd",
    "cron",
    "atd",
    "rsyslogd",
    "dbus-daemon",
    "NetworkManager",
    "wpa_supplicant",
    "dockerd",
    "containerd",
    "udevd",
    "systemd-udevd",
    "systemd-journald",
    "systemd-logind",
    "systemd-resolved",
    "systemd-networkd",
    "systemd-timesyncd",
    "polkitd",
    "accounts-daemon",
    "udisksd",
    "packagekitd",
    "thermald",
    "irqbalance",
    "auditd",
    "agetty",
    "python3",
}

SUSPICIOUS_INTERPRETER_ARGS = (
    "-c",
    "-e",
    "-i",
    "/dev/tcp/",
    "/dev/udp/",
)


def _header() -> None:
    console.print(
        Panel(
            Text.from_markup(
                "[dim]Review running processes for persistence and execution anomalies[/]"
            ),
            title="[bold cyan]PROCESS ANOMALY SCAN[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )
    console.print()


def _get_exe_path(proc) -> str:
    try:
        return proc.exe() or ""
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return ""


def _cmdline_str(proc) -> str:
    try:
        parts = proc.cmdline()
        return " ".join(parts) if parts else proc.name()
    except Exception:
        try:
            return proc.name()
        except Exception:
            return ""


def _is_deleted(proc) -> bool:
    try:
        exe = proc.exe()
        return bool(exe) and (
            exe.endswith(" (deleted)")
            or not os.path.exists(exe.replace(" (deleted)", ""))
        )
    except Exception:
        return False


def _is_kernel_thread(proc) -> bool:
    try:
        return not proc.cmdline() and not proc.exe()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return True
    except Exception:
        return False


def _get_username(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


def _severity(tags) -> str:
    if "proc_known_bad" in tags or "proc_deleted_exe" in tags:
        return "[red]CRITICAL[/]"

    if (
        "proc_root_suspicious_path" in tags
        or "proc_root_interpreter" in tags
        or "proc_hidden_name" in tags
    ):
        return "[yellow]WARNING[/]"

    return "[yellow]REVIEW[/]"


def scan_processes():
    flagged = []

    for proc in psutil.process_iter(["pid", "name", "uids", "cmdline", "ppid"]):
        try:
            info = proc.info
            pid = info["pid"]
            name = (info["name"] or "").strip()
            uids = info.get("uids")
            uid = uids.real if uids else -1

            cmdline = _cmdline_str(proc)
            exe = _get_exe_path(proc)
            base_name = os.path.basename(exe or name).lower().split()[0]

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue

        if _is_kernel_thread(proc):
            continue

        reasons = []
        tags = set()

        if uid == 0 and exe:
            for bad_path in SUSPICIOUS_SPAWN_PATHS:
                if exe.startswith(bad_path):
                    reasons.append(f"Root process spawned from {bad_path}")
                    tags.add("proc_root_suspicious_path")
                    break

        if _is_deleted(proc):
            reasons.append("Executable deleted from disk while process remains active")
            tags.add("proc_deleted_exe")

        lowered_cmdline = cmdline.lower()

        for bad in KNOWN_BAD_NAMES:
            if bad in base_name or bad in lowered_cmdline:
                reasons.append(f"Matches known offensive tool name: {bad}")
                tags.add("proc_known_bad")
                break

        if (
            uid == 0
            and base_name in SUSPICIOUS_INTERPRETERS
            and name not in WHITELISTED_ROOT_PROCS
            and base_name not in WHITELISTED_ROOT_PROCS
        ):
            suspicious_args = any(
                token in cmdline.lower() for token in SUSPICIOUS_INTERPRETER_ARGS
            )

            suspicious_path = any(
                exe.startswith(path) for path in SUSPICIOUS_SPAWN_PATHS
            )

            if suspicious_args or suspicious_path:
                reasons.append(
                    f"Privileged interpreter with suspicious execution context: {base_name}"
                )
                tags.add("proc_root_interpreter")

        if name.startswith("."):
            reasons.append(f"Process name starts with dot: {name}")
            tags.add("proc_hidden_name")

        if uid == 0 and not exe and name not in WHITELISTED_ROOT_PROCS:
            reasons.append("Root process with no resolvable executable path")
            tags.add("proc_no_exe")

        if reasons:
            flagged.append(
                {
                    "pid": pid,
                    "name": name,
                    "exe": exe or "(unknown)",
                    "user": _get_username(uid),
                    "cmdline": cmdline[:80],
                    "reasons": reasons,
                    "tags": sorted(tags),
                }
            )

    return flagged


def run_process_scan(silent: bool = False) -> dict:
    if get_os() != "Linux":
        if not silent:
            clear_screen()
            _header()

            console.print(
                Panel.fit(
                    "[yellow]Process Anomaly Scan is only supported on Linux.[/]",
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

    flagged = scan_processes()

    all_tags = set()
    for finding in flagged:
        all_tags.update(finding["tags"])

    details = [
        f"[PID {finding['pid']}] {finding['name']} — {reason}"
        for finding in flagged
        for reason in finding["reasons"]
    ]

    if silent:
        return {
            "status": "warning" if flagged else "ok",
            "details": details[:10] if flagged else [],
            "tags": sorted(all_tags),
        }

    clear_screen()
    _header()

    if not flagged:
        console.print(
            Panel.fit(
                "[green]No suspicious process conditions detected.[/]\n"
                "[dim]No deleted executables, suspicious spawn paths, "
                "or known offensive tool names were found.[/]",
                title="[bold green]STATUS: OK[/]",
                border_style="green",
                box=box.ROUNDED,
            )
        )

        pause_return()

        return {
            "status": "ok",
            "details": [],
            "tags": [],
        }

    finding_count = sum(len(finding["reasons"]) for finding in flagged)

    console.print(
        Panel.fit(
            f"[dim]Processes:[/] [white]{len(flagged)}[/]   "
            f"[dim]Findings:[/] [yellow]{finding_count}[/]",
            title="[bold cyan]SUMMARY[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    table = Table(
        title="[italic cyan]Process Findings[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )

    table.add_column("PID", style="cyan", no_wrap=True)
    table.add_column("Process", style="white", no_wrap=True)
    table.add_column("User", style="white", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Reason", style="white")
    table.add_column("Command", style="dim", overflow="fold")

    for finding in flagged:
        table.add_row(
            str(finding["pid"]),
            finding["name"],
            finding["user"],
            _severity(finding["tags"]),
            "\n".join(finding["reasons"]),
            finding["cmdline"],
        )

    console.print(table)
    console.print()

    console.print(
        Panel.fit(
            f"[yellow]{len(flagged)} process(es) require review.[/]\n"
            "[dim]Validate suspicious execution paths, deleted binaries, "
            "privileged interpreters, and unexpected process names.[/]",
            title="[bold yellow]REVIEW REQUIRED[/]",
            border_style="yellow",
            box=box.ROUNDED,
        )
    )

    pause_return()

    return {
        "status": "warning",
        "details": details,
        "tags": sorted(all_tags),
    }
