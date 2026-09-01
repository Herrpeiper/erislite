# Project: ErisLITE
# Module: rapid_response.py
# Author: Liam Piper-Brandon
# Version: 1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-04-05
# Description: Triage scan with dry-run and live containment modes.

from __future__ import annotations

import json, os, pwd, shutil, subprocess, time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

import psutil

from rich import box
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from erislite.config.settings import APP_NAME, APP_VERSION
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, get_os, pause_return

_REPO_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR    = _REPO_ROOT / "data" / "logs" / "rapid_response"

# ── Helpers ───────────────────────────────────────────────────────────────────

def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _run(args: List[str], timeout: int = 10) -> Tuple[int, str, str]:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return 1, "", str(e)


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _log_path() -> Path:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return LOG_DIR / f"rapid_response_{ts}.json"


# ── Triage scan ───────────────────────────────────────────────────────────────

def _triage_suspicious_processes() -> List[Dict[str, Any]]:
    """Find processes running from suspicious paths."""
    SUSPICIOUS_PATHS = ("/tmp/", "/dev/shm/", "/var/tmp/")
    found = []
    for proc in psutil.process_iter(["pid", "name", "uids", "cmdline"]):
        try:
            exe = proc.exe()
            uids = proc.info.get("uids")
            uid  = uids.real if uids else -1
            if exe and any(exe.startswith(p) for p in SUSPICIOUS_PATHS):
                found.append({
                    "pid":     proc.info["pid"],
                    "name":    proc.info["name"],
                    "exe":     exe,
                    "uid":     uid,
                    "cmdline": " ".join(proc.info.get("cmdline") or [])[:80],
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return found


def _triage_suspicious_connections() -> List[Dict[str, Any]]:
    """
    Find established outbound connections that look genuinely suspicious.
    Port 443/80 connections are extremely common on desktops and servers —
    we only flag those if the process itself is suspicious. Non-standard
    ports to public IPs are flagged regardless.
    """
    RFC1918 = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
               "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
               "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
               "172.30.", "172.31.", "192.168.", "127.", "::1", "::ffff:127.")

    # Ports considered normal for outbound traffic — only flag if process is suspicious
    COMMON_PORTS = {80, 443, 53, 123, 465, 587, 993, 995}

    # Processes that are expected to make outbound connections on common ports
    TRUSTED_PROCS = {
        "firefox", "chrome", "chromium", "brave", "curl", "wget",
        "apt", "apt-get", "python3", "python", "snap", "snapd",
        "update-manager", "packagekitd", "systemd", "NetworkManager",
        "ssh", "git", "code", "node", "npm",
    }

    # Processes that should NOT be making outbound connections
    SUSPICIOUS_PROCS = {
        "bash", "sh", "dash", "zsh", "nc", "ncat", "netcat", "socat",
        "perl", "ruby", "lua", "php",
    }

    found = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status != "ESTABLISHED":
                continue
            raddr = conn.raddr
            if not raddr:
                continue
            ip   = raddr.ip
            port = raddr.port

            # Skip RFC1918 / loopback
            if any(ip.startswith(p) for p in RFC1918):
                continue

            # Get process name if available
            proc_name = ""
            if conn.pid:
                try:
                    proc_name = psutil.Process(conn.pid).name().lower()
                except Exception:
                    pass

            # Always flag connections from known-suspicious processes
            if proc_name and any(s in proc_name for s in SUSPICIOUS_PROCS):
                found.append({
                    "pid":       conn.pid,
                    "proc":      proc_name,
                    "laddr":     f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—",
                    "raddr":     f"{ip}:{port}",
                    "remote_ip": ip,
                    "reason":    f"suspicious process ({proc_name}) with outbound connection",
                })
                continue

            # Skip common ports from trusted processes
            if port in COMMON_PORTS and proc_name in TRUSTED_PROCS:
                continue

            # Flag non-standard ports to public IPs (these are unusual)
            if port not in COMMON_PORTS:
                found.append({
                    "pid":       conn.pid,
                    "proc":      proc_name or "unknown",
                    "laddr":     f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—",
                    "raddr":     f"{ip}:{port}",
                    "remote_ip": ip,
                    "reason":    f"non-standard port {port} to public IP",
                })

    except Exception:
        pass
    return found


def _triage_flagged_users() -> List[str]:
    """Find non-root accounts with UID 0 or interactive shells on system UIDs."""
    INTERACTIVE = {"/bin/bash", "/bin/sh", "/usr/bin/zsh", "/usr/bin/fish"}
    flagged = []
    try:
        for user in pwd.getpwall():
            if user.pw_uid == 0 and user.pw_name != "root":
                flagged.append(user.pw_name)
            elif user.pw_uid < 1000 and user.pw_shell in INTERACTIVE and user.pw_name != "root":
                flagged.append(user.pw_name)
    except Exception:
        pass
    return list(set(flagged))


def _triage_writable_crons() -> List[str]:
    """Find world-writable cron files in system cron dirs."""
    CRON_DIRS = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                 "/etc/cron.weekly", "/etc/cron.monthly"]
    flagged = []
    for d in CRON_DIRS:
        if not os.path.isdir(d):
            continue
        for entry in os.scandir(d):
            try:
                mode = os.lstat(entry.path).st_mode
                if mode & 0o002:  # world-writable
                    flagged.append(entry.path)
            except Exception:
                continue
    return flagged


# ── Action builders ───────────────────────────────────────────────────────────

def _build_action_plan(procs, conns, users, crons) -> List[Dict[str, Any]]:
    """Build a list of proposed actions from triage findings."""
    actions = []

    for p in procs:
        actions.append({
            "type":    "kill_process",
            "label":   f"Kill PID {p['pid']} ({p['name']}) — running from {p['exe']}",
            "data":    p,
            "undo":    None,   # cannot undo a killed process
        })

    for c in conns:
        actions.append({
            "type":    "block_ip",
            "label":   f"Block outbound to {c['remote_ip']} — {c.get('reason', 'suspicious connection')} (from {c['laddr']})",
            "data":    c,
            "undo":    f"iptables -D OUTPUT -d {c['remote_ip']} -j DROP",
        })

    for u in users:
        actions.append({
            "type":    "lock_user",
            "label":   f"Lock account: {u}",
            "data":    {"username": u},
            "undo":    f"usermod -U {u}",
        })

    for path in crons:
        actions.append({
            "type":    "remove_cron",
            "label":   f"Remove world-writable cron file: {path}",
            "data":    {"path": path},
            "undo":    None,   # backed up before removal
        })

    return actions


# ── Executors ─────────────────────────────────────────────────────────────────

def _execute_action(action: Dict[str, Any], log: List[Dict]) -> bool:
    atype = action["type"]
    data  = action["data"]
    ts    = _now()
    entry = {"time": ts, "type": atype, "data": data, "result": None, "undo": action["undo"]}

    if atype == "kill_process":
        pid = data["pid"]
        try:
            os.kill(pid, 9)
            entry["result"] = f"Killed PID {pid}"
            console.print(f"  [green]Killed PID {pid} ({data['name']})[/]")
            log.append(entry)
            return True
        except ProcessLookupError:
            entry["result"] = f"PID {pid} already gone"
            console.print(f"  [yellow]PID {pid} already gone[/]")
            log.append(entry)
            return True
        except Exception as e:
            entry["result"] = f"Failed: {e}"
            console.print(f"  [red]Failed to kill PID {pid}: {e}[/]")
            log.append(entry)
            return False

    elif atype == "block_ip":
        ip = data["remote_ip"]
        if not _have("iptables"):
            console.print(f"  [red]iptables not available — cannot block {ip}[/]")
            return False
        rc, _, err = _run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"])
        if rc == 0:
            entry["result"] = f"Blocked {ip}"
            console.print(f"  [green]Blocked outbound to {ip}[/]")
        else:
            entry["result"] = f"Failed: {err}"
            console.print(f"  [red]Failed to block {ip}: {err}[/]")
        log.append(entry)
        return rc == 0

    elif atype == "lock_user":
        username = data["username"]
        if not _have("usermod"):
            console.print(f"  [red]usermod not available — cannot lock {username}[/]")
            return False
        rc, _, err = _run(["usermod", "-L", username])
        if rc == 0:
            entry["result"] = f"Locked {username}"
            console.print(f"  [green]Locked account: {username}[/]")
        else:
            entry["result"] = f"Failed: {err}"
            console.print(f"  [red]Failed to lock {username}: {err}[/]")
        log.append(entry)
        return rc == 0

    elif atype == "remove_cron":
        path = data["path"]
        # Back up before removing
        backup = path + f".rr_backup_{int(time.time())}"
        try:
            shutil.copy2(path, backup)
            os.remove(path)
            entry["result"] = f"Removed {path} (backup: {backup})"
            entry["undo"]   = f"cp {backup} {path}"
            console.print(f"  [green]Removed {path} (backup: {backup})[/]")
        except Exception as e:
            entry["result"] = f"Failed: {e}"
            console.print(f"  [red]Failed to remove {path}: {e}[/]")
        log.append(entry)
        return "Removed" in entry["result"]

    return False


# ── Undo ──────────────────────────────────────────────────────────────────────

def _run_undo(log_file: Path) -> None:
    clear_screen()
    show_header("RAPID RESPONSE — UNDO")

    if not log_file.exists():
        console.print(f"[red]Log file not found: {log_file}[/]")
        pause_return()
        return

    with open(log_file) as f:
        entries = json.load(f).get("actions", [])

    undoable = [e for e in entries if e.get("undo")]
    if not undoable:
        console.print("[yellow]No undoable actions found in this log.[/]")
        pause_return()
        return

    console.print(f"\n[bold]Undoable actions ({len(undoable)}):[/]\n")
    for i, e in enumerate(undoable, 1):
        console.print(f"  [{i}] {e['type']} — {e['undo']}")

    console.print()
    if not Confirm.ask("Run all undo commands?", default=False):
        console.print("[yellow]Undo cancelled.[/]")
        pause_return()
        return

    for e in undoable:
        cmd = e["undo"].split()
        rc, _, err = _run(cmd)
        if rc == 0:
            console.print(f"  [green]Undone: {e['undo']}[/]")
        else:
            console.print(f"  [red]Failed: {e['undo']} — {err}[/]")

    pause_return()


# ── Main entry point ──────────────────────────────────────────────────────────

def run_rapid_response(dry_run: bool = False) -> None:
    if get_os() != "Linux":
        console.print("[yellow]Rapid Response is only supported on Linux.[/]")
        pause_return()
        return

    if os.geteuid() != 0:
        console.print("[bold red]Rapid Response requires root privileges.[/]")
        console.print("[dim]Run ErisLITE with sudo to use this feature.[/dim]")
        pause_return()
        return

    clear_screen()
    _header("RAPID RESPONSE", "[dim]Triage and containment workflow[/]")

    if dry_run:
        console.print(
            Panel.fit(
                "[bold yellow]DRY RUN[/]   [dim]No system changes will be made.[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )
    else:
        console.print(
            Panel.fit(
                "[bold red]LIVE MODE[/]   [white]Containment actions will modify this system.[/]",
                border_style="red",
                box=box.ROUNDED,
            )
        )

    console.print()
    console.print("[dim]Running triage scan...[/]")
    console.print()

    # ── Triage ────────────────────────────────────────────────────────────────
    procs = _triage_suspicious_processes()
    conns = _triage_suspicious_connections()
    users = _triage_flagged_users()
    crons = _triage_writable_crons()

    total = len(procs) + len(conns) + len(users) + len(crons)

    if total == 0:
        console.print("[green]Triage complete — no immediate threats detected.[/]")
        console.print("[dim]Consider running a full Threat Sweep for a deeper analysis.[/dim]")
        pause_return()
        return

    # ── Display findings ──────────────────────────────────────────────────────
    if procs:
        table = Table(
            title=f"[italic cyan]Suspicious Processes ({len(procs)})[/]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            show_edge=False,
            padding=(0, 1),
        )
        table.add_column("PID", style="cyan", no_wrap=True)
        table.add_column("Name", style="white", no_wrap=True)
        table.add_column("Path", style="white")

        for proc in procs:
            table.add_row(str(proc["pid"]), proc["name"], proc["exe"])

        console.print(table)
        console.print()

    if conns:
        table = Table(
            title=f"[italic cyan]Suspicious Connections ({len(conns)})[/]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            show_edge=False,
            padding=(0, 1),
        )
        table.add_column("Local", style="white")
        table.add_column("Remote", style="red")
        table.add_column("Process", style="cyan")

        for conn in conns:
            table.add_row(
                conn["laddr"],
                conn["raddr"],s
                conn.get("proc", "unknown"),
            )

        console.print(table)
        console.print()

    if users:
        console.print(f"\n[bold red]Flagged accounts:[/] {', '.join(users)}")

    if crons:
        console.print(f"\n[bold red]World-writable cron files:[/]")
        for path in crons:
            console.print(f"  [yellow]{path}[/]")

    # ── Action plan ───────────────────────────────────────────────────────────
    actions = _build_action_plan(procs, conns, users, crons)

    action_table = Table(
        title=f"[italic cyan]Proposed Actions ({len(actions)})[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )
    action_table.add_column("#", style="cyan", justify="right")
    action_table.add_column("Action", style="white")
    action_table.add_column("Recovery", no_wrap=True)

    for index, action in enumerate(actions, start=1):
        recovery = (
            "[green]Reversible[/]"
            if action["undo"]
            else "[yellow]Irreversible[/]"
        )
        action_table.add_row(str(index), action["label"], recovery)

    console.print(action_table)
    console.print()

    console.print()

    if dry_run:
        console.print("[yellow]Dry run complete — no changes made.[/]")
        pause_return()
        return

    if not Confirm.ask(
        "\n[bold red]Execute all actions?[/] This will make changes to the system",
        default=False
    ):
        console.print("[yellow]Rapid Response cancelled.[/]")
        pause_return()
        return

    # ── Execute ───────────────────────────────────────────────────────────────
    console.print("\n[bold]Executing actions...[/]\n")

    action_log: List[Dict] = []
    success = 0
    failed  = 0

    for action in actions:
        if _execute_action(action, action_log):
            success += 1
        else:
            failed += 1

    # ── Save log ──────────────────────────────────────────────────────────────
    log_path = _log_path()
    log_data = {
        "timestamp": _now(),
        "mode":      "live",
        "summary":   {"success": success, "failed": failed, "total": len(actions)},
        "actions":   action_log,
    }
    with open(log_path, "w") as f:
        json.dump(log_data, f, indent=2)

    # ── Summary ───────────────────────────────────────────────────────────────
    console.print(f"\n[bold]Done.[/] {success} succeeded, {failed} failed.")
    console.print(f"[dim]Log saved to: {log_path}[/dim]")

    if any(a.get("undo") for a in action_log):
        console.print(
            f"\n[dim]To undo reversible actions, run Rapid Response → Undo "
            f"and select: {log_path.name}[/dim]"
        )

    pause_return()


def run_rapid_response_menu() -> None:
    while True:
        clear_screen()
        _header("RAPID RESPONSE")

        console.print(
            Panel.fit(
                "[bold red]CAUTION[/]\n"
                "[white]Rapid Response can modify system state.[/]\n"
                "[dim]Review proposed actions with Dry Run before executing Live Run.[/]",
                border_style="red",
                box=box.ROUNDED,
            )
        )
        console.print()

        menu = Table(show_header=False, box=None, padding=(0, 1), collapse_padding=True)
        menu.add_column(no_wrap=True)
        menu.add_column()

        menu.add_row("[bold cyan]ACTIONS[/]", "")
        menu.add_row("[cyan][1][/]", "Dry Run", "[dim]Scan and preview actions[/]")
        menu.add_row("[red][2][/]", "[red]Live Run[/]", "[dim]Execute containment actions[/]")
        menu.add_row("[yellow][3][/]", "Undo Previous Run", "[dim]Reverse supported actions[/]")
        menu.add_row("", "")
        menu.add_row("[cyan][0][/]", "Back", "")

        console.print(menu)

        choice = Prompt.ask(
            "\n[cyan]Select an option[/]",
            choices=["0", "1", "2", "3"],
            default="1",
        )

        if choice == "1":
            run_rapid_response(dry_run=True)
        elif choice == "2":
            run_rapid_response(dry_run=False)
        elif choice == "3":
            _select_and_undo()
        elif choice == "0":
            break


def _select_and_undo() -> None:
    clear_screen()
    _header("RAPID RESPONSE — UNDO")

    if not LOG_DIR.exists():
        console.print("[yellow]No rapid response logs found.[/]")
        pause_return()
        return

    logs = sorted(LOG_DIR.glob("rapid_response_*.json"), reverse=True)

    if not logs:
        console.print("[yellow]No rapid response logs found.[/]")
        pause_return()
        return

    table = Table(
        title="[italic cyan]Available Response Logs[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )
    table.add_column("Index", style="cyan", justify="right")
    table.add_column("File", style="white")
    table.add_column("Timestamp", style="dim")

    for index, log in enumerate(logs, start=1):
        try:
            with open(log, "r", encoding="utf-8") as file:
                timestamp = json.load(file).get("timestamp", "—")
        except Exception:
            timestamp = "—"

        table.add_row(str(index), log.name, timestamp)

    console.print(table)

    choice = Prompt.ask(
        "\n[cyan]Select a log[/] [dim](0 to cancel)[/]",
        default="0",
    )

    if choice == "0":
        return

    try:
        _run_undo(logs[int(choice) - 1])
    except (ValueError, IndexError):
        console.print("[red]Invalid selection.[/]")
        pause_return()