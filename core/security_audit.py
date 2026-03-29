# Project: ErisLITE
# Module: security_audit.py
# Author: Liam Piper-Brandon
# Version: 0.5
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-17
# Description:
#   This module provides functionality for performing a security posture snapshot on the local system.
#   It includes checks for firewall status, suspicious processes, world-writable files, SSH keys
#   and recent failed login attempts. The results are displayed in a rich table and logged for later review.

import os, re, stat, shutil, subprocess
from pathlib import Path
from datetime import datetime

import psutil
from rich.console import Console
from rich.table import Table
from rich.align import Align

from tools.security_log import write_audit_log
from ui.utils import clear_screen, show_header, pause_return

console = Console()


#----------------------------
# Helpers
#----------------------------

def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _safe_run(args: list[str]) -> subprocess.CompletedProcess:
    # Avoid throwing on nonzero return codes; we interpret stdout/stderr ourselves.
    return subprocess.run(args, capture_output=True, text=True)


# ----------------------------
# Checks
# ----------------------------

def check_firewall_status():
    """
    Snapshot-style: identify an active firewall mechanism quickly.
    """
    try:
        # UFW
        if _have("ufw"):
            ufw = _safe_run(["ufw", "status"])
            out = (ufw.stdout or "") + (ufw.stderr or "")
            if "Status: active" in out:
                return "🟢 UFW - Active"
            if "Status: inactive" in out or "inactive" in out:
                return "🔴 UFW - Inactive"

        # firewalld
        if _have("systemctl"):
            firewalld = _safe_run(["systemctl", "is-active", "firewalld"])
            out = (firewalld.stdout or "").strip()
            if out == "active":
                return "🟢 firewalld - Active"
            if out in {"inactive", "failed", "unknown"}:
                # keep checking other mechanisms
                pass

        # nftables
        if _have("nft"):
            nft = _safe_run(["nft", "list", "ruleset"])
            if (nft.stdout or "").strip():
                return "🟡 nftables rules present"

        # iptables fallback
        if _have("iptables"):
            ipt = _safe_run(["iptables", "-S"])
            # If there is at least one rule/policy line, we treat as "present"
            if (ipt.stdout or "").strip():
                return "🟡 iptables rules present"

        return "🔴 No firewall rules detected"

    except Exception as e:
        return f"⚠️ Error: {str(e)}"

# Note: the following checks are designed to be "snapshot-style" - they look for strong indicators of potential compromise or misconfiguration, but do not attempt to be exhaustive or definitive. The goal is to quickly surface notable findings that may warrant further investigation, without overwhelming the user with noise or false positives.
def check_suspicious_procs():
    """
    Snapshot-style (low-noise):
    Flags processes if they:
      - execute from /tmp, /dev/shm, /var/tmp
      - OR have commandline patterns strongly associated with malicious staging/execution
    """
    flagged = []

    shady_paths = ("/tmp", "/dev/shm", "/var/tmp")
    # Strong signals (not just "curl exists")
    suspicious_cmd_patterns = [
        r"\|\s*(ba?sh|sh)\b",                 # curl/wget | bash
        r"\bbase64\b.*\s-d\b",                # base64 decode then exec often
        r"\bpython\d*\b\s+-c\s+",             # python -c one-liners
        r"\bperl\b\s+-e\s+",                  # perl -e one-liners
        r"\bruby\b\s+-e\s+",                  # ruby -e
        r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+",   # bash tcp trick
        r"\bnc\b.*\s(-e|--exec)\b",           # netcat exec
        r"\bsocat\b.*EXEC:",                  # socat EXEC
        r"\bcurl\b.*\bhttp",                  # staged download (only counts if paired w/ other signals below)
        r"\bwget\b.*\bhttp",
    ]

    # If curl/wget seen alone, it's normal; require "shaping" indicators too
    curl_wget_amplifiers = [
        r"\|\s*(ba?sh|sh)\b",
        r"\b-o\s*/tmp/",
        r"\b-O\s*/tmp/",
        r"/dev/shm/",
        r"\bchmod\s+\+x\b",
    ]

    try:
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            pid = proc.info.get('pid')
            name = (proc.info.get('name') or "").strip()
            exe = (proc.info.get('exe') or "").strip()
            cmdline_list = proc.info.get('cmdline') or []
            cmd = " ".join(cmdline_list).strip().lower()
            exe_l = exe.lower()

            reasons = []

            # Executed from shady path
            if exe and exe_l.startswith(shady_paths):
                reasons.append(f"exe_in_shady_path:{exe}")

            # Strong commandline patterns
            for pat in suspicious_cmd_patterns:
                if re.search(pat, cmd):
                    # Reduce curl/wget false positives: require amplifiers for those
                    if "curl" in pat or "wget" in pat:
                        if any(re.search(a, cmd) for a in curl_wget_amplifiers):
                            reasons.append("staged_download_exec")
                    else:
                        reasons.append(f"cmd_match:{pat}")
                    break

            if reasons:
                flagged.append(f"{name or 'unknown'} (PID {pid}) [{', '.join(reasons)}]")

        if flagged:
            return f"[red]⚠️  {len(flagged)} suspicious[/]"
        return "🟢 No obvious suspicious processes"

    except Exception as e:
        return f"⚠️ Error: {str(e)}"

# The following check is designed to identify "high-risk" world-writable items in critical system locations. While world-writable files/directories are not inherently malicious, those that are located in sensitive areas (like /etc or /usr/bin) and especially if they are executable or root-owned, can be strong indicators of potential compromise or misconfiguration. This check focuses on surfacing those high-risk items while ignoring more common and less risky world-writable files that are often found in places like /tmp.
def check_world_writable():
    """
    Snapshot-style HIGH-RISK world-writable detector.

    Returns:
      (status_str, preview_paths)

    Flags items that are world-writable AND:
      - directories in critical roots (drop locations), OR
      - executable files in critical roots (especially root-owned)
    """
    critical_roots = [
        "/etc",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/etc/systemd",
        "/lib/systemd",
        "/usr/lib/systemd",
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
    ]

    skip_prefixes = (
        "/proc", "/sys", "/run", "/dev", "/snap",
        "/var/lib/docker", "/var/lib/snapd"
    )

    preview = []
    max_store = 50  # how many paths we keep for logging
    total_flagged = 0

    try:
        for base in critical_roots:
            if not os.path.exists(base):
                continue

            for root, dirs, files in os.walk(base, topdown=True, followlinks=False):
                if root.startswith(skip_prefixes):
                    dirs[:] = []
                    continue

                # prune common noise if present
                dirs[:] = [d for d in dirs if d not in {".git", ".cache"}]

                for name in dirs + files:
                    full_path = os.path.join(root, name)
                    try:
                        st = os.lstat(full_path)

                        if not (st.st_mode & stat.S_IWOTH):
                            continue

                        is_dir = stat.S_ISDIR(st.st_mode)
                        is_reg = stat.S_ISREG(st.st_mode)
                        is_executable = bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                        is_root_owned = (st.st_uid == 0)

                        high_risk = False

                        # Directories in critical roots are high-risk: enables dropping binaries/scripts
                        if is_dir:
                            high_risk = True

                        # Executable files in critical roots are high-risk
                        if is_reg and is_executable:
                            high_risk = True

                        # Root-owned executable is especially notable
                        if is_reg and is_executable and is_root_owned:
                            high_risk = True

                        if high_risk:
                            total_flagged += 1
                            if len(preview) < max_store:
                                meta = []
                                if is_dir:
                                    meta.append("dir")
                                if is_executable:
                                    meta.append("exec")
                                if is_root_owned:
                                    meta.append("root-owned")
                                preview.append(f"{full_path} ({', '.join(meta)})")

                    except (FileNotFoundError, PermissionError):
                        continue

        if total_flagged:
            return (f"[yellow]⚠️  {total_flagged} high-risk world-writable[/]", preview)
        return ("🟢 No high-risk world-writable items", [])

    except Exception as e:
        return (f"⚠️ Error: {str(e)}", [])

# The following check looks for the presence of SSH authorized_keys files in user home directories and root, and counts the number of key lines. While the mere presence of authorized_keys is not necessarily a sign of compromise (as it can be used for legitimate key-based access), it is still a notable finding that may warrant review, especially if there are many keys or if the file is found in unexpected locations. This check is designed to be "snapshot-style" by reporting the presence and count of keys without making assumptions about their validity or intent.
def check_ssh_keys():
    """
    Snapshot-style:
    Report presence, not "keys are bad".
    """
    paths_to_check = []

    try:
        # user homes
        for user_home in [p for p in Path("/home").glob("*") if p.is_dir()]:
            ssh_file = user_home / ".ssh" / "authorized_keys"
            if ssh_file.exists():
                paths_to_check.append(ssh_file)

        # root
        root_keys = Path("/root/.ssh/authorized_keys")
        if root_keys.exists():
            paths_to_check.append(root_keys)

        if not paths_to_check:
            return "🟢 No authorized_keys found"

        key_lines = 0
        for path in paths_to_check:
            try:
                with open(path, "r", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            key_lines += 1
            except (PermissionError, FileNotFoundError):
                continue

        # Even if key_lines == 0, presence is still notable.
        return f"🟡 authorized_keys present ({len(paths_to_check)} file(s), {key_lines} key line(s))"

    except Exception as e:
        return f"⚠️ Error: {str(e)}"

# The following check looks for failed SSH login attempts in the system authentication logs (like auth.log or secure) for the current day. While failed login attempts can be common and not necessarily indicative of a compromise, a high number of them in a short period can be a strong signal of brute-force attacks or unauthorized access attempts. This check is designed to be "snapshot-style" by counting today's failed SSH logins and reporting the total, without attempting to analyze patterns or correlate with other events.
def check_login_events():
    """
    Snapshot-style:
    Today’s failed SSH logins (auth.log or secure)
    """
    failed = 0
    log_paths = ["/var/log/auth.log", "/var/log/secure"]
    today = datetime.now().strftime("%b %d")  # e.g., "Feb 16"

    try:
        for log_path in log_paths:
            if not os.path.exists(log_path):
                continue

            with open(log_path, "r", errors='ignore') as log:
                for line in log:
                    if today in line and "Failed password" in line:
                        failed += 1

            break  # stop after first existing log file

        if failed > 0:
            return f"[yellow]⚠️ {failed} failed SSH login(s) today[/]"
        return "🟢 No failed SSH logins today"

    except Exception as e:
        return f"⚠️ Error: {str(e)}"


# ----------------------------
# Runner
# ----------------------------

def run(profile: dict):
    clear_screen()
    show_header("POSTURE SNAPSHOT")  # rename the header to match behavior

    findings = []

    firewall_status = check_firewall_status()
    if firewall_status.startswith(("🔴", "⚠️")):
        findings.append(f"Firewall: {firewall_status}")

    proc_status = check_suspicious_procs()
    if "⚠️" in proc_status or "Error" in proc_status:
        findings.append(f"Processes: {proc_status}")

    ssh_key_status = check_ssh_keys()
    # Presence is noteworthy but not necessarily "bad"; still include in findings as INFO
    if ssh_key_status.startswith(("🟡", "⚠️")):
        findings.append(f"SSH Keys: {ssh_key_status}")

    writable_status, writable_preview = check_world_writable()
    if "⚠️" in writable_status or "Error" in writable_status:
        findings.append(f"World-writable: {writable_status}")
        if writable_preview:
            findings.append("World-writable preview:")
            findings.extend(writable_preview)

    login_status = check_login_events()
    if "⚠️" in login_status or "Error" in login_status:
        findings.append(f"Auth Logs: {login_status}")

    table = Table(title="Posture Snapshot (Fast)", show_lines=True)
    table.add_column("Check", style="cyan", no_wrap=True)
    table.add_column("Status", style="green")

    table.add_row("Firewall", firewall_status)
    table.add_row("Suspicious Processes", proc_status)
    table.add_row("SSH Authorized Keys", ssh_key_status)
    table.add_row("High-Risk World-Writable", writable_status)
    table.add_row("Failed SSH Logins (Today)", login_status)

    console.print(Align.center(table))

    # Log the findings (will be mostly actionable or notable info now)
    log_path = write_audit_log(profile, findings)
    console.print(f"\n[green]Snapshot saved to:[/] {log_path}")

    pause_return()
