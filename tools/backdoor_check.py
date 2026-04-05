# Project: ErisLITE
# Module: backdoor_check.py
# Author: Liam Piper-Brandon
# Version: 1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-04-05
# Description: Shell init files, profile.d, LD_PRELOAD persistence indicators.

import os
import re
import pwd
import stat

from rich.console import Console
from rich.table import Table
from rich.align import Align

from ui.utils import clear_screen, show_header, pause_return, get_os

console = Console()

# ── Suspicious command patterns ───────────────────────────────────────────────
# These regex patterns match commands commonly used to establish persistence
# or call back to a C2 in shell init files.

SUSPICIOUS_PATTERNS = [
    (re.compile(r"\bnc\b.*(-e|--exec|-c)\b",           re.I), "netcat backdoor"),
    (re.compile(r"\bncat\b.*(-e|--exec|-c)\b",          re.I), "ncat backdoor"),
    (re.compile(r"\bsocat\b.*EXEC:",                    re.I), "socat backdoor"),
    (re.compile(r"/dev/tcp/\d{1,3}(\.\d{1,3}){3}/\d+", re.I), "bash TCP reverse shell"),
    (re.compile(r"\bcurl\b.*(sh|bash|python)\b",        re.I), "staged download/exec"),
    (re.compile(r"\bwget\b.*(sh|bash|python)\b",        re.I), "staged download/exec"),
    (re.compile(r"\bbase64\b\s+(-d|--decode)",          re.I), "base64 decode exec"),
    (re.compile(r"\bpython\d*\b\s+-c\b",                re.I), "python one-liner"),
    (re.compile(r"\bperl\b\s+-e\b",                     re.I), "perl one-liner"),
    (re.compile(r"\bruby\b\s+-e\b",                     re.I), "ruby one-liner"),
    (re.compile(r"\bchmod\s+[0-7]*[67][0-7]{2}\b",      re.I), "chmod making executable"),
    (re.compile(r"\bnohup\b",                            re.I), "nohup persistence"),
    (re.compile(r"\bat\b\s+now",                         re.I), "at-job execution"),
    (re.compile(r"LD_PRELOAD\s*=",                       re.I), "LD_PRELOAD override"),
]

# ── Locations to scan ─────────────────────────────────────────────────────────

# System-wide shell init files
SYSTEM_INIT_FILES = [
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/bashrc",
    "/etc/environment",
    "/etc/zshrc",
    "/etc/zshenv",
]

# Directories whose contents are sourced on login/shell start
SYSTEM_INIT_DIRS = [
    "/etc/profile.d",
    "/etc/update-motd.d",
]

# Per-user init files (relative to home dir)
USER_INIT_FILES = [
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".xinitrc",
    ".xsession",
    ".config/autostart",
]

# ── Preload/LD checks ─────────────────────────────────────────────────────────

def _check_ld_preload() -> list:
    """Check /etc/ld.so.preload for injected libraries."""
    findings = []
    path = "/etc/ld.so.preload"
    if not os.path.exists(path):
        return findings

    try:
        with open(path, "r", errors="ignore") as f:
            content = f.read().strip()
        if content:
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    findings.append({
                        "location": path,
                        "line":     line,
                        "reason":   f"Library injected via ld.so.preload: {line}",
                        "tag":      "backdoor_ld_preload",
                    })
    except Exception as e:
        findings.append({
            "location": path,
            "line":     "",
            "reason":   f"Could not read {path}: {e}",
            "tag":      "backdoor_read_error",
        })
    return findings


def _check_env_ld_preload() -> list:
    """Check running process environments for LD_PRELOAD."""
    findings = []

    # Snap packages legitimately use LD_PRELOAD to inject platform libs.
    # These paths and bare library names are safe and extremely noisy.
    SNAP_PRELOAD_WHITELIST = (
        "/snap/",
        "/var/lib/snapd/",
    )

    # Bare library names (no path) that are known legitimate.
    # Firefox/Mozilla uses libmozsandbox.so as a bare name.
    BARE_LIB_WHITELIST = {
        "libmozsandbox.so",
        "bindtextdomain.so",
    }

    try:
        for entry in os.scandir("/proc"):
            if not entry.is_dir() or not entry.name.isdigit():
                continue
            env_path = f"/proc/{entry.name}/environ"
            try:
                with open(env_path, "rb") as f:
                    env = f.read().decode("utf-8", errors="replace")
                if "LD_PRELOAD=" in env:
                    for var in env.split("\x00"):
                        if var.startswith("LD_PRELOAD="):
                            val = var.split("=", 1)[1]
                            # LD_PRELOAD can contain multiple libs separated by
                            # spaces or colons — check each one individually.
                            libs = re.split(r"[ :]", val)
                            suspicious_libs = [
                                lib for lib in libs
                                if lib
                                and not any(lib.startswith(p) for p in SNAP_PRELOAD_WHITELIST)
                                and lib not in BARE_LIB_WHITELIST
                            ]
                            if suspicious_libs:
                                findings.append({
                                    "location": f"PID {entry.name} environment",
                                    "line":     var,
                                    "reason":   f"LD_PRELOAD active in PID {entry.name}: {', '.join(suspicious_libs)}",
                                    "tag":      "backdoor_ld_preload_env",
                                })
                            break
            except (PermissionError, FileNotFoundError):
                continue
    except Exception:
        pass
    return findings


# ── File scanner ──────────────────────────────────────────────────────────────

def _scan_file(path: str) -> list:
    """Scan a single file for suspicious patterns. Returns list of findings."""
    findings = []
    try:
        with open(path, "r", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                for pattern, label in SUSPICIOUS_PATTERNS:
                    if pattern.search(stripped):
                        findings.append({
                            "location": f"{path}:{lineno}",
                            "line":     stripped[:120],
                            "reason":   f"{label} pattern in {os.path.basename(path)}",
                            "tag":      "backdoor_init_file",
                        })
                        break  # one finding per line
    except (PermissionError, FileNotFoundError):
        pass
    except Exception as e:
        findings.append({
            "location": path,
            "line":     "",
            "reason":   f"Read error: {e}",
            "tag":      "backdoor_read_error",
        })
    return findings


def _scan_dir(directory: str) -> list:
    """Scan all files in a directory."""
    findings = []
    if not os.path.isdir(directory):
        return findings
    try:
        for entry in os.scandir(directory):
            if entry.is_file():
                findings.extend(_scan_file(entry.path))
    except PermissionError:
        pass
    return findings


# ── Main scanner ──────────────────────────────────────────────────────────────

def scan_backdoors() -> list:
    findings = []

    # System init files
    for path in SYSTEM_INIT_FILES:
        if os.path.isfile(path):
            findings.extend(_scan_file(path))

    # System init directories
    for directory in SYSTEM_INIT_DIRS:
        findings.extend(_scan_dir(directory))

    # Per-user init files for all users with real home dirs
    try:
        for user in pwd.getpwall():
            if user.pw_uid < 1000 and user.pw_name != "root":
                continue
            home = user.pw_dir
            if not home or not os.path.isdir(home):
                continue
            for rel_path in USER_INIT_FILES:
                full_path = os.path.join(home, rel_path)
                if os.path.isfile(full_path):
                    findings.extend(_scan_file(full_path))
                elif os.path.isdir(full_path):
                    findings.extend(_scan_dir(full_path))
    except Exception:
        pass

    # LD_PRELOAD checks
    findings.extend(_check_ld_preload())
    findings.extend(_check_env_ld_preload())

    return findings


# ── Main entry point ──────────────────────────────────────────────────────────

def run_backdoor_check(silent: bool = False) -> dict:
    os_type = get_os()

    if os_type != "Linux":
        if not silent:
            clear_screen()
            show_header("BACKDOOR DETECTION")
            console.print("[yellow]This module is only supported on Linux.[/]")
            pause_return()
        return {"status": "unsupported", "details": [], "tags": []}

    findings = scan_backdoors()

    all_tags = set(f["tag"] for f in findings)

    # ── Silent mode ───────────────────────────────────────────────────────────
    if silent:
        if not findings:
            return {"status": "ok", "details": [], "tags": []}

        details = [f"{f['location']} — {f['reason']}" for f in findings]
        return {
            "status": "warning",
            "details": details[:10],
            "tags":    sorted(all_tags),
        }

    # ── Interactive mode ──────────────────────────────────────────────────────
    clear_screen()
    show_header("BACKDOOR DETECTION")

    if not findings:
        console.print("[green]No backdoor or persistence indicators detected.[/]")
        pause_return()
        return {"status": "ok", "details": [], "tags": []}

    table = Table(title=f"Backdoor / Persistence Findings ({len(findings)} found)",
                  show_lines=True)
    table.add_column("Location", style="cyan",    overflow="fold", min_width=30)
    table.add_column("Reason",   style="yellow",  overflow="fold")
    table.add_column("Content",  style="dim",     overflow="fold", max_width=60)

    for f in findings:
        table.add_row(f["location"], f["reason"], f["line"])

    console.print(Align.center(table))
    console.print(
        f"\n[bold red]⚠  {len(findings)} persistence indicator(s) detected.[/]\n"
        "[dim]Review each finding — some may be legitimate admin scripts.[/dim]"
    )
    pause_return()

    return {
        "status": "warning",
        "details": [f"{f['location']} — {f['reason']}" for f in findings],
        "tags":    sorted(all_tags),
    }