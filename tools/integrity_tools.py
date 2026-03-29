# Project: ErisLITE
# Module: integrity_tools.py
# Author: Liam Piper-Brandon
# Version: 0.5
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-03-17
# Description:
#   This module provides tools for monitoring the integrity of critical system files. It allows users to create 
#   a baseline of file hashes, scan for changes against that baseline, and check for potential tampering or 
#   unauthorized modifications. The module is designed to be cross-platform, with specific monitored files and 
#   scan profiles tailored for both Linux and Windows systems. It also includes functionality to detect suspicious 
#   copies of monitored files in common temporary locations, which could indicate an attacker attempting to bypass 
#   integrity checks or exfiltrate data.

import os, json, hashlib, glob

from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.align import Align

from ui.utils import clear_screen, show_header, pause_return, get_os

BASELINE_PATH = "data/integrity/baseline.json"

os_type = get_os()

if os_type == "Linux":
    MONITORED_FILES = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh/sshd_config"
    ]

    SCAN_PROFILES = {
        "critical": [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/ssh/sshd_config"
        ],
        "system": [
            "/etc/",
            "/usr/bin/",
            "/lib/",
            "/lib64/"
        ],
        "user": [
            os.path.expanduser("~/.bashrc"),
            os.path.expanduser("~/.ssh/authorized_keys"),
            os.path.expanduser("~/.profile")
        ]
    }

elif os_type == "Windows":
    MONITORED_FILES = [
        r"C:\Windows\System32\config\SAM",
        r"C:\Windows\System32\config\SYSTEM",
        r"C:\Windows\System32\drivers\etc\hosts",
        r"C:\Windows\System32\config\SECURITY"
    ]

    SCAN_PROFILES = {
        "critical": [
            r"C:\Windows\System32\config\SAM",
            r"C:\Windows\System32\config\SYSTEM",
            r"C:\Windows\System32\drivers\etc\hosts",
            r"C:\Windows\System32\config\SECURITY"
        ],
        "system": [
            r"C:\Windows\System32",
            r"C:\Program Files",
            r"C:\Program Files (x86)"
        ],
        "user": [
            os.path.expanduser(r"~\Documents"),
            os.path.expanduser(r"~\AppData\Roaming"),
            os.path.expanduser(r"~\AppData\Local")
        ]
    }

else:
    MONITORED_FILES = []
    SCAN_PROFILES = {}


console = Console()

# Helper function to compute SHA256 hash of a file
def get_sha256(path):
    try:
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None  # file missing or unreadable

# Check the integrity of the baseline file itself to detect potential tampering or corruption
def check_baseline_integrity():
    if not os.path.exists(BASELINE_PATH):
        return {
            "status": "error",
            "details": ["Baseline file missing"],
            "tags": ["baseline_missing"]
        }

    try:
        stat = os.stat(BASELINE_PATH)
        mtime = datetime.fromtimestamp(stat.st_mtime)

        with open(BASELINE_PATH, 'r') as f:
            data = json.load(f)

        metadata = data.get("_metadata", {})
        created_at = metadata.get("created_at", None)
        hashes = data.get("hashes", {})

        if not created_at or not isinstance(hashes, dict):
            return {
                "status": "warning",
                "details": ["Missing or malformed baseline metadata"],
                "tags": ["baseline_tamper"]
            }

        created_dt = datetime.fromisoformat(created_at)
        issues = []

        if mtime > created_dt:
            issues.append(f"Baseline modified after creation (mtime: {mtime}, created_at: {created_dt})")

        if len(hashes) < 3:
            issues.append("Baseline contains fewer than 3 entries — may be incomplete or tampered.")

        return {
            "status": "warning" if issues else "ok",
            "details": issues,
            "tags": ["baseline_tamper"] if issues else []
        }

    except Exception as e:
        return {
            "status": "error",
            "details": [f"Failed to validate baseline integrity: {e}"],
            "tags": ["baseline_check_error"]
        }

# Scan common temporary locations for potential copies of monitored files, which could indicate an attacker trying to exfiltrate data or bypass integrity checks by placing copies in less monitored areas.
def scan_for_copies(baseline):
    if get_os() == "Windows":
        shady_locations = [r"C:\Temp", r"C:\Users"]
    else:
        shady_locations = ["/tmp", "/dev/shm", "/home", "/run", "/var/tmp"]

    keywords = ["passwd", "shadow", "sudoers", "sshd_config", "SAM", "SYSTEM", "SECURITY", "hosts"]
    flagged = []

    for root in shady_locations:
        for keyword in keywords:
            pattern = os.path.join(root, "**", f"*{keyword}*")
            for path in glob.glob(pattern, recursive=True):
                if os.path.isfile(path):
                    copy_hash = get_sha256(path)
                    for base_path, base_hash in baseline.items():
                        if keyword.lower() in base_path.lower() and copy_hash == base_hash:
                            flagged.append((path, "Exact copy of known file"))
                            break

    if flagged:
        console.print("\n[red]⚠️  Suspicious file copies detected:[/]")
        for path, reason in flagged:
            console.print(f" - {path}  [yellow]({reason})[/]")
    else:
        console.print("\n[green]No suspicious file copies found.[/]")

# Create a baseline of monitored files with their SHA256 hashes and include metadata about when the baseline was created. This allows for future integrity checks against this baseline to detect any unauthorized changes to critical system files.
def create_baseline():
    baseline = {}
    for path in MONITORED_FILES:
        hash_val = get_sha256(path)
        if hash_val:
            baseline[path] = hash_val

    baseline_payload = {
        "_metadata": {
            "created_at": datetime.now().isoformat()
        },
        "hashes": baseline
    }

    os.makedirs(os.path.dirname(BASELINE_PATH), exist_ok=True)
    with open(BASELINE_PATH, 'w') as f:
        json.dump(baseline_payload, f, indent=2)

    console.print("[green]✅ Integrity baseline created with metadata.[/]")
    pause_return()

# Scan the monitored files and compare their current hashes against the baseline to detect any modifications, missing files, or potential integrity issues. The results are displayed in a table format, and any issues are highlighted for the user to review.
def scan_integrity(profile="critical", silent=False):
    os_type = get_os()

    if os_type == "Other":
        if not silent:
            console.print("[yellow]This module is not supported on this OS.[/]")
            pause_return()
        return {
            "status": "unsupported",
            "details": [],
            "tags": []
        }

    if not os.path.exists(BASELINE_PATH):
        if not silent:
            console.print("[red]❌ No baseline found. Please create one first.[/]")
            pause_return()
        return {
            "status": "error",
            "details": ["Baseline file missing"],
            "tags": ["file_integrity_issue"]
        }

    with open(BASELINE_PATH, 'r') as f:
        payload = json.load(f)

    baseline = payload.get("hashes", {})

    baseline_check = check_baseline_integrity()
    if baseline_check["status"] != "ok":
        if not silent:
            console.print(f"\n[bold red]⚠️ Baseline Warning:[/] {'; '.join(baseline_check['details'])}")
        return baseline_check

    # Determine which paths to scan based on the profile
    if profile not in SCAN_PROFILES:
        targets = list(baseline.keys())  # fallback to baseline paths
    else:
        targets = []
        for item in SCAN_PROFILES[profile]:
            if os.path.isdir(item):
                for root, dirs, files in os.walk(item):
                    for file in files:
                        full_path = os.path.join(root, file)
                        targets.append(full_path)
            elif os.path.isfile(item):
                targets.append(item)

    if not targets:
        if not silent:
            console.print("[yellow]No files found to scan for this profile.[/]")
            pause_return()
        return {
            "status": "ok",
            "details": ["No files found to scan."],
            "tags": []
        }

    table = Table(title=f"File Integrity Check ({profile.title()} Profile)", show_lines=True)
    table.add_column("File")
    table.add_column("Status")

    issues = []

    for path in targets:
        old_hash = baseline.get(path)
        new_hash = get_sha256(path)

        if not new_hash:
            table.add_row(path, "[red]Missing[/]")
            issues.append(f"{path} is missing")
        elif old_hash and new_hash != old_hash:
            table.add_row(path, "[red]Modified[/]")
            issues.append(f"{path} was modified")
        elif old_hash:
            table.add_row(path, "[green]Unchanged[/]")

    result = {
        "status": "warning" if issues else "ok",
        "details": issues,
        "tags": ["file_integrity_issue"] if issues else []
    }

    if not silent:
        clear_screen()
        show_header("FILE INTEGRITY SCAN")
        console.print(Align.center(table))
        if issues:
            console.print(f"\n[red]⚠️ {len(issues)} issue(s) detected.[/]")
        else:
            console.print("\n[green]✅ No issues detected.[/]")
        scan_for_copies(baseline)
        pause_return()

    return result

# Main menu for the file integrity monitoring tool, allowing users to create a baseline, run a quick scan with different profiles, or return to the previous menu. The interface is designed to be user-friendly and informative, guiding users through the integrity monitoring process.
def integrity_menu():
    while True:
        clear_screen()
        show_header("FILE INTEGRITY MONITOR")

        menu = Table(show_header=False, box=None, padding=(0, 1))
        menu.add_row("[1]", "📄  Create Integrity Baseline")
        menu.add_row("", "")
        menu.add_row("[2]", "🔎  Run Quick Scan")
        menu.add_row("", "")
        menu.add_row("[3]", "↩️   Back to Security Menu")
        console.print(menu)

        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            create_baseline()
        elif choice == "2":
            clear_screen()
            show_header("SELECT SCAN PROFILE")
            console.print("Available Profiles: [cyan]critical[/], [yellow]system[/], [magenta]user[/]")
            selected = input("\nEnter profile name [default: critical]: ").strip().lower() or "critical"
            scan_integrity(profile=selected)
        elif choice == "3":
            break
        else:
            console.print("[red]Invalid option.[/]")
            pause_return()