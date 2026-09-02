# Project: ErisLITE
# Module: threat_sweep.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: Threat sweep orchestrator: runs selected modules, scores risk, and saves results.

import json
from datetime import datetime

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from erislite.accounts import login_audit, users, ssh_keys, ssh_config
from erislite.containers import docker
from erislite.network import listeners, firewall, hosts
from erislite.persistence import world_writable, cron, suid, backdoors
from erislite.system import integrity, kernel_modules, processes
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, pause_return
from erislite.vulnerability import cve_checker

from erislite.config.settings import (
    APP_NAME,
    APP_VERSION,
    LAST_SWEEP_FILE,
    SWEEP_LOG_DIR,
    SWEEP_PROFILES,
)

# 🧠 Tag-to-Insight Mapping
THREAT_TAG_MAP = {
    "cve_match": "Outdated or vulnerable software version detected.",
    "firewall_disabled": "No active firewall detected — system may be fully exposed to the network.",
    "firewall_ufw_inactive": "UFW is installed but currently inactive.",
    "firewall_ip_empty": "iptables is present but no rules are loaded — system may be unprotected.",
    "suspicious_login": "Unauthorized or shell-access account detected.",
    "rogue_kernel_mod": "Potential rootkit or unsigned module loaded.",
    "world_writable": "Files or directories allow any-user write access.",
    "suspicious_listener": "Unusual open network listener(s) found.",
    "suspicious_cron": "Automated task may indicate persistence or backdoor.",
    "unauthorized_key": "Unexpected SSH key found under a user profile.",
    "suid_sgid": "SUID or SGID binaries can allow privilege escalation if misconfigured.",
    "suid_dangerous_path": "SUID/SGID binary found in a high-risk path (tmp, home, shm).",
    "suid_interpreter": "SUID/SGID set on a script interpreter — extremely dangerous.",
    "ssh_keys_suspicious": "SSH key(s) found in user authorized_keys files.",
    "ssh_keys_user_root": "SSH key found under root's account — may allow privileged backdoor access.",
    "ssh_keys_multiple_users": "Multiple users have SSH authorized_keys — review for lateral movement risks.",
    "ssh_keys_system_user": "SSH key assigned to system-level user — uncommon and may be suspicious.",
    "proc_root_suspicious_path": "Root process spawned from a high-risk path (tmp, shm, home).",
    "proc_deleted_exe": "Process running from a deleted executable — common rootkit indicator.",
    "proc_known_bad": "Process name matches a known offensive or post-exploitation tool.",
    "proc_root_interpreter": "Script interpreter running as root without a named service wrapper.",
    "proc_hidden_name": "Process name starts with a dot — may be intentionally hidden.",
    "proc_no_exe": "Root process with no resolvable executable path.",
    "hosts_critical_redirect": "A critical domain (update server, CA, security tool) has been redirected in /etc/hosts.",
    "hosts_loopback_redirect": "A non-localhost hostname is redirected to loopback — may block security or update tools.",
    "hosts_suspicious_entry": "Suspicious hostname pattern detected in /etc/hosts.",
    "hosts_duplicate_mapping": "A hostname maps to multiple different IPs — possible hijack.",
    "hosts_unreadable": "/etc/hosts could not be read.",
    "backdoor_init_file": "Suspicious command found in a shell init or profile file.",
    "backdoor_ld_preload": "Library injected via /etc/ld.so.preload — high-confidence rootkit indicator.",
    "backdoor_ld_preload_env": "LD_PRELOAD is active in a running process environment.",
    "backdoor_read_error": "Could not read a file during backdoor scan.",
    "no_home_dir": "User account has no valid home directory.",
    "nonstandard_shell": "User account has an unusual or non-standard login shell.",
    "hosts_private_redirect": "External-looking hostname is mapped to a private address.",
    "ssh_keys_unknown_type": "Authorized key uses an unrecognized SSH key format.",
    "suid_nonstandard_location": "SUID/SGID binary is located outside standard executable paths.",
}


def calculate_risk_score(results: dict):
    weights = {
        "integrity": 20,
        "listeners": 15,
        "users": 15,
        "kernel": 15,
        "sshkeys": 10,
        "worldwritable": 10,
        "cron": 15,
        "login": 10,
        "sshconfig": 10,
        "docker": 15,
        "firewall": 15,
        "cve": 20,
        "suid": 10,
        "processes": 20,
        "hosts": 20,
        "backdoor": 25,
    }

    total_score = 0
    breakdown = {}
    max_score = 0

    for module in results:
        if module in weights:
            weight = weights[module]
            max_score += weight
            status = results[module].get("status", "").lower()
            if status in ("warning", "error", "issue"):
                total_score += weight
                breakdown[module] = weight
            else:
                breakdown[module] = 0

    return total_score, breakdown, max_score


def run_sweep(user_profile, sweep_profile="standard"):
    clear_screen()
    _render_header(user_profile, sweep_profile)
    console.print("[dim]Running security checks...[/]")
    console.print()

    profiles = SWEEP_PROFILES

    results = {}

    if "integrity" in profiles[sweep_profile]:
        results["integrity"] = integrity.scan_integrity(silent=True)

    if "listeners" in profiles[sweep_profile]:
        results["listeners"] = listeners.run_listener_scan(silent=True)

    if "users" in profiles[sweep_profile]:
        results["users"] = users.run_user_scan(silent=True)

    if "kernel" in profiles[sweep_profile]:
        results["kernel"] = kernel_modules.run_kernel_module_check(silent=True)

    if "sshkeys" in profiles[sweep_profile]:
        results["sshkeys"] = ssh_keys.run_ssh_key_check(silent=True)

    if "worldwritable" in profiles[sweep_profile]:
        results["worldwritable"] = world_writable.run_world_writable_check(silent=True)

    if "cron" in profiles[sweep_profile]:
        results["cron"] = cron.run_cron_timer_scan(silent=True)

    if "login" in profiles[sweep_profile]:
        results["login"] = login_audit.run_login_audit(silent=True)

    if "sshconfig" in profiles[sweep_profile]:
        results["sshconfig"] = ssh_config.run_ssh_config_check(silent=True)

    if "docker" in profiles[sweep_profile]:
        results["docker"] = docker.run_docker_scan(silent=True)

    # FIX #7: suid was in the weights dict and in the full profile list but was never
    # assigned to results{}, so it could never contribute to the risk score. Wired in now.
    if "suid" in profiles[sweep_profile]:
        results["suid"] = suid.run_suid_scan(silent=True)

    if "processes" in profiles[sweep_profile]:
        results["processes"] = processes.run_process_scan(silent=True)

    if "hosts" in profiles[sweep_profile]:
        results["hosts"] = hosts.run_hosts_check(silent=True)

    if "backdoor" in profiles[sweep_profile]:
        results["backdoor"] = backdoors.run_backdoor_check(silent=True)

    if "cve" in profiles[sweep_profile]:
        results["cve"] = cve_checker.run_cve_check(silent=True)

    # Firewall check is always run as a baseline signal
    try:
        results["firewall"] = firewall.run_firewall_check(silent=True)
    except Exception:
        pass

    _display_results(results, sweep_profile, user_profile)
    _save_sweep(results, sweep_profile, user_profile)


def _display_results(results, sweep_profile, user_profile):
    label_map = {
        "integrity": "Integrity",
        "firewall": "Firewall Status",
        "listeners": "Listeners",
        "users": "User Accounts",
        "kernel": "Kernel Modules",
        "sshkeys": "SSH Keys",
        "worldwritable": "World-Writable Files",
        "cron": "Cron Jobs / Timers",
        "login": "Login / Auth Logs",
        "sshconfig": "SSH Config Audit",
        "docker": "Docker Security",
        "cve": "CVE Version Check",
        "suid": "SUID / SGID Binaries",
        "processes": "Process Anomaly Scan",
        "hosts": "/etc/hosts Tamper Check",
        "backdoor": "Backdoor Detection",
    }

    def status_text(result):
        status = result.get("status", "unknown").lower()

        if status == "ok":
            return "[green]OK[/]"
        if status in ("warning", "issue"):
            return "[yellow]WARNING[/]"
        if status == "error":
            return "[red]ERROR[/]"
        if status == "unsupported":
            return "[dim]UNSUPPORTED[/]"

        return f"[dim]{status.upper()}[/]"

    table = Table(
        title=f"[italic cyan]Threat Sweep — {sweep_profile.capitalize()}[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )
    table.add_column("Module", style="cyan", no_wrap=True, min_width=22)
    table.add_column("Status", no_wrap=True, min_width=11)
    table.add_column("Detail", style="white")

    for module, result in results.items():
        details = result.get("details", [])
        detail = details[0] if details else "No issues detected"

        table.add_row(
            label_map.get(module, module.title()),
            status_text(result),
            detail,
        )

    console.print(table)
    console.print()

    score, breakdown, max_possible = calculate_risk_score(results)
    percent = round((score / max_possible) * 100) if max_possible else 0

    info_present = any(
        r.get("status", "").lower() == "ok" and r.get("details")
        for r in results.values()
    )

    if percent == 0:
        color = "grey37"
        risk_label = "Secure / Informational" if info_present else "Secure"
    elif percent <= 30:
        color = "green"
        risk_label = "Low"
    elif percent <= 70:
        color = "yellow"
        risk_label = "Moderate"
    else:
        color = "red"
        risk_label = "High"

    risk_body = (
        f"[dim]Risk Level:[/] [bold {color}]{risk_label}[/]   "
        f"[dim]Score:[/] [bold {color}]{score}/{max_possible}[/]   "
        f"[dim]Rating:[/] [bold {color}]{percent}%[/]"
    )

    console.print(
        Panel.fit(
            risk_body,
            title="[bold cyan]Risk Summary[/]",
            border_style=color,
            box=box.ROUNDED,
        )
    )

    contributors = [
        (module, points) for module, points in breakdown.items() if points > 0
    ]

    if contributors:
        console.print()

        breakdown_table = Table(
            title="[italic cyan]Top Contributors[/]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            show_edge=False,
            padding=(0, 1),
        )
        breakdown_table.add_column("Module", style="cyan")
        breakdown_table.add_column("Points", justify="right", style="yellow")

        for module, points in contributors:
            breakdown_table.add_row(
                label_map.get(module, module.title()),
                str(points),
            )

        console.print(breakdown_table)

    all_tags = set()

    for result in results.values():
        all_tags.update(result.get("tags", []))

    cve_result = results.get("cve", {})
    if cve_result.get("status") == "warning" and not cve_result.get("tags"):
        cve_result["tags"] = ["cve_match"]
        all_tags.add("cve_match")

    if all_tags:
        console.print()

        insight_lines = [
            f"[cyan]{tag}[/]  [dim]{THREAT_TAG_MAP.get(tag, 'No description.')}[/]"
            for tag in sorted(all_tags)
        ]

        console.print(
            Panel.fit(
                "\n".join(insight_lines),
                title="[bold cyan]Threat Insights[/]",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )

    console.print()
    pause_return()


def _save_sweep(results, sweep_profile, user_profile):
    """Persist the latest sweep and a timestamped historical sweep log."""
    try:
        all_tags = []

        for result in results.values():
            all_tags.extend(
                result.get("tags", [])
            )

        score, _, max_possible = calculate_risk_score(results)

        risk_percent = (
            round((score / max_possible) * 100)
            if max_possible
            else 0
        )

        summary = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "hostname": user_profile.get(
                "hostname",
                "unknown",
            ),
            "profile": sweep_profile,
            "risk_score": score,
            "risk_max": max_possible,
            "risk_percent": risk_percent,
            "tags": sorted(set(all_tags)),
            "results": results,
        }

        LAST_SWEEP_FILE.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with open(
            LAST_SWEEP_FILE,
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                summary,
                file,
                indent=2,
                default=str,
            )

        SWEEP_LOG_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        log_path = (
            SWEEP_LOG_DIR
            / f"sweep_log_{timestamp}.json"
        )

        with open(
            log_path,
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                summary,
                file,
                indent=2,
                default=str,
            )

    except Exception as exc:
        console.print(
            f"[yellow]Warning: could not save sweep log: {exc}[/]"
        )


def _render_header(profile: dict, sweep_profile: str) -> None:
    hostname = profile.get("hostname", "unknown-host")
    role = profile.get("role", "unknown-role")
    analyst_id = profile.get("analyst_id", "N/A")

    metadata = Text.from_markup(
        f"[dim]Host:[/] [white]{hostname}[/]   "
        f"[dim]Role:[/] [white]{role}[/]   "
        f"[dim]Analyst:[/] [white]{analyst_id}[/]   "
        f"[dim]Profile:[/] [white]{sweep_profile.capitalize()}[/]"
    )

    console.print(
        Panel(
            metadata,
            title="[bold cyan]THREAT SWEEP[/]",
            subtitle=f"[dim cyan]{APP_NAME} v{APP_VERSION}[/]",
            border_style="cyan",
            box=box.SQUARE,
            padding=(0, 1),
        )
    )
    console.print()
