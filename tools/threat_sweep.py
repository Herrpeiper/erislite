# tools/threat_sweep.py

import os, json

from datetime import datetime
from pathlib import Path

from core import login_audit, cve_checker

from tools import (
    integrity_tools,
    listener_check,
    user_anomaly,
    threat_sweep,
    kernel_module_check,
    ssh_key_check,
    ssh_config_check,
    world_writable_check,
    cron_timer_check,
    suid_check,
    firewall_check,
    docker_check,
    process_check,
    hosts_check,
    backdoor_check,
)

from ui.utils import clear_screen, show_header, pause_return

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align

console = Console()

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
    "hosts_critical_redirect":  "A critical domain (update server, CA, security tool) has been redirected in /etc/hosts.",
    "hosts_loopback_redirect":  "A non-localhost hostname is redirected to loopback — may block security or update tools.",
    "hosts_suspicious_entry":   "Suspicious hostname pattern detected in /etc/hosts.",
    "hosts_duplicate_mapping":  "A hostname maps to multiple different IPs — possible hijack.",
    "hosts_unreadable":         "/etc/hosts could not be read.",
    "backdoor_init_file":       "Suspicious command found in a shell init or profile file.",
    "backdoor_ld_preload":      "Library injected via /etc/ld.so.preload — high-confidence rootkit indicator.",
    "backdoor_ld_preload_env":  "LD_PRELOAD is active in a running process environment.",
    "backdoor_read_error":      "Could not read a file during backdoor scan.",
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

    return min(total_score, 100), breakdown, max_score

def run_sweep(user_profile, sweep_profile="standard"):
    clear_screen()
    show_header("THREAT SWEEP")

    console.print(Panel.fit("[bold red]🚨 Running Consolidated Threat Sweep...[/bold red]"))

    # FIX #8: "quick" was listener-only which is too sparse for useful triage.
    # Now includes users and login so a fast sweep still catches the most common
    # indicators of compromise without taking much longer.
    profiles = {
        "quick":    ["listeners", "users", "login"],
        "standard": ["integrity", "listeners", "users", "login", "cve"],
        "full":     ["integrity", "listeners", "users", "kernel", "sshkeys",
                     "worldwritable", "cron", "login", "sshconfig", "docker",
                     "suid", "processes", "hosts", "backdoor", "cve"],
    }

    results = {}

    if "integrity" in profiles[sweep_profile]:
        results["integrity"] = integrity_tools.scan_integrity(silent=True)

    if "listeners" in profiles[sweep_profile]:
        results["listeners"] = listener_check.run_listener_scan(silent=True)

    if "users" in profiles[sweep_profile]:
        results["users"] = user_anomaly.run_user_scan(silent=True)

    if "kernel" in profiles[sweep_profile]:
        results["kernel"] = kernel_module_check.run_kernel_module_check(silent=True)

    if "sshkeys" in profiles[sweep_profile]:
        results["sshkeys"] = ssh_key_check.run_ssh_key_check(silent=True)

    if "worldwritable" in profiles[sweep_profile]:
        results["worldwritable"] = world_writable_check.run_world_writable_check(silent=True)

    if "cron" in profiles[sweep_profile]:
        results["cron"] = cron_timer_check.run_cron_timer_scan(silent=True)

    if "login" in profiles[sweep_profile]:
        results["login"] = login_audit.run_login_audit(silent=True)

    if "sshconfig" in profiles[sweep_profile]:
        results["sshconfig"] = ssh_config_check.run_ssh_config_check(silent=True)

    if "docker" in profiles[sweep_profile]:
        results["docker"] = docker_check.run_docker_scan(silent=True)

    # FIX #7: suid was in the weights dict and in the full profile list but was never
    # assigned to results{}, so it could never contribute to the risk score. Wired in now.
    if "suid" in profiles[sweep_profile]:
        results["suid"] = suid_check.run_suid_scan(silent=True)

    if "processes" in profiles[sweep_profile]:
        results["processes"] = process_check.run_process_scan(silent=True)

    if "hosts" in profiles[sweep_profile]:
        results["hosts"] = hosts_check.run_hosts_check(silent=True)

    if "backdoor" in profiles[sweep_profile]:
        results["backdoor"] = backdoor_check.run_backdoor_check(silent=True)

    if "cve" in profiles[sweep_profile]:
        results["cve"] = cve_checker.run_cve_check(silent=True)

    # Firewall check is always run as a baseline signal
    try:
        results["firewall"] = firewall_check.run_firewall_check(silent=True)
    except Exception:
        pass

    _display_results(results, sweep_profile, user_profile)
    _save_sweep(results, sweep_profile, user_profile)


def _display_results(results, sweep_profile, user_profile):
    label_map = {
        "integrity":     "Integrity",
        "firewall":      "Firewall Status",
        "listeners":     "Listeners",
        "users":         "User Accounts",
        "kernel":        "Kernel Modules",
        "sshkeys":       "SSH Keys",
        "worldwritable": "World-Writable Files",
        "cron":          "Cron Jobs / Timers",
        "login":         "Login/Auth Logs",
        "sshconfig":     "SSH Config Audit",
        "docker":        "Docker Security",
        "cve":           "CVE Version Check",
        "suid":          "SUID/SGID Binaries",
        "processes":     "Process Anomaly Scan",
        "hosts":         "/etc/hosts Tamper Check",
        "backdoor":      "Backdoor Detection",
    }

    table = Table(title="Threat Sweep Results", show_lines=True)
    table.add_column("Module", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Detail", style="dim")

    def status_row(label, result):
        status = result.get("status", "unknown").lower()
        if status == "ok":
            emoji = "✅"
            status_text = "[green]OK[/green]"
        elif status in ("warning", "issue"):
            emoji = "⚠️"
            status_text = "[yellow]WARNING[/yellow]"
        elif status == "error":
            emoji = "❌"
            status_text = "[red]ERROR[/red]"
        else:
            emoji = "❓"
            status_text = f"[dim]{status.upper()}[/dim]"

        detail = result.get("details", ["None"])
        detail_str = detail[0] if detail else "No issues detected"
        return [label, f"{emoji} {status_text}", detail_str]

    for module, result in results.items():
        label = label_map.get(module, module.title())
        table.add_row(*status_row(label, result))

    console.print("\n")
    console.print(Align.center(table))
    console.print(Align.center("[grey62]Legend: ✅ OK   ⚠️ WARNING   ❌ ERROR[/]"))

    # 📊 Risk score
    score, breakdown, max_possible = calculate_risk_score(results)
    percent = round((score / max_possible) * 100) if max_possible else 0

    info_present = any(
        (r.get("status", "").lower() == "ok") and (r.get("details") and len(r.get("details")) > 0)
        for r in results.values()
    )

    if percent == 0:
        color = "grey37"
        label = "Secure (Info Findings)" if info_present else "Secure"
    elif percent <= 30:
        color = "green"
        label = "Low Risk"
    elif percent <= 70:
        color = "yellow"
        label = "Moderate Risk"
    else:
        color = "red"
        label = "High Risk"

    console.print("\n")
    console.print(Align.center(Panel.fit(
        f"[bold]{label}[/bold]\n"
        f"Threat Score: [bold {color}]{score}/{max_possible}[/bold {color}]\n"
        f"Threat Rating: [bold {color}]{percent}%[/bold {color}]",
        title="System Risk Level",
        border_style=color
    )))

    if max_possible < 100:
        console.print(Align.center(f"[dim]Scanned modules contributed {score}/{max_possible} to score[/dim]"))

    # 🧮 Risk breakdown table
    breakdown_table = Table(title="Risk Score Breakdown", show_lines=True)
    breakdown_table.add_column("Module", style="cyan", justify="left")
    breakdown_table.add_column("Points", style="bold yellow", justify="right")

    for module, value in breakdown.items():
        if value > 0:
            lbl = label_map.get(module, module.title())
            breakdown_table.add_row(lbl, str(value))

    if any(v > 0 for v in breakdown.values()):
        console.print("\n")
        console.print(Align.center(breakdown_table))

    # 🧠 Threat insights
    all_tags = set()
    for result in results.values():
        all_tags.update(result.get("tags", []))

    sshkey_result = results.get("sshkeys", {})
    if sshkey_result.get("flagged") and not sshkey_result.get("tags"):
        sshkey_result["tags"] = ["ssh_keys_suspicious"]
        all_tags.add("ssh_keys_suspicious")

    cve_result = results.get("cve", {})
    if cve_result.get("status") == "warning" and not cve_result.get("tags"):
        cve_result["tags"] = ["cve_match"]
        all_tags.add("cve_match")

    if all_tags:
        insights = "\n".join(
            f"• [bold]{tag}[/bold]: {THREAT_TAG_MAP.get(tag, 'No description.')}"
            for tag in sorted(all_tags)
        )
        console.print("\n")
        console.print(Panel.fit(insights, title="🧠 Threat Insights", border_style="cyan"))

    pause_return()


def _save_sweep(results, sweep_profile, user_profile):
    """Persist the sweep summary to ~/.erislite/last_sweep.json for the dashboard panel."""
    try:
        all_tags = []
        for r in results.values():
            all_tags.extend(r.get("tags", []))

        score, _, _ = calculate_risk_score(results)

        summary = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "profile": sweep_profile,
            "risk_score": score,
            "tags": sorted(set(all_tags)),
            "results": results,
            "sweep_profile": sweep_profile,
        }

        save_dir = Path.home() / ".erislite"
        save_dir.mkdir(parents=True, exist_ok=True)

        with open(save_dir / "last_sweep.json", "w") as f:
            json.dump(summary, f, indent=2, default=str)

        # Also write a dated log to data/logs/
        hostname = user_profile.get("hostname", "unknown")
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_dir = Path("data/logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"{hostname}_sweep_{ts}.json"

        with open(log_path, "w") as f:
            json.dump(summary, f, indent=2, default=str)

    except Exception as e:
        console.print(f"[yellow]Warning: could not save sweep log: {e}[/]")