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
    docker_check
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
    "ssh_keys_suspicious": "SSH key(s) found in user authorized_keys files.",
    "ssh_keys_user_root": "SSH key found under root's account — may allow privileged backdoor access.",
    "ssh_keys_multiple_users": "Multiple users have SSH authorized_keys — review for lateral movement risks.",
    "ssh_keys_system_user": "SSH key assigned to system-level user — uncommon and may be suspicious.",
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
        "suid": 10 
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

    profiles = {
        "quick": ["listeners"],
        "standard": ["integrity", "listeners", "users", "login", "cve"],
        "full": ["integrity", "listeners", "users", "kernel", "sshkeys", "worldwritable", "cron", "login", "sshconfig", "docker", "cve"]
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

    if "suid" in profiles[sweep_profile]:
        results["suid"] = suid_check.run_suid_scan(silent=True)

    if "sshconfig" in profiles[sweep_profile]:
        results["sshconfig"] = ssh_config_check.run_ssh_config_check(silent=True)

    if "docker" in profiles[sweep_profile]:
        results["docker"] = docker_check.run_docker_scan(silent=True)

    if "firewall" in profiles[sweep_profile]:
        results["firewall"] = firewall_check.run_firewall_check(silent=True)

    if "cve" in profiles[sweep_profile]:
        results["cve"] = cve_checker.run_cve_check(silent=True)


    # 🧾 Summary table
    table = Table(title="Sweep Results Summary", show_lines=True)
    table.add_column("Module", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Details")

    def status_row(label, result):
        status_map = {
            "ok": ("✅", "OK"),
            "warning": ("⚠️", "WARNING"),
            "error": ("❌", "ERROR"),
            "unsupported": ("🚫", "UNSUPPORTED")
        }
        emoji, status_text = status_map.get(result["status"].lower(), ("❔", result["status"].upper()))
        detail = result.get("details", ["None"])[0] if result.get("details") else "No issues detected"
        return [label, f"{emoji} {status_text}", detail]

    label_map = {
        "integrity": "Integrity",
        "firewall": "Firewall Status",
        "listeners": "Listeners",
        "users": "User Accounts",
        "kernel": "Kernel Modules",
        "sshkeys": "SSH Keys",
        "worldwritable": "World-Writable Files",
        "cron": "Cron Jobs / Timers",
        "login": "Login/Auth Logs",
        "sshconfig": "SSH Config Audit",
        "docker": "Docker Security",
        "cve": "CVE Version Check"
    }


    for module, result in results.items():
        label = label_map.get(module, module.title())
        table.add_row(*status_row(label, result))

    console.print("\n")
    console.print(Align.center(table))
    console.print(Align.center("[grey62]Legend: ✅ OK   ⚠️ WARNING   ❌ ERROR[/]"))


    # 📊 Calculate and show risk score
    score, breakdown, max_possible = calculate_risk_score(results)
    percent = round((score / max_possible) * 100) if max_possible else 0

    # Optional nuance: show "Secure" but acknowledge informational findings
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

    # Optional note on raw score
    if max_possible < 100:
        console.print(Align.center(f"[dim]Scanned modules contributed {score}/{max_possible} to score[/dim]"))


    # 🧮 Display module-by-module risk breakdown
    breakdown_table = Table(title="Risk Score Breakdown", show_lines=True)
    breakdown_table.add_column("Module", style="cyan", justify="left")
    breakdown_table.add_column("Points", style="bold yellow", justify="right")

    for module, value in breakdown.items():
        if value > 0:
            label = label_map.get(module, module.title())
            breakdown_table.add_row(label, str(value))

    if any(score > 0 for score in breakdown.values()):
        console.print("\n")
        console.print(Align.center(breakdown_table))

    # 🧠 Display threat insights
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
        console.print(Align.center(Panel(
            insights,
            title="🧠 Threat Insights",
            border_style="magenta"
        )))


   # 💾 JSON log export
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename_ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    log_data = {
        "timestamp": timestamp,
        "hostname": user_profile.get("hostname", "unknown"),
        "role": user_profile.get("role", "unknown"),
        "sweep_profile": sweep_profile.lower(),
        "risk_score": percent,
        "risk_score_raw": score,
        "risk_score_max": max_possible,
        "results": results
    }

    # 🔄 Save lightweight summary to last_sweep.json
    summary_path = Path.home() / ".erislite" / "last_sweep.json"
    summary_path.parent.mkdir(exist_ok=True)

    quick_summary = {
        "timestamp": timestamp,
        "risk_score": percent,
        "profile": sweep_profile,
        "tags": sorted(list(all_tags))
    }

    with open(summary_path, "w") as f:
        json.dump(quick_summary, f)

    # 📁 Structured export directory
    log_type = "threat_sweeps"  # or dynamically set based on context
    log_dir = Path("data/logs") / log_type
    log_dir.mkdir(parents=True, exist_ok=True)

    log_path = log_dir / f"sweep_log_{filename_ts}.json"

    with open(log_path, 'w') as f:
        json.dump(log_data, f, indent=4)

    console.print(f"\n[green]✅ Threat Sweep results saved to:[/] [bold]{log_path}[/]")

    pause_return()
