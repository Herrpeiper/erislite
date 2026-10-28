# Project: ErisLITE
# Module: threat_sweep.py
# Author: Liam Piper-Brandon
# Version: 1.5.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-10-14
# Description: Threat sweep orchestrator: runs selected modules, scores risk, and saves results.

import json
from datetime import datetime
from uuid import uuid4

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from erislite.accounts import login_audit, ssh_config, ssh_keys, users
from erislite.config.settings import (
    APP_NAME,
    APP_VERSION,
    LAST_SWEEP_FILE,
    SWEEP_LOG_DIR,
    SWEEP_PROFILES,
)
from erislite.containers import docker
from erislite.intelligence.adapters.listeners import adapt_listeners
from erislite.intelligence.evidence import EvidenceSensitivity
from erislite.network import firewall, hosts, listeners
from erislite.persistence import backdoors, cron, suid, world_writable
from erislite.results import make_result, validate_result
from erislite.security.safe_io import write_private_json
from erislite.system import integrity, kernel_modules, processes
from erislite.ui.console import console
from erislite.ui.utils import clear_screen, get_analyst_id, pause_return
from erislite.vulnerability import cve_checker

SCORING_SCHEMA_VERSION = 1

RISK_WEIGHTS = {
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
    "suid": 10,
    "processes": 20,
    "hosts": 20,
    "backdoor": 25,
}

# CVE version matching reports REVIEW at most, because vendors backport
# fixes without changing version strings. It never scores, so it has no
# weight. A weight here put 20 unreachable points in the denominator.
NON_SCORING_MODULES = {"cve"}

# A module that could not run says nothing about risk on this host.
UNSCORED_STATUSES = {"unsupported"}


def assessment_label(
    risk_percent: int,
    info_present: bool,
    coverage: dict,
) -> tuple:
    """Select an assessment label without hiding incomplete coverage."""
    if coverage["failed"] > 0 or coverage.get("partial", 0) > 0:
        return "yellow", "Incomplete Assessment"

    if coverage["complete"] == 0:
        return "yellow", "Not Assessed"

    if risk_percent == 0:
        return (
            "grey37",
            "Secure / Informational" if info_present else "Secure",
        )

    if risk_percent <= 30:
        return "green", "Low"

    if risk_percent <= 70:
        return "yellow", "Moderate"

    return "red", "High"


def inspection_coverage(module: str, result: dict) -> str:
    """Classify inspection completeness separately from security risk."""
    status = result.get("status", "").lower()
    tags = set(result.get("tags", []))

    if status == "unsupported":
        return "unsupported"

    if module == "listeners" and status == "error" and "listener_check_failed" in tags:
        return "failed"

    if module == "integrity":
        if tags & {
            "baseline_missing",
            "baseline_check_error",
            "baseline_tamper",
        }:
            return "failed"

        if "integrity_scan_incomplete" in tags:
            return "partial"

    if module == "login":
        if "auth_audit_failed" in tags:
            return "failed"

        if "auth_audit_incomplete" in tags:
            return "partial"

    if module == "firewall":
        if "firewall_permission_denied" in tags:
            return "partial"

        if "firewall_check_failed" in tags:
            return "failed"

    # A generic collection failure must belong to this module.
    if status == "error" and f"{module}_check_failed" in tags:
        return "failed"

    return "complete"


def contributes_detected_risk(module: str, result: dict) -> bool:
    """Determine whether a module contributes detected risk points."""
    status = result.get("status", "").lower()

    if status not in {"warning", "error", "issue"}:
        return False

    coverage = inspection_coverage(module, result)

    if coverage in {"unsupported", "failed"}:
        return False

    if coverage == "partial":
        tags = set(result.get("tags", []))

        confirmed_risk_tags = {
            "integrity": {
                "file_integrity_issue",
                "suspicious_file_copy",
            },
            "login": {"auth_failures", "uid0_shells"},
        }

        return bool(tags & confirmed_risk_tags.get(module, set()))

    return True


def summarize_inspection_coverage(results: dict) -> dict:
    """Summarize inspection coverage for scoring modules."""
    summary = {
        "complete": 0,
        "partial": 0,
        "failed": 0,
        "unsupported": 0,
        "total": 0,
        "partial_modules": [],
        "failed_modules": [],
    }

    for module, result in results.items():
        if module not in RISK_WEIGHTS:
            continue

        coverage = inspection_coverage(module, result)

        summary["total"] += 1
        summary[coverage] += 1

        if coverage == "partial":
            summary["partial_modules"].append(module)
        elif coverage == "failed":
            summary["failed_modules"].append(module)

    summary["partial_modules"].sort()
    summary["failed_modules"].sort()

    return summary


# 🧠 Tag-to-Insight Mapping
THREAT_TAG_MAP = {
    "cve_match": "Outdated or vulnerable software version detected.",
    "cve_version_match": (
        "Installed software version matches a known CVE range; verify vendor patch level."
    ),
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
    "uid0_clone": "A non-root account has UID 0 and root-equivalent privileges.",
    "weak_ssh_config": "One or more SSH server settings differ from the hardening baseline.",
    "firewall_permission_denied": (
        "Firewall state could not be fully inspected with the current privileges."
    ),
    "firewall_check_failed": "One or more firewall inspection commands failed.",
    "suspicious_file_copy": (
        "An exact copy of a monitored file was detected in "
        "a scanned location; investigate whether it was authorized."
    ),
    "auth_audit_incomplete": (
        "One or more authentication audit data sources could not be inspected."
    ),
    "kernel_module_inspection_incomplete": (
        "One or more loaded kernel modules could not be fully inspected."
    ),
    "baseline_missing": (
        "An integrity baseline is unavailable; file changes "
        "cannot be assessed until a baseline is created."
    ),
    "baseline_check_error": ("The stored integrity baseline could not be validated."),
    "baseline_tamper": (
        "Integrity baseline validation reported inconsistencies; "
        "review the baseline before trusting comparisons."
    ),
    "integrity_scan_incomplete": (
        "Some monitored files could not be inspected; integrity coverage is incomplete."
    ),
}


def calculate_risk_score(results: dict):
    """Score verified risk without penalizing unavailable inspections."""
    total_score = 0
    breakdown = {}
    max_score = 0

    for module, result in results.items():
        if module not in RISK_WEIGHTS:
            continue

        weight = RISK_WEIGHTS[module]
        coverage = inspection_coverage(module, result)

        if coverage in {"unsupported", "failed"}:
            breakdown[module] = 0
            continue

        # Unverified portions cannot be treated as assessed.
        # A partial module with confirmed risk remains in
        # the score so that its finding is not suppressed.
        if coverage == "partial" and not contributes_detected_risk(module, result):
            breakdown[module] = 0
            continue

        max_score += weight

        if contributes_detected_risk(module, result):
            total_score += weight
            breakdown[module] = weight
        else:
            breakdown[module] = 0

    return total_score, breakdown, max_score


def compare_historical_scores(current: dict, previous: dict) -> dict:
    """Compare risk scores only when their scoring scope matches.

    Older snapshots without coverage metadata remain readable,
    but their numerical scores are not assumed comparable.
    """
    unavailable = {
        "comparable": False,
        "reason": None,
        "previous_percent": None,
        "current_percent": None,
        "delta": None,
    }

    required = (
        "scoring_schema_version",
        "scored_modules",
        "coverage",
        "risk_score",
        "risk_max",
        "risk_percent",
        "results",
    )

    if any(key not in snapshot for snapshot in (current, previous) for key in required):
        return {
            **unavailable,
            "reason": "Historical coverage metadata unavailable",
        }

    if (
        current["scoring_schema_version"] != SCORING_SCHEMA_VERSION
        or previous["scoring_schema_version"] != SCORING_SCHEMA_VERSION
    ):
        return {
            **unavailable,
            "reason": "Scoring methodology differs or is unsupported",
        }

    current_modules = current["scored_modules"]
    previous_modules = previous["scored_modules"]

    if (
        not isinstance(current_modules, list)
        or not isinstance(previous_modules, list)
        or any(
            not isinstance(module, str) or module not in RISK_WEIGHTS
            for module in current_modules + previous_modules
        )
        or len(set(current_modules)) != len(current_modules)
        or len(set(previous_modules)) != len(previous_modules)
    ):
        return {
            **unavailable,
            "reason": "Invalid scored-module metadata",
        }

    if set(current_modules) != set(previous_modules):
        return {
            **unavailable,
            "reason": "Different modules contributed to risk scoring",
        }

    for snapshot in (current, previous):
        if not isinstance(snapshot["coverage"], dict):
            return {
                **unavailable,
                "reason": "Invalid coverage metadata",
            }

        if not isinstance(snapshot["results"], dict):
            return {
                **unavailable,
                "reason": "Invalid module results",
            }

        expected_coverage = summarize_inspection_coverage(snapshot["results"])

        if snapshot["coverage"] != expected_coverage:
            return {
                **unavailable,
                "reason": "Saved coverage metadata is inconsistent",
            }

        expected_score, _, expected_max = calculate_risk_score(snapshot["results"])

        if (
            type(snapshot["risk_score"]) is not int
            or type(snapshot["risk_max"]) is not int
            or type(snapshot["risk_percent"]) is not int
            or snapshot["risk_score"] != expected_score
            or snapshot["risk_max"] != expected_max
            or snapshot["risk_percent"]
            != (round(expected_score / expected_max * 100) if expected_max else 0)
            or set(snapshot["scored_modules"])
            != {
                module
                for module, result in snapshot["results"].items()
                if module in RISK_WEIGHTS
                and inspection_coverage(module, result) not in {"failed", "unsupported"}
                and (
                    inspection_coverage(module, result) == "complete"
                    or contributes_detected_risk(module, result)
                )
            }
        ):
            return {
                **unavailable,
                "reason": "Saved score metadata is inconsistent",
            }

    current_coverage = {
        module: inspection_coverage(module, result)
        for module, result in current["results"].items()
        if module in RISK_WEIGHTS
    }
    previous_coverage = {
        module: inspection_coverage(module, result)
        for module, result in previous["results"].items()
        if module in RISK_WEIGHTS
    }

    if current_coverage != previous_coverage:
        return {
            **unavailable,
            "reason": "Inspection coverage changed between sweeps",
        }

    current_percent = current["risk_percent"]
    previous_percent = previous["risk_percent"]

    return {
        "comparable": True,
        "reason": None,
        "previous_percent": previous_percent,
        "current_percent": current_percent,
        "delta": current_percent - previous_percent,
    }


def prioritize_findings(results: dict) -> list:
    """
    Return actionable sweep findings ordered by analyst priority.

    Higher-risk modules are presented first. Clean and unsupported
    modules are excluded.
    """
    status_priority = {
        "error": 3,
        "warning": 2,
        "issue": 2,
    }

    findings = []

    for module, result in results.items():
        status = result.get("status", "").lower()

        if status not in status_priority:
            continue

        if not contributes_detected_risk(module, result):
            continue

        findings.append(
            {
                "module": module,
                "status": status,
                "weight": RISK_WEIGHTS.get(module, 0),
                "details": result.get("details", []),
                "tags": result.get("tags", []),
            }
        )

    findings.sort(
        key=lambda finding: (
            finding["weight"],
            status_priority[finding["status"]],
        ),
        reverse=True,
    )

    return findings


SWEEP_CHECKS = {
    "integrity": lambda: integrity.scan_integrity(silent=True),
    "listeners": lambda: listeners.run_listener_scan(silent=True),
    "users": lambda: users.run_user_scan(silent=True),
    "kernel": lambda: kernel_modules.run_kernel_module_check(silent=True),
    "sshkeys": lambda: ssh_keys.run_ssh_key_check(silent=True),
    "worldwritable": lambda: world_writable.run_world_writable_check(silent=True),
    "cron": lambda: cron.run_cron_timer_scan(silent=True),
    "login": lambda: login_audit.run_login_audit(silent=True),
    "sshconfig": lambda: ssh_config.run_ssh_config_check(silent=True),
    "docker": lambda: docker.run_docker_scan(silent=True),
    "suid": lambda: suid.run_suid_scan(silent=True),
    "processes": lambda: processes.run_process_scan(silent=True),
    "hosts": lambda: hosts.run_hosts_check(silent=True),
    "backdoor": lambda: backdoors.run_backdoor_check(silent=True),
    "cve": lambda: cve_checker.run_cve_check(silent=True),
}


def run_module_check(module: str, check) -> dict:
    """Run one sweep module so a crash in it cannot lose the whole sweep."""

    try:
        result = check()
    except Exception as exc:
        return make_result(
            "error",
            details=[f"{module} check failed: {type(exc).__name__}: {exc}"],
            tags=[f"{module}_check_failed"],
        )

    if not validate_result(result):
        return make_result(
            "error",
            details=[f"{module} check returned an invalid result"],
            tags=[f"{module}_check_failed"],
        )

    return result


def run_listener_intelligence_check(hostname: str):
    """Collect listeners once, preserving the legacy result.

    Returns:
        (module_result, intelligence_findings, conversion_error)
    """
    if listeners.get_os() != "Linux":
        return make_result("unsupported"), [], None

    try:
        collection = listeners.collect_listeners()

        result = listeners.run_listener_scan(
            silent=True,
            collection=collection,
        )
    except Exception:
        return (
            make_result(
                "error",
                details=["Listener inspection failed"],
                tags=["listener_check_failed"],
            ),
            [],
            None,
        )

    if not validate_result(result):
        return (
            make_result(
                "error",
                details=["Listener check returned an invalid result"],
                tags=["listener_check_failed"],
            ),
            [],
            None,
        )

    if collection.error is not None:
        return result, [], None

    try:
        findings = adapt_listeners(
            collection.observations,
            hostname=hostname,
        )
    except (ValueError, TypeError):
        return result, [], "Listener intelligence conversion failed"

    return result, findings, None


def run_sweep(user_profile, sweep_profile="standard"):
    clear_screen()
    _render_header(user_profile, sweep_profile)
    console.print("[dim]Running security checks...[/]")
    console.print()

    profiles = SWEEP_PROFILES

    results = {}
    intelligence_findings = None
    intelligence_errors = []

    hostname = user_profile.get(
        "hostname",
        "unknown",
    )

    for module in profiles[sweep_profile]:
        if module == "listeners":
            (
                listener_result,
                listener_findings,
                conversion_error,
            ) = run_listener_intelligence_check(hostname)

            results[module] = listener_result
            intelligence_findings = listener_findings

            if conversion_error:
                intelligence_errors.append(conversion_error)

            continue

        check = SWEEP_CHECKS.get(module)

        if check is not None:
            results[module] = run_module_check(module, check)

    # Firewall check is always run as a baseline signal
    results["firewall"] = run_module_check(
        "firewall", lambda: firewall.run_firewall_check(silent=True)
    )

    hostname = user_profile.get(
        "hostname",
        "unknown",
    )

    previous = _load_previous_comparable_sweep(
        hostname,
        sweep_profile,
    )

    if previous:
        changes = compare_sweep_results(
            results,
            previous.get("results", {}),
        )
    else:
        changes = {
            "new": [],
            "changed": [],
            "persisting": [],
            "resolved": [],
        }

    score_comparison = None

    if previous is not None:
        current_metadata = build_score_metadata(results)

        score_comparison = compare_historical_scores(
            current_metadata,
            previous,
        )

    _display_results(
        results,
        sweep_profile,
        user_profile,
        changes,
        comparison_available=previous is not None,
        intelligence_findings=intelligence_findings,
        intelligence_errors=intelligence_errors,
        score_comparison=score_comparison,
    )

    _save_sweep(
        results,
        sweep_profile,
        user_profile,
        changes,
    )


def _finding_signals(results: dict) -> set:
    """
    Convert actionable module results into stable comparison signals.

    Prefer module + tag when tags exist. If an actionable result has no
    tags, fall back to module + status.
    """
    signals = set()

    for module, result in results.items():
        status = result.get("status", "").lower()

        if status not in {"warning", "issue", "error"}:
            continue

        tags = result.get("tags", [])

        if tags:
            for tag in tags:
                signals.add(f"{module}:{tag}")
        else:
            signals.add(f"{module}:status:{status}")

    return signals


def _comparison_unavailable(
    module: str,
    current_results: dict,
    previous_results: dict,
) -> bool:
    """Identify modules whose historical state cannot be compared."""
    if module not in current_results or module not in previous_results:
        return True

    if module in current_results:
        coverage = inspection_coverage(
            module,
            current_results[module],
        )
        if coverage != "complete":
            return True

    if module in previous_results:
        coverage = inspection_coverage(
            module,
            previous_results[module],
        )
        if coverage != "complete":
            return True

    return False


def compare_sweep_results(
    current_results: dict,
    previous_results: dict,
) -> dict:
    """Compare sweeps without treating unavailable data as resolution."""
    comparable_current = {}
    comparable_previous = {}
    unverified = set()

    modules = set(current_results) | set(previous_results)

    for module in modules:
        if _comparison_unavailable(
            module,
            current_results,
            previous_results,
        ):
            # Retain actionable signals from whichever side
            # actually completed its inspection.
            if module in current_results:
                current = current_results[module]
                if inspection_coverage(module, current) == "complete":
                    unverified.update(_finding_signals({module: current}))

            if module in previous_results:
                previous = previous_results[module]
                if inspection_coverage(module, previous) == "complete":
                    unverified.update(_finding_signals({module: previous}))

            continue

        if module in current_results:
            comparable_current[module] = current_results[module]

        if module in previous_results:
            comparable_previous[module] = previous_results[module]

    current = _finding_signals(comparable_current)
    previous = _finding_signals(comparable_previous)

    changes = {
        "new": sorted(current - previous),
        "persisting": sorted(current & previous),
        "resolved": sorted(previous - current),
        "changed": _changed_findings(
            comparable_current,
            comparable_previous,
        ),
    }

    if unverified:
        changes["unverified"] = sorted(unverified)

    return changes


def _changed_findings(current_results: dict, previous_results: dict) -> list:
    """Report actionable modules whose details changed under persistent tags."""

    changed = []

    for module, result in current_results.items():
        status = result.get("status", "").lower()

        if status not in {"warning", "issue", "error"}:
            continue

        previous = previous_results.get(module)

        if not previous:
            continue

        if previous.get("status", "").lower() not in {"warning", "issue", "error"}:
            continue

        current_tags = set(result.get("tags", []))
        previous_tags = set(previous.get("tags", []))

        # CHANGED should describe an existing finding that evolved,
        # not a completely new finding replacing an old one.
        if not current_tags.intersection(previous_tags):
            continue

        before = set(previous.get("details", []))

        for detail in result.get("details", []):
            if detail not in before:
                changed.append(f"{module}: {detail}")

    return sorted(changed)


def _load_previous_comparable_sweep(
    hostname: str,
    sweep_profile: str,
):
    """
    Load the newest historical sweep for the same host and profile.
    """
    if not SWEEP_LOG_DIR.exists():
        return None

    paths = sorted(
        SWEEP_LOG_DIR.glob("sweep_log_*.json"),
        reverse=True,
    )

    for path in paths:
        try:
            with open(
                path,
                "r",
                encoding="utf-8",
            ) as file:
                data = json.load(file)
        except (
            OSError,
            json.JSONDecodeError,
            UnicodeDecodeError,
        ):
            continue

        if not isinstance(data, dict):
            continue

        if data.get("hostname") != hostname:
            continue

        if data.get("profile") != sweep_profile:
            continue

        return data

    return None


def _display_results(
    results,
    sweep_profile,
    user_profile,
    changes,
    comparison_available=False,
    intelligence_findings=None,
    intelligence_errors=None,
    score_comparison=None,
):
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
        if status == "review":
            return "[cyan]REVIEW[/]"
        if status == "info":
            return "[cyan]INFO[/]"
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
        if details:
            detail = details[0]
        elif result.get("status") == "unsupported":
            detail = "Inspection not supported"
        elif result.get("status") == "error":
            detail = "Inspection failed"
        else:
            detail = "No issues detected"

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
        r.get("status", "").lower() in {"ok", "info", "review"} and r.get("details")
        for r in results.values()
    )

    coverage = summarize_inspection_coverage(results)

    color, risk_label = assessment_label(
        percent,
        info_present,
        coverage,
    )

    risk_body = (
        f"[dim]Assessment:[/] [bold {color}]{risk_label}[/]   "
        f"[dim]Detected Risk:[/] [bold {color}]"
        f"{score}/{max_possible}[/]   "
        f"[dim]Scored Rating:[/] [bold {color}]{percent}%[/]\n"
        f"[dim]Coverage:[/] "
        f"[white]{coverage['complete']}/{coverage['total']}[/] "
        f"complete   "
        f"[dim]Partial:[/] [yellow]{coverage['partial']}[/]   "
        f"[dim]Failed:[/] [yellow]{coverage['failed']}[/]   "
        f"[dim]Unsupported:[/] "
        f"[white]{coverage['unsupported']}[/]"
    )

    console.print(
        Panel.fit(
            risk_body,
            title="[bold cyan]Risk Summary[/]",
            border_style=color,
            box=box.ROUNDED,
        )
    )

    if coverage["failed"] or coverage["partial"]:
        coverage_details = []

        if coverage["failed_modules"]:
            coverage_details.append("Failed: " + ", ".join(coverage["failed_modules"]))

        if coverage["partial_modules"]:
            coverage_details.append("Partial: " + ", ".join(coverage["partial_modules"]))

        console.print()
        console.print(
            Panel.fit(
                Text(
                    "One or more security inspections were incomplete.\n"
                    + "\n".join(coverage_details)
                    + "\nUnverified conditions are not treated as "
                    "confirmed security risks. "
                    "Risk scoring may exclude unavailable checks, "
                    "and historical findings remain unverified."
                ),
                title="[bold yellow]INCOMPLETE COVERAGE[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    contributors = [(module, points) for module, points in breakdown.items() if points > 0]

    if contributors:
        console.print()

        breakdown_table = Table(
            title="[italic cyan]Top Contributors[/]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            show_edge=False,
            padding=(0, 1),
        )
        breakdown_table.add_column(
            "Module",
            style="cyan",
        )
        breakdown_table.add_column(
            "Points",
            justify="right",
            style="yellow",
        )

        for module, points in contributors:
            breakdown_table.add_row(
                label_map.get(
                    module,
                    module.title(),
                ),
                str(points),
            )

        console.print(breakdown_table)

    if intelligence_findings is not None:
        _display_intelligence_findings(
            intelligence_findings,
            intelligence_errors,
        )

    priorities = prioritize_findings(results)

    if priorities:
        console.print()

        priority_table = Table(
            title="[italic cyan]Analyst Priority[/]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            show_edge=False,
            padding=(0, 1),
        )

        priority_table.add_column(
            "#",
            style="cyan",
            justify="right",
            no_wrap=True,
        )
        priority_table.add_column(
            "Module",
            style="cyan",
            no_wrap=True,
        )
        priority_table.add_column(
            "Status",
            no_wrap=True,
        )
        priority_table.add_column(
            "Primary Signal",
            style="white",
        )

        for index, finding in enumerate(
            priorities,
            1,
        ):
            details = finding["details"]

            primary_detail = details[0] if details else "Review module findings"

            priority_table.add_row(
                str(index),
                label_map.get(
                    finding["module"],
                    finding["module"].title(),
                ),
                finding["status"].upper(),
                primary_detail,
            )

        console.print(priority_table)

    if comparison_available:
        console.print()

        change_table = Table(
            title="[italic cyan]Changes Since Previous Comparable Sweep[/]",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            show_edge=False,
            padding=(0, 1),
        )

        change_table.add_column(
            "State",
            no_wrap=True,
        )
        change_table.add_column(
            "Count",
            justify="right",
        )
        change_table.add_column(
            "Signals",
            style="white",
        )

        change_rows = (
            (
                "[red]NEW[/]",
                changes["new"],
            ),
            (
                "[magenta]CHANGED[/]",
                changes.get("changed", []),
            ),
            (
                "[yellow]PERSISTING[/]",
                changes["persisting"],
            ),
            (
                "[green]RESOLVED[/]",
                changes["resolved"],
            ),
        )

        if changes.get("unverified"):
            change_rows += (
                (
                    "[yellow]UNVERIFIED[/]",
                    changes["unverified"],
                ),
            )

        for label, signals in change_rows:
            display_signals = ", ".join(signals[:4]) if signals else "None"

            if len(signals) > 4:
                display_signals += f" (+{len(signals) - 4} more)"

            change_table.add_row(
                label,
                str(len(signals)),
                display_signals,
            )

        console.print(change_table)

    if score_comparison is not None:
        console.print()

        if score_comparison["comparable"]:
            previous_percent = score_comparison["previous_percent"]
            current_percent = score_comparison["current_percent"]
            delta = score_comparison["delta"]

            if delta > 0:
                change_description = f"+{delta} percentage points"
                change_style = "yellow"
            elif delta < 0:
                change_description = f"{delta} percentage points"
                change_style = "green"
            else:
                change_description = "No change"
                change_style = "cyan"

            comparison_text = Text()
            comparison_text.append(f"Previous: {previous_percent}%   Current: {current_percent}%\n")
            comparison_text.append(
                f"Change: {change_description}",
                style=change_style,
            )

            console.print(
                Panel.fit(
                    comparison_text,
                    title="[bold cyan]HISTORICAL RISK COMPARISON[/]",
                    border_style="cyan",
                    box=box.ROUNDED,
                )
            )
        else:
            console.print(
                Panel.fit(
                    Text(
                        "Risk percentages cannot be directly compared.\n"
                        + str(score_comparison["reason"])
                    ),
                    title="[bold yellow]SCORE COMPARISON UNAVAILABLE[/]",
                    border_style="yellow",
                    box=box.ROUNDED,
                )
            )

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


def _display_intelligence_evidence(findings):
    """Display bounded, sensitivity-aware evidence summaries."""
    if not findings:
        return

    details = Table(
        title="[italic cyan]Intelligence Evidence Details[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )

    details.add_column("#", justify="right", no_wrap=True)
    details.add_column("Finding", max_width=36)
    details.add_column("Evidence Summary")
    details.add_column("Sensitivity", no_wrap=True)

    max_evidence_per_finding = 2
    max_summary_chars = 180

    for finding_index, finding in enumerate(findings[:20], start=1):
        evidence_records = finding.evidence
        finding_title = Text(finding.title[:60])

        if not evidence_records:
            details.add_row(
                str(finding_index),
                finding_title,
                Text("No evidence attached", style="dim"),
                "-",
            )
            continue

        for evidence in evidence_records[:max_evidence_per_finding]:
            sensitivity = evidence.sensitivity

            if sensitivity in (
                EvidenceSensitivity.PUBLIC,
                EvidenceSensitivity.INTERNAL,
            ):
                summary = evidence.summary

                if len(summary) > max_summary_chars:
                    summary = summary[:max_summary_chars] + "..."

                display_summary = Text(summary)
                sensitivity_label = sensitivity.value
            else:
                # Includes SENSITIVE and any unrecognized level.
                display_summary = Text(
                    "Evidence withheld by sensitivity policy",
                    style="dim",
                )
                sensitivity_label = "REDACTED"

            details.add_row(
                str(finding_index),
                finding_title,
                display_summary,
                sensitivity_label,
            )

        omitted = len(evidence_records) - max_evidence_per_finding

        if omitted > 0:
            details.add_row(
                str(finding_index),
                finding_title,
                Text(
                    f"{omitted} additional evidence record(s) not shown",
                    style="dim",
                ),
                "-",
            )

    console.print(details)


def _display_intelligence_findings(findings, errors=None):
    """Render structured findings without changing legacy results."""
    errors = errors or []

    console.print()

    table = Table(
        title="[bold cyan]Intelligence Findings[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        show_edge=False,
        padding=(0, 1),
    )

    table.add_column(
        "#",
        style="cyan",
        justify="right",
        no_wrap=True,
    )

    table.add_column("Severity", no_wrap=True)
    table.add_column("Confidence", no_wrap=True)
    table.add_column("Finding")
    table.add_column("Affected Asset")
    table.add_column("Evidence", justify="right")

    severity_colors = {
        "CRITICAL": "red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
        "INFO": "cyan",
    }

    for index, finding in enumerate(findings[:20], start=1):
        severity = finding.severity.value

        table.add_row(
            str(index),
            Text(
                severity,
                style=severity_colors.get(severity, "white"),
            ),
            Text(finding.confidence.value),
            Text(finding.title),
            Text(finding.asset),
            Text(str(len(finding.evidence))),
        )

    if findings:
        console.print(table)

        _display_intelligence_evidence(findings)

        if len(findings) > 20:
            console.print(f"[dim]Showing 20 of {len(findings)} intelligence findings.[/]")
    elif not errors:
        console.print(
            Panel.fit(
                "[green]No structured intelligence findings "
                "were generated by the enabled adapters.[/]",
                title="[bold cyan]Intelligence Findings[/]",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )

    for error in errors:
        console.print(
            Panel.fit(
                Text(error),
                title="[bold yellow]INTELLIGENCE INCOMPLETE[/]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )


def build_score_metadata(results: dict) -> dict:
    """Build consistent scoring metadata for display and persistence."""
    score, _, maximum = calculate_risk_score(results)

    scored_modules = sorted(
        module
        for module, result in results.items()
        if module in RISK_WEIGHTS
        and inspection_coverage(module, result) not in {"failed", "unsupported"}
        and (
            inspection_coverage(module, result) == "complete"
            or contributes_detected_risk(module, result)
        )
    )

    return {
        "scoring_schema_version": SCORING_SCHEMA_VERSION,
        "scored_modules": scored_modules,
        "coverage": summarize_inspection_coverage(results),
        "risk_score": score,
        "risk_max": maximum,
        "risk_percent": (round(score / maximum * 100) if maximum else 0),
        "results": results,
    }


def _save_sweep(results, sweep_profile, user_profile, changes):
    """Persist the latest sweep and a timestamped historical sweep log."""
    try:
        all_tags = []

        for result in results.values():
            all_tags.extend(result.get("tags", []))

        score_metadata = build_score_metadata(results)
        priorities = prioritize_findings(results)

        summary = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "hostname": user_profile.get("hostname", "unknown"),
            "profile": sweep_profile,
            **score_metadata,
            "tags": sorted(set(all_tags)),
            "priorities": priorities,
            "changes": changes,
        }

        write_private_json(LAST_SWEEP_FILE, summary, default=str)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_id = uuid4().hex

        log_path = SWEEP_LOG_DIR / f"sweep_log_{timestamp}_{unique_id}.json"

        write_private_json(log_path, summary, default=str)

    except OSError as exc:
        console.print(f"[yellow]Warning: could not save sweep log: {exc}[/]")


def _render_header(profile: dict, sweep_profile: str) -> None:
    hostname = profile.get("hostname", "unknown-host")
    role = profile.get("role", "unknown-role")
    analyst_id = get_analyst_id(profile)

    metadata_parts = [
        f"[dim]Host:[/] [white]{hostname}[/]",
        f"[dim]Role:[/] [white]{role}[/]",
    ]

    if analyst_id:
        metadata_parts.append(f"[dim]Analyst:[/] [white]{analyst_id}[/]")

    metadata_parts.append(f"[dim]Profile:[/] [white]{sweep_profile.capitalize()}[/]")

    metadata = Text.from_markup("   ".join(metadata_parts))

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
