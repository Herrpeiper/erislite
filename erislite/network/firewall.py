# Project: ErisLITE
# Module: firewall.py
# Author: Liam Piper-Brandon
# Version: 1.2.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-11
# Description: Firewall status inspection for UFW, firewalld, nftables, and iptables.

import subprocess

from rich.align import Align
from rich.console import Console
from rich.table import Table

from erislite.config.settings import DEFAULT_COMMAND_TIMEOUT
from erislite.ui.utils import clear_screen, pause_return, show_header

console = Console()

PERMISSION_ERRORS = (
    "permission denied",
    "operation not permitted",
    "must be root",
    "you must be root",
)


def _run_command(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=DEFAULT_COMMAND_TIMEOUT,
        )
        return result, None
    except FileNotFoundError:
        return None, "unavailable"
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except OSError:
        return None, "failed"


def _permission_denied(result) -> bool:
    error = (result.stderr or "").lower()

    return any(
        marker in error
        for marker in PERMISSION_ERRORS
    )


def _iptables_has_rules(output: str) -> bool:
    for line in output.splitlines():
        line = line.strip()

        if line.startswith("-A "):
            return True

        if line.startswith("-P "):
            policy = line.rsplit(maxsplit=1)[-1].upper()

            if policy != "ACCEPT":
                return True

    return False


def _nftables_has_rules(output: str) -> bool:
    indicators = (
        " hook ",
        " accept",
        " drop",
        " reject",
        " jump ",
        " dnat ",
        " snat ",
        " masquerade",
    )

    for line in output.splitlines():
        normalized = f" {line.strip().lower()}"

        if any(
            indicator in normalized
            for indicator in indicators
        ):
            return True

    return False


def _return_result(
    fw_type,
    status,
    detail,
    tags,
    silent,
):
    result = {
        "status": status,
        "details": [detail],
        "tags": tags,
    }

    if silent:
        return result

    clear_screen()
    show_header("FIREWALL STATUS CHECK")

    table = Table(
        title="Firewall Check Results",
        show_lines=True,
    )
    table.add_column(
        "Firewall Type",
        style="cyan",
    )
    table.add_column(
        "Status",
        style="green" if status == "ok" else "red",
    )

    table.add_row(
        fw_type or "Unknown",
        detail,
    )

    console.print(Align.center(table))
    pause_return()

    return result


def run_firewall_check(silent=False):
    inactive_frontends = []
    permission_failure = False
    command_failure = False
    empty_iptables = False
    empty_nftables = False

    # Check UFW.
    ufw, ufw_error = _run_command(
        ["ufw", "status"]
    )

    if ufw is not None:
        output = ufw.stdout.strip().lower()

        if ufw.returncode == 0 and "status: active" in output:
            return _return_result(
                "ufw",
                "ok",
                "UFW is active",
                [],
                silent,
            )

        if "status: inactive" in output:
            inactive_frontends.append("UFW")
        elif _permission_denied(ufw):
            permission_failure = True
        elif ufw.returncode != 0:
            command_failure = True
    elif ufw_error not in (None, "unavailable"):
        command_failure = True

    # Check firewalld.
    firewalld, firewalld_error = _run_command(
        ["systemctl", "is-active", "firewalld"]
    )

    if firewalld is not None:
        state = firewalld.stdout.strip().lower()

        if state == "active":
            return _return_result(
                "firewalld",
                "ok",
                "firewalld is active",
                [],
                silent,
            )

        if state == "inactive":
            inactive_frontends.append("firewalld")
        elif _permission_denied(firewalld):
            permission_failure = True
        elif firewalld.returncode != 0 and state not in (
            "unknown",
            "not-found",
        ):
            command_failure = True
    elif firewalld_error not in (None, "unavailable"):
        command_failure = True

    # Check nftables.
    nftables, nftables_error = _run_command(
        ["nft", "list", "ruleset"]
    )

    if nftables is not None:
        if nftables.returncode == 0:
            if _nftables_has_rules(nftables.stdout):
                return _return_result(
                    "nftables",
                    "ok",
                    "nftables ruleset detected",
                    [],
                    silent,
                )

            empty_nftables = True
        elif _permission_denied(nftables):
            permission_failure = True
        else:
            command_failure = True
    elif nftables_error not in (None, "unavailable"):
        command_failure = True

    # Check iptables.
    iptables, iptables_error = _run_command(
        ["iptables", "-S"]
    )

    if iptables is not None:
        if iptables.returncode == 0:
            if _iptables_has_rules(iptables.stdout):
                return _return_result(
                    "iptables",
                    "ok",
                    "iptables ruleset detected",
                    [],
                    silent,
                )

            empty_iptables = True
        elif _permission_denied(iptables):
            permission_failure = True
        else:
            command_failure = True
    elif iptables_error not in (None, "unavailable"):
        command_failure = True

    if permission_failure:
        return _return_result(
            None,
            "warning",
            "Firewall state could not be fully inspected due to insufficient permissions",
            ["firewall_permission_denied"],
            silent,
        )

    if empty_iptables or empty_nftables:
        firewall_type = (
            "iptables"
            if empty_iptables
            else "nftables"
        )

        return _return_result(
            firewall_type,
            "warning",
            "No meaningful firewall rules were detected",
            ["firewall_ip_empty"],
            silent,
        )

    if command_failure:
        return _return_result(
            None,
            "error",
            "Firewall inspection commands failed",
            ["firewall_check_failed"],
            silent,
        )

    if inactive_frontends:
        detail = (
            f"{', '.join(inactive_frontends)} "
            "reported an inactive state"
        )

        tags = (
            ["firewall_ufw_inactive"]
            if inactive_frontends == ["UFW"]
            else ["firewall_disabled"]
        )

        return _return_result(
            inactive_frontends[0],
            "warning",
            detail,
            tags,
            silent,
        )

    return _return_result(
        None,
        "warning",
        "No supported active firewall was detected",
        ["firewall_disabled"],
        silent,
    )