# Project: ErisLITE
# Module: firewall.py
# Author: Liam Piper-Brandon
# Version: 1.5.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-10-12
# Description: Firewall status inspection for UFW, firewalld, nftables, and iptables.

import ipaddress
import subprocess

from rich.align import Align
from rich.console import Console
from rich.table import Table

from erislite.results import make_result
from erislite.security.command_resolver import CommandResolutionError
from erislite.security.command_runner import run_command
from erislite.ui.utils import clear_screen, pause_return, show_header

console = Console()

PERMISSION_ERRORS = (
    "permission denied",
    "operation not permitted",
    "must be root",
    "you must be root",
)


def detect_firewall_backend():
    ufw, _ = _run_command(["ufw", "status"])

    if ufw is not None:
        output = ufw.stdout.strip().lower()

        if ufw.returncode == 0 and "status: active" in output:
            return "ufw"

    firewalld, _ = _run_command(
        ["systemctl", "is-active", "firewalld"]
    )

    if (
        firewalld is not None
        and firewalld.returncode == 0
        and firewalld.stdout.strip().lower() == "active"
    ):
        return "firewalld"

    nftables, _ = _run_command(
        ["nft", "list", "ruleset"]
    )

    if (
        nftables is not None
        and nftables.returncode == 0
        and _nftables_has_rules(nftables.stdout)
    ):
        return "nftables"

    iptables, _ = _run_command(
        ["iptables", "-S"]
    )

    if (
        iptables is not None
        and iptables.returncode == 0
        and _iptables_has_rules(iptables.stdout)
    ):
        return "iptables"

    return None


NFT_TABLE = "erislite"


def _nftables_setup_commands():
    """Idempotent commands that create the ErisLITE block table.

    The table has its own output base chain that drops anything in the
    blocked4 or blocked6 sets. A drop in any base chain is final, so this
    works alongside an existing ruleset without editing it. Flushing and
    re-adding the two rules keeps repeated runs from duplicating them.
    """

    table = ["inet", NFT_TABLE]

    return [
        ["nft", "add", "table", *table],
        [
            "nft",
            "add",
            "chain",
            *table,
            "output",
            "{ type filter hook output priority -10 ; policy accept ; }",
        ],
        ["nft", "add", "set", *table, "blocked4", "{ type ipv4_addr ; }"],
        ["nft", "add", "set", *table, "blocked6", "{ type ipv6_addr ; }"],
        ["nft", "flush", "chain", *table, "output"],
        ["nft", "add", "rule", *table, "output", "ip", "daddr", "@blocked4", "drop"],
        ["nft", "add", "rule", *table, "output", "ip6", "daddr", "@blocked6", "drop"],
    ]


def build_ip_block_commands(ip, backend):
    """Return the commands that block outbound traffic to ip.

    The result has "apply" and "undo" commands. It can also have "setup"
    commands to run first and a "fallback" to try when apply fails.

    Rules are placed ahead of existing rules where the backend allows it.
    An appended rule sits behind any ESTABLISHED accept rule, so an
    attacker's live session would survive the block.
    """

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None

    ip = str(address)
    v6 = address.version == 6

    if backend == "ufw":
        return {
            "apply": ["ufw", "insert", "1", "deny", "out", "to", ip],
            # ufw refuses "insert 1" on an empty rule list and when an
            # IPv6 rule would land ahead of IPv4 rules.
            "fallback": ["ufw", "deny", "out", "to", ip],
            "undo": ["ufw", "delete", "deny", "out", "to", ip],
            "established_note": (
                "ufw accepts ESTABLISHED traffic before user rules, so an existing "
                "session to this address can survive. Terminate the owning process."
            ),
        }

    if backend == "firewalld":
        # A rich rule with a destination address filters incoming traffic
        # in a zone. It never matched outbound packets.
        family = "ipv6" if v6 else "ipv4"
        rule = [family, "filter", "OUTPUT", "0", "-d", ip, "-j", "DROP"]

        return {
            "apply": ["firewall-cmd", "--direct", "--add-rule", *rule],
            "undo": ["firewall-cmd", "--direct", "--remove-rule", *rule],
        }

    if backend == "iptables":
        tool = "ip6tables" if v6 else "iptables"

        return {
            "apply": [tool, "-I", "OUTPUT", "1", "-d", ip, "-j", "DROP"],
            "undo": [tool, "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
        }

    if backend == "nftables":
        element_set = "blocked6" if v6 else "blocked4"
        element = f"{{ {ip} }}"

        return {
            "setup": _nftables_setup_commands(),
            "apply": ["nft", "add", "element", "inet", NFT_TABLE, element_set, element],
            "undo": ["nft", "delete", "element", "inet", NFT_TABLE, element_set, element],
        }

    return None


def _run_command(command):
    try:
        return run_command(command), None

    except CommandResolutionError:
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
    result = make_result(
        status,
        details=[detail],
        tags=tags,
    )

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