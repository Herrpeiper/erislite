# Project: ErisLITE
# Module: actions.py
# Author: Liam Piper-Brandon
# Version: 1.2.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-11
# Description: Rapid Response containment and remediation actions.

from __future__ import annotations

import os
import pwd
import shutil
import time
from typing import Any, Dict, List

from erislite.network.firewall import (
    build_ip_block_commands,
    detect_firewall_backend,
)
from erislite.response.rapid_response.utils import have, now, run_cmd
from erislite.ui.console import console

PROTECTED_SHELLS = {
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/bin/false",
}


def _validate_lock_target(username: str) -> tuple[bool, str]:
    if not username:
        return False, "username is empty"

    if username == "root":
        return False, "root account cannot be locked by Rapid Response"

    try:
        account = pwd.getpwnam(username)
    except KeyError:
        return False, f"user does not exist: {username}"

    current_user = pwd.getpwuid(os.getuid()).pw_name

    if username == current_user:
        return False, "current ErisLITE operator cannot be locked"

    if account.pw_shell in PROTECTED_SHELLS:
        return False, f"{username} appears to be a service account"

    return True, ""


def _terminate_user_sessions(username: str) -> tuple[bool, str]:
    if have("loginctl"):
        rc, _, err = run_cmd(
            [
                "loginctl",
                "terminate-user",
                username,
            ]
        )

        if rc == 0:
            return True, "sessions terminated with loginctl"

    if have("pkill"):
        rc, _, err = run_cmd(
            [
                "pkill",
                "-KILL",
                "-u",
                username,
            ]
        )

        if rc == 0:
            return True, "user processes terminated with pkill"

        return False, err or "pkill failed"

    return False, "no supported session termination command available"


def build_action_plan(procs, conns, users, crons) -> List[Dict[str, Any]]:
    actions = []

    for proc in procs:
        actions.append(
            {
                "type": "kill_process",
                "label": f"Kill PID {proc['pid']} ({proc['name']}) — running from {proc['exe']}",
                "data": proc,
                "undo": None,
            }
        )

    for conn in conns:
        actions.append(
            {
                "type": "block_ip",
                "label": (
                    f"Block outbound to {conn['remote_ip']} — "
                    f"{conn.get('reason', 'suspicious connection')} "
                    f"(from {conn['laddr']})"
                ),
                "data": conn,
                "undo": None,
            }
        )

    for user in users:
        actions.append(
            {
                "type": "lock_user",
                "label": f"Lock account and terminate sessions: {user}",
                "data": {"username": user},
                "undo": [
                    "usermod",
                    "-U",
                    user,
                ],
            }
        )

    for path in crons:
        actions.append(
            {
                "type": "remove_cron",
                "label": f"Remove world-writable cron file: {path}",
                "data": {"path": path},
                "undo": None,
            }
        )

    return actions


def execute_action(action: Dict[str, Any], log: List[Dict]) -> bool:
    atype = action["type"]
    data = action["data"]

    entry = {
        "time": now(),
        "type": atype,
        "data": data,
        "result": None,
        "undo": action["undo"],
    }

    if atype == "kill_process":
        pid = data["pid"]

        try:
            os.kill(pid, 9)
            entry["result"] = f"Killed PID {pid}"
            console.print(f"[green]Killed PID {pid} ({data['name']})[/]")
            log.append(entry)
            return True

        except ProcessLookupError:
            entry["result"] = f"PID {pid} already gone"
            console.print(f"[yellow]PID {pid} already gone[/]")
            log.append(entry)
            return True

        except Exception as e:
            entry["result"] = f"Failed: {e}"
            console.print(f"[red]Failed to kill PID {pid}: {e}[/]")
            log.append(entry)
            return False

    if atype == "block_ip":
        ip = data["remote_ip"]

        backend = detect_firewall_backend()

        if backend is None:
            entry["result"] = (
                f"Failed: no supported active firewall detected for {ip}"
            )
            console.print(
                f"[red]No supported active firewall detected — "
                f"cannot block {ip}[/]"
            )
            log.append(entry)
            return False

        commands = build_ip_block_commands(ip, backend)

        if commands is None:
            entry["result"] = (
                f"Failed: {backend} cannot safely block {ip} "
                f"with the current configuration"
            )
            console.print(
                f"[red]{backend} is active, but Rapid Response cannot "
                f"safely create a block rule for {ip}[/]"
            )
            log.append(entry)
            return False

        rc, _, err = run_cmd(commands["apply"])

        entry["data"]["firewall_backend"] = backend
        entry["undo"] = commands["undo"]

        entry["result"] = (
            f"Blocked {ip} using {backend}"
            if rc == 0
            else f"Failed: {err}"
        )

        console.print(
            f"[green]Blocked outbound to {ip} using {backend}[/]"
            if rc == 0
            else f"[red]Failed to block {ip}: {err}[/]"
        )

        log.append(entry)
        return rc == 0

    if atype == "lock_user":
        username = data["username"]

        valid, reason = _validate_lock_target(username)

        if not valid:
            entry["result"] = f"Failed: {reason}"
            console.print(
                f"[red]Cannot contain account {username}: {reason}[/]"
            )
            log.append(entry)
            return False

        if not have("usermod"):
            entry["result"] = "Failed: usermod not available"
            console.print(
                f"[red]usermod not available — cannot lock {username}[/]"
            )
            log.append(entry)
            return False

        rc, _, err = run_cmd(
            [
                "usermod",
                "-L",
                username,
            ]
        )

        if rc != 0:
            entry["result"] = f"Failed to lock {username}: {err}"
            console.print(
                f"[red]Failed to lock {username}: {err}[/]"
            )
            log.append(entry)
            return False

        terminated, detail = _terminate_user_sessions(username)

        if terminated:
            entry["result"] = (
                f"Locked {username}; {detail}"
            )

            console.print(
                f"[green]Locked account and terminated active sessions: "
                f"{username}[/]"
            )

            log.append(entry)
            return True

        entry["result"] = (
            f"Locked {username}; session termination failed: {detail}"
        )

        console.print(
            f"[yellow]Locked account {username}, but active sessions "
            f"could not be terminated: {detail}[/]"
        )

        log.append(entry)

        # Account locking itself succeeded, so containment was partial.
        return True

    if atype == "remove_cron":
        path = data["path"]
        backup = path + f".rr_backup_{int(time.time())}"

        try:
            shutil.copy2(path, backup)
            os.remove(path)

            entry["result"] = f"Removed {path} (backup: {backup})"
            entry["undo"] = {
                "type": "restore_file",
                "source": backup,
                "destination": path,
            }

            console.print(f"[green]Removed {path} (backup: {backup})[/]")
            log.append(entry)
            return True

        except Exception as e:
            entry["result"] = f"Failed: {e}"
            console.print(f"[red]Failed to remove {path}: {e}[/]")
            log.append(entry)
            return False

    return False
