# Project: ErisLITE
# Module: actions.py
# Author: Liam Piper-Brandon
# Version: 1.1.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-02
# Description: Rapid Response containment and remediation actions.

from __future__ import annotations

import os
import shutil
import time
from typing import Any, Dict, List

from erislite.response.rapid_response.utils import have, now, run_cmd
from erislite.ui.console import console


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
                "undo": f"iptables -D OUTPUT -d {conn['remote_ip']} -j DROP",
            }
        )

    for user in users:
        actions.append(
            {
                "type": "lock_user",
                "label": f"Lock account: {user}",
                "data": {"username": user},
                "undo": f"usermod -U {user}",
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

        if not have("iptables"):
            console.print(f"[red]iptables not available — cannot block {ip}[/]")
            return False

        rc, _, err = run_cmd(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"])
        entry["result"] = f"Blocked {ip}" if rc == 0 else f"Failed: {err}"

        console.print(
            f"[green]Blocked outbound to {ip}[/]"
            if rc == 0
            else f"[red]Failed to block {ip}: {err}[/]"
        )

        log.append(entry)
        return rc == 0

    if atype == "lock_user":
        username = data["username"]

        if not have("usermod"):
            console.print(f"[red]usermod not available — cannot lock {username}[/]")
            return False

        rc, _, err = run_cmd(["usermod", "-L", username])
        entry["result"] = f"Locked {username}" if rc == 0 else f"Failed: {err}"

        console.print(
            f"[green]Locked account: {username}[/]"
            if rc == 0
            else f"[red]Failed to lock {username}: {err}[/]"
        )

        log.append(entry)
        return rc == 0

    if atype == "remove_cron":
        path = data["path"]
        backup = path + f".rr_backup_{int(time.time())}"

        try:
            shutil.copy2(path, backup)
            os.remove(path)

            entry["result"] = f"Removed {path} (backup: {backup})"
            entry["undo"] = f"cp {backup} {path}"

            console.print(f"[green]Removed {path} (backup: {backup})[/]")
            log.append(entry)
            return True

        except Exception as e:
            entry["result"] = f"Failed: {e}"
            console.print(f"[red]Failed to remove {path}: {e}[/]")
            log.append(entry)
            return False

    return False
