# Project: ErisLITE
# Module: actions.py
# Author: Liam Piper-Brandon
# Version: 1.5.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-10-14
# Description: Rapid Response containment and remediation actions.

from __future__ import annotations

import os
import pwd
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import psutil

from erislite.network.firewall import (
    build_ip_block_commands,
    canonical_ip,
    detect_firewall_backend,
)
from erislite.response.rapid_response import utils
from erislite.response.rapid_response.triage import (
    CRON_DIRS,
    _login_uid_min,
    is_suspicious_process_name,
    operator_source_ips,
)
from erislite.response.rapid_response.utils import have, now, run_cmd
from erislite.security.safe_io import read_regular_bytes, write_private_bytes
from erislite.ui.console import console

PROTECTED_SHELLS = {
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/bin/false",
    "/usr/bin/false",
}


# ---------------------------------------------------------------------------
# Operator and process identity
# ---------------------------------------------------------------------------


def operator_identity() -> Tuple[Set[str], Set[int]]:
    """Return the usernames and UIDs of the person running ErisLITE.

    Under sudo, getuid() is 0, so the old check only ever protected root.
    SUDO_USER and SUDO_UID identify the real operator.
    """

    names: Set[str] = set()
    uids: Set[int] = {os.getuid()}

    sudo_uid = os.environ.get("SUDO_UID", "")

    if sudo_uid.isdigit():
        uids.add(int(sudo_uid))

    sudo_user = os.environ.get("SUDO_USER")

    if sudo_user:
        names.add(sudo_user)

    try:
        names.add(os.getlogin())
    except OSError:
        pass

    for uid in list(uids):
        try:
            names.add(pwd.getpwuid(uid).pw_name)
        except KeyError:
            continue

    return names, uids


def _protected_pids() -> Set[int]:
    pids = {0, 1, os.getpid()}

    try:
        pids.update(parent.pid for parent in psutil.Process().parents())
    except (psutil.Error, OSError):
        pass

    return pids


def process_identity(pid: int) -> Optional[Dict[str, Any]]:
    """Return name, exe and start time for a PID, or None if unavailable."""

    try:
        proc = psutil.Process(pid)
        return {
            "pid": pid,
            "name": proc.name(),
            "exe": proc.exe(),
            "create_time": proc.create_time(),
        }
    except (psutil.Error, OSError):
        return None


def _same_process(data: Dict[str, Any]) -> Tuple[bool, str]:
    """Confirm the PID still belongs to the process triage reported."""

    current = process_identity(data["pid"])

    if current is None:
        return False, "process is gone or cannot be inspected"

    expected_start = data.get("create_time")

    if expected_start is not None and abs(current["create_time"] - expected_start) > 0.01:
        return False, "PID now belongs to a different process"

    if data.get("exe") and current["exe"] != data["exe"]:
        return False, f"executable changed to {current['exe']}"

    return True, ""


def _read_process_cgroup(pid: int) -> str:
    """Read kernel cgroup membership for a process."""
    return Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8")


def _process_service_safety(pid: int) -> Tuple[bool, str]:
    """Allow only processes in identifiable non-service user sessions.

    Fail closed when cgroup ownership is unavailable or ambiguous.
    """
    try:
        content = _read_process_cgroup(pid)
    except (OSError, UnicodeError) as exc:
        return False, f"cannot inspect process cgroup: {exc}"

    paths = []

    for line in content.splitlines():
        parts = line.split(":", 2)

        if len(parts) != 3 or not parts[2].startswith("/"):
            return False, "invalid cgroup membership data"

        paths.append(parts[2])

    if not paths:
        return False, "no cgroup membership information"

    for path in paths:
        components = path.strip("/").split("/")

        if any(component.endswith(".service") for component in components):
            return False, f"process belongs to a managed service: {path}"

    # Only identifiable login sessions qualify for automatic
    # process containment. Unknown cgroup layouts require review.
    for path in paths:
        components = path.strip("/").split("/")

        if "user.slice" in components and any(
            component.startswith("session-")
            and component.endswith(".scope")
            and component[8:-6].isdigit()
            for component in components
        ):
            return True, ""

    return False, "process is not in a verified user session"


# ---------------------------------------------------------------------------
# Action plan
# ---------------------------------------------------------------------------


def build_action_plan(procs, conns, users, crons) -> List[Dict[str, Any]]:
    actions = []
    planned_pids = set()

    for proc in procs:
        planned_pids.add(proc["pid"])
        actions.append(
            {
                "type": "kill_process",
                "label": f"Kill PID {proc['pid']} ({proc['name']}) running from {proc['exe']}",
                "data": proc,
                "undo": None,
            }
        )

    for conn in conns:
        actions.append(
            {
                "type": "block_ip",
                "label": (
                    f"Block outbound to {conn['remote_ip']}: "
                    f"{conn.get('reason', 'suspicious connection')} "
                    f"(local {conn['laddr']})"
                ),
                "data": conn,
                "undo": None,
            }
        )

        pid = conn.get("pid")

        # A firewall block does not always end an established session, so
        # offer to end the shell or netcat process that holds it.
        if pid and pid not in planned_pids and is_suspicious_process_name(conn.get("proc", "")):
            identity = process_identity(pid)

            if identity is not None:
                planned_pids.add(pid)
                actions.append(
                    {
                        "type": "kill_process",
                        "label": (
                            f"Kill PID {pid} ({identity['name']}) holding the "
                            f"connection to {conn['remote_ip']}"
                        ),
                        "data": identity,
                        "undo": None,
                    }
                )

    for user in users:
        actions.append(
            {
                "type": "lock_user",
                "label": f"Lock UID 0 account: {user}",
                "data": {"username": user},
                "undo": ["usermod", "-U", user],
            }
        )

    for path in crons:
        actions.append(
            {
                "type": "remove_cron",
                "label": f"Quarantine world-writable cron file: {path}",
                "data": {"path": path},
                "undo": None,
            }
        )

    return actions


# ---------------------------------------------------------------------------
# kill_process
# ---------------------------------------------------------------------------


def _kill_process(data: Dict[str, Any], entry: Dict[str, Any]) -> bool:
    pid = data["pid"]

    if pid in _protected_pids():
        entry["result"] = f"Refused: PID {pid} is ErisLITE, an ancestor of it, or init"
        console.print(f"[red]Refused to kill PID {pid}: protected process[/]")
        return False

    same, reason = _same_process(data)

    if not same:
        entry["result"] = f"Skipped PID {pid}: {reason}"
        console.print(f"[yellow]Skipped PID {pid}: {reason}[/]")
        # A process that already exited is not a failure.
        return reason.startswith("process is gone")

    safe, reason = _process_service_safety(pid)

    if not safe:
        entry["result"] = f"Refused: PID {pid}: {reason}"
        console.print(f"[red]Refused to kill PID {pid}: {reason}[/]")
        return False

    try:
        os.kill(pid, 9)
    except ProcessLookupError:
        entry["result"] = f"PID {pid} already gone"
        console.print(f"[yellow]PID {pid} already gone[/]")
        return True
    except OSError as exc:
        entry["result"] = f"Failed: {exc}"
        console.print(f"[red]Failed to kill PID {pid}: {exc}[/]")
        return False

    entry["result"] = f"Killed PID {pid}"
    console.print(f"[green]Killed PID {pid} ({data.get('name', '?')})[/]")
    return True


# ---------------------------------------------------------------------------
# block_ip
# ---------------------------------------------------------------------------


def _block_ip(data: Dict[str, Any], entry: Dict[str, Any]) -> bool:

    ip = canonical_ip(data["remote_ip"]) or data["remote_ip"]

    try:
        operator_ips = {canonical_ip(addr) or addr for addr in operator_source_ips()}
    except (OSError, psutil.Error, RuntimeError) as exc:
        entry["result"] = f"Refused: operator SSH source inspection failed: {exc}"
        console.print(f"[red]{entry['result']}[/]")
        return False

    if not operator_ips:
        entry["result"] = "Refused: operator SSH source could not be established"
        console.print("[red]Refused IP block: operator network identity is unknown.[/]")
        return False

    if ip in operator_ips:
        entry["result"] = f"Refused: {ip} is the source of the operator's SSH session"
        console.print(f"[red]Refused to block {ip}: it is your own SSH session[/]")
        return False

    backend = detect_firewall_backend()

    if backend is None:
        entry["result"] = f"Failed: no supported active firewall detected for {ip}"
        console.print(f"[red]No supported active firewall detected. Cannot block {ip}[/]")
        return False

    commands = build_ip_block_commands(ip, backend)

    if commands is None:
        entry["result"] = (
            f"Failed: {backend} cannot safely block {ip} with the current configuration"
        )
        console.print(
            f"[red]{backend} is active, but Rapid Response cannot "
            f"safely create a block rule for {ip}[/]"
        )
        return False

    entry["data"]["firewall_backend"] = backend

    for setup in commands.get("setup", []):
        rc, _, err = run_cmd(setup)

        if rc != 0:
            # nftables setup is intentionally repeatable. On later block
            # actions, the ErisLITE table, chain, and sets may already exist.
            if backend == "nftables" and "file exists" in (err or "").lower():
                continue

            entry["result"] = f"Failed: {backend} setup failed: {err}"
            console.print(f"[red]Failed to prepare {backend} block table: {err}[/]")
            return False

    rc, _, err = run_cmd(commands["apply"])

    if rc != 0 and commands.get("fallback"):
        rc, _, err = run_cmd(commands["fallback"])

    if rc != 0:
        entry["result"] = f"Failed: {err}"
        console.print(f"[red]Failed to block {ip}: {err}[/]")
        return False

    entry["undo"] = commands["undo"]
    entry["result"] = f"Blocked {ip} using {backend}"
    console.print(f"[green]Blocked outbound to {ip} using {backend}[/]")

    note = commands.get("established_note")

    if note:
        entry["result"] += f". {note}"
        console.print(f"[yellow]{note}[/]")

    return True


# ---------------------------------------------------------------------------
# lock_user
# ---------------------------------------------------------------------------


def _service_account_safety(uid: int) -> Tuple[bool, str]:
    """Refuse containment when a UID owns a running service process.

    Preserve the existing special handling of UID 0 accounts.
    Fail closed when process ownership cannot be inspected.
    """
    if uid == 0:
        return True, ""

    try:
        for proc in psutil.process_iter(["pid", "uids"]):
            info = proc.info
            process_uids = info.get("uids")

            if process_uids is None:
                return False, "cannot establish process ownership"

            owned_uids = {
                process_uids.real,
                process_uids.effective,
                process_uids.saved,
            }

            if uid not in owned_uids:
                continue

            pid = info["pid"]

            try:
                content = _read_process_cgroup(pid)
            except (OSError, UnicodeError):
                return False, f"cannot inspect cgroup for PID {pid}"

            if not content.strip():
                return False, f"missing cgroup information for PID {pid}"

            for line in content.splitlines():
                parts = line.split(":", 2)

                if len(parts) != 3 or not parts[2].startswith("/"):
                    return False, f"invalid cgroup information for PID {pid}"

                components = parts[2].strip("/").split("/")

                for component in components:
                    if component.endswith(".service") and not component.startswith("user@"):
                        return (
                            False,
                            f"UID {uid} owns running service {component} (PID {pid})",
                        )

    except (psutil.Error, OSError) as exc:
        return False, f"process ownership inspection failed: {exc}"

    return True, ""


def _validate_lock_target(username: str) -> Tuple[bool, str]:
    if not username:
        return False, "username is empty"

    if username == "root":
        return False, "root account cannot be locked by Rapid Response"

    try:
        account = pwd.getpwnam(username)
    except KeyError:
        return False, f"user does not exist: {username}"

    operator_names, operator_uids = operator_identity()

    if username in operator_names or (account.pw_uid in operator_uids and account.pw_uid != 0):
        return False, "current ErisLITE operator cannot be locked"

    if account.pw_shell in PROTECTED_SHELLS:
        return False, f"{username} appears to be a service account"

    if 0 < account.pw_uid < _login_uid_min():
        return (
            False,
            f"{username} is a system account (UID {account.pw_uid})",
        )

    safe, reason = _service_account_safety(account.pw_uid)

    if not safe:
        return False, reason

    return True, ""


def _uid_is_shared(username: str, uid: int) -> bool:
    try:
        accounts = pwd.getpwall()
    except Exception:
        return True

    return any(other.pw_uid == uid and other.pw_name != username for other in accounts)


def _terminate_user_sessions(username: str) -> Tuple[bool, str]:
    """End a user's sessions.

    loginctl and pkill both act on the UID, not the name. For a UID 0 clone
    that would kill every root process, including ErisLITE, so accounts that
    share a UID with another account are never terminated this way.
    """

    try:
        uid = pwd.getpwnam(username).pw_uid
    except KeyError:
        return False, f"user does not exist: {username}"

    if uid == 0 or _uid_is_shared(username, uid):
        return False, (
            f"{username} shares UID {uid} with another account, so killing by user "
            f"would hit that account too. End its sessions by PID (w, who, loginctl list-sessions)"
        )

    err = ""

    if have("loginctl"):
        rc, _, err = run_cmd(["loginctl", "terminate-user", username])

        if rc == 0:
            return True, "sessions terminated with loginctl"

    if have("pkill"):
        rc, _, err = run_cmd(["pkill", "-KILL", "-u", username])

        if rc == 0:
            return True, "user processes terminated with pkill"

        return False, err or "pkill failed"

    return False, err or "no supported session termination command available"


def _password_lock_state(username: str) -> Tuple[Optional[str], str]:
    """Inspect password status without reading or logging password hashes."""

    if not have("passwd"):
        return None, "passwd utility unavailable"

    rc, output, _ = run_cmd(["passwd", "-S", username])

    if rc != 0:
        return None, "password status inspection failed"

    fields = output.split()

    if len(fields) < 2 or fields[0] != username:
        return None, "invalid password status response"

    status = fields[1]

    if status == "P":
        return "unlocked", ""

    if status == "L":
        return "locked", ""

    if status == "NP":
        return "passwordless", ""

    return None, "unrecognized password status"


def _lock_user(data: Dict[str, Any], entry: Dict[str, Any]) -> bool:
    username = data["username"]

    # Undo must not be available until a new password lock succeeds.
    entry["undo"] = None

    valid, reason = _validate_lock_target(username)

    if not valid:
        entry["result"] = f"Failed: {reason}"
        console.print(f"[red]Cannot contain account {username}: {reason}[/]")
        return False

    state, reason = _password_lock_state(username)

    if state != "unlocked":
        if state == "locked":
            reason = "account password was already locked"
        elif state == "passwordless":
            reason = "account has no usable password to lock"

        entry["result"] = f"Refused: {reason}"
        console.print(f"[yellow]Refused to lock {username}: {reason}[/]")
        return False

    if not have("usermod"):
        entry["result"] = "Failed: usermod not available"
        console.print("[red]usermod not available.[/]")
        return False

    rc, _, err = run_cmd(["usermod", "-L", username])

    if rc != 0:
        entry["result"] = f"Failed to lock {username}: {err}"
        console.print(f"[red]Failed to lock {username}: {err}[/]")
        return False

    # This account was initially unlocked, and our lock succeeded.
    entry["undo"] = ["usermod", "-U", username]

    terminated, detail = _terminate_user_sessions(username)

    if terminated:
        entry["result"] = f"Password authentication locked for {username}; {detail}"
        console.print(
            f"[green]Locked password authentication and terminated active sessions: {username}[/]"
        )
        return True

    entry["result"] = (
        f"Password authentication locked for {username}; sessions not terminated: {detail}"
    )

    console.print(
        f"[yellow]Locked password authentication for {username}, "
        f"but active sessions were not terminated: {detail}[/]"
    )
    console.print("[yellow]Review SSH keys and other authentication methods for this account.[/]")

    return True


# ---------------------------------------------------------------------------
# remove_cron
# ---------------------------------------------------------------------------


def _is_cron_path(path: str) -> bool:
    parent = os.path.dirname(os.path.abspath(path))
    return parent in CRON_DIRS


def _remove_cron(data: Dict[str, Any], entry: Dict[str, Any]) -> bool:
    path = data["path"]

    if not _is_cron_path(path):
        entry["result"] = f"Refused: {path} is not inside a cron directory"
        console.print(f"[red]Refused to remove {path}: not a cron directory entry[/]")
        return False

    try:
        info = os.lstat(path)
        content = read_regular_bytes(path)

        quarantine = Path(utils.QUARANTINE_DIR) / (
            f"{path.strip('/').replace('/', '_')}.{secrets.token_hex(16)}"
        )
        write_private_bytes(quarantine, content)
        os.remove(path)
    except OSError as exc:
        entry["result"] = f"Failed: {exc}"
        console.print(f"[red]Failed to remove {path}: {exc}[/]")
        return False

    entry["result"] = f"Removed {path} (quarantined copy: {quarantine})"
    entry["undo"] = {
        "type": "restore_file",
        "source": str(quarantine),
        "destination": path,
        "mode": info.st_mode & 0o7777,
        "uid": info.st_uid,
        "gid": info.st_gid,
    }

    console.print(f"[green]Removed {path} (quarantined copy: {quarantine})[/]")
    return True


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_HANDLERS = {
    "kill_process": _kill_process,
    "block_ip": _block_ip,
    "lock_user": _lock_user,
    "remove_cron": _remove_cron,
}


def execute_action(action: Dict[str, Any], log: List[Dict]) -> bool:
    handler = _HANDLERS.get(action["type"])

    if handler is None:
        return False

    entry = {
        "time": now(),
        "type": action["type"],
        "data": action["data"],
        "result": None,
        "undo": action["undo"],
    }

    try:
        succeeded = handler(action["data"], entry)
    except Exception as exc:
        entry["result"] = f"Failed: {type(exc).__name__}: {exc}"
        console.print(f"[red]{action['type']} failed: {exc}[/]")
        succeeded = False

    # An action that did not apply has nothing to undo.
    if not succeeded:
        entry["undo"] = None

    log.append(entry)
    return succeeded
