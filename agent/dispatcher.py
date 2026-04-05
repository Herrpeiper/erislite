# agent/dispatcher.py
# Routes incoming jobs from the Basalt controller to the appropriate ErisLITE module.
#
# HOW IT WORKS
# ------------
# Every module already supports silent=True, which suppresses CLI output and
# returns a structured dict: {"status": ..., "details": [...], "tags": [...]}.
# Each handler here calls the module in silent mode, then wraps the result in
# the standard agent envelope the controller expects:
#
#   {
#       "module":  "security.users",
#       "status":  "success" | "error",
#       "errors":  [],
#       "results": <raw module result dict>,
#       "summary": {"status": ..., "tags": [...], "detail": [...]}
#   }
#
# ADDING A NEW MODULE
# -------------------
# 1. Import its run_* function below.
# 2. Write a one-liner handler that calls it with silent=True.
# 3. Add an entry to MODULE_MAP: "dotted.name": handler_function.
# That's it — execute_job() handles everything else automatically.

from __future__ import annotations

import sys
import os
import traceback
from typing import Any, Dict
from pathlib import Path

# ── Path fix ───────────────────────────────────────────────────────────────────
# The agent may be launched from any working directory (e.g. the basalt-controller
# folder). The ErisLITE modules all import from ui.utils, tools.*, core.*, etc.
# which only resolve when the ErisLITE repo root is on sys.path.
# We resolve that root as the parent of this file's parent (agent/ -> ErisLITE/)
# and prepend it if it isn't already present.
_ERISLITE_ROOT = str(Path(__file__).resolve().parent.parent)
if _ERISLITE_ROOT not in sys.path:
    sys.path.insert(0, _ERISLITE_ROOT)

# ── Core modules ───────────────────────────────────────────────────────────────
from core.network_scan import get_network_listeners_data
from core.login_audit import run_login_audit
from core.cve_checker import run_cve_check

# ── Tools ──────────────────────────────────────────────────────────────────────
from tools.listener_check import run_listener_scan
from tools.user_anomaly import run_user_scan
from tools.kernel_module_check import run_kernel_module_check
from tools.ssh_key_check import run_ssh_key_check
from tools.ssh_config_check import run_ssh_config_check
from tools.world_writable_check import run_world_writable_check
from tools.cron_timer_check import run_cron_timer_scan
from tools.suid_check import run_suid_scan
from tools.docker_check import run_docker_scan
from tools.firewall_check import run_firewall_check
from tools.integrity_tools import scan_integrity
from tools.process_check import run_process_scan
from tools.hosts_check import run_hosts_check
from tools.backdoor_check import run_backdoor_check
from tools.rapid_response import run_rapid_response


# ── Envelope helper ────────────────────────────────────────────────────────────

def _wrap(module_name: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrap a module's silent-mode result dict in the standard agent envelope.
    raw is expected to have at least: status, details, tags.
    """
    return {
        "module":  module_name,
        "status":  "success",
        "errors":  [],
        "results": raw,
        "summary": {
            "status": raw.get("status", "unknown"),
            "tags":   raw.get("tags", []),
            "detail": raw.get("details", []),
        },
    }


# ── Handlers ───────────────────────────────────────────────────────────────────
# Each handler receives the args dict from the job and returns a wrapped result.

def _run_network_listeners(args: Dict[str, Any]) -> Dict[str, Any]:
    """Raw network scan — returns the full structured listener data."""
    result = get_network_listeners_data()
    if not isinstance(result, dict):
        raise ValueError(f"network.listeners returned non-dict: {type(result).__name__}")
    result.setdefault("module",  "network.listeners")
    result.setdefault("status",  "success")
    result.setdefault("errors",  [])
    result.setdefault("results", [])
    result.setdefault("summary", {})
    return result


def _run_listeners(args: Dict[str, Any]) -> Dict[str, Any]:
    return _wrap("security.listeners", run_listener_scan(silent=True))

def _run_users(args: Dict[str, Any]) -> Dict[str, Any]:
    return _wrap("security.users", run_user_scan(silent=True))

def _run_kernel(args: Dict[str, Any]) -> Dict[str, Any]:
    return _wrap("security.kernel", run_kernel_module_check(silent=True))

def _run_ssh_keys(args: Dict[str, Any]) -> Dict[str, Any]:
    return _wrap("security.ssh_keys", run_ssh_key_check(silent=True))

def _run_ssh_config(args: Dict[str, Any]) -> Dict[str, Any]:
    return _wrap("security.ssh_config", run_ssh_config_check(silent=True))

def _run_world_writable(args: Dict[str, Any]) -> Dict[str, Any]:
    return _wrap("security.world_writable", run_world_writable_check(silent=True))

def _run_cron(args: Dict[str, Any]) -> Dict[str, Any]:
    return _wrap("security.cron", run_cron_timer_scan(silent=True))

def _run_suid(args: Dict[str, Any]) -> Dict[str, Any]:
    return _wrap("security.suid", run_suid_scan(silent=True))

def _run_docker(args: Dict[str, Any]) -> Dict[str, Any]:
    return _wrap("security.docker", run_docker_scan(silent=True))

def _run_firewall(args: Dict[str, Any]) -> Dict[str, Any]:
    return _wrap("security.firewall", run_firewall_check(silent=True))

def _run_integrity(args: Dict[str, Any]) -> Dict[str, Any]:
    # profile arg lets the controller request a specific scan profile: critical, system, user
    profile = args.get("profile", "critical")
    return _wrap("security.integrity", scan_integrity(profile=profile, silent=True))

def _run_login(args: Dict[str, Any]) -> Dict[str, Any]:
    return _wrap("security.login", run_login_audit(silent=True))

def _run_cve(args: Dict[str, Any]) -> Dict[str, Any]:
    return _wrap("security.cve", run_cve_check(silent=True))

def _run_processes(args: Dict[str, Any]) -> Dict[str, Any]:
    return _wrap("security.processes", run_process_scan(silent=True))

def _run_hosts(args: Dict[str, Any]) -> Dict[str, Any]:
    return _wrap("security.hosts", run_hosts_check(silent=True))

def _run_backdoor(args: Dict[str, Any]) -> Dict[str, Any]:
    return _wrap("security.backdoor", run_backdoor_check(silent=True))

def _run_rapid_response(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Remote rapid response via the controller.
    Pass {"dry_run": true} in args for a safe triage-only run.
    Defaults to dry_run=True for safety — must explicitly pass
    {"dry_run": false} to execute live actions remotely.
    """
    dry_run = args.get("dry_run", True)

    # Run the triage scan and return findings without executing actions
    # The actual execution path (run_rapid_response) is interactive-only
    # so we call the triage functions directly here and return structured data.
    import psutil, pwd, os, shutil
    from tools.rapid_response import (
        _triage_suspicious_processes,
        _triage_suspicious_connections,
        _triage_flagged_users,
        _triage_writable_crons,
        _build_action_plan,
        _execute_action,
        _log_path,
    )
    import json
    from datetime import datetime

    procs = _triage_suspicious_processes()
    conns = _triage_suspicious_connections()
    users = _triage_flagged_users()
    crons = _triage_writable_crons()

    actions = _build_action_plan(procs, conns, users, crons)

    summary = {
        "suspicious_processes": len(procs),
        "suspicious_connections": len(conns),
        "flagged_users": len(users),
        "writable_crons": len(crons),
        "total_actions": len(actions),
        "dry_run": dry_run,
    }

    if dry_run or not actions:
        return _wrap("security.rapid_response", {
            "status":  "warning" if actions else "ok",
            "details": [a["label"] for a in actions] or ["No immediate threats detected"],
            "tags":    ["rapid_response_dry_run"] if actions else [],
            "summary": summary,
        })

    # Live execution
    action_log = []
    success = 0
    failed  = 0
    for action in actions:
        if _execute_action(action, action_log):
            success += 1
        else:
            failed += 1

    log_path = _log_path()
    log_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "mode":      "live_remote",
        "summary":   {"success": success, "failed": failed, "total": len(actions)},
        "actions":   action_log,
    }
    with open(log_path, "w") as f:
        json.dump(log_data, f, indent=2)

    details = [e.get("result", "") for e in action_log]

    return _wrap("security.rapid_response", {
        "status":  "warning" if failed else "ok",
        "details": details[:15],
        "tags":    ["rapid_response_executed"],
        "summary": {**summary, "success": success, "failed": failed,
                    "log": str(log_path)},
    })


# ── Module map ─────────────────────────────────────────────────────────────────
# Maps the dotted module name (sent by the controller) to its handler function.
# Add new entries here when you add new modules — nothing else needs changing.

MODULE_MAP: Dict[str, Any] = {
    # Network (legacy key kept for compatibility with existing frontend)
    "network.listeners":       _run_network_listeners,

    # Security checks
    "security.listeners":      _run_listeners,
    "security.users":          _run_users,
    "security.kernel":         _run_kernel,
    "security.ssh_keys":       _run_ssh_keys,
    "security.ssh_config":     _run_ssh_config,
    "security.world_writable": _run_world_writable,
    "security.cron":           _run_cron,
    "security.suid":           _run_suid,
    "security.docker":         _run_docker,
    "security.firewall":       _run_firewall,
    "security.integrity":      _run_integrity,
    "security.login":          _run_login,
    "security.cve":            _run_cve,
    "security.processes":      _run_processes,
    "security.hosts":          _run_hosts,
    "security.backdoor":       _run_backdoor,
    "security.rapid_response": _run_rapid_response,
}


# ── Entry point ────────────────────────────────────────────────────────────────

def execute_job(module: str, action: str, args: Dict[str, Any]) -> Dict[str, Any]:
    if action != "run":
        return {
            "module":  module,
            "status":  "error",
            "errors":  [f"Unsupported action: {action}"],
            "results": {},
            "summary": {},
        }

    handler = MODULE_MAP.get(module)
    if not handler:
        return {
            "module":  module,
            "status":  "error",
            "errors":  [f"Unknown module: '{module}'. Available: {sorted(MODULE_MAP.keys())}"],
            "results": {},
            "summary": {},
        }

    try:
        return handler(args or {})
    except Exception as exc:
        return {
            "module":  module,
            "status":  "error",
            "errors":  [
                f"Exception in module '{module}': {exc}",
                traceback.format_exc(),
            ],
            "results": {},
            "summary": {},
        }