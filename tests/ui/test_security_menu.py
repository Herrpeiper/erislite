# Project: ErisLITE
# Module: test_security_menu.py
# Author: Liam Piper-Brandon
# Version: 1.4.0
# License: MIT
# Created: 2026-09-28
# Last Updated: 2026-09-28
# Description: Locks Security Tools menu numbering so options keep their numbers across releases.

"""Analysts build muscle memory on menu numbers during competitions.

New tools are appended. Existing numbers never move. These tests fail if a
change renumbers an option that shipped in an earlier release.
"""

from types import SimpleNamespace

import pytest
from rich.console import Console

from erislite.ui.menus import security_menu

# option -> (module attribute on security_menu, function name, label)
EXPECTED_OPTIONS = {
    "4": ("listeners", "run_listener_scan", "Listener Check"),
    "5": ("users", "run_user_scan", "User Account Scan"),
    "6": ("processes", "run_process_scan", "Process Anomaly Scan"),
    "7": ("login_audit", "run_login_audit", "Login / Auth Logs"),
    "8": ("kernel_modules", "run_kernel_module_check", "Kernel Module Check"),
    "9": ("integrity", "integrity_menu", "File Integrity"),
    "10": ("world_writable", "run_world_writable_check", "World-Writable Files"),
    "11": ("suid", "run_suid_scan", "SUID / SGID Scan"),
    "12": ("cron", "run_cron_timer_scan", "Cron / Timer Check"),
    "13": ("ssh_config", "run_ssh_config_check", "SSH Config Audit"),
    "14": ("ssh_keys", "run_ssh_key_check", "SSH Key Check"),
    "15": ("hosts", "run_hosts_check", "Hosts Tamper Check"),
    "16": ("docker", "run_docker_scan", "Docker Security"),
    "17": ("cve_checker", "run_cve_check", "CVE Version Check"),
    "18": ("backdoors", "run_backdoor_check", "Backdoor Detection"),
    "19": ("rapid_response", "run_rapid_response_menu", "Rapid Response"),
    "20": ("soc_mode", "interactive_soc_mode", "SOC Mode"),
    "21": ("odyssey_menu", "run_odyssey_menu", "Odyssey Lite"),
}


def _menu_text() -> str:
    console = Console(record=True, width=120, force_terminal=False)
    console.print(security_menu._build_menu())
    return console.export_text()


@pytest.mark.parametrize("option,expected", EXPECTED_OPTIONS.items())
def test_menu_label_matches_number(option, expected):
    _, _, label = expected
    lines = [line for line in _menu_text().splitlines() if f"[{option}]" in line]

    assert len(lines) == 1
    assert label in lines[0]


@pytest.mark.parametrize("option,expected", EXPECTED_OPTIONS.items())
def test_menu_option_dispatches_to_expected_tool(monkeypatch, option, expected):
    module_attr, func_name, _ = expected
    called = []

    for name in ("clear_screen", "pause_return", "_render_header", "_render_last_sweep"):
        monkeypatch.setattr(security_menu, name, lambda *a, **k: None)

    monkeypatch.setattr(security_menu, "get_last_sweep_summary", lambda: None)
    monkeypatch.setattr(security_menu, "console", SimpleNamespace(print=lambda *a, **k: None))

    target_module = getattr(security_menu, module_attr)
    monkeypatch.setattr(target_module, func_name, lambda *a, **k: called.append(option))

    answers = iter([option, "0"])
    monkeypatch.setattr(security_menu.Prompt, "ask", lambda *a, **k: next(answers))

    security_menu.run({})

    assert called == [option]


def test_format_risk_uses_profile_maximum_and_percent():
    text, percent = security_menu._format_risk(
        {
            "risk_score": 15,
            "risk_max": 95,
            "risk_percent": 16,
        }
    )

    assert text == "15/95 (16%)"
    assert percent == 16


def test_score_color_uses_percentage_not_raw_points():
    assert security_menu._score_color(0) == "grey37"
    assert security_menu._score_color(16) == "green"
    assert security_menu._score_color(50) == "yellow"
    assert security_menu._score_color(80) == "red"
