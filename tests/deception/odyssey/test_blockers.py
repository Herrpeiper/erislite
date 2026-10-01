# Project: ErisLITE
# Module: test_blockers.py
# Author: Liam Piper-Brandon
# Version: 1.4.0
# License: MIT
# Created: 2026-09-28
# Last Updated: 2026-09-28
# Description: Regression tests for the v1.4 Odyssey Lite merge blockers.

import os
import socket
from pathlib import Path
from types import SimpleNamespace
 
import pytest
 
from erislite.deception.odyssey import manager as manager_module
from erislite.deception.odyssey import menu
from erislite.deception.odyssey.config import ListenerConfig
from erislite.deception.odyssey.manager import (
    OdysseyManager,
    active_canary_ports,
    get_manager,
)
from erislite.network import listeners
 
ODYSSEY_DIR = Path(manager_module.__file__).parent
 
 
def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
 
 
@pytest.fixture
def shared_manager(monkeypatch):
    """Install a loopback-only shared manager and stop it after the test."""
 
    monkeypatch.setattr(manager_module, "append_event", lambda event: None)
 
    manager = OdysseyManager(
        configs=(ListenerConfig(port=_free_port(), service="test"),),
        host="127.0.0.1",
    )
    monkeypatch.setattr(manager_module, "_shared_manager", manager)
 
    yield manager
 
    manager.stop()
 
 
# ---------------------------------------------------------------------------
# Blocker 1: Python 3.9 compatibility
# ---------------------------------------------------------------------------
 
 
@pytest.mark.parametrize(
    "path",
    sorted(ODYSSEY_DIR.glob("*.py")) + [Path(listeners.__file__)],
    ids=lambda path: path.name,
)
def test_modules_postpone_annotation_evaluation(path):
    """PEP 604 unions in signatures crash at import on Python 3.9.
 
    The 3.9 CI job is the real check. This guard catches it on newer
    interpreters too, before the push.
    """
 
    source = path.read_text(encoding="utf-8")
 
    if "|" not in source or path.name == "__init__.py":
        pytest.skip("no union syntax in module")
 
    assert "from __future__ import annotations" in source
 
 
# ---------------------------------------------------------------------------
# Blocker 2: listener lifecycle across menu visits
# ---------------------------------------------------------------------------
 
 
def test_get_manager_returns_same_instance(monkeypatch):
    monkeypatch.setattr(manager_module, "_shared_manager", None)
    monkeypatch.setattr(manager_module.atexit, "register", lambda func: None)
 
    assert get_manager() is get_manager()
 
 
def test_get_manager_registers_shutdown_once(monkeypatch):
    monkeypatch.setattr(manager_module, "_shared_manager", None)
 
    registered = []
    monkeypatch.setattr(manager_module.atexit, "register", registered.append)
 
    first = get_manager()
    get_manager()
 
    assert registered == [first.stop]
 
 
def test_menu_reentry_keeps_running_listeners(monkeypatch, shared_manager):
    """Start, leave the menu, come back: state must survive."""
 
    monkeypatch.setattr(menu, "clear_screen", lambda: None)
    monkeypatch.setattr(menu, "pause_return", lambda: None)
    monkeypatch.setattr(menu, "console", SimpleNamespace(print=lambda *a, **k: None))
 
    answers = iter(["1", "0"])
    monkeypatch.setattr(menu, "prompt_option", lambda *a, **k: next(answers))
 
    menu.run_odyssey_menu()
 
    assert shared_manager.running
 
    errors = []
    monkeypatch.setattr(
        menu,
        "console",
        SimpleNamespace(print=lambda *a, **k: errors.extend(map(str, a))),
    )
 
    answers = iter(["1", "0"])
    menu.run_odyssey_menu()
 
    assert shared_manager.running
    assert not any("failed to start" in line for line in errors)
 
 
# ---------------------------------------------------------------------------
# Blocker 3: listener scan must not flag ErisLITE's own canaries
# ---------------------------------------------------------------------------
 
 
def test_active_canary_ports_empty_when_odyssey_never_opened(monkeypatch):
    monkeypatch.setattr(manager_module, "_shared_manager", None)
 
    assert active_canary_ports() == frozenset()
 
 
def test_active_canary_ports_tracks_running_state(shared_manager):
    port = shared_manager.configs[0].port
 
    assert active_canary_ports() == frozenset()
 
    shared_manager.start()
    assert active_canary_ports() == frozenset({port})
 
    shared_manager.stop()
    assert active_canary_ports() == frozenset()
 
 
def _fake_ss(monkeypatch, lines):
    header = "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
 
    monkeypatch.setattr(listeners, "resolve_command", lambda command: "/usr/bin/ss")
    monkeypatch.setattr(
        listeners.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(
            stdout=header + "\n".join(lines) + "\n",
            stderr="",
            returncode=0,
        ),
    )
 
 
def _ss_line(port: int, pid: int, proc: str = "python3") -> str:
    return f'tcp LISTEN 0 128 0.0.0.0:{port} 0.0.0.0:* users:(("{proc}",pid={pid},fd=3))'
 
 
def test_own_canary_is_labeled_and_not_suspicious(monkeypatch):
    monkeypatch.setattr(listeners, "active_canary_ports", lambda: frozenset({2323}))
    _fake_ss(monkeypatch, [_ss_line(2323, os.getpid())])
 
    ((_, _, _, flags, is_whitelisted),) = listeners.parse_listeners()
 
    assert "ErisLITE Canary" in flags
    assert is_whitelisted
    assert not listeners._is_suspicious(flags, is_whitelisted)
 
 
def test_other_process_on_canary_port_is_still_suspicious(monkeypatch):
    monkeypatch.setattr(listeners, "active_canary_ports", lambda: frozenset({2323}))
    _fake_ss(monkeypatch, [_ss_line(2323, os.getpid() + 1)])
 
    ((_, _, _, flags, is_whitelisted),) = listeners.parse_listeners()
 
    assert "ErisLITE Canary" not in flags
    assert listeners._is_suspicious(flags, is_whitelisted)
 
 
def test_canary_port_is_suspicious_when_odyssey_is_stopped(monkeypatch):
    monkeypatch.setattr(listeners, "active_canary_ports", lambda: frozenset())
    _fake_ss(monkeypatch, [_ss_line(2323, os.getpid())])
 
    ((_, _, _, flags, is_whitelisted),) = listeners.parse_listeners()
 
    assert listeners._is_suspicious(flags, is_whitelisted)
 
 
def test_sweep_status_ok_with_only_own_canaries(monkeypatch):
    monkeypatch.setattr(listeners, "get_os", lambda: "Linux")
    monkeypatch.setattr(
        listeners,
        "active_canary_ports",
        lambda: frozenset({2121, 2222, 2323, 3389, 8080}),
    )
    _fake_ss(
        monkeypatch,
        [_ss_line(port, os.getpid()) for port in (2121, 2222, 2323, 3389, 8080)],
    )
 
    result = listeners.run_listener_scan(silent=True)
 
    assert result["status"] == "ok"
    assert "suspicious_listener" not in result["tags"]
