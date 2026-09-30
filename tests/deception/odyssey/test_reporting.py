# Project: ErisLITE
# Module: test_reporting.py
# Author: Liam Piper-Brandon
# Version: 1.4.0
# License: MIT
# Created: 2026-09-30
# Last Updated: 2026-09-30
# Description: Tests that Odyssey Lite surfaces start, logging and event handling failures.

"""A detection tool that fails silently is worse than one that crashes.

These tests ensure every Odyssey failure path is visible to the analyst.
"""

import socket
import time

import pytest
from rich.console import Console

from erislite.deception.odyssey import manager as manager_module
from erislite.deception.odyssey import menu
from erislite.deception.odyssey.config import ListenerConfig
from erislite.deception.odyssey.events import OdysseyEvent
from erislite.deception.odyssey.listeners import CanaryListener
from erislite.deception.odyssey.manager import OdysseyManager


@pytest.fixture
def occupied_ports():
    """Yield a factory for ports that are already bound, and release them after."""

    sockets = []

    def occupy() -> int:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        sockets.append(sock)
        return sock.getsockname()[1]

    yield occupy

    for sock in sockets:
        sock.close()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _capture(monkeypatch) -> Console:
    console = Console(record=True, width=160, force_terminal=False)
    monkeypatch.setattr(menu, "console", console)
    monkeypatch.setattr(menu, "clear_screen", lambda: None)
    monkeypatch.setattr(menu, "pause_return", lambda: None)
    return console


def _event() -> OdysseyEvent:
    return OdysseyEvent(
        source_ip="192.0.2.10",
        source_port=54321,
        destination_port=2323,
        service="telnet-alt",
        severity="high",
    )


def _run_start(monkeypatch, manager: OdysseyManager) -> str:
    console = _capture(monkeypatch)
    answers = iter(["1", "0"])
    monkeypatch.setattr(menu.Prompt, "ask", lambda *a, **k: next(answers))

    try:
        menu.run_odyssey_menu(manager)
    finally:
        manager.stop()

    return console.export_text()


# ---------------------------------------------------------------------------
# Start results
# ---------------------------------------------------------------------------


def test_menu_reports_when_no_canary_can_bind(monkeypatch, occupied_ports):
    first, second = occupied_ports(), occupied_ports()
    manager = OdysseyManager(
        configs=(
            ListenerConfig(port=first, service="a"),
            ListenerConfig(port=second, service="b"),
        ),
        host="127.0.0.1",
    )

    output = _run_start(monkeypatch, manager)

    assert "no canaries could bind" in output
    assert str(first) in output
    assert str(second) in output


def test_menu_reports_partial_start(monkeypatch, occupied_ports):
    busy = occupied_ports()
    manager = OdysseyManager(
        configs=(
            ListenerConfig(port=busy, service="a"),
            ListenerConfig(port=_free_port(), service="b"),
        ),
        host="127.0.0.1",
    )

    output = _run_start(monkeypatch, manager)

    assert "started 1 of 2 canaries" in output
    assert str(busy) in output


def test_menu_is_quiet_when_every_canary_starts(monkeypatch):
    manager = OdysseyManager(
        configs=(ListenerConfig(port=_free_port(), service="a"),),
        host="127.0.0.1",
    )

    output = _run_start(monkeypatch, manager)

    assert "Ports unavailable" not in output


def test_status_panel_and_table_show_failed_ports(monkeypatch, occupied_ports):
    busy = occupied_ports()
    manager = OdysseyManager(
        configs=(ListenerConfig(port=busy, service="a"),),
        host="127.0.0.1",
    )
    manager.start()

    console = _capture(monkeypatch)
    menu._status_panel(manager)
    menu._show_listener_status(manager)
    output = console.export_text()

    assert f"Failed ports: {busy}" in output
    assert "FAILED" in output


# ---------------------------------------------------------------------------
# Event log failures
# ---------------------------------------------------------------------------


def test_persistence_error_is_recorded_and_cleared(monkeypatch):
    manager = OdysseyManager(configs=())

    def refuse(event):
        raise OSError("Refusing to use Odyssey log directory owned by uid 1000")

    monkeypatch.setattr(manager_module, "append_event", refuse)
    manager._record_event(_event())

    assert "owned by uid 1000" in manager.persistence_error
    assert len(manager.events) == 1

    monkeypatch.setattr(manager_module, "append_event", lambda event: None)
    manager.clear_events()
    manager._record_event(_event())

    assert manager.persistence_error is None


def test_status_panel_shows_failing_event_log(monkeypatch):
    manager = OdysseyManager(configs=())
    manager._persistence_error = "disk full"

    console = _capture(monkeypatch)
    menu._status_panel(manager)
    output = console.export_text()

    assert "FAILING" in output
    assert "disk full" in output


def test_status_panel_escapes_error_markup(monkeypatch):
    """Error text comes from paths and the OS. It must not be parsed as markup."""

    manager = OdysseyManager(configs=())
    manager._persistence_error = "bad path [/red] [bold]x"

    console = _capture(monkeypatch)
    menu._status_panel(manager)

    assert "[/red] [bold]x" in console.export_text()


# ---------------------------------------------------------------------------
# Event handling failures
# ---------------------------------------------------------------------------


def test_callback_failures_are_counted_not_hidden():
    def broken(event):
        raise ValueError("boom")

    port = _free_port()
    listener = CanaryListener(
        config=ListenerConfig(port=port, service="t"),
        event_callback=broken,
        host="127.0.0.1",
    )
    listener.start()

    try:
        for _ in range(2):
            socket.create_connection(("127.0.0.1", port), timeout=2).close()

        deadline = time.time() + 2
        while listener.callback_errors < 2 and time.time() < deadline:
            time.sleep(0.02)

        assert listener.running
        assert listener.callback_errors == 2
        assert listener.last_callback_error == "ValueError: boom"
    finally:
        listener.stop()


def test_status_panel_shows_event_handling_errors(monkeypatch):
    manager = OdysseyManager(configs=())
    listener = CanaryListener(
        config=ListenerConfig(port=_free_port(), service="t"),
        event_callback=lambda event: None,
    )
    listener.callback_errors = 3
    manager._listeners = [listener]

    console = _capture(monkeypatch)
    menu._status_panel(manager)

    assert "Event handling errors: 3" in console.export_text()
