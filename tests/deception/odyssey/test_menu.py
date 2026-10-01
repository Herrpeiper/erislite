from datetime import datetime, timezone

from rich.console import Console

from erislite.deception.odyssey import menu
from erislite.deception.odyssey.config import ListenerConfig
from erislite.deception.odyssey.events import OdysseyEvent
from erislite.deception.odyssey.manager import OdysseyManager


def _capture_console(monkeypatch):
    console = Console(
        record=True,
        width=120,
        force_terminal=False,
    )

    monkeypatch.setattr(menu, "console", console)

    return console


def test_status_panel_inactive(monkeypatch):
    console = _capture_console(monkeypatch)

    manager = OdysseyManager(configs=())

    menu._status_panel(manager)

    output = console.export_text()

    assert "INACTIVE" in output
    assert "Listeners: 0" in output
    assert "Events: 0" in output


def test_build_menu_inactive():
    manager = OdysseyManager(configs=())

    table = menu._build_menu(manager)

    console = Console(
        record=True,
        width=120,
        force_terminal=False,
    )

    console.print(table)

    output = console.export_text()

    assert "Start Odyssey" in output
    assert "Activate canary listeners" in output
    assert "Already stopped" in output


def test_listener_status_stopped(monkeypatch):
    console = _capture_console(monkeypatch)

    manager = OdysseyManager(
        configs=(
            ListenerConfig(
                port=18080,
                service="test-canary",
                severity="high",
            ),
        ),
        host="127.0.0.1",
    )

    monkeypatch.setattr(
        menu,
        "pause_return",
        lambda: None,
    )

    menu._show_listener_status(manager)

    output = console.export_text()

    assert "18080" in output
    assert "test-canary" in output
    assert "HIGH" in output
    assert "YES" in output
    assert "STOPPED" in output


def test_recent_events_empty(monkeypatch):
    console = _capture_console(monkeypatch)

    manager = OdysseyManager(configs=())

    monkeypatch.setattr(
        menu,
        "pause_return",
        lambda: None,
    )

    menu._show_recent_events(manager)

    output = console.export_text()

    assert "No Odyssey events have been observed." in output


def test_recent_events_render_event(monkeypatch):
    console = _capture_console(monkeypatch)

    manager = OdysseyManager(configs=())

    manager._record_event(
        OdysseyEvent(
            source_ip="192.0.2.10",
            source_port=54321,
            destination_port=18080,
            service="test-canary",
            severity="high",
            timestamp=datetime(
                2026,
                9,
                26,
                14,
                30,
                tzinfo=timezone.utc,
            ),
        )
    )

    monkeypatch.setattr(
        menu,
        "pause_return",
        lambda: None,
    )

    menu._show_recent_events(manager)

    output = console.export_text()

    assert "192.0.2.10:54321" in output
    assert "18080" in output
    assert "test-canary" in output
    assert "HIGH" in output
