from unittest.mock import Mock

import pytest

import erislite.response.rapid_response.menu as menu
from erislite.response.rapid_response.menu import parse_action_selection


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("", []),
        ("0", []),
        ("none", []),
        ("all", [0, 1, 2, 3, 4]),
        ("1", [0]),
        ("1,3", [0, 2]),
        ("2-4", [1, 2, 3]),
        ("5, 1-2", [0, 1, 4]),
        ("1,1", [0]),
    ],
)
def test_parse_action_selection_valid(raw, expected):
    assert parse_action_selection(raw, 5) == expected


@pytest.mark.parametrize("raw", ["6", "0-2", "3-1", "a", "1;2", "1-2-3", "-1"])
def test_parse_action_selection_invalid(raw):
    assert parse_action_selection(raw, 5) is None


def _prepare_live_response(monkeypatch, tmp_path):
    actions = [
        {"type": "test", "label": "First", "undo": None},
        {"type": "test", "label": "Second", "undo": None},
    ]

    monkeypatch.setattr(menu, "get_os", lambda: "Linux")
    monkeypatch.setattr(menu.os, "geteuid", lambda: 0)
    monkeypatch.setattr(menu, "clear_screen", lambda: None)
    monkeypatch.setattr(menu, "_header", lambda *a: None)
    monkeypatch.setattr(menu, "pause_return", lambda: None)
    monkeypatch.setattr(menu, "suspicious_processes", lambda: [{}])
    monkeypatch.setattr(menu, "suspicious_connections", lambda: ([], None))
    monkeypatch.setattr(menu, "flagged_users", lambda: ([], [], None))
    monkeypatch.setattr(menu, "writable_crons", lambda: ([], []))
    monkeypatch.setattr(menu, "build_action_plan", lambda *a: actions)
    monkeypatch.setattr(menu, "_show_processes", lambda *a: None)
    monkeypatch.setattr(menu, "_show_connections", lambda *a: None)
    monkeypatch.setattr(menu, "_show_actions", lambda *a: None)
    monkeypatch.setattr(menu, "_select_actions", lambda *a: actions)
    monkeypatch.setattr(menu.Confirm, "ask", lambda *a, **kw: True)
    monkeypatch.setattr(menu, "log_path", lambda: tmp_path / "audit.json")

    return actions


def test_initial_audit_failure_aborts(monkeypatch, tmp_path):
    _prepare_live_response(monkeypatch, tmp_path)

    execute = Mock()
    monkeypatch.setattr(menu, "execute_action", execute)

    def fail_write(*args):
        raise OSError("disk full")

    monkeypatch.setattr(menu, "_write_response_log", fail_write)

    menu.run_rapid_response()

    execute.assert_not_called()


def test_audit_failure_stops_remaining_actions(monkeypatch, tmp_path):
    _prepare_live_response(monkeypatch, tmp_path)

    execute = Mock(side_effect=lambda action, log: log.append({"type": action["type"]}) or True)
    monkeypatch.setattr(menu, "execute_action", execute)

    writes = Mock(side_effect=[None, OSError("disk full")])
    monkeypatch.setattr(menu, "_write_response_log", writes)

    menu.run_rapid_response()

    assert execute.call_count == 1
    assert writes.call_count == 2


def test_successful_audit_processes_all_actions(monkeypatch, tmp_path):
    _prepare_live_response(monkeypatch, tmp_path)

    execute = Mock(side_effect=lambda action, log: log.append({"type": action["type"]}) or True)
    monkeypatch.setattr(menu, "execute_action", execute)

    writes = Mock()
    monkeypatch.setattr(menu, "_write_response_log", writes)

    menu.run_rapid_response()

    assert execute.call_count == 2
    assert writes.call_count == 3
