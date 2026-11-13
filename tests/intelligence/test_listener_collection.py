# Project: ErisLITE
# Module: test_listener_collection.py
# Version: 1.6.0
# License: MIT
# Description: Tests for shared listener collection.

from types import SimpleNamespace

from erislite.network import listeners


def test_collection_success(monkeypatch):
    records = [
        (
            "tcp",
            "0.0.0.0:2222",
            "socat",
            ["External Bind"],
            False,
        )
    ]

    monkeypatch.setattr(
        listeners,
        "parse_listeners",
        lambda: records,
    )

    result = listeners.collect_listeners()

    assert result.error is None
    assert result.observations == records


def test_collection_empty_success(monkeypatch):
    monkeypatch.setattr(
        listeners,
        "parse_listeners",
        lambda: [],
    )

    result = listeners.collect_listeners()

    assert result.error is None
    assert result.observations == []


def test_collection_failure(monkeypatch):
    monkeypatch.setattr(
        listeners,
        "parse_listeners",
        lambda: [
            (
                "error",
                "-",
                "inspection failed",
                ["Error"],
                False,
            )
        ],
    )

    result = listeners.collect_listeners()

    assert result.error == "inspection failed"
    assert result.observations == []


def test_nonzero_command_is_not_clean(monkeypatch):
    monkeypatch.setattr(
        listeners,
        "run_command",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="permission denied",
        ),
    )

    records = listeners.parse_listeners()

    assert len(records) == 1
    assert records[0][0] == "error"


def test_successful_empty_command(monkeypatch):
    monkeypatch.setattr(
        listeners,
        "run_command",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="Netid State Recv-Q Send-Q Local Peer\n",
            stderr="",
        ),
    )

    monkeypatch.setattr(
        listeners,
        "active_canary_ports",
        lambda: frozenset(),
    )

    result = listeners.collect_listeners()

    assert result.error is None
    assert result.observations == []
