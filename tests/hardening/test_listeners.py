from types import SimpleNamespace

from erislite.network import listeners


def test_listener_scan_uses_shared_command_runner(monkeypatch):
    captured = {}

    def fake_run(command):
        captured["command"] = command

        return SimpleNamespace(
            stdout=(
                "Netid State Recv-Q Send-Q Local Address:Port "
                "Peer Address:Port Process\n"
            ),
            stderr="",
            returncode=0,
        )

    monkeypatch.setattr(
        listeners,
        "run_command",
        fake_run,
    )

    result = listeners.parse_listeners()

    assert result == []
    assert captured["command"] == ["ss", "-tulnp"]