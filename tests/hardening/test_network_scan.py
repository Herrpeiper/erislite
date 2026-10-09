from types import SimpleNamespace

from erislite.network import scan


def test_network_scan_uses_shared_command_runner(monkeypatch):
    monkeypatch.setattr(
        scan.platform,
        "system",
        lambda: "Linux",
    )
    monkeypatch.setattr(
        scan.platform,
        "node",
        lambda: "test-host",
    )

    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs

        return SimpleNamespace(
            stdout=(
                "Netid State Recv-Q Send-Q Local Address:Port "
                "Peer Address:Port Process\n"
            ),
            stderr="",
            returncode=0,
        )

    monkeypatch.setattr(
        scan,
        "run_command",
        fake_run,
    )

    result = scan.get_network_listeners_data()

    assert result["status"] == "success"
    assert result["command"] == "ss -lntup"
    assert captured["command"] == ["ss", "-lntup"]
    assert captured["kwargs"]["timeout"] == 15