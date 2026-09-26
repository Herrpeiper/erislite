from types import SimpleNamespace

from erislite.network import listeners


def test_listener_scan_ignores_poisoned_path(monkeypatch, tmp_path):
    fake_ss = tmp_path / "ss"
    fake_ss.write_text("#!/bin/sh\necho hijacked\n")
    fake_ss.chmod(0o755)

    monkeypatch.setenv("PATH", str(tmp_path))

    captured = {}

    def fake_resolve(command):
        assert command == "ss"
        return "/usr/bin/ss"

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(
            stdout="Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\n",
            stderr="",
            returncode=0,
        )

    monkeypatch.setattr(listeners, "resolve_command", fake_resolve)
    monkeypatch.setattr(listeners.subprocess, "run", fake_run)

    result = listeners.parse_listeners()

    assert result == []
    assert captured["command"][0] != str(fake_ss)
    assert captured["command"][0] == "/usr/bin/ss"
    assert captured["command"][1:] == ["-tulnp"]