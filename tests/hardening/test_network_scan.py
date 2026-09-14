from types import SimpleNamespace

from erislite.network import scan


def test_network_scan_ignores_poisoned_path(monkeypatch, tmp_path):
    fake_ss = tmp_path / "ss"
    fake_ss.write_text("#!/bin/sh\necho hijacked\n")
    fake_ss.chmod(0o755)

    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(scan.platform, "system", lambda: "Linux")
    monkeypatch.setattr(scan.platform, "node", lambda: "test-host")

    captured = {}

    def fake_resolve(command):
        assert command == "ss"
        return "/usr/bin/ss"

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(
            stdout=(
                "Netid State Recv-Q Send-Q Local Address:Port "
                "Peer Address:Port Process\n"
            ),
            stderr="",
            returncode=0,
        )

    monkeypatch.setattr(scan, "resolve_command", fake_resolve)
    monkeypatch.setattr(scan.subprocess, "run", fake_run)

    result = scan.get_network_listeners_data()

    assert result["status"] == "success"
    assert result["results"] == []
    assert captured["command"][0] != str(fake_ss)
    assert captured["command"][0] == "/usr/bin/ss"
    assert captured["command"][1:] == ["-lntup"]