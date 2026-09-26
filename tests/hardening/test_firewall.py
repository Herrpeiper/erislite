from types import SimpleNamespace

from erislite.network import firewall


def test_run_command_ignores_poisoned_path(monkeypatch, tmp_path):
    fake_iptables = tmp_path / "iptables"
    fake_iptables.write_text("#!/bin/sh\necho hijacked\n")
    fake_iptables.chmod(0o755)

    monkeypatch.setenv("PATH", str(tmp_path))

    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(
            stdout="-P INPUT ACCEPT\n",
            stderr="",
            returncode=0,
        )

    monkeypatch.setattr(firewall.subprocess, "run", fake_run)

    result, error = firewall._run_command(["iptables", "-S"])

    assert error is None
    assert result is not None
    assert captured["command"][0] != str(fake_iptables)
    assert captured["command"][0].endswith("/iptables")
    assert captured["command"][1:] == ["-S"]