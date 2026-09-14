from types import SimpleNamespace

from erislite.system import security_audit


def test_safe_run_ignores_poisoned_path(monkeypatch, tmp_path):
    fake_iptables = tmp_path / "iptables"
    fake_iptables.write_text("#!/bin/sh\necho hijacked\n")
    fake_iptables.chmod(0o755)

    monkeypatch.setenv("PATH", str(tmp_path))

    captured = {}

    def fake_resolve(command):
        assert command == "iptables"
        return "/usr/sbin/iptables"

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(
            stdout="-P INPUT ACCEPT\n",
            stderr="",
            returncode=0,
        )

    monkeypatch.setattr(security_audit, "resolve_command", fake_resolve)
    monkeypatch.setattr(security_audit.subprocess, "run", fake_run)

    result = security_audit._safe_run(["iptables", "-S"])

    assert result.returncode == 0
    assert captured["command"][0] != str(fake_iptables)
    assert captured["command"][0] == "/usr/sbin/iptables"
    assert captured["command"][1:] == ["-S"]