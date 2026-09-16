from types import SimpleNamespace

from erislite.accounts import login_audit


def test_failed_logins_ignores_poisoned_path(monkeypatch, tmp_path):
    fake_journalctl = tmp_path / "journalctl"
    fake_journalctl.write_text("#!/bin/sh\necho hijacked\n")
    fake_journalctl.chmod(0o755)

    monkeypatch.setenv("PATH", str(tmp_path))

    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(
            stdout=(
                "Failed password for invalid user admin "
                "from 10.0.0.5 port 2222\n"
            ),
            stderr="",
            returncode=0,
        )

    monkeypatch.setattr(login_audit.subprocess, "run", fake_run)

    results, error = login_audit.get_failed_logins()

    assert error is None
    assert captured["command"][0] != str(fake_journalctl)
    assert captured["command"][0].endswith("/journalctl")
    assert captured["command"][1:] == ["-u", "ssh", "-n", "100"]
    assert len(results) == 1