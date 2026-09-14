import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from erislite.network import tools
from erislite.security.command_resolver import (
    CommandResolutionError,
    resolve_command,
)


def test_resolver_ignores_poisoned_path(monkeypatch, tmp_path):
    fake_ip = tmp_path / "ip"
    fake_ip.write_text("#!/bin/sh\nexit 0\n")
    fake_ip.chmod(0o755)

    monkeypatch.setenv("PATH", str(tmp_path))

    resolved = resolve_command("ip")

    assert resolved != str(fake_ip)
    assert Path(resolved).name == "ip"


def test_resolver_rejects_explicit_paths():
    with pytest.raises(CommandResolutionError):
        resolve_command("/tmp/ip")


def test_resolver_rejects_relative_paths():
    with pytest.raises(CommandResolutionError):
        resolve_command("./ip")


def test_resolver_rejects_unknown_command():
    with pytest.raises(CommandResolutionError):
        resolve_command("erislite-command-that-does-not-exist")




def test_show_gateway_uses_trusted_ip_binary(monkeypatch, tmp_path):
    fake_ip = tmp_path / "ip"
    fake_ip.write_text("#!/bin/sh\nexit 0\n")
    fake_ip.chmod(0o755)

    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(tools, "clear_screen", lambda: None)
    monkeypatch.setattr(tools, "pause_return", lambda: None)
    monkeypatch.setattr(tools.platform, "system", lambda: "Linux")

    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        return SimpleNamespace(
            returncode=0,
            stdout="default via 192.168.1.1 dev eth0\n",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    tools.show_gateway()

    assert captured["args"][0] != str(fake_ip)
    assert captured["args"][0].endswith("/ip")
    assert captured["args"][1:] == ["route"]