import functools
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from erislite.network import tools
from erislite.security.command_resolver import (
    CommandResolutionError,
    resolve_command,
)


def _make_executable(directory: Path, name: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(0o755)
    return path


def test_resolver_ignores_poisoned_path(monkeypatch, tmp_path):
    fake_ip = _make_executable(tmp_path / "poisoned", "ip")
    trusted_ip = _make_executable(tmp_path / "trusted", "ip")

    monkeypatch.setenv("PATH", str(fake_ip.parent))

    resolved = resolve_command("ip", trusted_dirs=(trusted_ip.parent,))

    assert resolved != str(fake_ip)
    assert resolved == str(trusted_ip)


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
    fake_ip = _make_executable(tmp_path / "poisoned", "ip")
    trusted_ip = _make_executable(tmp_path / "trusted", "ip")

    monkeypatch.setenv("PATH", str(fake_ip.parent))
    monkeypatch.setattr(
        tools,
        "resolve_command",
        functools.partial(resolve_command, trusted_dirs=(trusted_ip.parent,)),
    )
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
    assert captured["args"][0] == str(trusted_ip)
    assert captured["args"][1:] == ["route"]
