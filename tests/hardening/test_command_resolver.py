from pathlib import Path

import pytest

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