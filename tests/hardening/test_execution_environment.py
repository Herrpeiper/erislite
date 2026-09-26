"""Security tests for ErisLITE's execution environment."""

import os
import shutil


def test_path_does_not_prefer_current_directory(monkeypatch, tmp_path):
    """
    Demonstrate why attacker-controlled PATH entries are dangerous.

    This does not execute the fake binary. It verifies that Python's command
    resolution would select an attacker-controlled executable if that
    directory appears first in PATH.
    """
    fake_ip = tmp_path / "ip"
    fake_ip.write_text("#!/bin/sh\nexit 0\n")
    fake_ip.chmod(0o755)

    original_path = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{original_path}")

    resolved = shutil.which("ip")

    assert resolved == str(fake_ip)