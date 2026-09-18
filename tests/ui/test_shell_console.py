# Project: ErisLITE
# Module: test_shell_console.py
# Author: Liam Piper-Brandon
# Version: 1.3.0
# License: MIT
# Created: 2026-09-18
# Last Updated: 2026-09-18
# Description: Tests for interactive shell resolution and launching.

from types import SimpleNamespace
from unittest.mock import Mock

from erislite.ui import shell_console


def make_executable_shell(tmp_path, name="test-shell"):
    shell_path = tmp_path / name
    shell_path.write_text("#!/bin/sh\n", encoding="utf-8")
    shell_path.chmod(0o755)
    return shell_path


def test_resolve_prefers_environment_shell(monkeypatch, tmp_path):
    shell_path = make_executable_shell(tmp_path)

    monkeypatch.setenv(
        "SHELL",
        str(shell_path),
    )
    monkeypatch.setattr(
        shell_console.pwd,
        "getpwuid",
        lambda uid: SimpleNamespace(pw_shell="/bin/sh"),
    )

    assert shell_console.resolve_user_shell() == str(shell_path)


def test_resolve_uses_account_shell(monkeypatch, tmp_path):
    shell_path = make_executable_shell(tmp_path)

    monkeypatch.delenv(
        "SHELL",
        raising=False,
    )
    monkeypatch.setattr(
        shell_console.pwd,
        "getpwuid",
        lambda uid: SimpleNamespace(pw_shell=str(shell_path)),
    )

    assert shell_console.resolve_user_shell() == str(shell_path)


def test_resolve_returns_none_when_no_shell_exists(monkeypatch):
    monkeypatch.delenv(
        "SHELL",
        raising=False,
    )

    def missing_account(uid):
        raise KeyError(uid)

    monkeypatch.setattr(
        shell_console.pwd,
        "getpwuid",
        missing_account,
    )
    monkeypatch.setattr(
        shell_console.shutil,
        "which",
        lambda command: None,
    )

    assert shell_console.resolve_user_shell() is None


def test_launch_shell_uses_argument_list(monkeypatch):
    run_mock = Mock()

    monkeypatch.setattr(
        shell_console,
        "clear_screen",
        Mock(),
    )
    monkeypatch.setattr(
        shell_console,
        "resolve_user_shell",
        lambda: "/bin/bash",
    )
    monkeypatch.setattr(
        shell_console,
        "show_shell_header",
        Mock(),
    )
    monkeypatch.setattr(
        shell_console.subprocess,
        "run",
        run_mock,
    )

    profile = {
        "hostname": "test-host",
    }

    shell_console.launch_shell_console(profile)

    run_mock.assert_called_once_with(
        ["/bin/bash"],
        check=False,
    )


def test_privilege_label_for_root(monkeypatch):
    monkeypatch.setattr(
        shell_console.os,
        "geteuid",
        lambda: 0,
    )

    assert shell_console.get_privilege_label() == "[bold red]ROOT ACCESS[/]"


def test_privilege_label_for_user(monkeypatch):
    monkeypatch.setattr(
        shell_console.os,
        "geteuid",
        lambda: 1000,
    )

    assert shell_console.get_privilege_label() == "[green]User Session[/]"