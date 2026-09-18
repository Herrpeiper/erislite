# Project: ErisLITE
# Module: test_shell_console.py
# Author: Liam Piper-Brandon
# Version: 1.3.0
# License: MIT
# Created: 2026-09-18
# Last Updated: 2026-09-18
# Description: Tests for interactive shell resolution and launching.

from unittest.mock import Mock

from erislite.ui import shell_console


def test_resolve_uses_trusted_bash(monkeypatch):
    monkeypatch.setattr(
        shell_console,
        "resolve_command",
        lambda command: "/bin/bash" if command == "bash" else "/bin/sh",
    )

    assert shell_console.resolve_user_shell() == "/bin/bash"


def test_resolve_falls_back_to_trusted_sh(monkeypatch):
    def fake_resolve(command):
        if command == "bash":
            raise shell_console.CommandResolutionError("missing")
        if command == "sh":
            return "/bin/sh"
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(
        shell_console,
        "resolve_command",
        fake_resolve,
    )

    assert shell_console.resolve_user_shell() == "/bin/sh"


def test_resolve_returns_none_when_no_trusted_shell_exists(monkeypatch):
    def fake_resolve(command):
        raise shell_console.CommandResolutionError(
            f"{command} unavailable"
        )

    monkeypatch.setattr(
        shell_console,
        "resolve_command",
        fake_resolve,
    )

    assert shell_console.resolve_user_shell() is None

def test_resolve_ignores_environment_shell(monkeypatch):
    monkeypatch.setenv(
        "SHELL",
        "/tmp/evil-shell",
    )

    monkeypatch.setattr(
        shell_console,
        "resolve_command",
        lambda command: "/bin/bash",
    )

    assert shell_console.resolve_user_shell() == "/bin/bash"


def test_launch_shell_uses_hardened_command_and_environment(monkeypatch):
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

    monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
    monkeypatch.setenv("BASH_ENV", "/tmp/evilrc")
    monkeypatch.setenv("PROMPT_COMMAND", "evil")

    profile = {
        "hostname": "test-host",
    }

    shell_console.launch_shell_console(profile)

    run_mock.assert_called_once()

    args, kwargs = run_mock.call_args

    assert args[0] == [
        "/bin/bash",
        "--noprofile",
        "--norc",
    ]

    assert kwargs["check"] is False

    env = kwargs["env"]

    assert env["PATH"] == (
        "/usr/local/sbin:"
        "/usr/local/bin:"
        "/usr/sbin:"
        "/usr/bin:"
        "/sbin:"
        "/bin"
    )

    assert "LD_PRELOAD" not in env
    assert "BASH_ENV" not in env
    assert "PROMPT_COMMAND" not in env


def test_build_shell_command_hardens_bash():
    assert shell_console.build_shell_command("/bin/bash") == [
        "/bin/bash",
        "--noprofile",
        "--norc",
    ]


def test_build_shell_command_plain_sh():
    assert shell_console.build_shell_command("/bin/sh") == [
        "/bin/sh",
    ]


def test_build_shell_environment_removes_unsafe_variables(monkeypatch):
    monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
    monkeypatch.setenv("LD_LIBRARY_PATH", "/tmp/evil")
    monkeypatch.setenv("BASH_ENV", "/tmp/evilrc")
    monkeypatch.setenv("ENV", "/tmp/evilenv")
    monkeypatch.setenv("PROMPT_COMMAND", "evil-command")
    monkeypatch.setenv("PYTHONPATH", "/tmp/python")

    env = shell_console.build_shell_environment()

    assert "LD_PRELOAD" not in env
    assert "LD_LIBRARY_PATH" not in env
    assert "BASH_ENV" not in env
    assert "ENV" not in env
    assert "PROMPT_COMMAND" not in env
    assert "PYTHONPATH" not in env

    assert env["PATH"] == (
        "/usr/local/sbin:"
        "/usr/local/bin:"
        "/usr/sbin:"
        "/usr/bin:"
        "/sbin:"
        "/bin"
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