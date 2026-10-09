import subprocess

import pytest

from erislite.security import command_runner


def test_run_command_resolves_executable(monkeypatch):
    monkeypatch.setattr(
        command_runner,
        "resolve_command",
        lambda command: f"/resolved/{command}",
    )

    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs

        return subprocess.CompletedProcess(
            command,
            0,
            stdout="ok\n",
            stderr="",
        )

    monkeypatch.setattr(
        command_runner.subprocess,
        "run",
        fake_run,
    )

    result = command_runner.run_command(
        ["example", "--test"],
        timeout=5,
    )

    assert captured["command"] == [
        "/resolved/example",
        "--test",
    ]
    assert captured["kwargs"]["capture_output"] is True
    assert captured["kwargs"]["text"] is True
    assert captured["kwargs"]["timeout"] == 5
    assert captured["kwargs"]["check"] is False
    assert result.stdout == "ok\n"


def test_run_command_uses_default_timeout(monkeypatch):
    monkeypatch.setattr(
        command_runner,
        "resolve_command",
        lambda command: command,
    )

    captured = {}

    def fake_run(command, **kwargs):
        captured["timeout"] = kwargs["timeout"]

        return subprocess.CompletedProcess(
            command,
            0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        command_runner.subprocess,
        "run",
        fake_run,
    )

    command_runner.run_command(["example"])

    assert (
        captured["timeout"]
        == command_runner.DEFAULT_COMMAND_TIMEOUT
    )


def test_run_command_forwards_check(monkeypatch):
    monkeypatch.setattr(
        command_runner,
        "resolve_command",
        lambda command: command,
    )

    captured = {}

    def fake_run(command, **kwargs):
        captured["check"] = kwargs["check"]

        return subprocess.CompletedProcess(
            command,
            0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        command_runner.subprocess,
        "run",
        fake_run,
    )

    command_runner.run_command(
        ["example"],
        check=True,
    )

    assert captured["check"] is True


def test_run_command_rejects_empty_command():
    with pytest.raises(
        ValueError,
        match="Command cannot be empty",
    ):
        command_runner.run_command([])