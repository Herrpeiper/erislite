import subprocess
from types import SimpleNamespace

from erislite.system import kernel_modules


def test_lsmod_uses_shared_command_runner(monkeypatch):
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs

        return SimpleNamespace(
            stdout="Module Size Used by\n",
            stderr="",
            returncode=0,
        )

    monkeypatch.setattr(
        kernel_modules,
        "run_command",
        fake_run,
    )

    modules, error = kernel_modules.get_loaded_modules()

    assert error is None
    assert modules == []
    assert captured["command"] == ["lsmod"]
    assert captured["kwargs"]["timeout"] == 10


def test_modinfo_uses_shared_command_runner(monkeypatch):
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs

        return SimpleNamespace(
            stdout="/lib/modules/test/kernel/example.ko\n",
            stderr="",
            returncode=0,
        )

    monkeypatch.setattr(
        kernel_modules,
        "run_command",
        fake_run,
    )

    path, error = kernel_modules.get_module_path("example")

    assert error is None
    assert path == "/lib/modules/test/kernel/example.ko"
    assert captured["command"] == ["modinfo", "-n", "example"]
    assert captured["kwargs"]["timeout"] == 5


def test_modinfo_failure_returns_error(monkeypatch):
    monkeypatch.setattr(
        kernel_modules,
        "run_command",
        lambda *a, **k: SimpleNamespace(
            stdout="",
            stderr="modinfo failed",
            returncode=1,
        ),
    )

    path, error = kernel_modules.get_module_path("example")

    assert path is None
    assert error == "modinfo failed"


def test_modinfo_timeout_returns_error(monkeypatch):
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=["modinfo", "-n", "example"],
            timeout=5,
        )

    monkeypatch.setattr(
        kernel_modules,
        "run_command",
        fake_run,
    )

    path, error = kernel_modules.get_module_path("example")

    assert path is None
    assert error == "modinfo timed out for example"