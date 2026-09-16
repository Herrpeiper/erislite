from types import SimpleNamespace

from erislite.system import kernel_modules


def test_lsmod_ignores_poisoned_path(monkeypatch, tmp_path):
    fake_lsmod = tmp_path / "lsmod"
    fake_lsmod.write_text("#!/bin/sh\necho hijacked\n")
    fake_lsmod.chmod(0o755)

    monkeypatch.setenv("PATH", str(tmp_path))

    captured = {}

    def fake_resolve(command):
        assert command == "lsmod"
        return "/usr/bin/lsmod"

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(
            stdout="Module Size Used by\n",
            stderr="",
            returncode=0,
        )

    monkeypatch.setattr(
        kernel_modules,
        "resolve_command",
        fake_resolve,
    )
    monkeypatch.setattr(
        kernel_modules.subprocess,
        "run",
        fake_run,
    )

    modules, error = kernel_modules.get_loaded_modules()

    assert error is None
    assert modules == []
    assert captured["command"][0] != str(fake_lsmod)
    assert captured["command"][0] == "/usr/bin/lsmod"


def test_modinfo_resolves_trusted_path(monkeypatch):
    captured = {}

    def fake_resolve(command):
        assert command == "modinfo"
        return "/usr/sbin/modinfo"

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(
            stdout="/lib/modules/test/kernel/example.ko\n",
            stderr="",
            returncode=0,
        )

    monkeypatch.setattr(
        kernel_modules,
        "resolve_command",
        fake_resolve,
    )
    monkeypatch.setattr(
        kernel_modules.subprocess,
        "run",
        fake_run,
    )

    path, error = kernel_modules.get_module_path("example")

    assert error is None
    assert path == "/lib/modules/test/kernel/example.ko"
    assert captured["command"][0] == "/usr/sbin/modinfo"


def test_modinfo_failure_returns_error(monkeypatch):
    monkeypatch.setattr(
        kernel_modules,
        "resolve_command",
        lambda command: "/usr/sbin/modinfo",
    )

    monkeypatch.setattr(
        kernel_modules.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            stdout="",
            stderr="module not found",
            returncode=1,
        ),
    )

    path, error = kernel_modules.get_module_path("example")

    assert path is None
    assert error == "module not found"


def test_modinfo_timeout_returns_error(monkeypatch):
    monkeypatch.setattr(
        kernel_modules,
        "resolve_command",
        lambda command: "/usr/sbin/modinfo",
    )

    def fake_run(*args, **kwargs):
        raise kernel_modules.subprocess.TimeoutExpired(
            cmd="modinfo",
            timeout=5,
        )

    monkeypatch.setattr(
        kernel_modules.subprocess,
        "run",
        fake_run,
    )

    path, error = kernel_modules.get_module_path("example")

    assert path is None
    assert error == "modinfo timed out for example"