from types import SimpleNamespace

from erislite.containers import docker


def test_docker_ps_ignores_poisoned_path(monkeypatch, tmp_path):
    fake_docker = tmp_path / "docker"
    fake_docker.write_text("#!/bin/sh\necho hijacked\n")
    fake_docker.chmod(0o755)

    monkeypatch.setenv("PATH", str(tmp_path))

    captured = {}

    def fake_resolve(command):
        assert command == "docker"
        return "/usr/bin/docker"

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(
            stdout="abc123\n",
            stderr="",
            returncode=0,
        )

    monkeypatch.setattr(docker, "resolve_command", fake_resolve)
    monkeypatch.setattr(docker.subprocess, "run", fake_run)

    containers, error = docker.get_running_containers()

    assert error is None
    assert containers == ["abc123"]
    assert captured["command"][0] != str(fake_docker)
    assert captured["command"][0] == "/usr/bin/docker"
    assert captured["command"][1:] == ["ps", "-q"]