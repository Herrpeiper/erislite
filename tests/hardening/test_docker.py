from types import SimpleNamespace

from erislite.containers import docker


def test_docker_ps_uses_shared_command_runner(monkeypatch):
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs

        return SimpleNamespace(
            stdout="abc123\n",
            stderr="",
            returncode=0,
        )

    monkeypatch.setattr(
        docker,
        "run_command",
        fake_run,
    )

    containers, error = docker.get_running_containers()

    assert error is None
    assert containers == ["abc123"]
    assert captured["command"] == ["docker", "ps", "-q"]
    assert captured["kwargs"]["timeout"] == 10