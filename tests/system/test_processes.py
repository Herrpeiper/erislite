from types import SimpleNamespace

import psutil

from erislite.system import processes


class FakeProcess:
    def __init__(
        self,
        *,
        pid=123,
        name="safeproc",
        uid=1000,
        exe="/usr/bin/safeproc",
        cmdline=None,
        ppid=1,
    ):
        self.info = {
            "pid": pid,
            "name": name,
            "uids": SimpleNamespace(real=uid),
            "cmdline": cmdline or [name],
            "ppid": ppid,
        }
        self._exe = exe
        self._cmdline = cmdline or [name]

    def exe(self):
        return self._exe

    def cmdline(self):
        return self._cmdline

    def name(self):
        return self.info["name"]


def test_process_scan_clean(monkeypatch):
    fake = FakeProcess()

    monkeypatch.setattr(
        processes.psutil,
        "process_iter",
        lambda attrs: [fake],
    )
    monkeypatch.setattr(
        processes,
        "get_os",
        lambda: "Linux",
    )
    monkeypatch.setattr(
        processes.os.path,
        "exists",
        lambda path: True,
    )

    result = processes.run_process_scan(silent=True)

    assert result["status"] == "ok"
    assert result["details"] == []
    assert result["tags"] == []


def test_process_scan_enumeration_failure(monkeypatch):
    def fail_process_iter(attrs):
        raise OSError("process table unavailable")

    monkeypatch.setattr(
        processes.psutil,
        "process_iter",
        fail_process_iter,
    )
    monkeypatch.setattr(
        processes,
        "get_os",
        lambda: "Linux",
    )

    result = processes.run_process_scan(silent=True)

    assert result["status"] == "error"
    assert "process_scan_incomplete" in result["tags"]
    assert any(
        "process table unavailable" in detail
        for detail in result["details"]
    )


def test_process_scan_detects_suspicious_process(monkeypatch):
    fake = FakeProcess(
        name="linpeas",
        exe="/tmp/linpeas",
        cmdline=["/tmp/linpeas"],
    )

    monkeypatch.setattr(
        processes.psutil,
        "process_iter",
        lambda attrs: [fake],
    )
    monkeypatch.setattr(
        processes,
        "get_os",
        lambda: "Linux",
    )

    result = processes.run_process_scan(silent=True)

    assert result["status"] == "warning"
    assert "proc_known_bad" in result["tags"]


def test_process_scan_finding_with_collection_error(monkeypatch):
    fake = FakeProcess(
        name="linpeas",
        exe="/tmp/linpeas",
        cmdline=["/tmp/linpeas"],
    )

    monkeypatch.setattr(
        processes.psutil,
        "process_iter",
        lambda attrs: [fake],
    )
    monkeypatch.setattr(
        processes,
        "get_os",
        lambda: "Linux",
    )
    monkeypatch.setattr(
        processes,
        "_is_kernel_thread",
        lambda proc: (
            False,
            "inspection failed",
        ),
    )

    result = processes.run_process_scan(silent=True)

    assert result["status"] == "warning"
    assert "proc_known_bad" in result["tags"]
    assert "process_scan_incomplete" in result["tags"]


def test_is_deleted_ignores_no_such_process():
    class VanishedProcess:
        def exe(self):
            raise psutil.NoSuchProcess(pid=123)

    deleted, error = processes._is_deleted(
        VanishedProcess()
    )

    assert deleted is False
    assert error is None


def test_is_kernel_thread_ignores_no_such_process():
    class VanishedProcess:
        def cmdline(self):
            raise psutil.NoSuchProcess(pid=123)

        def exe(self):
            raise psutil.NoSuchProcess(pid=123)

    is_kernel, error = processes._is_kernel_thread(
        VanishedProcess()
    )

    assert is_kernel is False
    assert error is None
