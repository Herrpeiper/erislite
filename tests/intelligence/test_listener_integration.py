# Project: ErisLITE
# Module: test_listener_integration.py
# Version: 1.6.0
# License: MIT
# Description: Operational listener intelligence tests.

from erislite.network import listeners


def suspicious_collection():
    return listeners.ListenerCollection(
        observations=[
            (
                "tcp",
                "0.0.0.0:2222",
                "socat",
                [
                    "External Bind",
                    "High Port",
                    "Potential LOLBin Listener",
                ],
                False,
            )
        ],
        error=None,
    )


def test_combined_scan_collects_once(monkeypatch):
    calls = []

    def collect():
        calls.append("collect")
        return suspicious_collection()

    monkeypatch.setattr(listeners, "get_os", lambda: "Linux")
    monkeypatch.setattr(listeners, "collect_listeners", collect)

    result, findings = listeners.run_listener_intelligence("test-host")

    assert calls == ["collect"]
    assert result["status"] == "warning"
    assert len(findings) == 1


def test_combined_scan_preserves_legacy_contract(monkeypatch):
    monkeypatch.setattr(listeners, "get_os", lambda: "Linux")
    monkeypatch.setattr(
        listeners,
        "collect_listeners",
        suspicious_collection,
    )

    result, findings = listeners.run_listener_intelligence("test-host")

    assert set(result) == {"status", "details", "tags"}
    assert "suspicious_listener" in result["tags"]
    assert findings[0].module == "listeners"


def test_failed_collection_returns_no_findings(monkeypatch):
    monkeypatch.setattr(listeners, "get_os", lambda: "Linux")
    monkeypatch.setattr(
        listeners,
        "collect_listeners",
        lambda: listeners.ListenerCollection(
            observations=[],
            error="inspection failed",
        ),
    )

    result, findings = listeners.run_listener_intelligence("test-host")

    assert result["status"] == "error"
    assert "listener_check_failed" in result["tags"]
    assert findings == []


def test_empty_collection_returns_ok(monkeypatch):
    monkeypatch.setattr(listeners, "get_os", lambda: "Linux")
    monkeypatch.setattr(
        listeners,
        "collect_listeners",
        lambda: listeners.ListenerCollection(
            observations=[],
        ),
    )

    result, findings = listeners.run_listener_intelligence("test-host")

    assert result["status"] == "ok"
    assert findings == []


def test_unsupported_platform_skips_collection(monkeypatch):
    monkeypatch.setattr(listeners, "get_os", lambda: "Windows")

    def unexpected_collection():
        raise AssertionError("Collector should not run")

    monkeypatch.setattr(
        listeners,
        "collect_listeners",
        unexpected_collection,
    )

    result, findings = listeners.run_listener_intelligence("test-host")

    assert result["status"] == "unsupported"
    assert findings == []


def test_existing_scan_uses_supplied_collection(monkeypatch):
    monkeypatch.setattr(listeners, "get_os", lambda: "Linux")

    def unexpected_collection():
        raise AssertionError("Collector ran twice")

    monkeypatch.setattr(
        listeners,
        "collect_listeners",
        unexpected_collection,
    )

    result = listeners.run_listener_scan(
        silent=True,
        collection=suspicious_collection(),
    )

    assert result["status"] == "warning"


def test_adapter_failure_is_reported(monkeypatch):
    monkeypatch.setattr(listeners, "get_os", lambda: "Linux")
    monkeypatch.setattr(
        listeners,
        "collect_listeners",
        suspicious_collection,
    )

    result, findings = listeners.run_listener_intelligence("")

    assert result["status"] == "error"
    assert result["tags"] == ["listener_intelligence_failed"]
    assert findings == []
