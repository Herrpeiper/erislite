# Project: ErisLITE
# Module: test_sweep_intelligence.py
# Version: 1.6.0
# License: MIT
# Description: Threat Sweep intelligence integration tests.

from rich.console import Console

from erislite.network import listeners
from erislite.sweep import threat_sweep


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
        ]
    )


def test_sweep_listener_collection_runs_once(monkeypatch):
    calls = []

    def collect():
        calls.append("collect")
        return suspicious_collection()

    monkeypatch.setattr(listeners, "get_os", lambda: "Linux")
    monkeypatch.setattr(listeners, "collect_listeners", collect)

    result, findings, error = threat_sweep.run_listener_intelligence_check("test-host")

    assert calls == ["collect"]
    assert result["status"] == "warning"
    assert len(findings) == 1
    assert error is None


def test_collection_failure_has_no_findings(monkeypatch):
    monkeypatch.setattr(listeners, "get_os", lambda: "Linux")
    monkeypatch.setattr(
        listeners,
        "collect_listeners",
        lambda: listeners.ListenerCollection(
            observations=[],
            error="inspection failed",
        ),
    )

    result, findings, error = threat_sweep.run_listener_intelligence_check("test-host")

    assert result["status"] == "error"
    assert "listener_check_failed" in result["tags"]
    assert findings == []
    assert error is None


def test_adapter_failure_preserves_warning(monkeypatch):
    monkeypatch.setattr(listeners, "get_os", lambda: "Linux")
    monkeypatch.setattr(
        listeners,
        "collect_listeners",
        suspicious_collection,
    )

    def failed_adapter(*args, **kwargs):
        raise ValueError("Conversion failed")

    monkeypatch.setattr(
        threat_sweep,
        "adapt_listeners",
        failed_adapter,
    )

    result, findings, error = threat_sweep.run_listener_intelligence_check("test-host")

    assert result["status"] == "warning"
    assert result["tags"] == ["suspicious_listener"]
    assert findings == []
    assert error == "Listener intelligence conversion failed"


def test_unsupported_platform_skips_collection(monkeypatch):
    monkeypatch.setattr(listeners, "get_os", lambda: "Windows")

    def fail_if_called():
        raise AssertionError("Collection must not run")

    monkeypatch.setattr(
        listeners,
        "collect_listeners",
        fail_if_called,
    )

    result, findings, error = threat_sweep.run_listener_intelligence_check("test-host")

    assert result["status"] == "unsupported"
    assert findings == []
    assert error is None


def test_intelligence_panel_displays_findings(monkeypatch):
    output = Console(
        record=True,
        force_terminal=False,
        color_system=None,
        width=160,
    )

    monkeypatch.setattr(threat_sweep, "console", output)

    _, findings, _ = (
        None,
        threat_sweep.adapt_listeners(
            suspicious_collection().observations,
            hostname="test-host",
        ),
        None,
    )

    threat_sweep._display_intelligence_findings(findings)

    rendered = output.export_text()

    assert "Intelligence Findings" in rendered
    assert "HIGH" in rendered
    assert "MEDIUM" in rendered
    assert "0.0.0.0:2222" in rendered
    assert "socat" in rendered


def test_intelligence_failure_visible(monkeypatch):
    output = Console(
        record=True,
        force_terminal=False,
        color_system=None,
        width=120,
    )

    monkeypatch.setattr(threat_sweep, "console", output)

    threat_sweep._display_intelligence_findings(
        [],
        ["Listener intelligence conversion failed"],
    )

    rendered = output.export_text()

    assert "INTELLIGENCE INCOMPLETE" in rendered
    assert "Listener intelligence conversion failed" in rendered


def test_normal_sweep_receives_intelligence(monkeypatch):
    captured = {}
    calls = []

    monkeypatch.setattr(
        threat_sweep,
        "SWEEP_PROFILES",
        {"standard": ["listeners"]},
    )

    def fake_listener_check(hostname):
        calls.append(hostname)
        return (
            {
                "status": "warning",
                "details": ["Suspicious listener"],
                "tags": ["suspicious_listener"],
            },
            ["sentinel-finding"],
            None,
        )

    monkeypatch.setattr(
        threat_sweep,
        "run_listener_intelligence_check",
        fake_listener_check,
    )
    monkeypatch.setattr(threat_sweep, "clear_screen", lambda: None)
    monkeypatch.setattr(threat_sweep, "_render_header", lambda *a: None)
    monkeypatch.setattr(
        threat_sweep,
        "_load_previous_comparable_sweep",
        lambda *a: None,
    )

    def capture_display(results, *args, **kwargs):
        captured["results"] = results
        captured["findings"] = kwargs["intelligence_findings"]

    monkeypatch.setattr(
        threat_sweep,
        "_display_results",
        capture_display,
    )
    monkeypatch.setattr(
        threat_sweep,
        "_save_sweep",
        lambda *a: None,
    )
    monkeypatch.setattr(
        threat_sweep.firewall,
        "run_firewall_check",
        lambda silent: {
            "status": "ok",
            "details": [],
            "tags": [],
        },
    )

    threat_sweep.run_sweep(
        {"hostname": "test-host"},
        "standard",
    )

    assert calls == ["test-host"]
    assert captured["results"]["listeners"]["status"] == "warning"
    assert captured["findings"] == ["sentinel-finding"]
