# Project: ErisLITE
# Module: test_historical_score_ui.py
# Version: 1.6.0
# License: MIT
# Description: Historical score comparison UI tests.

from rich.console import Console

from erislite.results import make_result
from erislite.sweep import threat_sweep as sweep


def render(monkeypatch, score_comparison):
    console = Console(
        record=True,
        force_terminal=False,
        color_system=None,
        width=160,
    )

    monkeypatch.setattr(sweep, "console", console)
    monkeypatch.setattr(sweep, "pause_return", lambda: None)

    sweep._display_results(
        {"listeners": make_result("ok")},
        "standard",
        {"hostname": "test-host"},
        {
            "new": [],
            "changed": [],
            "persisting": [],
            "resolved": [],
        },
        score_comparison=score_comparison,
    )

    return console.export_text()


def test_comparable_risk_change_is_visible(monkeypatch):
    rendered = render(
        monkeypatch,
        {
            "comparable": True,
            "reason": None,
            "previous_percent": 0,
            "current_percent": 50,
            "delta": 50,
        },
    )

    assert "HISTORICAL RISK COMPARISON" in rendered
    assert "Previous: 0%" in rendered
    assert "Current: 50%" in rendered
    assert "+50 percentage points" in rendered


def test_noncomparable_scores_explain_why(monkeypatch):
    rendered = render(
        monkeypatch,
        {
            "comparable": False,
            "reason": "Inspection coverage changed between sweeps",
            "previous_percent": None,
            "current_percent": None,
            "delta": None,
        },
    )

    assert "SCORE COMPARISON UNAVAILABLE" in rendered
    assert "Inspection coverage changed" in rendered


def test_legacy_snapshot_reason_is_visible(monkeypatch):
    rendered = render(
        monkeypatch,
        {
            "comparable": False,
            "reason": "Historical coverage metadata unavailable",
            "previous_percent": None,
            "current_percent": None,
            "delta": None,
        },
    )

    assert "Historical coverage metadata unavailable" in rendered


def test_no_previous_snapshot_omits_comparison(monkeypatch):
    rendered = render(monkeypatch, None)

    assert "HISTORICAL RISK COMPARISON" not in rendered
    assert "SCORE COMPARISON UNAVAILABLE" not in rendered


def test_metadata_builder_matches_scoring_engine():
    results = {
        "integrity": make_result("error", tags=["baseline_missing"]),
        "listeners": make_result("warning", tags=["suspicious_listener"]),
        "firewall": make_result("warning", tags=["firewall_permission_denied"]),
    }

    metadata = sweep.build_score_metadata(results)

    assert metadata["risk_score"] == 15
    assert metadata["risk_max"] == 15
    assert metadata["scored_modules"] == ["listeners"]
    assert metadata["coverage"]["partial"] == 1
    assert metadata["coverage"]["failed"] == 1


def test_run_sweep_passes_score_comparison(monkeypatch):
    captured = {}

    monkeypatch.setattr(
        sweep,
        "SWEEP_PROFILES",
        {"standard": ["users"]},
    )
    monkeypatch.setattr(
        sweep,
        "run_module_check",
        lambda module, check: make_result("ok"),
    )
    monkeypatch.setattr(sweep, "clear_screen", lambda: None)
    monkeypatch.setattr(sweep, "_render_header", lambda *args: None)
    monkeypatch.setattr(sweep, "_save_sweep", lambda *args: None)

    previous = {
        **sweep.build_score_metadata(
            {
                "users": make_result("ok"),
                "firewall": make_result("ok"),
            }
        ),
        "hostname": "test-host",
        "profile": "standard",
    }

    monkeypatch.setattr(
        sweep,
        "_load_previous_comparable_sweep",
        lambda *args: previous,
    )

    def capture_display(*args, **kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(sweep, "_display_results", capture_display)

    sweep.run_sweep(
        {"hostname": "test-host"},
        sweep_profile="standard",
    )

    comparison = captured["score_comparison"]

    assert comparison is not None
    assert comparison["comparable"] is True
    assert comparison["delta"] == 0
