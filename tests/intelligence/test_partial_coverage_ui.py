# Project: ErisLITE
# Module: test_partial_coverage_ui.py
# Version: 1.6.0
# License: MIT
# Description: Incomplete coverage UI tests.

from rich.console import Console

from erislite.results import make_result
from erislite.sweep import threat_sweep


def test_partial_coverage_produces_incomplete_label():
    coverage = {
        "complete": 2,
        "partial": 1,
        "failed": 0,
        "unsupported": 0,
    }

    assert threat_sweep.assessment_label(25, False, coverage) == ("yellow", "Incomplete Assessment")


def test_failed_coverage_produces_incomplete_label():
    coverage = {
        "complete": 2,
        "partial": 0,
        "failed": 1,
        "unsupported": 0,
    }

    assert threat_sweep.assessment_label(0, False, coverage) == ("yellow", "Incomplete Assessment")


def test_complete_coverage_preserves_risk_label():
    coverage = {
        "complete": 3,
        "partial": 0,
        "failed": 0,
        "unsupported": 0,
    }

    assert threat_sweep.assessment_label(50, False, coverage) == ("yellow", "Moderate")


def test_incomplete_coverage_visible_in_risk_summary(monkeypatch):
    output = Console(
        record=True,
        force_terminal=False,
        color_system=None,
        width=160,
    )

    monkeypatch.setattr(threat_sweep, "console", output)
    monkeypatch.setattr(threat_sweep, "pause_return", lambda: None)

    results = {
        "integrity": make_result(
            "error",
            details=["Critical baseline file missing"],
            tags=["baseline_missing"],
        ),
        "listeners": make_result(
            "warning",
            details=["Unidentified external listener"],
            tags=["suspicious_listener"],
        ),
        "firewall": make_result(
            "warning",
            details=["Insufficient permissions"],
            tags=["firewall_permission_denied"],
        ),
    }

    threat_sweep._display_results(
        results,
        "standard",
        {"hostname": "test-host"},
        {
            "new": [],
            "changed": [],
            "persisting": [],
            "resolved": [],
        },
    )

    rendered = output.export_text()

    assert "Incomplete Assessment" in rendered
    assert "INCOMPLETE COVERAGE" in rendered
    assert "Partial: firewall" in rendered
    assert "Failed: integrity" in rendered
    assert "Scored Rating:" in rendered


def test_baseline_missing_insight_has_description():
    description = threat_sweep.THREAT_TAG_MAP["baseline_missing"]

    assert "baseline" in description.lower()
    assert "No description." not in description
