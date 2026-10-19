# Project: ErisLITE
# Module: test_coverage_ui.py
# Version: 1.6.0
# License: MIT
# Description: Threat Sweep coverage display regression tests.

from rich.console import Console

from erislite.sweep import threat_sweep


def result(status, tags=None):
    return {
        "status": status,
        "details": [],
        "tags": tags if tags is not None else [],
    }


def test_coverage_all_complete():
    coverage = threat_sweep.summarize_inspection_coverage(
        {
            "listeners": result("ok"),
            "firewall": result("warning"),
            "users": result("ok"),
        }
    )

    assert coverage["complete"] == 3
    assert coverage["failed"] == 0
    assert coverage["total"] == 3


def test_coverage_with_failed_listener():
    coverage = threat_sweep.summarize_inspection_coverage(
        {
            "listeners": result("error", ["listener_check_failed"]),
            "firewall": result("ok"),
        }
    )

    assert coverage["complete"] == 1
    assert coverage["failed"] == 1
    assert coverage["failed_modules"] == ["listeners"]


def test_unsupported_is_counted_separately():
    coverage = threat_sweep.summarize_inspection_coverage(
        {
            "listeners": result("unsupported"),
            "firewall": result("ok"),
        }
    )

    assert coverage["complete"] == 1
    assert coverage["unsupported"] == 1
    assert coverage["total"] == 2


def test_non_scoring_module_not_counted():
    coverage = threat_sweep.summarize_inspection_coverage(
        {
            "listeners": result("ok"),
            "cve": result("review"),
        }
    )

    assert coverage["total"] == 1
    assert coverage["complete"] == 1


def test_incomplete_assessment_overrides_secure_label():
    color, label = threat_sweep.assessment_label(
        0,
        False,
        {"complete": 1, "failed": 1},
    )

    assert color == "yellow"
    assert label == "Incomplete Assessment"


def test_incomplete_assessment_with_detected_risk():
    _, label = threat_sweep.assessment_label(
        75,
        False,
        {"complete": 2, "failed": 1},
    )

    assert label == "Incomplete Assessment"


def test_no_assessments_not_labeled_secure():
    _, label = threat_sweep.assessment_label(
        0,
        False,
        {"complete": 0, "failed": 0},
    )

    assert label == "Not Assessed"


def test_clean_assessment_retains_secure_label():
    _, label = threat_sweep.assessment_label(
        0,
        False,
        {"complete": 3, "failed": 0},
    )

    assert label == "Secure"


def test_existing_risk_labels_retained():
    coverage = {"complete": 3, "failed": 0}

    assert threat_sweep.assessment_label(20, False, coverage)[1] == "Low"

    assert threat_sweep.assessment_label(50, False, coverage)[1] == "Moderate"

    assert threat_sweep.assessment_label(85, False, coverage)[1] == "High"


def test_tui_displays_failed_coverage(monkeypatch):
    output = Console(
        record=True,
        force_terminal=False,
        color_system=None,
        width=130,
    )

    monkeypatch.setattr(threat_sweep, "console", output)
    monkeypatch.setattr(
        threat_sweep,
        "pause_return",
        lambda: None,
    )

    results = {
        "listeners": result("error", ["listener_check_failed"]),
        "firewall": result("ok"),
    }

    changes = {
        "new": [],
        "changed": [],
        "persisting": [],
        "resolved": [],
    }

    threat_sweep._display_results(
        results,
        "standard",
        {"hostname": "test-host"},
        changes,
        comparison_available=False,
    )

    text = output.export_text()

    assert "Incomplete Assessment" in text
    assert "INCOMPLETE COVERAGE" in text
    assert "listeners" in text
    assert "1/2" in text
