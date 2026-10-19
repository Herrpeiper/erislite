# Project: ErisLITE
# Module: test_coverage_scoring.py
# Version: 1.6.0
# License: MIT
# Description: Coverage-aware Threat Sweep scoring tests.

from erislite.sweep.threat_sweep import (
    calculate_risk_score,
    inspection_coverage,
)


def result(status, tags=None):
    return {
        "status": status,
        "details": [],
        "tags": tags if tags is not None else [],
    }


def test_failed_listener_inspection_is_excluded():
    results = {
        "listeners": result("error", ["listener_check_failed"]),
        "firewall": result("ok"),
    }

    score, breakdown, maximum = calculate_risk_score(results)

    assert score == 0
    assert breakdown["listeners"] == 0
    assert maximum == 15


def test_listener_warning_retains_existing_score():
    results = {
        "listeners": result("warning", ["suspicious_listener"]),
    }

    score, breakdown, maximum = calculate_risk_score(results)

    assert score == 15
    assert breakdown["listeners"] == 15
    assert maximum == 15


def test_clean_listener_stays_in_denominator():
    score, breakdown, maximum = calculate_risk_score(
        {
            "listeners": result("ok"),
        }
    )

    assert score == 0
    assert breakdown["listeners"] == 0
    assert maximum == 15


def test_unsupported_listener_is_excluded():
    score, breakdown, maximum = calculate_risk_score(
        {
            "listeners": result("unsupported"),
        }
    )

    assert score == 0
    assert breakdown["listeners"] == 0
    assert maximum == 0


def test_other_module_error_behavior_is_preserved():
    score, breakdown, maximum = calculate_risk_score(
        {
            "firewall": result("error", ["firewall_check_failed"]),
        }
    )

    assert score == 15
    assert breakdown["firewall"] == 15
    assert maximum == 15


def test_listener_unclassified_error_unchanged():
    score, breakdown, maximum = calculate_risk_score(
        {
            "listeners": result("error", ["other_error"]),
        }
    )

    assert score == 15
    assert breakdown["listeners"] == 15
    assert maximum == 15


def test_coverage_states():
    assert (
        inspection_coverage(
            "listeners",
            result("error", ["listener_check_failed"]),
        )
        == "failed"
    )

    assert (
        inspection_coverage(
            "listeners",
            result("ok"),
        )
        == "complete"
    )

    assert (
        inspection_coverage(
            "listeners",
            result("unsupported"),
        )
        == "unsupported"
    )


def test_failure_tag_without_error_does_not_exclude():
    score, _, maximum = calculate_risk_score(
        {
            "listeners": result("warning", ["listener_check_failed"]),
        }
    )

    assert score == 15
    assert maximum == 15


def test_failure_tag_is_module_specific():
    assert (
        inspection_coverage(
            "firewall",
            result("error", ["listener_check_failed"]),
        )
        == "complete"
    )


def test_mixed_results_preserve_detected_risk():
    results = {
        "listeners": result("error", ["listener_check_failed"]),
        "firewall": result("warning", ["firewall_disabled"]),
        "users": result("ok"),
    }

    score, breakdown, maximum = calculate_risk_score(results)

    assert score == 15
    assert breakdown["listeners"] == 0
    assert breakdown["firewall"] == 15
    assert breakdown["users"] == 0
    assert maximum == 30


def test_all_failed_or_unsupported_has_zero_maximum():
    results = {
        "listeners": result("error", ["listener_check_failed"]),
        "firewall": result("unsupported"),
    }

    score, _, maximum = calculate_risk_score(results)

    assert score == 0
    assert maximum == 0
    assert inspection_coverage("listeners", results["listeners"]) == "failed"
