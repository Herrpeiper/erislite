# Project: ErisLITE
# Module: test_partial_coverage.py
# Version: 1.6.0
# License: MIT
# Description: Partial inspection coverage and risk-scoring tests.

import pytest

from erislite.results import make_result
from erislite.sweep import threat_sweep as sweep


@pytest.mark.parametrize(
    ("module", "tag", "expected"),
    [
        ("integrity", "baseline_missing", "failed"),
        ("integrity", "baseline_check_error", "failed"),
        ("integrity", "baseline_tamper", "failed"),
        ("integrity", "integrity_scan_incomplete", "partial"),
        ("firewall", "firewall_permission_denied", "partial"),
        ("firewall", "firewall_check_failed", "failed"),
        ("listeners", "listener_check_failed", "failed"),
    ],
)
def test_coverage_classification(module, tag, expected):
    result = make_result("error", tags=[tag])
    assert sweep.inspection_coverage(module, result) == expected


def test_missing_baseline_does_not_score():
    results = {"integrity": make_result("error", tags=["baseline_missing"])}

    assert sweep.calculate_risk_score(results) == (0, {"integrity": 0}, 0)


def test_firewall_permission_denied_does_not_score():
    results = {"firewall": make_result("warning", tags=["firewall_permission_denied"])}

    assert sweep.calculate_risk_score(results) == (0, {"firewall": 0}, 0)


def test_partial_integrity_without_changes_does_not_score():
    results = {"integrity": make_result("error", tags=["integrity_scan_incomplete"])}

    assert sweep.calculate_risk_score(results) == (0, {"integrity": 0}, 0)


def test_partial_integrity_with_changes_preserves_risk():
    results = {
        "integrity": make_result(
            "warning",
            tags=["integrity_scan_incomplete", "file_integrity_issue"],
        )
    }

    assert sweep.calculate_risk_score(results) == (20, {"integrity": 20}, 20)


def test_confirmed_firewall_warning_still_scores():
    results = {"firewall": make_result("warning", tags=["firewall_ip_empty"])}

    assert sweep.calculate_risk_score(results) == (15, {"firewall": 15}, 15)


def test_codespaces_case():
    results = {
        "integrity": make_result("error", tags=["baseline_missing"]),
        "listeners": make_result("warning", tags=["suspicious_listener"]),
        "users": make_result("ok"),
        "login": make_result("ok"),
        "firewall": make_result("warning", tags=["firewall_permission_denied"]),
    }

    score, breakdown, maximum = sweep.calculate_risk_score(results)
    coverage = sweep.summarize_inspection_coverage(results)

    assert (score, maximum) == (15, 40)
    assert breakdown["integrity"] == 0
    assert breakdown["firewall"] == 0
    assert coverage["complete"] == 3
    assert coverage["partial"] == 1
    assert coverage["failed"] == 1


def test_incomplete_integrity_cannot_resolve_prior_issue():
    previous = {"integrity": make_result("warning", tags=["file_integrity_issue"])}
    current = {"integrity": make_result("error", tags=["integrity_scan_incomplete"])}

    changes = sweep.compare_sweep_results(current, previous)

    assert changes["resolved"] == []
    assert "integrity:file_integrity_issue" in changes["unverified"]


def test_missing_baseline_not_in_risk_priorities():
    results = {
        "integrity": make_result("error", tags=["baseline_missing"]),
        "listeners": make_result("warning", tags=["suspicious_listener"]),
    }

    priorities = sweep.prioritize_findings(results)

    assert [item["module"] for item in priorities] == ["listeners"]
