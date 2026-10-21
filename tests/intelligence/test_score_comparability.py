# Project: ErisLITE
# Module: test_score_comparability.py
# Version: 1.6.0
# License: MIT
# Description: Historical risk score comparability tests.

from erislite.results import make_result
from erislite.sweep import threat_sweep as sweep


def snapshot(results):
    score, _, maximum = sweep.calculate_risk_score(results)

    coverage = sweep.summarize_inspection_coverage(results)

    scored_modules = sorted(
        module
        for module, result in results.items()
        if module in sweep.RISK_WEIGHTS
        and sweep.inspection_coverage(module, result) not in {"failed", "unsupported"}
        and (
            sweep.inspection_coverage(module, result) == "complete"
            or sweep.contributes_detected_risk(module, result)
        )
    )

    return {
        "scoring_schema_version": sweep.SCORING_SCHEMA_VERSION,
        "scored_modules": scored_modules,
        "coverage": coverage,
        "risk_score": score,
        "risk_max": maximum,
        "risk_percent": round(score / maximum * 100) if maximum else 0,
        "results": results,
    }


def test_comparable_scores_report_delta():
    previous = snapshot(
        {
            "listeners": make_result("ok"),
            "firewall": make_result("ok"),
        }
    )

    current = snapshot(
        {
            "listeners": make_result("warning", tags=["suspicious_listener"]),
            "firewall": make_result("ok"),
        }
    )

    comparison = sweep.compare_historical_scores(current, previous)

    assert comparison["comparable"] is True
    assert comparison["previous_percent"] == 0
    assert comparison["current_percent"] == 50
    assert comparison["delta"] == 50


def test_different_scoring_modules_not_comparable():
    previous = snapshot(
        {
            "listeners": make_result("ok"),
            "firewall": make_result("ok"),
        }
    )

    current = snapshot(
        {
            "listeners": make_result("ok"),
            "firewall": make_result("warning", tags=["firewall_permission_denied"]),
        }
    )

    comparison = sweep.compare_historical_scores(current, previous)

    assert comparison["comparable"] is False
    assert "modules" in comparison["reason"].lower()


def test_changed_coverage_not_comparable():
    previous = snapshot(
        {
            "integrity": make_result("ok"),
        }
    )

    current = snapshot(
        {
            "integrity": make_result(
                "warning",
                tags=[
                    "integrity_scan_incomplete",
                    "file_integrity_issue",
                ],
            ),
        }
    )

    comparison = sweep.compare_historical_scores(current, previous)

    assert comparison["comparable"] is False
    assert "coverage" in comparison["reason"].lower()


def test_legacy_snapshot_not_comparable():
    current = snapshot(
        {
            "listeners": make_result("ok"),
        }
    )

    previous = {
        "risk_score": 0,
        "risk_max": 15,
        "risk_percent": 0,
        "results": {"listeners": make_result("ok")},
    }

    comparison = sweep.compare_historical_scores(current, previous)

    assert comparison["comparable"] is False
    assert "metadata" in comparison["reason"].lower()


def test_different_scoring_version_not_comparable():
    previous = snapshot(
        {
            "listeners": make_result("ok"),
        }
    )
    previous["scoring_schema_version"] = 999

    current = snapshot(
        {
            "listeners": make_result("ok"),
        }
    )

    comparison = sweep.compare_historical_scores(current, previous)

    assert comparison["comparable"] is False
    assert "methodology" in comparison["reason"].lower()


def test_inconsistent_saved_score_is_rejected():
    previous = snapshot(
        {
            "listeners": make_result("ok"),
        }
    )
    previous["risk_score"] = 15

    current = snapshot(
        {
            "listeners": make_result("ok"),
        }
    )

    comparison = sweep.compare_historical_scores(current, previous)

    assert comparison["comparable"] is False
    assert "inconsistent" in comparison["reason"].lower()


def test_inconsistent_coverage_counts_are_rejected():
    previous = snapshot(
        {
            "listeners": make_result("ok"),
        }
    )
    current = snapshot(
        {
            "listeners": make_result("ok"),
        }
    )

    previous["coverage"]["complete"] = 99

    comparison = sweep.compare_historical_scores(current, previous)

    assert comparison["comparable"] is False
    assert "coverage metadata is inconsistent" in comparison["reason"]


def test_inconsistent_coverage_module_lists_are_rejected():
    previous = snapshot(
        {
            "integrity": make_result(
                "error",
                tags=["integrity_scan_incomplete"],
            ),
            "listeners": make_result("ok"),
        }
    )
    current = snapshot(
        {
            "integrity": make_result(
                "error",
                tags=["integrity_scan_incomplete"],
            ),
            "listeners": make_result("ok"),
        }
    )

    previous["coverage"]["partial_modules"] = []

    comparison = sweep.compare_historical_scores(current, previous)

    assert comparison["comparable"] is False
    assert "coverage metadata is inconsistent" in comparison["reason"]
