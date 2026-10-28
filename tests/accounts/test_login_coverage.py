"""Regression tests for EL-002: authentication coverage scoring."""

import pytest

from erislite.accounts import login_audit
from erislite.sweep.threat_sweep import (
    calculate_risk_score,
    contributes_detected_risk,
    inspection_coverage,
)


@pytest.mark.parametrize(
    ("tags", "expected_coverage", "expected_risk"),
    [
        ([], "complete", False),
        (["auth_failures"], "complete", True),
        (["uid0_shells"], "complete", True),
        (["auth_audit_incomplete"], "partial", False),
        (
            ["auth_audit_incomplete", "auth_failures"],
            "partial",
            True,
        ),
        (
            ["auth_audit_incomplete", "uid0_shells"],
            "partial",
            True,
        ),
        (["auth_audit_failed"], "failed", False),
    ],
)
def test_authentication_coverage_and_risk(
    tags,
    expected_coverage,
    expected_risk,
):
    result = {
        "status": "warning" if tags else "ok",
        "tags": tags,
        "details": [],
    }

    assert inspection_coverage("login", result) == expected_coverage
    assert contributes_detected_risk("login", result) is expected_risk

    score, breakdown, maximum = calculate_risk_score({"login": result})

    assert score == (10 if expected_risk else 0)
    assert breakdown["login"] == score
    assert maximum == (
        0
        if expected_coverage == "failed"
        else (10 if expected_coverage == "complete" or expected_risk else 0)
    )


def test_partial_authentication_collection_without_anomalies(monkeypatch):
    monkeypatch.setattr(login_audit, "get_os", lambda: "Linux")
    monkeypatch.setattr(
        login_audit,
        "get_failed_logins",
        lambda: ([], "Authentication log unavailable"),
    )
    monkeypatch.setattr(
        login_audit,
        "get_recent_logins",
        lambda: (["user pts/0"], None),
    )
    monkeypatch.setattr(
        login_audit,
        "get_uid0_shells",
        lambda: ([], None),
    )

    result = login_audit.run_login_audit(silent=True)

    assert "auth_audit_incomplete" in result["tags"]
    assert inspection_coverage("login", result) == "partial"
    assert contributes_detected_risk("login", result) is False


def test_partial_authentication_with_confirmed_anomaly(monkeypatch):
    monkeypatch.setattr(login_audit, "get_os", lambda: "Linux")
    monkeypatch.setattr(
        login_audit,
        "get_failed_logins",
        lambda: (["failed attempt"] * 5, None),
    )
    monkeypatch.setattr(
        login_audit,
        "get_recent_logins",
        lambda: ([], "Recent login history unavailable"),
    )
    monkeypatch.setattr(
        login_audit,
        "get_uid0_shells",
        lambda: ([], None),
    )

    result = login_audit.run_login_audit(silent=True)

    assert "auth_failures" in result["tags"]
    assert "auth_audit_incomplete" in result["tags"]
    assert inspection_coverage("login", result) == "partial"
    assert contributes_detected_risk("login", result) is True


def test_total_authentication_collection_failure(monkeypatch):
    monkeypatch.setattr(login_audit, "get_os", lambda: "Linux")
    monkeypatch.setattr(
        login_audit,
        "get_failed_logins",
        lambda: ([], "Failed logins unavailable"),
    )
    monkeypatch.setattr(
        login_audit,
        "get_recent_logins",
        lambda: ([], "Recent logins unavailable"),
    )
    monkeypatch.setattr(
        login_audit,
        "get_uid0_shells",
        lambda: ([], "Process inspection unavailable"),
    )

    result = login_audit.run_login_audit(silent=True)

    assert "auth_audit_failed" in result["tags"]
    assert inspection_coverage("login", result) == "failed"
    assert contributes_detected_risk("login", result) is False

    score, _, maximum = calculate_risk_score({"login": result})

    assert score == 0
    assert maximum == 0
