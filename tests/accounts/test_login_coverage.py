"""Regression tests for EL-002: authentication coverage scoring."""

from subprocess import CompletedProcess
from unittest.mock import Mock, mock_open

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


@pytest.mark.parametrize(
    ("journal_output", "journal_status", "auth_error", "expected_matches", "incomplete"),
    [
        ("Accepted publickey for alice", 0, None, ["auth"], False),
        ("Failed password for bob from 192.0.2.1 port 123", 0, None, ["journal"], False),
        ("Accepted publickey for alice", 0, FileNotFoundError(), [], False),
        ("", 0, FileNotFoundError(), [], True),
        ("journal error", 1, None, ["auth"], False),
    ],
)
def test_failed_login_source_fallback(
    monkeypatch, journal_output, journal_status, auth_error, expected_matches, incomplete
):
    journal_attempt = "Failed password for bob from 192.0.2.1 port 123"
    auth_attempt = "Failed password for alice from 192.0.2.2 port 456"
    journal = Mock(return_value=CompletedProcess([], journal_status, stdout=journal_output))
    read_auth = mock_open(read_data=f"sshd: {auth_attempt} ssh2")
    read_auth.side_effect = auth_error

    monkeypatch.setattr(login_audit, "run_command", journal)
    monkeypatch.setattr(login_audit, "open", read_auth, raising=False)

    matches, error = login_audit.get_failed_logins()

    attempts = {"journal": journal_attempt, "auth": auth_attempt}
    assert matches == [attempts[source] for source in expected_matches]
    assert (error is not None) is incomplete
    if expected_matches == ["journal"]:
        read_auth.assert_not_called()
