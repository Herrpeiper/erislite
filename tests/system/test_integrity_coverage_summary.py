# Project: ErisLITE
# Module: test_integrity_coverage_summary.py
# Version: 1.6.0
# License: MIT
# Description: Integrity coverage summary regression tests.

import pytest

from erislite.system.integrity import summarize_integrity_rows


def test_codespaces_partial_integrity_coverage():
    rows = [
        ("/etc/passwd", "UNCHANGED"),
        ("/etc/shadow", "UNAVAILABLE"),
        ("/etc/sudoers", "UNAVAILABLE"),
        ("/etc/ssh/sshd_config", "UNCHANGED"),
    ]

    assert summarize_integrity_rows(rows) == {
        "targets": 4,
        "verified": 2,
        "unavailable": 2,
        "changes": 0,
    }


def test_modified_file_is_verified_and_changed():
    rows = [
        ("/etc/passwd", "MODIFIED"),
        ("/etc/shadow", "UNCHANGED"),
    ]

    assert summarize_integrity_rows(rows) == {
        "targets": 2,
        "verified": 2,
        "unavailable": 0,
        "changes": 1,
    }


def test_missing_and_created_files_count_as_changes():
    rows = [
        ("/etc/passwd", "MISSING"),
        ("/etc/ssh/sshd_config", "CREATED"),
    ]

    assert summarize_integrity_rows(rows) == {
        "targets": 2,
        "verified": 0,
        "unavailable": 0,
        "changes": 2,
    }


def test_expected_absence_is_not_a_change():
    rows = [
        ("/etc/ssh/sshd_config", "ABSENT"),
        ("/etc/passwd", "UNCHANGED"),
    ]

    assert summarize_integrity_rows(rows) == {
        "targets": 2,
        "verified": 1,
        "unavailable": 0,
        "changes": 0,
    }


@pytest.mark.parametrize(
    "status",
    ["UNAVAILABLE", "BROKEN LINK"],
)
def test_unverified_states_never_count_as_verified(status):
    summary = summarize_integrity_rows(
        [
            ("/example", status),
        ]
    )

    assert summary["verified"] == 0
    assert summary["targets"] == 1


def test_empty_scan_has_zero_counts():
    assert summarize_integrity_rows([]) == {
        "targets": 0,
        "verified": 0,
        "unavailable": 0,
        "changes": 0,
    }
