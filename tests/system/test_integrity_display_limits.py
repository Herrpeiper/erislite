# Project: ErisLITE
# Module: test_integrity_display_limits.py
# Version: 1.6.0
# License: MIT
# Description: Bounded integrity display and hidden-result tests.

from erislite.system.integrity import (
    MAX_DISPLAY_ROWS,
    select_integrity_display_rows,
)


def test_large_scan_is_bounded():
    rows = [(f"/usr/bin/file{i}", "UNCHANGED") for i in range(1500)]

    selected, hidden_important, hidden_routine = select_integrity_display_rows(rows)

    assert len(selected) == MAX_DISPLAY_ROWS
    assert hidden_important == 0
    assert hidden_routine == 1500 - MAX_DISPLAY_ROWS


def test_important_results_come_first():
    rows = [
        ("/etc/passwd", "UNCHANGED"),
        ("/etc/shadow", "UNAVAILABLE"),
        ("/etc/hosts", "MODIFIED"),
    ]

    selected, hidden_important, hidden_routine = select_integrity_display_rows(rows)

    assert selected[0] == ("/etc/shadow", "UNAVAILABLE")
    assert selected[1] == ("/etc/hosts", "MODIFIED")
    assert hidden_important == 0
    assert hidden_routine == 0


def test_overflow_important_results_are_counted():
    rows = [(f"/tmp/file{i}", "MODIFIED") for i in range(MAX_DISPLAY_ROWS + 20)]

    selected, hidden_important, hidden_routine = select_integrity_display_rows(rows)

    assert len(selected) == MAX_DISPLAY_ROWS
    assert hidden_important == 20
    assert hidden_routine == 0
    assert all(status == "MODIFIED" for _, status in selected)


def test_mixed_overflow_is_accounted_for():
    rows = [(f"/tmp/suspicious{i}", "UNAVAILABLE") for i in range(MAX_DISPLAY_ROWS + 5)] + [
        (f"/usr/bin/file{i}", "UNCHANGED") for i in range(100)
    ]

    selected, hidden_important, hidden_routine = select_integrity_display_rows(rows)

    assert len(selected) == MAX_DISPLAY_ROWS
    assert hidden_important == 5
    assert hidden_routine == 100
    assert len(selected) + hidden_important + hidden_routine == len(rows)
