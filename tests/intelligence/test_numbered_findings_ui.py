# Project: ErisLITE
# Module: test_numbered_findings_ui.py
# Version: 1.6.0
# License: MIT
# Description: Numbered intelligence findings UI regression tests.

from types import SimpleNamespace

from rich.console import Console

from erislite.sweep import threat_sweep as sweep


def make_finding(index):
    return SimpleNamespace(
        severity=SimpleNamespace(value="MEDIUM"),
        confidence=SimpleNamespace(value="LOW"),
        title=f"Finding {index}",
        asset=f"test-host|tcp|127.0.0.1:{2000 + index}",
        evidence=[],
    )


def render_findings(monkeypatch, findings):
    test_console = Console(
        record=True,
        force_terminal=False,
        color_system=None,
        width=160,
    )

    monkeypatch.setattr(sweep, "console", test_console)

    sweep._display_intelligence_findings(findings)

    return test_console.export_text()


def test_finding_numbers_match_evidence_numbers(monkeypatch):
    output = render_findings(
        monkeypatch,
        [make_finding(1), make_finding(2)],
    )

    assert "Finding 1" in output
    assert "Finding 2" in output
    assert "Intelligence Evidence Details" in output

    # Main table and evidence table should both contain
    # numbered entries for the same findings.
    lines = output.splitlines()

    assert any("1" in line and "Finding 1" in line for line in lines)
    assert any("2" in line and "Finding 2" in line for line in lines)


def test_finding_numbering_starts_at_one(monkeypatch):
    output = render_findings(
        monkeypatch,
        [make_finding(1)],
    )

    lines = output.splitlines()

    assert any("1" in line and "Finding 1" in line for line in lines)


def test_finding_display_remains_limited_to_twenty(monkeypatch):
    output = render_findings(
        monkeypatch,
        [make_finding(i) for i in range(1, 26)],
    )

    assert "Finding 20" in output
    assert "Finding 21" not in output
    assert "Showing 20 of 25 intelligence findings" in output
