# Project: ErisLITE
# Module: test_evidence_presentation.py
# Version: 1.6.0
# License: MIT
# Description: Intelligence evidence presentation regression tests.

from types import SimpleNamespace

from rich.console import Console

from erislite.intelligence.evidence import EvidenceSensitivity
from erislite.sweep import threat_sweep as sweep


def make_finding(title, evidence):
    return SimpleNamespace(
        title=title,
        evidence=evidence,
    )


def make_evidence(summary, sensitivity):
    return SimpleNamespace(
        summary=summary,
        sensitivity=sensitivity,
    )


def render(monkeypatch, findings):
    test_console = Console(
        record=True,
        force_terminal=False,
        color_system=None,
        width=180,
    )

    monkeypatch.setattr(sweep, "console", test_console)

    sweep._display_intelligence_evidence(findings)

    return test_console.export_text()


def test_evidence_displays_parent_finding(monkeypatch):
    output = render(
        monkeypatch,
        [
            make_finding(
                "Suspicious network listener",
                [
                    make_evidence(
                        "External listener observed",
                        EvidenceSensitivity.INTERNAL,
                    )
                ],
            )
        ],
    )

    assert "Suspicious network listener" in output
    assert "External listener observed" in output
    assert "INTERNAL" in output


def test_sensitive_evidence_remains_redacted(monkeypatch):
    secret = "DO_NOT_DISPLAY_SECRET_EVIDENCE"

    output = render(
        monkeypatch,
        [
            make_finding(
                "Sensitive finding",
                [
                    make_evidence(
                        secret,
                        EvidenceSensitivity.SENSITIVE,
                    )
                ],
            )
        ],
    )

    assert secret not in output
    assert "Evidence withheld by sensitivity policy" in output
    assert "REDACTED" in output


def test_empty_evidence_has_clear_label(monkeypatch):
    output = render(
        monkeypatch,
        [make_finding("No evidence finding", [])],
    )

    assert "No evidence finding" in output
    assert "No evidence attached" in output


def test_evidence_display_limit_preserved(monkeypatch):
    records = [
        make_evidence(
            f"Evidence record {i}",
            EvidenceSensitivity.INTERNAL,
        )
        for i in range(5)
    ]

    output = render(
        monkeypatch,
        [make_finding("Bounded finding", records)],
    )

    assert "Evidence record 0" in output
    assert "Evidence record 1" in output
    assert "Evidence record 2" not in output
    assert "3 additional evidence record(s) not shown" in output
