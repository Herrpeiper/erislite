# Project: ErisLITE
# Module: test_evidence_tui.py
# Version: 1.6.0
# License: MIT
# Description: Sensitivity-aware intelligence evidence display tests.

from rich.console import Console

from erislite.intelligence.adapters.listeners import adapt_listeners
from erislite.intelligence.evidence import (
    Evidence,
    EvidenceSensitivity,
    EvidenceType,
)
from erislite.sweep import threat_sweep


def make_finding():
    records = [
        (
            "tcp",
            "0.0.0.0:2000",
            "unknown",
            ["External Bind", "High Port"],
            False,
        )
    ]
    return adapt_listeners(records, hostname="test-host")[0]


def capture_output(monkeypatch, findings):
    output = Console(
        record=True,
        force_terminal=False,
        color_system=None,
        width=160,
    )
    monkeypatch.setattr(threat_sweep, "console", output)
    threat_sweep._display_intelligence_evidence(findings)
    return output.export_text()


def test_evidence_summary_visible(monkeypatch):
    rendered = capture_output(monkeypatch, [make_finding()])

    assert "Intelligence Evidence Details" in rendered
    assert "ownership could not be determined" in rendered


def test_internal_evidence_visible(monkeypatch):
    rendered = capture_output(monkeypatch, [make_finding()])

    assert "INTERNAL" in rendered


def test_sensitive_evidence_redacted(monkeypatch):
    finding = make_finding()
    finding.evidence = [
        Evidence(
            source="test",
            evidence_type=EvidenceType.EVENT,
            summary="SECRET_EVIDENCE_SENTINEL",
            reference="SECRET_REFERENCE_SENTINEL",
            sensitivity=EvidenceSensitivity.SENSITIVE,
        )
    ]

    rendered = capture_output(monkeypatch, [finding])

    assert "REDACTED" in rendered
    assert "SECRET_EVIDENCE_SENTINEL" not in rendered
    assert "SECRET_REFERENCE_SENTINEL" not in rendered


def test_reference_not_displayed(monkeypatch):
    finding = make_finding()
    finding.evidence = [
        Evidence(
            source="test",
            evidence_type=EvidenceType.EVENT,
            summary="Safe summary",
            reference="PRIVATE_REFERENCE_SENTINEL",
            sensitivity=EvidenceSensitivity.INTERNAL,
        )
    ]

    rendered = capture_output(monkeypatch, [finding])

    assert "Safe summary" in rendered
    assert "PRIVATE_REFERENCE_SENTINEL" not in rendered


def test_missing_evidence_handled(monkeypatch):
    finding = make_finding()
    finding.evidence = []

    rendered = capture_output(monkeypatch, [finding])

    assert "No evidence attached" in rendered


def test_long_summary_is_truncated(monkeypatch):
    finding = make_finding()
    finding.evidence = [
        Evidence(
            source="test",
            evidence_type=EvidenceType.EVENT,
            summary="X" * 400,
            sensitivity=EvidenceSensitivity.INTERNAL,
        )
    ]

    rendered = capture_output(monkeypatch, [finding])

    assert "X" * 181 not in rendered
    assert "…" in rendered or "..." in rendered


def test_evidence_display_limit(monkeypatch):
    finding = make_finding()
    finding.evidence = [
        Evidence(
            source="test",
            evidence_type=EvidenceType.EVENT,
            summary=f"Observation {index}",
        )
        for index in range(5)
    ]

    rendered = capture_output(monkeypatch, [finding])

    assert "Observation 0" in rendered
    assert "Observation 1" in rendered
    assert "Observation 2" not in rendered
    assert "3 additional evidence record(s) not shown" in rendered


def test_empty_findings_do_not_render(monkeypatch):
    rendered = capture_output(monkeypatch, [])
    assert "Intelligence Evidence Details" not in rendered


def test_markup_is_not_interpreted(monkeypatch):
    finding = make_finding()
    finding.evidence = [
        Evidence(
            source="test",
            evidence_type=EvidenceType.EVENT,
            summary="[bold red]Untrusted observation[/]",
        )
    ]

    rendered = capture_output(monkeypatch, [finding])

    assert "[bold red]Untrusted observation[/]" in rendered
