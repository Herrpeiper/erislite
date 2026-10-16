# Project: ErisLITE
# Module: test_export.py
# Version: 1.6.0
# License: MIT
# Description: Tests for sensitivity-aware analyst exports.

import json

import pytest

from erislite.intelligence.evidence import (
    Evidence,
    EvidenceSensitivity,
    EvidenceType,
)
from erislite.intelligence.export import (
    ExportPolicy,
    export_finding,
    export_finding_json,
)
from erislite.intelligence.models import (
    Confidence,
    Finding,
    Severity,
)


def make_evidence(sensitivity, summary="Observation"):
    return Evidence(
        source="test_module",
        evidence_type=EvidenceType.EVENT,
        summary=summary,
        reference="artifact:test:123",
        sensitivity=sensitivity,
    )


def make_finding(evidence=None):
    return Finding(
        module="listeners",
        rule_id="test_rule",
        asset="SECRET_ASSET",
        title="SECRET_TITLE",
        description="SECRET_DESCRIPTION",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        tags=["SECRET_TAG"],
        evidence=evidence if evidence is not None else [],
    )


def test_default_policy_is_internal():
    report = export_finding(make_finding())

    assert report["export_policy"] == "INTERNAL"


def test_public_evidence_visible():
    finding = make_finding([make_evidence(EvidenceSensitivity.PUBLIC)])

    report = export_finding(finding, ExportPolicy.PUBLIC)

    assert report["evidence"][0]["redacted"] is False
    assert report["redacted_count"] == 0


def test_internal_evidence_hidden_from_public():
    finding = make_finding(
        [
            make_evidence(
                EvidenceSensitivity.INTERNAL,
                "PRIVATE_INTERNAL_VALUE",
            )
        ]
    )

    payload = export_finding_json(finding, ExportPolicy.PUBLIC)

    assert "PRIVATE_INTERNAL_VALUE" not in payload
    assert "artifact:test:123" not in payload


def test_internal_evidence_visible_in_internal_report():
    finding = make_finding([make_evidence(EvidenceSensitivity.INTERNAL)])

    report = export_finding(finding, ExportPolicy.INTERNAL)

    assert report["evidence"][0]["redacted"] is False


def test_sensitive_evidence_always_redacted():
    finding = make_finding(
        [
            make_evidence(
                EvidenceSensitivity.SENSITIVE,
                "SENSITIVE_SECRET_SENTINEL",
            )
        ]
    )

    for policy in ExportPolicy:
        payload = export_finding_json(finding, policy)

        assert "SENSITIVE_SECRET_SENTINEL" not in payload
        assert "artifact:test:123" not in payload


def test_mixed_sensitivity_counts():
    finding = make_finding(
        [
            make_evidence(EvidenceSensitivity.PUBLIC),
            make_evidence(EvidenceSensitivity.INTERNAL),
            make_evidence(EvidenceSensitivity.SENSITIVE),
        ]
    )

    public = export_finding(finding, ExportPolicy.PUBLIC)
    internal = export_finding(finding, ExportPolicy.INTERNAL)

    assert public["evidence_count"] == 3
    assert public["redacted_count"] == 2
    assert internal["redacted_count"] == 1


def test_unclassified_finding_fields_not_exported():
    payload = export_finding_json(make_finding())

    for secret in (
        "SECRET_ASSET",
        "SECRET_TITLE",
        "SECRET_DESCRIPTION",
        "SECRET_TAG",
    ):
        assert secret not in payload


def test_export_does_not_modify_original():
    finding = make_finding([make_evidence(EvidenceSensitivity.SENSITIVE)])

    before = finding.to_dict()
    export_finding(finding, ExportPolicy.PUBLIC)

    assert finding.to_dict() == before


def test_reject_invalid_export_policy():
    with pytest.raises(ValueError, match="policy"):
        export_finding(make_finding(), "PUBLIC")


def test_reject_invalid_finding():
    with pytest.raises(ValueError, match="Finding"):
        export_finding({"module": "listeners"})


def test_reject_invalid_evidence_collection():
    finding = make_finding()
    finding.evidence = "invalid"

    with pytest.raises(ValueError, match="collection"):
        export_finding(finding)


def test_reject_too_many_evidence_records():
    finding = make_finding()
    finding.evidence = [None] * 101

    with pytest.raises(ValueError, match="Too many"):
        export_finding(finding)


def test_reject_invalid_evidence_item():
    finding = make_finding()
    finding.evidence.append({"summary": "unvalidated"})

    with pytest.raises(ValueError, match="evidence"):
        export_finding(finding)


def test_analyst_report_is_not_a_finding():
    finding = make_finding()
    report = export_finding(finding)

    assert report["report_type"] == "erislite.analyst_report"

    with pytest.raises(ValueError):
        Finding.from_dict(report)


def test_export_json_is_valid():
    payload = export_finding_json(make_finding())
    report = json.loads(payload)

    assert report["report_schema_version"] == "1.0"
    assert report["evidence_count"] == 0
