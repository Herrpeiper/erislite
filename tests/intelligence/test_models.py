# Project: ErisLITE
# Module: test_models.py
# Version: 1.6.0
# License: MIT
# Description: Tests for unified security findings.

import json

import pytest

from erislite.intelligence.evidence import (
    Evidence,
    EvidenceSensitivity,
    EvidenceType,
)
from erislite.intelligence.models import (
    Confidence,
    Finding,
    FindingStatus,
    Severity,
)


def make_finding(**overrides):
    data = {
        "module": "listeners",
        "rule_id": "suspicious_listener",
        "asset": "tcp/2222",
        "title": "Suspicious listener",
        "description": "Unexpected listening port detected",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
    }
    data.update(overrides)
    return Finding(**data)


def test_finding_creation():
    finding = make_finding()

    assert finding.module == "listeners"
    assert finding.status == FindingStatus.OPEN
    assert finding.schema_version == "1.1"
    assert len(finding.fingerprint) == 64


def test_fingerprint_is_stable():
    first = make_finding()
    second = make_finding()

    assert first.fingerprint == second.fingerprint
    assert first.finding_id != second.finding_id


def test_different_assets_have_different_fingerprints():
    first = make_finding(asset="tcp/2222")
    second = make_finding(asset="tcp/3389")

    assert first.fingerprint != second.fingerprint


def test_json_serialization():
    finding = make_finding()
    data = json.loads(finding.to_json())

    assert data["severity"] == "MEDIUM"
    assert data["confidence"] == "HIGH"
    assert data["status"] == "OPEN"
    assert data["schema_version"] == "1.1"


@pytest.mark.parametrize(
    "invalid",
    ["", " ", None, 123],
)
def test_reject_invalid_module(invalid):
    with pytest.raises(ValueError):
        make_finding(module=invalid)


def test_reject_invalid_severity():
    with pytest.raises(ValueError):
        make_finding(severity="CRITICAL")


def test_reject_invalid_confidence():
    with pytest.raises(ValueError):
        make_finding(confidence="UNKNOWN")


def test_reject_invalid_status():
    with pytest.raises(ValueError):
        make_finding(status="CLOSED")


def test_reject_invalid_tags():
    with pytest.raises(ValueError):
        make_finding(tags=["valid", 123])


def test_finding_round_trip():
    original = make_finding()

    restored = Finding.from_json(original.to_json())

    assert restored.to_dict() == original.to_dict()
    assert restored.fingerprint == original.fingerprint
    assert restored.finding_id == original.finding_id


def test_from_dict_round_trip():
    original = make_finding()

    restored = Finding.from_dict(original.to_dict())

    assert restored.to_dict() == original.to_dict()


def test_reject_modified_fingerprint():
    data = make_finding().to_dict()
    data["fingerprint"] = "0" * 64

    with pytest.raises(ValueError, match="fingerprint"):
        Finding.from_dict(data)


def test_reject_changed_identity():
    data = make_finding().to_dict()
    data["asset"] = "tcp/9999"

    with pytest.raises(ValueError, match="fingerprint"):
        Finding.from_dict(data)


def test_reject_unsupported_schema():
    data = make_finding().to_dict()
    data["schema_version"] = "2.0"

    with pytest.raises(ValueError, match="schema"):
        Finding.from_dict(data)


def test_reject_missing_field():
    data = make_finding().to_dict()
    del data["module"]

    with pytest.raises(ValueError, match="Missing"):
        Finding.from_dict(data)


def test_reject_unexpected_field():
    data = make_finding().to_dict()
    data["unexpected"] = "value"

    with pytest.raises(ValueError, match="Unexpected"):
        Finding.from_dict(data)


def test_reject_invalid_uuid():
    data = make_finding().to_dict()
    data["finding_id"] = "not-a-uuid"

    with pytest.raises(ValueError, match="UUID"):
        Finding.from_dict(data)


def test_reject_non_utc_timestamp():
    data = make_finding().to_dict()
    data["observed_at"] = "2026-10-16T14:30:00-04:00"

    with pytest.raises(ValueError, match="UTC"):
        Finding.from_dict(data)


def test_reject_naive_timestamp():
    data = make_finding().to_dict()
    data["observed_at"] = "2026-10-16T14:30:00"

    with pytest.raises(ValueError, match="UTC"):
        Finding.from_dict(data)


def test_accept_utc_z_timestamp():
    data = make_finding().to_dict()
    data["observed_at"] = "2026-10-16T18:30:00Z"

    restored = Finding.from_dict(data)

    assert restored.observed_at.endswith("Z")


def test_reject_invalid_json():
    with pytest.raises(ValueError, match="JSON"):
        Finding.from_json("{invalid-json")


def test_reject_json_array():
    with pytest.raises(ValueError, match="dictionary"):
        Finding.from_json("[]")


def test_reject_invalid_deserialized_severity():
    data = make_finding().to_dict()
    data["severity"] = "UNKNOWN"

    with pytest.raises(ValueError, match="enum"):
        Finding.from_dict(data)


def make_test_evidence():
    return Evidence(
        source="listeners",
        evidence_type=EvidenceType.LISTENER,
        summary="Unexpected TCP listener detected",
        reference="listener:tcp:2222",
        sensitivity=EvidenceSensitivity.INTERNAL,
    )


def test_finding_with_evidence():
    evidence = make_test_evidence()
    finding = make_finding(evidence=[evidence])

    assert len(finding.evidence) == 1
    assert finding.evidence[0] == evidence
    assert finding.schema_version == "1.1"


def test_finding_evidence_round_trip():
    original = make_finding(evidence=[make_test_evidence()])

    restored = Finding.from_json(original.to_json())

    assert restored.to_dict() == original.to_dict()
    assert restored.evidence[0] == original.evidence[0]


def test_multiple_evidence_records():
    first = make_test_evidence()
    second = make_test_evidence()

    finding = make_finding(evidence=[first, second])

    assert len(finding.evidence) == 2
    assert finding.evidence[0].evidence_id != (finding.evidence[1].evidence_id)


def test_fingerprint_independent_of_evidence():
    first = make_finding()
    second = make_finding(evidence=[make_test_evidence()])

    assert first.fingerprint == second.fingerprint


def test_reject_non_evidence_object():
    with pytest.raises(ValueError, match="Evidence"):
        make_finding(evidence=[{"source": "listeners"}])


def test_reject_invalid_evidence_collection():
    with pytest.raises(ValueError, match="Evidence"):
        make_finding(evidence="invalid")


def test_reject_invalid_nested_evidence():
    data = make_finding(evidence=[make_test_evidence()]).to_dict()

    data["evidence"][0]["evidence_type"] = "INVALID"

    with pytest.raises(ValueError):
        Finding.from_dict(data)


def test_load_legacy_schema():
    original = make_finding()
    legacy = original.to_dict()

    legacy["schema_version"] = "1.0"
    del legacy["evidence"]

    restored = Finding.from_dict(legacy)

    assert restored.evidence == []
    assert restored.schema_version == "1.1"
    assert restored.fingerprint == original.fingerprint
    assert restored.finding_id == original.finding_id


def test_reject_evidence_in_legacy_schema():
    data = make_finding().to_dict()
    data["schema_version"] = "1.0"

    with pytest.raises(ValueError, match="Unexpected"):
        Finding.from_dict(data)


def test_reject_missing_evidence_in_schema_11():
    data = make_finding().to_dict()
    del data["evidence"]

    with pytest.raises(ValueError, match="Missing"):
        Finding.from_dict(data)
