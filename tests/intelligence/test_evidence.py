# Project: ErisLITE
# Module: test_evidence.py
# Version: 1.6.0
# License: MIT
# Description: Tests for structured evidence records.

import json
from dataclasses import FrozenInstanceError
from uuid import UUID

import pytest

from erislite.intelligence.evidence import (
    Evidence,
    EvidenceSensitivity,
    EvidenceType,
)


def make_evidence(**overrides):
    values = {
        "source": "listeners",
        "evidence_type": EvidenceType.LISTENER,
        "summary": "Unexpected TCP listener detected",
        "reference": "listener:tcp:2222",
    }
    values.update(overrides)
    return Evidence(**values)


def test_evidence_creation():
    evidence = make_evidence()

    assert evidence.source == "listeners"
    assert evidence.evidence_type == EvidenceType.LISTENER
    assert evidence.sensitivity == EvidenceSensitivity.INTERNAL
    assert evidence.schema_version == "1.0"


def test_unique_evidence_ids():
    first = make_evidence()
    second = make_evidence()

    assert first.evidence_id != second.evidence_id
    assert UUID(first.evidence_id).version == 4


def test_evidence_serialization():
    data = make_evidence().to_dict()

    assert data["evidence_type"] == "LISTENER"
    assert data["sensitivity"] == "INTERNAL"
    assert data["reference"] == "listener:tcp:2222"


def test_evidence_is_immutable():
    evidence = make_evidence()

    with pytest.raises(FrozenInstanceError):
        evidence.summary = "Modified observation"


@pytest.mark.parametrize(
    "invalid",
    ["", " ", None, 123],
)
def test_invalid_source(invalid):
    with pytest.raises(ValueError):
        make_evidence(source=invalid)


def test_invalid_evidence_type():
    with pytest.raises(ValueError):
        make_evidence(evidence_type="LISTENER")


def test_invalid_sensitivity():
    with pytest.raises(ValueError):
        make_evidence(sensitivity="UNKNOWN")


def test_invalid_timestamp():
    with pytest.raises(ValueError, match="UTC"):
        make_evidence(collected_at="2026-10-16T14:00:00")


def test_invalid_identifier():
    with pytest.raises(ValueError):
        make_evidence(evidence_id="invalid")


def test_reject_control_characters():
    with pytest.raises(ValueError):
        make_evidence(summary="Suspicious\nlistener")


def test_reject_oversized_summary():
    with pytest.raises(ValueError):
        make_evidence(summary="A" * 2049)


def test_optional_reference():
    evidence = make_evidence(reference=None)

    assert evidence.reference is None


def test_evidence_from_dict_round_trip():
    original = make_evidence()

    restored = Evidence.from_dict(original.to_dict())

    assert restored == original


def test_evidence_from_json_round_trip():
    original = make_evidence()
    payload = json.dumps(original.to_dict())

    restored = Evidence.from_json(payload)

    assert restored == original


def test_reject_evidence_missing_field():
    data = make_evidence().to_dict()
    del data["source"]

    with pytest.raises(ValueError, match="Missing"):
        Evidence.from_dict(data)


def test_reject_evidence_unknown_field():
    data = make_evidence().to_dict()
    data["unknown"] = "unexpected"

    with pytest.raises(ValueError, match="Unexpected"):
        Evidence.from_dict(data)


def test_reject_evidence_schema_version():
    data = make_evidence().to_dict()
    data["schema_version"] = "2.0"

    with pytest.raises(ValueError, match="schema"):
        Evidence.from_dict(data)


def test_reject_evidence_invalid_enum():
    data = make_evidence().to_dict()
    data["sensitivity"] = "SECRET"

    with pytest.raises(ValueError, match="enum"):
        Evidence.from_dict(data)


def test_reject_evidence_invalid_uuid_on_load():
    data = make_evidence().to_dict()
    data["evidence_id"] = "invalid"

    with pytest.raises(ValueError, match="identifier"):
        Evidence.from_dict(data)


def test_reject_evidence_duplicate_json_keys():
    payload = '{"source":"listeners","source":"firewall"}'

    with pytest.raises(ValueError, match="Duplicate"):
        Evidence.from_json(payload)


def test_reject_evidence_invalid_json():
    with pytest.raises(ValueError, match="JSON"):
        Evidence.from_json("{invalid")


def test_reject_evidence_json_array():
    with pytest.raises(ValueError, match="dictionary"):
        Evidence.from_json("[]")
