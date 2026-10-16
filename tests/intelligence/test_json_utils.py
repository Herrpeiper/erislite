# Project: ErisLITE
# Module: test_json_utils.py
# Version: 1.6.0
# License: MIT
# Description: Defensive intelligence JSON tests.

import pytest

from erislite.intelligence.json_utils import (
    MAX_RECORD_BYTES,
    load_intelligence_json,
)
from erislite.intelligence.models import (
    Confidence,
    Finding,
    Severity,
)


def test_valid_json():
    data = load_intelligence_json('{"module": "listeners"}')

    assert data["module"] == "listeners"


def test_reject_duplicate_keys():
    payload = '{"severity": "LOW", "severity": "HIGH"}'

    with pytest.raises(ValueError, match="Duplicate"):
        load_intelligence_json(payload)


def test_reject_nested_duplicate_keys():
    payload = '{"evidence": {"source": "a", "source": "b"}}'

    with pytest.raises(ValueError, match="Duplicate"):
        load_intelligence_json(payload)


def test_reject_oversized_record():
    payload = '{"data": "' + ("A" * MAX_RECORD_BYTES) + '"}'

    with pytest.raises(ValueError, match="size limit"):
        load_intelligence_json(payload)


@pytest.mark.parametrize(
    "constant",
    ["NaN", "Infinity", "-Infinity"],
)
def test_reject_nonstandard_constants(constant):
    with pytest.raises(ValueError, match="numeric constant"):
        load_intelligence_json('{"score": ' + constant + "}")


def test_reject_invalid_unicode():
    with pytest.raises(ValueError, match="Unicode"):
        load_intelligence_json('{"text": "\ud800"}')


def test_reject_non_string_payload():
    with pytest.raises(ValueError, match="string"):
        load_intelligence_json({"module": "listeners"})


def test_finding_rejects_duplicate_keys():
    finding = Finding(
        module="listeners",
        rule_id="suspicious_listener",
        asset="tcp/2222",
        title="Suspicious listener",
        description="Unexpected listening port",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
    )

    payload = finding.to_json()
    payload = payload.replace(
        '"module": "listeners"',
        '"module": "listeners", "module": "firewall"',
    )

    with pytest.raises(ValueError, match="Duplicate"):
        Finding.from_json(payload)
