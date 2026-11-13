# Project: ErisLITE
# Module: test_listener_adapter.py
# Version: 1.6.0
# License: MIT
# Description: Listener intelligence adapter tests.

import pytest

from erislite.intelligence.adapters.listeners import (
    adapt_listeners,
)
from erislite.intelligence.models import (
    Confidence,
    Severity,
)


def make_listener(
    proto="tcp",
    address="0.0.0.0:2222",
    process="socat",
    flags=None,
    whitelisted=False,
):
    if flags is None:
        flags = [
            "External Bind",
            "High Port",
            "Potential LOLBin Listener",
        ]

    return (
        proto,
        address,
        process,
        flags,
        whitelisted,
    )


def test_suspicious_listener_produces_finding():
    findings = adapt_listeners(
        [make_listener()],
        hostname="test-host",
    )

    assert len(findings) == 1
    assert findings[0].module == "listeners"
    assert findings[0].rule_id == "suspicious_listener"


def test_lolbin_listener_is_high_severity():
    finding = adapt_listeners(
        [make_listener()],
        hostname="test-host",
    )[0]

    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.MEDIUM


def test_external_unknown_listener_is_medium():
    record = make_listener(
        process="unknown-service",
        flags=["External Bind", "High Port"],
    )

    finding = adapt_listeners([record], hostname="test-host")[0]

    assert finding.severity == Severity.MEDIUM


def test_expected_listener_is_ignored():
    record = make_listener(
        process="sshd",
        flags=["Known Service"],
        whitelisted=True,
    )

    assert adapt_listeners([record], hostname="test-host") == []


def test_whitelisted_external_service_is_ignored():
    record = make_listener(
        process="sshd",
        flags=["External Bind", "Known Service"],
        whitelisted=True,
    )

    assert adapt_listeners([record], hostname="test-host") == []


def test_collection_failure_is_rejected():
    record = (
        "error",
        "-",
        "command failed",
        ["Error"],
        False,
    )

    with pytest.raises(ValueError, match="collection failed"):
        adapt_listeners([record], hostname="test-host")


def test_fingerprint_stable_across_observations():
    record = make_listener()

    first = adapt_listeners([record], hostname="test-host")[0]
    second = adapt_listeners([record], hostname="test-host")[0]

    assert first.fingerprint == second.fingerprint
    assert first.finding_id != second.finding_id


def test_different_hosts_have_different_fingerprints():
    record = make_listener()

    first = adapt_listeners([record], hostname="host-a")[0]
    second = adapt_listeners([record], hostname="host-b")[0]

    assert first.fingerprint != second.fingerprint


def test_distinct_listeners_have_distinct_fingerprints():
    first, second = adapt_listeners(
        [
            make_listener(address="0.0.0.0:2222"),
            make_listener(address="0.0.0.0:3389"),
        ],
        hostname="test-host",
    )

    assert first.fingerprint != second.fingerprint


def test_evidence_is_attached():
    finding = adapt_listeners(
        [make_listener()],
        hostname="test-host",
    )[0]

    assert len(finding.evidence) == 1
    assert finding.evidence[0].source == "listeners"


def test_adapter_does_not_modify_observation():
    record = make_listener()
    original = (
        record[0],
        record[1],
        record[2],
        list(record[3]),
        record[4],
    )

    adapt_listeners([record], hostname="test-host")

    assert record == original


def test_reject_invalid_hostname():
    with pytest.raises(ValueError, match="hostname"):
        adapt_listeners([make_listener()], hostname="")


def test_reject_malformed_record():
    with pytest.raises(ValueError, match="Invalid"):
        adapt_listeners(
            [("tcp", "0.0.0.0:2222")],
            hostname="test-host",
        )


def test_empty_observations():
    assert adapt_listeners([], hostname="test-host") == []


def test_unknown_process_has_low_confidence():
    record = make_listener(
        process="unknown",
        flags=["External Bind", "High Port"],
    )

    finding = adapt_listeners([record], hostname="codespace")[0]

    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == Confidence.LOW


def test_unknown_process_evidence_explains_uncertainty():
    record = make_listener(
        process="unknown",
        flags=["External Bind", "High Port"],
    )

    finding = adapt_listeners([record], hostname="codespace")[0]

    assert "ownership could not be determined" in (finding.evidence[0].summary)


def test_identified_external_process_retains_medium_confidence():
    record = make_listener(
        process="custom-daemon",
        flags=["External Bind", "High Port"],
    )

    finding = adapt_listeners([record], hostname="codespace")[0]

    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == Confidence.MEDIUM


def test_lolbin_evidence_explains_detection():
    finding = adapt_listeners(
        [make_listener()],
        hostname="codespace",
    )[0]

    assert finding.severity == Severity.HIGH
    assert "listener-capable utility" in (finding.evidence[0].summary)


def test_unknown_process_fingerprint_stays_stable():
    record = make_listener(
        process="unknown",
        flags=["External Bind"],
    )

    first = adapt_listeners([record], hostname="codespace")[0]
    second = adapt_listeners([record], hostname="codespace")[0]

    assert first.fingerprint == second.fingerprint
    assert first.confidence == Confidence.LOW
