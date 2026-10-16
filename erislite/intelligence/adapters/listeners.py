# Project: ErisLITE
# Module: listeners.py
# Version: 1.6.0
# License: MIT
# Description: Listener observations to intelligence findings.

from typing import Iterable, List, Tuple

from erislite.intelligence.evidence import (
    Evidence,
    EvidenceSensitivity,
    EvidenceType,
)
from erislite.intelligence.models import (
    Confidence,
    Finding,
    Severity,
)

ListenerRecord = Tuple[str, str, str, List[str], bool]


def adapt_listeners(
    observations: Iterable[ListenerRecord],
    hostname: str,
) -> List[Finding]:
    """Convert parsed suspicious listeners into findings."""
    if not isinstance(hostname, str) or not hostname.strip():
        raise ValueError("A valid hostname is required")

    findings = []

    for record in observations:
        if not isinstance(record, (tuple, list)) or len(record) != 5:
            raise ValueError("Invalid listener observation")

        proto, address, process, flags, whitelisted = record

        if (
            not isinstance(proto, str)
            or not proto.strip()
            or not isinstance(address, str)
            or not address.strip()
            or not isinstance(process, str)
            or not process.strip()
            or not isinstance(flags, list)
            or not all(isinstance(flag, str) for flag in flags)
            or not isinstance(whitelisted, bool)
        ):
            raise ValueError("Invalid listener observation fields")

        # parse_listeners() uses this sentinel on failure.
        # A failed inspection is not a confirmed security finding.
        if proto.lower() == "error":
            raise ValueError("Listener collection failed")

        has_lolbin = "Potential LOLBin Listener" in flags
        external = "External Bind" in flags

        suspicious = has_lolbin or (external and not whitelisted)

        if not suspicious:
            continue

        # Use a host-scoped listener identity rather than
        # the aggregate Threat Sweep summary.
        asset = "{}|{}|{}|{}".format(
            hostname,
            proto.lower(),
            address,
            process,
        )

        severity = Severity.HIGH if has_lolbin else Severity.MEDIUM

        evidence = Evidence(
            source="listeners",
            evidence_type=EvidenceType.LISTENER,
            summary="Suspicious listener observation",
            reference=None,
            sensitivity=EvidenceSensitivity.INTERNAL,
        )

        finding = Finding(
            module="listeners",
            rule_id="suspicious_listener",
            asset=asset,
            title="Suspicious network listener",
            description=(
                "Listener requires analyst review based on process or bind characteristics."
            ),
            severity=severity,
            confidence=Confidence.MEDIUM,
            tags=["suspicious_listener"],
            evidence=[evidence],
        )

        findings.append(finding)

    return findings
