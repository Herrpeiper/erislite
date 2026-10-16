# Project: ErisLITE
# Module: export.py
# Version: 1.6.0
# License: MIT
# Description: Sensitivity-aware intelligence report exports.

import json
from enum import Enum
from typing import Any, Dict, List

from erislite.intelligence.evidence import (
    Evidence,
    EvidenceSensitivity,
)
from erislite.intelligence.models import Finding


class ExportPolicy(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"


REPORT_SCHEMA_VERSION = "1.0"
REPORT_TYPE = "erislite.analyst_report"


def _visible_sensitivities(
    policy: ExportPolicy,
) -> set:
    """Return evidence levels allowed by the export policy."""
    if policy == ExportPolicy.PUBLIC:
        return {EvidenceSensitivity.PUBLIC}

    if policy == ExportPolicy.INTERNAL:
        return {
            EvidenceSensitivity.PUBLIC,
            EvidenceSensitivity.INTERNAL,
        }

    raise ValueError("Unsupported export policy")


def _export_evidence(
    evidence: Evidence,
    allowed: set,
) -> Dict[str, Any]:
    """Export an allowlisted evidence representation."""
    if not isinstance(evidence, Evidence):
        raise ValueError("Invalid evidence record")

    if not isinstance(evidence.sensitivity, EvidenceSensitivity):
        raise ValueError("Invalid evidence sensitivity")

    if evidence.sensitivity not in allowed:
        return {
            "redacted": True,
            "sensitivity": evidence.sensitivity.value,
        }

    return {
        "redacted": False,
        "evidence_id": evidence.evidence_id,
        "source": evidence.source,
        "evidence_type": evidence.evidence_type.value,
        "summary": evidence.summary,
        "reference": evidence.reference,
        "sensitivity": evidence.sensitivity.value,
        "collected_at": evidence.collected_at,
    }


def export_finding(
    finding: Finding,
    policy: ExportPolicy = ExportPolicy.INTERNAL,
) -> Dict[str, Any]:
    """Build a policy-filtered, non-importable analyst report."""
    if not isinstance(finding, Finding):
        raise ValueError("Expected a Finding object")

    if not isinstance(policy, ExportPolicy):
        raise ValueError("Invalid export policy")

    if not isinstance(finding.evidence, list):
        raise ValueError("Invalid finding evidence collection")

    if len(finding.evidence) > 100:
        raise ValueError("Too many evidence records")

    allowed = _visible_sensitivities(policy)

    records: List[Dict[str, Any]] = [_export_evidence(item, allowed) for item in finding.evidence]

    redacted_count = sum(1 for record in records if record["redacted"])

    return {
        "report_type": REPORT_TYPE,
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "export_policy": policy.value,
        "finding": {
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "status": finding.status.value,
        },
        "evidence_count": len(records),
        "redacted_count": redacted_count,
        "evidence": records,
    }


def export_finding_json(
    finding: Finding,
    policy: ExportPolicy = ExportPolicy.INTERNAL,
) -> str:
    """Serialize a filtered analyst report."""
    report = export_finding(finding, policy)

    return json.dumps(
        report,
        sort_keys=True,
        ensure_ascii=True,
    )
