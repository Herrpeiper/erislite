# Project: ErisLITE
# Module: models.py
# Version: 1.6.0
# License: MIT
# Description: Unified security finding model.

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List
from uuid import UUID, uuid4

from erislite.intelligence.evidence import Evidence
from erislite.intelligence.json_utils import load_intelligence_json


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


def generate_fingerprint(
    module: str,
    rule_id: str,
    asset: str,
) -> str:
    """Identify the same condition across multiple sweeps."""
    identity = json.dumps(
        [module, rule_id, asset],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


@dataclass
class Finding:
    module: str
    rule_id: str
    asset: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence

    tags: List[str] = field(default_factory=list)
    status: FindingStatus = FindingStatus.OPEN
    evidence: List[Evidence] = field(default_factory=list)

    finding_id: str = field(default_factory=lambda: str(uuid4()))
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    fingerprint: str = field(init=False)

    schema_version: str = field(default="1.1", init=False)

    def __post_init__(self) -> None:
        for name in (
            "module",
            "rule_id",
            "asset",
            "title",
            "description",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError("{} must be a non-empty string".format(name))

        if not isinstance(self.severity, Severity):
            raise ValueError("Invalid finding severity")

        if not isinstance(self.confidence, Confidence):
            raise ValueError("Invalid finding confidence")

        if not isinstance(self.status, FindingStatus):
            raise ValueError("Invalid finding status")

        if not isinstance(self.tags, list) or not all(isinstance(tag, str) for tag in self.tags):
            raise ValueError("Tags must be a list of strings")

        if not isinstance(self.evidence, list):
            raise ValueError("Evidence must be a list")

        if not all(isinstance(item, Evidence) for item in self.evidence):
            raise ValueError("Evidence entries must be Evidence objects")

        if len(self.evidence) > 100:
            raise ValueError("Finding exceeds maximum evidence count")

        self.fingerprint = generate_fingerprint(
            self.module,
            self.rule_id,
            self.asset,
        )

    def to_dict(self) -> dict:
        """Return a JSON-compatible finding record."""
        data = asdict(self)

        data["severity"] = self.severity.value
        data["confidence"] = self.confidence.value
        data["status"] = self.status.value

        data["evidence"] = [item.to_dict() for item in self.evidence]

        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """Validate and reconstruct schema 1.0 or 1.1 findings."""
        if not isinstance(data, dict):
            raise ValueError("Finding data must be a dictionary")

        version = data.get("schema_version")

        if version not in ("1.0", "1.1"):
            raise ValueError("Unsupported finding schema version")

        required = {
            "module",
            "rule_id",
            "asset",
            "title",
            "description",
            "severity",
            "confidence",
            "tags",
            "status",
            "finding_id",
            "observed_at",
            "fingerprint",
            "schema_version",
        }

        if version == "1.1":
            required.add("evidence")

        missing = required - data.keys()
        unexpected = data.keys() - required

        if missing:
            raise ValueError(f"Missing finding fields: {sorted(missing)}")

        if unexpected:
            raise ValueError(f"Unexpected finding fields: {sorted(unexpected)}")

        identifier = data["finding_id"]

        if not isinstance(identifier, str):
            raise ValueError("Finding ID must be a string")

        try:
            parsed_uuid = UUID(identifier)
        except ValueError as exc:
            raise ValueError("Invalid finding UUID") from exc

        if parsed_uuid.version != 4 or str(parsed_uuid) != identifier:
            raise ValueError("Finding ID must be canonical UUIDv4")

        observed_at = data["observed_at"]

        if not isinstance(observed_at, str):
            raise ValueError("Timestamp must be a string")

        try:
            parsed_time = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("Invalid finding timestamp") from exc

        if (
            parsed_time.tzinfo is None
            or parsed_time.utcoffset() is None
            or parsed_time.utcoffset().total_seconds() != 0
        ):
            raise ValueError("Finding timestamp must use UTC")

        try:
            severity = Severity(data["severity"])
            confidence = Confidence(data["confidence"])
            status = FindingStatus(data["status"])
        except (ValueError, TypeError) as exc:
            raise ValueError("Invalid finding enum value") from exc

        evidence_records = []

        if version == "1.1":
            raw_evidence = data["evidence"]

            if not isinstance(raw_evidence, list):
                raise ValueError("Finding evidence must be a list")

            if len(raw_evidence) > 100:
                raise ValueError("Finding exceeds maximum evidence count")

            evidence_records = [Evidence.from_dict(item) for item in raw_evidence]

        finding = cls(
            module=data["module"],
            rule_id=data["rule_id"],
            asset=data["asset"],
            title=data["title"],
            description=data["description"],
            severity=severity,
            confidence=confidence,
            tags=data["tags"],
            status=status,
            evidence=evidence_records,
            finding_id=identifier,
            observed_at=observed_at,
        )

        stored_fingerprint = data["fingerprint"]

        if not isinstance(stored_fingerprint, str) or not hmac.compare_digest(
            finding.fingerprint,
            stored_fingerprint,
        ):
            raise ValueError("Finding fingerprint verification failed")

        return finding

    @classmethod
    def from_json(cls, payload: str) -> "Finding":
        """Safely deserialize a finding from JSON."""
        data = load_intelligence_json(payload)
        return cls.from_dict(data)
