# Project: ErisLITE
# Module: evidence.py
# Version: 1.6.0
# License: MIT
# Description: Structured intelligence evidence records.

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from uuid import uuid4

from erislite.intelligence.json_utils import load_intelligence_json


class EvidenceType(str, Enum):
    LISTENER = "LISTENER"
    CONFIGURATION = "CONFIGURATION"
    FILE = "FILE"
    PROCESS = "PROCESS"
    ACCOUNT = "ACCOUNT"
    NETWORK = "NETWORK"
    EVENT = "EVENT"
    OTHER = "OTHER"


class EvidenceSensitivity(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    SENSITIVE = "SENSITIVE"


def validate_utc_timestamp(value: str) -> None:
    """Validate a timezone-aware UTC timestamp."""
    if not isinstance(value, str):
        raise ValueError("Timestamp must be a string")

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid evidence timestamp") from exc

    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
        or parsed.utcoffset().total_seconds() != 0
    ):
        raise ValueError("Evidence timestamp must use UTC")


@dataclass(frozen=True)
class Evidence:
    source: str
    evidence_type: EvidenceType
    summary: str

    reference: Optional[str] = None
    sensitivity: EvidenceSensitivity = EvidenceSensitivity.INTERNAL

    collected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    evidence_id: str = field(default_factory=lambda: str(uuid4()))

    schema_version: str = field(
        default="1.0",
        init=False,
    )

    def __post_init__(self) -> None:
        for name in ("source", "summary"):
            value = getattr(self, name)

            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")

            if len(value) > 2048:
                raise ValueError(f"{name} exceeds maximum length")

            if any(ord(char) < 32 for char in value):
                raise ValueError(f"{name} contains control characters")

        if not isinstance(self.evidence_type, EvidenceType):
            raise ValueError("Invalid evidence type")

        if not isinstance(self.sensitivity, EvidenceSensitivity):
            raise ValueError("Invalid evidence sensitivity")

        if self.reference is not None:
            if not isinstance(self.reference, str):
                raise ValueError("Evidence reference must be a string")

            if (
                not self.reference.strip()
                or len(self.reference) > 2048
                or any(ord(char) < 32 for char in self.reference)
            ):
                raise ValueError("Invalid evidence reference")

        validate_utc_timestamp(self.collected_at)

        try:
            from uuid import UUID

            parsed_id = UUID(self.evidence_id)
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError("Invalid evidence identifier") from exc

        if parsed_id.version != 4 or str(parsed_id) != self.evidence_id:
            raise ValueError("Evidence identifier must be UUIDv4")

    def to_dict(self) -> dict:
        """Return a JSON-compatible evidence record."""
        data = asdict(self)
        data["evidence_type"] = self.evidence_type.value
        data["sensitivity"] = self.sensitivity.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Evidence":
        """Validate and reconstruct an evidence record."""
        if not isinstance(data, dict):
            raise ValueError("Evidence data must be a dictionary")

        required = {
            "source",
            "evidence_type",
            "summary",
            "reference",
            "sensitivity",
            "collected_at",
            "evidence_id",
            "schema_version",
        }

        missing = required - data.keys()
        unexpected = data.keys() - required

        if missing:
            raise ValueError(f"Missing evidence fields: {sorted(missing)}")

        if unexpected:
            raise ValueError(f"Unexpected evidence fields: {sorted(unexpected)}")

        if data["schema_version"] != "1.0":
            raise ValueError("Unsupported evidence schema version")

        try:
            evidence_type = EvidenceType(data["evidence_type"])
            sensitivity = EvidenceSensitivity(data["sensitivity"])
        except (ValueError, TypeError) as exc:
            raise ValueError("Invalid evidence enum value") from exc

        return cls(
            source=data["source"],
            evidence_type=evidence_type,
            summary=data["summary"],
            reference=data["reference"],
            sensitivity=sensitivity,
            collected_at=data["collected_at"],
            evidence_id=data["evidence_id"],
        )

    @classmethod
    def from_json(cls, payload: str) -> "Evidence":
        """Safely deserialize an evidence record."""
        data = load_intelligence_json(payload)
        return cls.from_dict(data)
