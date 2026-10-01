# Project: ErisLITE
# Module: events.py
# Author: Liam Piper-Brandon
# Version: 1.4.0
# License: MIT
# Created: 2026-09-26
# Last Updated: 2026-09-30
# Description: Event model for Odyssey Lite deception listener activity.

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True)
class OdysseyEvent:
    """Represents a connection observed by an Odyssey Lite listener."""

    source_ip: str
    source_port: int
    destination_port: int
    service: str
    severity: str
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict[str, object]:
        """Return a serializable representation of the event."""

        return {
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "service": self.service,
            "severity": self.severity,
        }


@dataclass(frozen=True)
class OdysseyRepeatSummary:
    """Counts connections suppressed as repeats of a logged Odyssey event.

    Written to the event log when the duplicate window for a source and
    canary closes, so the log records every connection even though only
    the first in each window is logged as an event.
    """

    source_ip: str
    destination_port: int
    service: str
    severity: str
    first_seen: datetime
    last_seen: datetime
    repeat_count: int

    def to_dict(self) -> dict[str, object]:
        """Return a serializable representation of the summary."""

        return {
            "record": "repeat_summary",
            "source_ip": self.source_ip,
            "destination_port": self.destination_port,
            "service": self.service,
            "severity": self.severity,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "repeat_count": self.repeat_count,
        }
