from datetime import datetime, timezone

from erislite.deception.odyssey.events import OdysseyEvent


def test_odyssey_event_fields():
    timestamp = datetime(
        2026,
        9,
        26,
        14,
        30,
        tzinfo=timezone.utc,
    )

    event = OdysseyEvent(
        source_ip="192.0.2.10",
        source_port=54321,
        destination_port=23,
        service="telnet",
        severity="high",
        timestamp=timestamp,
    )

    assert event.source_ip == "192.0.2.10"
    assert event.source_port == 54321
    assert event.destination_port == 23
    assert event.service == "telnet"
    assert event.severity == "high"
    assert event.timestamp == timestamp


def test_odyssey_event_to_dict():
    timestamp = datetime(
        2026,
        9,
        26,
        14,
        30,
        tzinfo=timezone.utc,
    )

    event = OdysseyEvent(
        source_ip="192.0.2.10",
        source_port=54321,
        destination_port=23,
        service="telnet",
        severity="high",
        timestamp=timestamp,
    )

    result = event.to_dict()

    assert result == {
        "timestamp": "2026-09-26T14:30:00+00:00",
        "source_ip": "192.0.2.10",
        "source_port": 54321,
        "destination_port": 23,
        "service": "telnet",
        "severity": "high",
    }


def test_odyssey_event_default_timestamp_is_utc():
    event = OdysseyEvent(
        source_ip="192.0.2.10",
        source_port=54321,
        destination_port=23,
        service="telnet",
        severity="high",
    )

    assert event.timestamp.tzinfo is not None
    assert event.timestamp.utcoffset() == timezone.utc.utcoffset(event.timestamp)