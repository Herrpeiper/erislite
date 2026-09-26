import json
from datetime import datetime, timezone

from erislite.deception.odyssey.events import OdysseyEvent
from erislite.deception.odyssey.storage import append_event


def _make_event(
    source_ip: str = "192.0.2.10",
    source_port: int = 54321,
) -> OdysseyEvent:
    return OdysseyEvent(
        source_ip=source_ip,
        source_port=source_port,
        destination_port=2323,
        service="telnet-alt",
        severity="high",
        timestamp=datetime(
            2026,
            9,
            26,
            15,
            30,
            tzinfo=timezone.utc,
        ),
    )


def test_append_event_creates_log(tmp_path):
    path = tmp_path / "odyssey" / "events.jsonl"
    event = _make_event()

    append_event(event, path)

    assert path.exists()

    lines = path.read_text(encoding="utf-8").splitlines()

    assert len(lines) == 1
    assert json.loads(lines[0]) == event.to_dict()


def test_append_event_preserves_existing_events(tmp_path):
    path = tmp_path / "odyssey" / "events.jsonl"

    first = _make_event(
        source_ip="192.0.2.10",
        source_port=54321,
    )
    second = _make_event(
        source_ip="198.51.100.20",
        source_port=44444,
    )

    append_event(first, path)
    append_event(second, path)

    lines = path.read_text(encoding="utf-8").splitlines()

    assert len(lines) == 2
    assert json.loads(lines[0]) == first.to_dict()
    assert json.loads(lines[1]) == second.to_dict()
