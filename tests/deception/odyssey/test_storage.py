import json
import os
from datetime import datetime, timezone

import pytest

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


def test_append_event_creates_private_directory(tmp_path):
    path = tmp_path / "odyssey" / "events.jsonl"

    append_event(_make_event(), path)

    mode = path.parent.stat().st_mode & 0o777

    assert mode == 0o700


def test_append_event_creates_private_log(tmp_path):
    path = tmp_path / "odyssey" / "events.jsonl"

    append_event(_make_event(), path)

    mode = path.stat().st_mode & 0o777

    assert mode == 0o600


def test_append_event_rejects_symlink_log(tmp_path):
    real_path = tmp_path / "target.jsonl"
    real_path.write_text("do not modify\n", encoding="utf-8")

    log_dir = tmp_path / "odyssey"
    log_dir.mkdir()

    path = log_dir / "events.jsonl"
    path.symlink_to(real_path)

    with pytest.raises(OSError):
        append_event(_make_event(), path)

    assert real_path.read_text(encoding="utf-8") == "do not modify\n"


def test_append_event_repairs_existing_log_permissions(tmp_path):
    path = tmp_path / "odyssey" / "events.jsonl"
    path.parent.mkdir()

    path.write_text("", encoding="utf-8")
    path.chmod(0o644)

    append_event(_make_event(), path)

    mode = path.stat().st_mode & 0o777

    assert mode == 0o600

def test_append_event_rejects_symlink_directory(tmp_path):
    real_dir = tmp_path / "real_odyssey"
    real_dir.mkdir()

    log_dir = tmp_path / "odyssey"
    log_dir.symlink_to(real_dir, target_is_directory=True)

    path = log_dir / "events.jsonl"

    with pytest.raises(OSError):
        append_event(_make_event(), path)

    assert not (real_dir / "events.jsonl").exists()


def test_append_event_repairs_existing_directory_permissions(tmp_path):
    log_dir = tmp_path / "odyssey"
    log_dir.mkdir()
    log_dir.chmod(0o755)

    path = log_dir / "events.jsonl"

    append_event(_make_event(), path)

    mode = log_dir.stat().st_mode & 0o777

    assert mode == 0o700


def test_append_event_rejects_non_directory_parent(tmp_path):
    log_dir = tmp_path / "odyssey"
    log_dir.write_text("not a directory", encoding="utf-8")

    path = log_dir / "events.jsonl"

    with pytest.raises(OSError):
        append_event(_make_event(), path)
