import json
from datetime import datetime, timezone

import pytest

from erislite.deception.odyssey.events import OdysseyEvent
from erislite.deception.odyssey.storage import (
    MAX_LOG_BACKUPS,
    append_event,
)


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

def test_append_event_rotates_full_log(tmp_path):
    path = tmp_path / "odyssey" / "events.jsonl"
    path.parent.mkdir()

    original = '{"existing": "event"}\n'
    path.write_text(original, encoding="utf-8")
    path.chmod(0o600)

    append_event(
        _make_event(),
        path,
        max_bytes=len(original.encode("utf-8")),
    )

    rotated = path.with_name(f"{path.name}.1")

    assert rotated.exists()
    assert rotated.read_text(encoding="utf-8") == original

    lines = path.read_text(encoding="utf-8").splitlines()

    assert len(lines) == 1
    assert json.loads(lines[0]) == _make_event().to_dict()


def test_rotation_preserves_private_permissions(tmp_path):
    path = tmp_path / "odyssey" / "events.jsonl"
    path.parent.mkdir()

    original = '{"existing": "event"}\n'
    path.write_text(original, encoding="utf-8")
    path.chmod(0o600)

    append_event(
        _make_event(),
        path,
        max_bytes=len(original.encode("utf-8")),
    )

    rotated = path.with_name(f"{path.name}.1")

    assert path.stat().st_mode & 0o777 == 0o600
    assert rotated.stat().st_mode & 0o777 == 0o600


def test_rotation_shifts_existing_backups(tmp_path):
    path = tmp_path / "odyssey" / "events.jsonl"
    path.parent.mkdir()

    path.write_text("current\n", encoding="utf-8")
    path.chmod(0o600)

    for index in range(1, MAX_LOG_BACKUPS + 1):
        backup = path.with_name(f"{path.name}.{index}")
        backup.write_text(f"backup-{index}\n", encoding="utf-8")
        backup.chmod(0o600)

    append_event(
        _make_event(),
        path,
        max_bytes=1,
    )

    assert path.with_name(f"{path.name}.1").read_text(
        encoding="utf-8"
    ) == "current\n"

    for index in range(2, MAX_LOG_BACKUPS + 1):
        assert path.with_name(f"{path.name}.{index}").read_text(
            encoding="utf-8"
        ) == f"backup-{index - 1}\n"

    assert not path.with_name(
        f"{path.name}.{MAX_LOG_BACKUPS + 1}"
    ).exists()


def test_rotation_rejects_symlinked_backup(tmp_path):
    path = tmp_path / "odyssey" / "events.jsonl"
    path.parent.mkdir()

    path.write_text("current\n", encoding="utf-8")
    path.chmod(0o600)

    target = tmp_path / "target.txt"
    target.write_text("do not modify\n", encoding="utf-8")

    backup = path.with_name(f"{path.name}.1")
    backup.symlink_to(target)

    with pytest.raises(OSError):
        append_event(
            _make_event(),
            path,
            max_bytes=1,
        )

    assert target.read_text(encoding="utf-8") == "do not modify\n"
