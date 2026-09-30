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


# ---------------------------------------------------------------------------
# Attacker-controlled log directory
#
# Threat model: ErisLITE runs under sudo from a checkout owned by an
# unprivileged account the red team controls. That account can rename and
# replace entries under erislite/data/logs/ while root writes events.
# ---------------------------------------------------------------------------


def test_rotation_swap_does_not_chmod_symlink_target(monkeypatch, tmp_path):
    """Swapping the log for a symlink mid-rotation must not touch the target.

    The swap happens immediately before the log is renamed, after every check
    has passed. A chmod on the renamed file would follow the symlink as root.
    """

    import os
    import stat

    from erislite.deception.odyssey import storage

    path = tmp_path / "odyssey" / "events.jsonl"
    path.parent.mkdir()
    path.write_text("x" * 64, encoding="utf-8")
    path.chmod(0o600)

    victim = tmp_path / "setuid_binary"
    victim.write_text("#!/bin/sh\n", encoding="utf-8")
    victim.chmod(0o4755)

    real_replace = os.replace
    swapped = []

    def attacker_replace(src, dst, *args, **kwargs):
        if os.path.basename(os.fspath(src)) == path.name and not swapped:
            swapped.append(True)
            path.unlink()
            path.symlink_to(victim)
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(storage.os, "replace", attacker_replace)
    
    try:
        append_event(_make_event(), path, max_bytes=1)
    except OSError:
        pass

    assert swapped
    assert stat.S_IMODE(victim.stat().st_mode) == 0o4755
    assert victim.read_text(encoding="utf-8") == "#!/bin/sh\n"


def test_append_event_rejects_directory_owned_by_another_user(monkeypatch, tmp_path):
    import os

    from erislite.deception.odyssey import storage

    path = tmp_path / "odyssey" / "events.jsonl"
    path.parent.mkdir()

    real_uid = os.geteuid()
    monkeypatch.setattr(storage.os, "geteuid", lambda: real_uid + 1)

    with pytest.raises(OSError, match="owned by uid"):
        append_event(_make_event(), path)

    assert not path.exists()


def test_append_event_rejects_hard_linked_log(tmp_path):
    import os

    path = tmp_path / "odyssey" / "events.jsonl"
    path.parent.mkdir()

    other = tmp_path / "other_file"
    other.write_text("do not modify\n", encoding="utf-8")
    other.chmod(0o644)
    os.link(other, path)

    with pytest.raises(OSError, match="hard-linked"):
        append_event(_make_event(), path)

    assert other.read_text(encoding="utf-8") == "do not modify\n"
    assert other.stat().st_mode & 0o777 == 0o644


def test_directory_swap_after_verification_is_ignored(monkeypatch, tmp_path):
    """Writes follow the verified directory, not whatever the path now names."""

    from erislite.deception.odyssey import storage

    path = tmp_path / "odyssey" / "events.jsonl"
    path.parent.mkdir()

    moved = tmp_path / "moved"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    real_open_dir = storage._open_log_directory

    def open_then_swap(directory):
        dir_fd = real_open_dir(directory)
        directory.rename(moved)
        directory.symlink_to(elsewhere, target_is_directory=True)
        return dir_fd

    monkeypatch.setattr(storage, "_open_log_directory", open_then_swap)

    append_event(_make_event(), path)

    assert not (elsewhere / path.name).exists()
    assert (moved / path.name).exists()
