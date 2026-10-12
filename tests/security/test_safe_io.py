import json
import os

import pytest

from erislite.security import safe_io


def test_write_private_json_creates_dirs_and_private_file(tmp_path):
    target = tmp_path / "a" / "b" / "log.json"

    safe_io.write_private_json(target, {"ok": True})

    assert json.loads(target.read_text()) == {"ok": True}
    assert target.stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "a").stat().st_mode & 0o777 == 0o700


def test_write_replaces_planted_symlink_instead_of_following_it(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("original")
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "out.json").symlink_to(victim)

    safe_io.write_private_text(logs / "out.json", "new")

    assert victim.read_text() == "original"
    assert not (logs / "out.json").is_symlink()
    assert (logs / "out.json").read_text() == "new"


def test_write_does_not_modify_hard_linked_inode(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("original")
    logs = tmp_path / "logs"
    logs.mkdir()
    os.link(victim, logs / "out.json")

    safe_io.write_private_text(logs / "out.json", "new")

    assert victim.read_text() == "original"


def test_untrusted_directory_symlink_is_refused(monkeypatch, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (tmp_path / "logs").symlink_to(elsewhere)

    monkeypatch.setattr(safe_io, "_trusted_owner", lambda uid: False)

    with pytest.raises(safe_io.UnsafePathError):
        safe_io.write_private_text(tmp_path / "logs" / "out.txt", "x")

    assert list(elsewhere.iterdir()) == []


def test_trusted_directory_symlink_is_followed(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "logs").symlink_to(real)

    safe_io.write_private_text(tmp_path / "logs" / "out.txt", "x")

    assert (real / "out.txt").read_text() == "x"


def test_write_sets_requested_mode(tmp_path):
    target = tmp_path / "profile.json"

    safe_io.write_private_json(target, {}, mode=0o444)

    assert target.stat().st_mode & 0o777 == 0o444


def test_private_text_writer_only_writes_on_success(tmp_path):
    target = tmp_path / "report.txt"

    with pytest.raises(RuntimeError):
        with safe_io.private_text_writer(target) as file:
            file.write("partial")
            raise RuntimeError("boom")

    assert not target.exists()

    with safe_io.private_text_writer(target) as file:
        file.write("done")

    assert target.read_text() == "done"


def test_read_regular_bytes_refuses_symlink(tmp_path):
    real = tmp_path / "real"
    real.write_text("x")
    link = tmp_path / "link"
    link.symlink_to(real)

    with pytest.raises(OSError):
        safe_io.read_regular_bytes(link)
