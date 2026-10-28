import hashlib
import os

from erislite.system import integrity


def test_regular_file_hashes_correctly(tmp_path):
    path = tmp_path / "regular.txt"
    path.write_bytes(b"ErisLITE integrity test")

    digest, error = integrity.get_sha256(str(path))

    assert error is None
    assert digest == hashlib.sha256(b"ErisLITE integrity test").hexdigest()


def test_missing_file_returns_missing(tmp_path):
    path = tmp_path / "nonexistent.txt"

    digest, error = integrity.get_sha256(str(path))

    assert digest is None
    assert error == "missing"


def test_symlink_is_refused(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("secret", encoding="utf-8")

    link = tmp_path / "linked.txt"
    link.symlink_to(target)

    digest, error = integrity.get_sha256(str(link))

    assert digest is None
    assert error == "symbolic link refused"


def test_fifo_is_refused_without_blocking(tmp_path):
    fifo = tmp_path / "test.fifo"
    os.mkfifo(fifo)

    digest, error = integrity.get_sha256(str(fifo))

    assert digest is None
    assert error == "not a regular file"


def test_empty_regular_file_hashes_correctly(tmp_path):
    path = tmp_path / "empty.txt"
    path.write_bytes(b"")

    digest, error = integrity.get_sha256(str(path))

    assert error is None
    assert digest == hashlib.sha256(b"").hexdigest()


def test_file_change_during_hashing_is_rejected(monkeypatch, tmp_path):
    path = tmp_path / "changing.txt"
    path.write_bytes(b"original")

    original_fstat = integrity.os.fstat
    calls = 0

    def changed_fstat(fd):
        nonlocal calls
        calls += 1
        info = original_fstat(fd)

        if calls == 2:
            path.write_bytes(b"modified content")
            return original_fstat(fd)

        return info

    monkeypatch.setattr(integrity.os, "fstat", changed_fstat)

    digest, error = integrity.get_sha256(str(path))

    assert digest is None
    assert error == "file changed during hashing"
