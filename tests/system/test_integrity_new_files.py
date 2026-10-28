"""Regression tests for EL-001: new and deleted monitored files."""

import hashlib
import json

import pytest

from erislite.system import integrity


@pytest.fixture
def integrity_environment(tmp_path, monkeypatch):
    """Create an isolated integrity baseline and monitored directory."""
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()

    original = monitored_dir / "original.conf"
    original.write_text("original content", encoding="utf-8")

    baseline_path = tmp_path / "integrity_baseline_system.json"

    original_hash = hashlib.sha256(original.read_bytes()).hexdigest()

    baseline_data = {
        "_metadata": {
            "created_at": "2026-10-28T12:00:00",
            "algorithm": "SHA-256",
            "profile": "system",
            "monitored": [str(original)],
            "expected_absent": [],
            "unavailable": [],
            "collection_errors": [],
        },
        "hashes": {
            str(original): original_hash,
        },
    }

    baseline_path.write_text(
        json.dumps(baseline_data),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        integrity,
        "get_baseline_path",
        lambda profile: str(baseline_path),
    )
    monkeypatch.setattr(integrity, "get_os", lambda: "Linux")
    monkeypatch.setitem(
        integrity.SCAN_PROFILES,
        "system",
        [str(monitored_dir) + "/"],
    )

    return monitored_dir, original


def test_new_file_detected_as_created(integrity_environment):
    """A new readable file must be classified as a creation."""
    monitored_dir, _ = integrity_environment

    new_file = monitored_dir / "new.conf"
    new_file.write_text("new configuration", encoding="utf-8")

    result = integrity.scan_integrity(
        profile="system",
        silent=True,
    )

    assert result["status"] == "warning"
    assert "file_integrity_issue" in result["tags"]
    assert any(
        str(new_file) in detail and "discovered after baseline" in detail
        for detail in result["details"]
    )


def test_deleted_file_detected_as_missing(integrity_environment):
    """A previously hashed file disappearing is a change."""
    _, original = integrity_environment
    original.unlink()

    result = integrity.scan_integrity(
        profile="system",
        silent=True,
    )

    assert result["status"] == "warning"
    assert "file_integrity_issue" in result["tags"]
    assert any(str(original) in detail and "missing" in detail for detail in result["details"])


def test_unreadable_new_file_is_incomplete(
    integrity_environment,
    monkeypatch,
):
    """A new file that cannot be hashed must remain unverified."""
    monitored_dir, _ = integrity_environment

    new_file = monitored_dir / "restricted.conf"
    new_file.write_text("restricted", encoding="utf-8")

    original_hash_function = integrity.get_sha256

    def simulated_hash(path):
        if path == str(new_file):
            return None, "permission denied: simulated"

        return original_hash_function(path)

    monkeypatch.setattr(
        integrity,
        "get_sha256",
        simulated_hash,
    )

    result = integrity.scan_integrity(
        profile="system",
        silent=True,
    )

    assert result["status"] == "error"
    assert "integrity_scan_incomplete" in result["tags"]
    assert "file_integrity_issue" not in result["tags"]
    assert any(
        str(new_file) in detail and "could not be inspected" in detail
        for detail in result["details"]
    )


def test_collection_failure_does_not_claim_deletion(
    integrity_environment,
    monkeypatch,
):
    """An incomplete target collection must not confirm a deletion."""
    _, original = integrity_environment

    monkeypatch.setattr(
        integrity,
        "_collect_targets",
        lambda profile: ([], ["simulated directory read failure"]),
    )

    result = integrity.scan_integrity(
        profile="system",
        silent=True,
    )

    assert result["status"] == "error"
    assert "integrity_scan_incomplete" in result["tags"]
    assert "file_integrity_issue" not in result["tags"]
    assert not any(
        str(original) in detail and "is missing" in detail for detail in result["details"]
    )


def test_empty_directory_detects_deleted_baseline_file(
    integrity_environment,
):
    """A successfully scanned empty directory must detect deletions."""
    _, original = integrity_environment
    original.unlink()

    result = integrity.scan_integrity(
        profile="system",
        silent=True,
    )

    assert result["status"] == "warning"
    assert any(str(original) in detail and "is missing" in detail for detail in result["details"])


def test_unchanged_file_remains_clean(integrity_environment):
    """Unchanged baselined files should remain clean."""
    _, original = integrity_environment

    result = integrity.scan_integrity(
        profile="system",
        silent=True,
    )

    assert result["status"] == "ok"
    assert "file_integrity_issue" not in result["tags"]
    assert not any(str(original) in detail and "modified" in detail for detail in result["details"])
