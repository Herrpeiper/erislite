# Project: ErisLITE
# Module: test_integrity_baseline_unavailable.py
# Version: 1.6.0
# License: MIT
# Description: Integrity baseline unavailable-file regression tests.

import json

from erislite.system import integrity


def prepare_baseline(monkeypatch, tmp_path, unavailable=True):
    baseline_path = tmp_path / "baseline.json"

    metadata = {
        "created_at": "2026-10-21T12:00:00",
        "profile": "critical",
        "monitored": ["/etc/passwd", "/etc/shadow"],
        "expected_absent": [],
        "unavailable": (["/etc/shadow: permission denied"] if unavailable else []),
    }

    baseline_path.write_text(
        json.dumps(
            {
                "_metadata": metadata,
                "hashes": {"/etc/passwd": "original-hash"},
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        integrity,
        "get_baseline_path",
        lambda profile: str(baseline_path),
    )
    monkeypatch.setattr(integrity, "get_os", lambda: "Linux")
    monkeypatch.setattr(
        integrity,
        "_collect_targets",
        lambda profile: (["/etc/passwd", "/etc/shadow"], []),
    )

    return baseline_path


def test_unavailable_path_metadata():
    metadata = {
        "monitored": ["/etc/shadow", "/etc/passwd"],
        "unavailable": [
            "/etc/shadow: permission denied",
        ],
    }

    assert integrity._baseline_unavailable_paths(metadata) == {"/etc/shadow"}


def test_unavailable_file_remains_incomplete(monkeypatch, tmp_path):
    prepare_baseline(monkeypatch, tmp_path)

    def fake_hash(path):
        if path == "/etc/passwd":
            return "original-hash", None
        return None, "permission denied"

    monkeypatch.setattr(integrity, "get_sha256", fake_hash)

    result = integrity.scan_integrity(silent=True)

    assert result["status"] == "error"
    assert "integrity_scan_incomplete" in result["tags"]
    assert "file_integrity_issue" not in result["tags"]
    assert any("remains unverified" in detail for detail in result["details"])


def test_previously_unavailable_file_now_readable(monkeypatch, tmp_path):
    prepare_baseline(monkeypatch, tmp_path)

    def fake_hash(path):
        if path == "/etc/passwd":
            return "original-hash", None
        return "new-readable-hash", None

    monkeypatch.setattr(integrity, "get_sha256", fake_hash)

    result = integrity.scan_integrity(silent=True)

    assert result["status"] == "error"
    assert "integrity_scan_incomplete" in result["tags"]
    assert any("recreate the baseline" in detail for detail in result["details"])


def test_unexpected_baseline_omission_still_detected(monkeypatch, tmp_path):
    prepare_baseline(monkeypatch, tmp_path, unavailable=False)

    def fake_hash(path):
        if path == "/etc/passwd":
            return "original-hash", None
        return "readable-but-unrecorded", None

    monkeypatch.setattr(integrity, "get_sha256", fake_hash)

    result = integrity.scan_integrity(silent=True)

    assert result["status"] in {"warning", "error"}
    assert "baseline_tamper" in result["tags"] or "integrity_scan_incomplete" in result["tags"]


def test_existing_hash_change_remains_detected(monkeypatch, tmp_path):
    prepare_baseline(monkeypatch, tmp_path)

    def fake_hash(path):
        if path == "/etc/passwd":
            return "modified-hash", None
        return None, "permission denied"

    monkeypatch.setattr(integrity, "get_sha256", fake_hash)

    result = integrity.scan_integrity(silent=True)

    assert result["status"] == "warning"
    assert "file_integrity_issue" in result["tags"]
    assert "integrity_scan_incomplete" in result["tags"]
    assert any("/etc/passwd was modified" in detail for detail in result["details"])
