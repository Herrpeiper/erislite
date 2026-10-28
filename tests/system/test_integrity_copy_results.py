import hashlib
import json

from erislite.system import integrity


def _digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _prepare(monkeypatch, tmp_path):
    path = tmp_path / "baseline.json"
    digest = _digest("original")

    path.write_text(
        json.dumps(
            {
                "_metadata": {
                    "created_at": "2026-10-28T12:00:00",
                    "algorithm": "SHA-256",
                    "profile": "critical",
                    "monitored": ["/etc/passwd"],
                    "expected_absent": [],
                    "unavailable": [],
                },
                "hashes": {"/etc/passwd": digest},
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(integrity, "get_baseline_path", lambda profile: str(path))
    monkeypatch.setattr(integrity, "get_os", lambda: "Linux")
    monkeypatch.setattr(
        integrity,
        "_collect_targets",
        lambda profile: (["/etc/passwd"], []),
    )
    monkeypatch.setattr(
        integrity,
        "get_sha256",
        lambda path: (digest, None),
    )


def test_silent_scan_reports_suspicious_copy(monkeypatch, tmp_path):
    _prepare(monkeypatch, tmp_path)

    monkeypatch.setattr(
        integrity,
        "scan_for_copies",
        lambda baseline: [("/tmp/passwd.copy", "Exact copy of monitored file")],
    )

    result = integrity.scan_integrity(silent=True)

    assert result["status"] == "warning"
    assert "suspicious_file_copy" in result["tags"]
    assert "file_integrity_issue" not in result["tags"]
    assert any("/tmp/passwd.copy" in detail for detail in result["details"])


def test_copy_scan_limit_is_incomplete_not_detection(monkeypatch, tmp_path):
    _prepare(monkeypatch, tmp_path)

    monkeypatch.setattr(
        integrity,
        "scan_for_copies",
        lambda baseline: [("/tmp", "Copy scan stopped after 100 candidate files")],
    )

    result = integrity.scan_integrity(silent=True)

    assert result["status"] == "error"
    assert "integrity_scan_incomplete" in result["tags"]
    assert "suspicious_file_copy" not in result["tags"]


def test_clean_silent_scan_stays_ok(monkeypatch, tmp_path):
    _prepare(monkeypatch, tmp_path)

    monkeypatch.setattr(
        integrity,
        "scan_for_copies",
        lambda baseline: [],
    )

    result = integrity.scan_integrity(silent=True)

    assert result["status"] == "ok"
    assert "suspicious_file_copy" not in result["tags"]
