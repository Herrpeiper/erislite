import json

from erislite.system import integrity


def test_get_sha256_success(tmp_path):
    test_file = tmp_path / "sample.txt"
    test_file.write_text("hello world")

    digest, error = integrity.get_sha256(str(test_file))

    assert digest is not None
    assert error is None


def test_get_sha256_missing(tmp_path):
    missing = tmp_path / "missing.txt"

    digest, error = integrity.get_sha256(str(missing))

    assert digest is None
    assert error == "missing"


def test_get_sha256_permission_error(monkeypatch):
    def fail_open(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr("builtins.open", fail_open)

    digest, error = integrity.get_sha256("/etc/shadow")

    assert digest is None
    assert error is not None
    assert "permission denied" in error


def test_collect_targets_keeps_missing_explicit_file(
    monkeypatch,
    tmp_path,
):
    missing = tmp_path / "missing.conf"

    monkeypatch.setattr(
        integrity,
        "SCAN_PROFILES",
        {
            "test": [
                str(missing),
            ]
        },
    )

    targets, errors = integrity._collect_targets("test")

    assert str(missing) in targets
    assert errors == []


def test_collect_targets_reports_directory_error(
    monkeypatch,
    tmp_path,
):
    target_dir = tmp_path / "tree"
    target_dir.mkdir()

    monkeypatch.setattr(
        integrity,
        "SCAN_PROFILES",
        {
            "test": [
                str(target_dir) + "/",
            ]
        },
    )

    def fake_walk(path, onerror=None):
        if onerror:
            onerror(
                PermissionError(
                    13,
                    "Permission denied",
                    path,
                )
            )
        return []

    monkeypatch.setattr(
        integrity.os,
        "walk",
        fake_walk,
    )

    targets, errors = integrity._collect_targets("test")

    assert targets == []
    assert errors
    assert "Permission denied" in errors[0]


def test_scan_integrity_missing_file_is_warning(
    monkeypatch,
    tmp_path,
):
    baseline_path = tmp_path / "baseline.json"
    monitored_file = tmp_path / "important.conf"

    payload = {
        "_metadata": {
            "created_at": "2026-09-23T12:00:00",
            "algorithm": "SHA-256",
            "profile": "critical",
            "monitored": [str(monitored_file)],
            "unavailable": [],
        },
        "hashes": {
            str(monitored_file): "expectedhash",
        },
    }

    baseline_path.write_text(
        json.dumps(payload)
    )

    monkeypatch.setattr(
        integrity,
        "BASELINE_PATH",
        baseline_path,
    )
    monkeypatch.setattr(
        integrity,
        "get_os",
        lambda: "Linux",
    )
    monkeypatch.setattr(
        integrity,
        "_collect_targets",
        lambda profile: (
            [str(monitored_file)],
            [],
        ),
    )

    result = integrity.scan_integrity(
        profile="critical",
        silent=True,
    )

    assert result["status"] == "warning"
    assert "file_integrity_issue" in result["tags"]
    assert any(
        "is missing" in detail
        for detail in result["details"]
    )


def test_scan_integrity_unreadable_file_is_error(
    monkeypatch,
    tmp_path,
):
    baseline_path = tmp_path / "baseline.json"
    monitored_file = tmp_path / "important.conf"

    payload = {
        "_metadata": {
            "created_at": "2026-09-23T12:00:00",
            "algorithm": "SHA-256",
            "profile": "critical",
            "monitored": [str(monitored_file)],
            "unavailable": [],
        },
        "hashes": {
            str(monitored_file): "expectedhash",
        },
    }

    baseline_path.write_text(
        json.dumps(payload)
    )

    monkeypatch.setattr(
        integrity,
        "BASELINE_PATH",
        baseline_path,
    )
    monkeypatch.setattr(
        integrity,
        "get_os",
        lambda: "Linux",
    )
    monkeypatch.setattr(
        integrity,
        "_collect_targets",
        lambda profile: (
            [str(monitored_file)],
            [],
        ),
    )
    monkeypatch.setattr(
        integrity,
        "get_sha256",
        lambda path: (
            None,
            "permission denied",
        ),
    )

    result = integrity.scan_integrity(
        profile="critical",
        silent=True,
    )

    assert result["status"] == "error"
    assert "integrity_scan_incomplete" in result["tags"]
    assert any(
        "could not be inspected" in detail
        for detail in result["details"]
    )


def test_scan_integrity_modified_and_incomplete(
    monkeypatch,
    tmp_path,
):
    baseline_path = tmp_path / "baseline.json"

    changed = tmp_path / "changed.conf"
    unreadable = tmp_path / "unreadable.conf"

    payload = {
        "_metadata": {
            "created_at": "2026-09-23T12:00:00",
            "algorithm": "SHA-256",
            "profile": "critical",
            "monitored": [
                str(changed),
                str(unreadable),
            ],
            "unavailable": [],
        },
        "hashes": {
            str(changed): "oldhash",
            str(unreadable): "expectedhash",
        },
    }

    baseline_path.write_text(
        json.dumps(payload)
    )

    monkeypatch.setattr(
        integrity,
        "BASELINE_PATH",
        baseline_path,
    )
    monkeypatch.setattr(
        integrity,
        "get_os",
        lambda: "Linux",
    )
    monkeypatch.setattr(
        integrity,
        "_collect_targets",
        lambda profile: (
            [
                str(changed),
                str(unreadable),
            ],
            [],
        ),
    )

    def fake_hash(path):
        if path == str(changed):
            return "newhash", None

        return None, "permission denied"

    monkeypatch.setattr(
        integrity,
        "get_sha256",
        fake_hash,
    )

    result = integrity.scan_integrity(
        profile="critical",
        silent=True,
    )

    assert result["status"] == "warning"
    assert "file_integrity_issue" in result["tags"]
    assert "integrity_scan_incomplete" in result["tags"]


def test_scan_integrity_target_collection_failure(
    monkeypatch,
    tmp_path,
):
    baseline_path = tmp_path / "baseline.json"

    payload = {
        "_metadata": {
            "created_at": "2026-09-23T12:00:00",
            "algorithm": "SHA-256",
            "profile": "critical",
            "monitored": ["/etc/example"],
            "unavailable": [],
        },
        "hashes": {
            "/etc/example": "expectedhash",
        },
    }

    baseline_path.write_text(
        json.dumps(payload)
    )

    monkeypatch.setattr(
        integrity,
        "BASELINE_PATH",
        baseline_path,
    )
    monkeypatch.setattr(
        integrity,
        "get_os",
        lambda: "Linux",
    )
    monkeypatch.setattr(
        integrity,
        "_collect_targets",
        lambda profile: (
            [],
            ["Permission denied"],
        ),
    )

    result = integrity.scan_integrity(
        profile="critical",
        silent=True,
    )

    assert result["status"] == "error"
    assert "integrity_scan_incomplete" in result["tags"]
    assert any(
        "target collection incomplete" in detail.lower()
        for detail in result["details"]
    )
