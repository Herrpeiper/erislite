import json
import os

from erislite.system import integrity


def _write_baseline(
    baseline_path,
    *,
    profile="critical",
    monitored=None,
    hashes=None,
    expected_absent=None,
    unavailable=None,
    collection_errors=None,
):
    payload = {
        "_metadata": {
            "created_at": "2026-09-23T12:00:00",
            "algorithm": "SHA-256",
            "profile": profile,
            "monitored": monitored or [],
            "expected_absent": expected_absent or [],
            "unavailable": unavailable or [],
            "collection_errors": collection_errors or [],
        },
        "hashes": hashes or {},
    }

    baseline_path.write_text(json.dumps(payload))


def _patch_baseline_path(
    monkeypatch,
    baseline_path,
):
    monkeypatch.setattr(
        integrity,
        "get_baseline_path",
        lambda profile: str(baseline_path),
    )


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

    monkeypatch.setattr(
        "builtins.open",
        fail_open,
    )

    digest, error = integrity.get_sha256("/etc/shadow")

    assert digest is None
    assert error is not None
    assert "permission denied" in error


def test_baseline_paths_are_profile_specific():
    critical = integrity.get_baseline_path("critical")
    system = integrity.get_baseline_path("system")
    user = integrity.get_baseline_path("user")

    assert critical != system
    assert critical != user
    assert system != user

    assert critical.endswith("integrity_baseline_critical.json")
    assert system.endswith("integrity_baseline_system.json")
    assert user.endswith("integrity_baseline_user.json")


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

    _write_baseline(
        baseline_path,
        monitored=[str(monitored_file)],
        hashes={
            str(monitored_file): "expectedhash",
        },
    )

    _patch_baseline_path(
        monkeypatch,
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

    assert any("is missing" in detail for detail in result["details"])


def test_scan_integrity_unreadable_file_is_error(
    monkeypatch,
    tmp_path,
):
    baseline_path = tmp_path / "baseline.json"
    monitored_file = tmp_path / "important.conf"

    _write_baseline(
        baseline_path,
        monitored=[str(monitored_file)],
        hashes={
            str(monitored_file): "expectedhash",
        },
    )

    _patch_baseline_path(
        monkeypatch,
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

    assert any("could not be inspected" in detail for detail in result["details"])


def test_scan_integrity_modified_and_incomplete(
    monkeypatch,
    tmp_path,
):
    baseline_path = tmp_path / "baseline.json"

    changed = tmp_path / "changed.conf"
    unreadable = tmp_path / "unreadable.conf"

    _write_baseline(
        baseline_path,
        monitored=[
            str(changed),
            str(unreadable),
        ],
        hashes={
            str(changed): "oldhash",
            str(unreadable): "expectedhash",
        },
    )

    _patch_baseline_path(
        monkeypatch,
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

    _write_baseline(
        baseline_path,
        monitored=["/etc/example"],
        hashes={
            "/etc/example": "expectedhash",
        },
    )

    _patch_baseline_path(
        monkeypatch,
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

    assert any("target collection incomplete" in detail.lower() for detail in result["details"])


def test_scan_integrity_expected_absent_is_ok(
    monkeypatch,
    tmp_path,
):
    baseline_path = tmp_path / "baseline.json"

    present = tmp_path / "profile"
    absent = tmp_path / "authorized_keys"

    present.write_text("profile data")

    present_hash, error = integrity.get_sha256(str(present))

    assert error is None

    _write_baseline(
        baseline_path,
        monitored=[
            str(present),
            str(absent),
        ],
        hashes={
            str(present): present_hash,
        },
        expected_absent=[
            str(absent),
        ],
    )

    _patch_baseline_path(
        monkeypatch,
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
                str(present),
                str(absent),
            ],
            [],
        ),
    )

    result = integrity.scan_integrity(
        profile="critical",
        silent=True,
    )

    assert result["status"] == "ok"
    assert result["tags"] == []


def test_scan_integrity_expected_absent_created(
    monkeypatch,
    tmp_path,
):
    baseline_path = tmp_path / "baseline.json"

    present = tmp_path / "profile"
    appeared = tmp_path / "authorized_keys"

    present.write_text("profile data")
    appeared.write_text("ssh-rsa example")

    present_hash, error = integrity.get_sha256(str(present))

    assert error is None

    _write_baseline(
        baseline_path,
        monitored=[
            str(present),
            str(appeared),
        ],
        hashes={
            str(present): present_hash,
        },
        expected_absent=[
            str(appeared),
        ],
    )

    _patch_baseline_path(
        monkeypatch,
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
                str(present),
                str(appeared),
            ],
            [],
        ),
    )

    result = integrity.scan_integrity(
        profile="critical",
        silent=True,
    )

    assert result["status"] == "warning"
    assert "file_integrity_issue" in result["tags"]

    assert any("appeared but was absent" in detail for detail in result["details"])


def test_scan_integrity_expected_absent_broken_symlink(
    monkeypatch,
    tmp_path,
):
    baseline_path = tmp_path / "baseline.json"

    present = tmp_path / "profile"
    link = tmp_path / "authorized_keys"

    present.write_text("profile data")

    link.symlink_to(tmp_path / "missing_target")

    present_hash, error = integrity.get_sha256(str(present))

    assert error is None

    _write_baseline(
        baseline_path,
        monitored=[
            str(present),
            str(link),
        ],
        hashes={
            str(present): present_hash,
        },
        expected_absent=[
            str(link),
        ],
    )

    _patch_baseline_path(
        monkeypatch,
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
                str(present),
                str(link),
            ],
            [],
        ),
    )

    result = integrity.scan_integrity(
        profile="critical",
        silent=True,
    )

    assert result["status"] == "warning"
    assert "file_integrity_issue" in result["tags"]

    assert any("broken symbolic link" in detail for detail in result["details"])


def test_baseline_profile_mismatch(
    monkeypatch,
    tmp_path,
):
    baseline_path = tmp_path / "baseline.json"

    monitored = tmp_path / "important.conf"

    _write_baseline(
        baseline_path,
        profile="critical",
        monitored=[str(monitored)],
        hashes={
            str(monitored): "expectedhash",
        },
    )

    _patch_baseline_path(
        monkeypatch,
        baseline_path,
    )

    result = integrity.check_baseline_integrity(profile="system")

    assert result["status"] == "warning"
    assert "baseline_tamper" in result["tags"]

    assert any("does not match" in detail for detail in result["details"])


def _baseline_for(tmp_path, content=b"root:x:0:0:root:/root:/bin/bash\n"):
    source = tmp_path / "etc_passwd"
    source.write_bytes(content)
    digest = integrity.get_sha256(str(source))[0]
    return {"/etc/passwd": digest}, content


def test_scan_for_copies_finds_exact_copy(tmp_path):
    baseline, content = _baseline_for(tmp_path)
    root = tmp_path / "scan"
    (root / "stash").mkdir(parents=True)
    (root / "stash" / "passwd.bak").write_bytes(content)

    found = integrity.scan_for_copies(baseline, roots=(str(root),))

    assert found == [(str(root / "stash" / "passwd.bak"), "Exact copy of monitored file")]


def test_scan_for_copies_does_not_follow_symlink_loops(tmp_path):
    baseline, content = _baseline_for(tmp_path)
    root = tmp_path / "scan"
    root.mkdir()
    (root / "loop").symlink_to("..")
    (root / "to_root").symlink_to("/")
    (root / "passwd_link").symlink_to(tmp_path / "etc_passwd")

    # Completes promptly and ignores symlinked files and directories.
    assert integrity.scan_for_copies(baseline, roots=(str(root),)) == []


def test_scan_for_copies_skips_fifos(tmp_path):
    baseline, _ = _baseline_for(tmp_path)
    root = tmp_path / "scan"
    root.mkdir()
    os.mkfifo(root / "shadow_pipe")

    assert integrity.scan_for_copies(baseline, roots=(str(root),)) == []


def test_scan_for_copies_stops_at_candidate_limit(tmp_path):
    baseline, _ = _baseline_for(tmp_path)
    root = tmp_path / "scan"
    root.mkdir()

    for index in range(5):
        (root / f"passwd{index}").write_text("x")

    found = integrity.scan_for_copies(baseline, roots=(str(root),), max_candidates=3)

    assert found[-1][1] == "Copy scan stopped after 3 candidate files"