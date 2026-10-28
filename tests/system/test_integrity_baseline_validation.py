"""Regression tests for EL-003: integrity baseline validation."""

import copy
import hashlib
import json

import pytest

from erislite.system import integrity


@pytest.fixture
def baseline_environment(tmp_path, monkeypatch):
    """Create an isolated, valid integrity baseline."""
    monitored_dir = tmp_path / "monitored"
    monitored_dir.mkdir()

    original = monitored_dir / "original.conf"
    original.write_text("trusted content", encoding="utf-8")

    second = monitored_dir / "second.conf"
    second.write_text("second trusted file", encoding="utf-8")

    original_path = str(original)
    second_path = str(second)

    # Configure the isolated critical profile for these test files.
    monkeypatch.setitem(
        integrity.SCAN_PROFILES,
        "critical",
        [original_path, second_path],
    )

    baseline_path = tmp_path / "integrity_baseline_critical.json"

    baseline = {
        "_metadata": {
            "created_at": "2026-10-28T12:00:00",
            "algorithm": "SHA-256",
            "profile": "critical",
            "monitored": [original_path, second_path],
            "expected_absent": [],
            "unavailable": [],
            "collection_errors": [],
        },
        "hashes": {
            original_path: hashlib.sha256(original.read_bytes()).hexdigest(),
            second_path: hashlib.sha256(second.read_bytes()).hexdigest(),
        },
    }

    monkeypatch.setattr(
        integrity,
        "get_baseline_path",
        lambda profile: str(baseline_path),
    )

    def save_baseline(data):
        baseline_path.write_text(
            json.dumps(data),
            encoding="utf-8",
        )

    save_baseline(baseline)

    return {
        "path": baseline_path,
        "baseline": baseline,
        "original": original_path,
        "second": second_path,
        "save": save_baseline,
    }


def validate_baseline(environment):
    """Run baseline validation using the isolated fixture."""
    return integrity.check_baseline_integrity("critical")


def assert_baseline_rejected(result):
    """Verify malformed baseline data is not accepted."""
    assert result["status"] != "ok"
    assert "baseline_tamper" in result["tags"]
    assert result["details"]


def test_valid_baseline_passes(baseline_environment):
    """A structurally valid baseline should pass."""
    result = validate_baseline(baseline_environment)

    assert result["status"] == "ok"
    assert "baseline_tamper" not in result["tags"]


def test_invalid_sha256_digest_rejected(baseline_environment):
    """SHA-256 records must contain valid hexadecimal digests."""
    env = baseline_environment
    data = copy.deepcopy(env["baseline"])

    data["hashes"][env["original"]] = "invalid_hash"

    env["save"](data)

    result = validate_baseline(env)

    assert_baseline_rejected(result)
    assert any("sha-256" in detail.lower() for detail in result["details"])


@pytest.mark.parametrize(
    "digest",
    [
        "",
        "abc123",
        "g" * 64,
        "0" * 63,
        "0" * 65,
        None,
        12345,
    ],
)
def test_malformed_digest_values_rejected(
    baseline_environment,
    digest,
):
    """Reject invalid digest lengths, characters, and types."""
    env = baseline_environment
    data = copy.deepcopy(env["baseline"])

    data["hashes"][env["original"]] = digest
    env["save"](data)

    assert_baseline_rejected(validate_baseline(env))


def test_duplicate_monitored_paths_rejected(baseline_environment):
    """Monitored paths must not contain duplicates."""
    env = baseline_environment
    data = copy.deepcopy(env["baseline"])

    data["_metadata"]["monitored"].append(env["original"])
    env["save"](data)

    result = validate_baseline(env)

    assert_baseline_rejected(result)
    assert any("duplicate monitored" in detail.lower() for detail in result["details"])


def test_duplicate_json_hash_keys_rejected(baseline_environment):
    """Duplicate JSON keys must not silently overwrite one another."""
    env = baseline_environment
    data = copy.deepcopy(env["baseline"])

    path = env["original"]
    digest = data["hashes"][path]

    duplicate_hashes = (
        "{"
        + json.dumps(path)
        + ":"
        + json.dumps(digest)
        + ","
        + json.dumps(path)
        + ":"
        + json.dumps("0" * 64)
        + "}"
    )

    raw = '{"_metadata":' + json.dumps(data["_metadata"]) + ',"hashes":' + duplicate_hashes + "}"

    env["path"].write_text(raw, encoding="utf-8")

    result = validate_baseline(env)

    assert_baseline_rejected(result)
    assert any("duplicate json key" in detail.lower() for detail in result["details"])


def test_unmonitored_hash_path_rejected(baseline_environment):
    """Hash records must correspond to monitored paths."""
    env = baseline_environment
    data = copy.deepcopy(env["baseline"])

    data["hashes"][str(env["path"].parent / "unknown.conf")] = "0" * 64

    env["save"](data)

    result = validate_baseline(env)

    assert_baseline_rejected(result)
    assert any("unmonitored" in detail.lower() for detail in result["details"])


def test_overlapping_hash_and_absent_rejected(baseline_environment):
    """One path cannot be both hashed and expected absent."""
    env = baseline_environment
    data = copy.deepcopy(env["baseline"])

    data["_metadata"]["expected_absent"].append(env["original"])
    env["save"](data)

    result = validate_baseline(env)

    assert_baseline_rejected(result)
    assert any("overlap" in detail.lower() for detail in result["details"])


def test_overlapping_hash_and_unavailable_rejected(
    baseline_environment,
):
    """A hashed path cannot also be marked unavailable."""
    env = baseline_environment
    data = copy.deepcopy(env["baseline"])

    data["_metadata"]["unavailable"].append(f"{env['original']}: permission denied")

    env["save"](data)

    result = validate_baseline(env)

    assert_baseline_rejected(result)
    assert any("overlap" in detail.lower() for detail in result["details"])


def test_missing_creation_metadata_rejected(baseline_environment):
    """Baseline creation metadata is required."""
    env = baseline_environment
    data = copy.deepcopy(env["baseline"])

    del data["_metadata"]["created_at"]
    env["save"](data)

    assert_baseline_rejected(validate_baseline(env))


def test_missing_monitored_metadata_rejected(baseline_environment):
    """A baseline requires its monitored-path inventory."""
    env = baseline_environment
    data = copy.deepcopy(env["baseline"])

    del data["_metadata"]["monitored"]
    env["save"](data)

    assert_baseline_rejected(validate_baseline(env))


def test_invalid_hash_algorithm_rejected(baseline_environment):
    """Only the expected SHA-256 algorithm should be accepted."""
    env = baseline_environment
    data = copy.deepcopy(env["baseline"])

    data["_metadata"]["algorithm"] = "MD5"
    env["save"](data)

    result = validate_baseline(env)

    assert_baseline_rejected(result)
    assert any("algorithm" in detail.lower() for detail in result["details"])


def test_mismatched_profile_rejected(baseline_environment):
    """Baseline metadata must match the requested profile."""
    env = baseline_environment
    data = copy.deepcopy(env["baseline"])

    data["_metadata"]["profile"] = "system"
    env["save"](data)

    assert_baseline_rejected(validate_baseline(env))


def test_duplicate_expected_absent_rejected(baseline_environment):
    """Expected-absent paths must be unique."""
    env = baseline_environment
    data = copy.deepcopy(env["baseline"])

    data["hashes"].pop(env["second"])
    data["_metadata"]["expected_absent"] = [
        env["second"],
        env["second"],
    ]

    env["save"](data)

    assert_baseline_rejected(validate_baseline(env))


def test_duplicate_unavailable_records_rejected(
    baseline_environment,
):
    """A path cannot have multiple unavailable records."""
    env = baseline_environment
    data = copy.deepcopy(env["baseline"])

    data["hashes"].pop(env["second"])
    data["_metadata"]["unavailable"] = [
        f"{env['second']}: permission denied",
        f"{env['second']}: read failed",
    ]

    env["save"](data)

    assert_baseline_rejected(validate_baseline(env))


def test_valid_unavailable_file_accepted(baseline_environment):
    """Previously unavailable files remain valid baseline records."""
    env = baseline_environment
    data = copy.deepcopy(env["baseline"])

    data["hashes"].pop(env["second"])
    data["_metadata"]["unavailable"] = [f"{env['second']}: permission denied"]

    env["save"](data)

    result = validate_baseline(env)

    assert result["status"] == "ok"
    assert "baseline_tamper" not in result["tags"]


def test_valid_expected_absent_file_accepted(baseline_environment):
    """An expected-absent path is a legitimate baseline state."""
    env = baseline_environment
    data = copy.deepcopy(env["baseline"])

    data["hashes"].pop(env["second"])
    data["_metadata"]["expected_absent"] = [env["second"]]

    env["save"](data)

    result = validate_baseline(env)

    assert result["status"] == "ok"


def test_unavailable_unmonitored_path_rejected(
    baseline_environment,
):
    """Unavailable records must reference monitored paths."""
    env = baseline_environment
    data = copy.deepcopy(env["baseline"])

    data["_metadata"]["unavailable"] = [
        str(env["path"].parent / "unknown.conf") + ": permission denied"
    ]

    env["save"](data)

    assert_baseline_rejected(validate_baseline(env))


def test_missing_hash_classification_rejected(
    baseline_environment,
):
    """Every monitored path must have exactly one baseline state."""
    env = baseline_environment
    data = copy.deepcopy(env["baseline"])

    data["hashes"].pop(env["second"])
    env["save"](data)

    result = validate_baseline(env)

    assert_baseline_rejected(result)
    assert any("coverage" in detail.lower() for detail in result["details"])


@pytest.mark.parametrize(
    "invalid_path",
    [
        "relative/path.conf",
        "../outside.conf",
        "/tmp/../etc/passwd",
        "/tmp/./config",
    ],
)
def test_invalid_monitored_paths_rejected(
    baseline_environment,
    invalid_path,
):
    """Reject paths that are not absolute and normalized."""
    env = baseline_environment
    data = copy.deepcopy(env["baseline"])

    data["_metadata"]["monitored"][0] = invalid_path
    data["hashes"][invalid_path] = data["hashes"].pop(env["original"])

    env["save"](data)

    assert_baseline_rejected(validate_baseline(env))


def test_malformed_json_rejected(baseline_environment):
    """Malformed JSON must not be accepted."""
    env = baseline_environment

    env["path"].write_text(
        '{"_metadata": invalid JSON',
        encoding="utf-8",
    )

    assert_baseline_rejected(validate_baseline(env))


def test_non_object_json_root_rejected(baseline_environment):
    """The baseline root must be a JSON object."""
    env = baseline_environment

    env["path"].write_text(
        '["not", "a", "baseline"]',
        encoding="utf-8",
    )

    assert_baseline_rejected(validate_baseline(env))


def test_malformed_metadata_rejected(baseline_environment):
    """Metadata must be a JSON object."""
    env = baseline_environment
    data = copy.deepcopy(env["baseline"])

    data["_metadata"] = ["invalid metadata"]
    env["save"](data)

    assert_baseline_rejected(validate_baseline(env))


def test_malformed_hash_structure_rejected(
    baseline_environment,
):
    """Hash records must be a JSON object."""
    env = baseline_environment
    data = copy.deepcopy(env["baseline"])

    data["hashes"] = ["invalid hash structure"]
    env["save"](data)

    assert_baseline_rejected(validate_baseline(env))


def test_missing_baseline_file_reports_error(
    baseline_environment,
):
    """Missing baseline files should report baseline_missing."""
    env = baseline_environment
    env["path"].unlink()

    result = validate_baseline(env)

    assert result["status"] == "error"
    assert "baseline_missing" in result["tags"]


def test_invalid_baseline_blocks_integrity_scan(
    baseline_environment,
    monkeypatch,
):
    """An invalid baseline must not be used to compare files."""
    env = baseline_environment
    data = copy.deepcopy(env["baseline"])

    data["hashes"][env["original"]] = "invalid"
    env["save"](data)

    monkeypatch.setattr(
        integrity,
        "get_os",
        lambda: "Linux",
    )

    result = integrity.scan_integrity(
        profile="critical",
        silent=True,
    )

    assert result["status"] != "ok"
    assert "baseline_tamper" in result["tags"]
    assert "file_integrity_issue" not in result["tags"]
