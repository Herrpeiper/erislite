# Project: ErisLITE
# Module: test_coverage_persistence.py
# Version: 1.6.0
# License: MIT
# Description: Historical coverage metadata persistence tests.

import json

from erislite.results import make_result
from erislite.sweep import threat_sweep as sweep


def capture_saved_sweep(monkeypatch, tmp_path, results):
    saved = []

    def fake_write(path, payload, **kwargs):
        # Simulate serialization and preserve the saved payload.
        saved.append((path, json.loads(json.dumps(payload))))

    monkeypatch.setattr(sweep, "write_private_json", fake_write)
    monkeypatch.setattr(sweep, "LAST_SWEEP_FILE", tmp_path / "last_sweep.json")
    monkeypatch.setattr(sweep, "SWEEP_LOG_DIR", tmp_path)

    sweep._save_sweep(
        results,
        "standard",
        {"hostname": "test-host"},
        {
            "new": [],
            "changed": [],
            "persisting": [],
            "resolved": [],
        },
    )

    assert len(saved) == 2
    assert saved[0][1] == saved[1][1]

    return saved[0][1]


def test_saves_complete_coverage(monkeypatch, tmp_path):
    summary = capture_saved_sweep(
        monkeypatch,
        tmp_path,
        {
            "listeners": make_result("ok"),
            "firewall": make_result("ok"),
        },
    )

    assert summary["coverage"]["complete"] == 2
    assert summary["coverage"]["partial"] == 0
    assert summary["coverage"]["failed"] == 0
    assert summary["coverage"]["total"] == 2
    assert summary["scored_modules"] == ["firewall", "listeners"]
    assert summary["scoring_schema_version"] == 1


def test_saves_partial_and_failed_coverage(monkeypatch, tmp_path):
    summary = capture_saved_sweep(
        monkeypatch,
        tmp_path,
        {
            "integrity": make_result("error", tags=["baseline_missing"]),
            "listeners": make_result("warning", tags=["suspicious_listener"]),
            "firewall": make_result("warning", tags=["firewall_permission_denied"]),
        },
    )

    assert summary["coverage"]["complete"] == 1
    assert summary["coverage"]["partial"] == 1
    assert summary["coverage"]["failed"] == 1

    assert summary["coverage"]["partial_modules"] == ["firewall"]
    assert summary["coverage"]["failed_modules"] == ["integrity"]

    assert summary["scored_modules"] == ["listeners"]
    assert summary["risk_score"] == 15
    assert summary["risk_max"] == 15


def test_partial_verified_risk_is_recorded(monkeypatch, tmp_path):
    summary = capture_saved_sweep(
        monkeypatch,
        tmp_path,
        {
            "integrity": make_result(
                "warning",
                tags=[
                    "integrity_scan_incomplete",
                    "file_integrity_issue",
                ],
            )
        },
    )

    assert summary["coverage"]["partial"] == 1
    assert summary["scored_modules"] == ["integrity"]
    assert summary["risk_score"] == 20
    assert summary["risk_max"] == 20


def test_existing_snapshot_fields_preserved(monkeypatch, tmp_path):
    summary = capture_saved_sweep(
        monkeypatch,
        tmp_path,
        {"listeners": make_result("ok")},
    )

    for field in (
        "timestamp",
        "hostname",
        "profile",
        "risk_score",
        "risk_max",
        "risk_percent",
        "tags",
        "priorities",
        "changes",
        "results",
    ):
        assert field in summary
