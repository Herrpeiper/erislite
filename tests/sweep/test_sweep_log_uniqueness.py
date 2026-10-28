import json

from erislite.sweep import threat_sweep


def test_historical_sweep_logs_do_not_collide(monkeypatch, tmp_path):
    log_dir = tmp_path / "history"
    log_dir.mkdir()

    latest_file = tmp_path / "last_sweep.json"

    monkeypatch.setattr(threat_sweep, "SWEEP_LOG_DIR", log_dir)
    monkeypatch.setattr(threat_sweep, "LAST_SWEEP_FILE", latest_file)

    results = {
        "integrity": {
            "status": "ok",
            "tags": [],
            "details": [],
        }
    }

    profile = {"hostname": "test-host"}

    # Both calls occur within the same second.
    threat_sweep._save_sweep(results, "critical", profile, [])
    threat_sweep._save_sweep(results, "critical", profile, [])

    history_files = sorted(log_dir.glob("sweep_log_*.json"))

    assert len(history_files) == 2
    assert history_files[0].name != history_files[1].name

    for path in history_files:
        with path.open("r", encoding="utf-8") as file:
            snapshot = json.load(file)

        assert snapshot["hostname"] == "test-host"
        assert snapshot["profile"] == "critical"

    assert latest_file.exists()
