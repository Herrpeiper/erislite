from unittest.mock import Mock

from erislite.system import integrity


def test_explicit_profile_file_allowed(monkeypatch):
    monkeypatch.setitem(
        integrity.SCAN_PROFILES,
        "critical",
        ["/etc/passwd"],
    )

    assert integrity._path_in_profile("/etc/passwd", "critical")


def test_unrelated_file_rejected(monkeypatch):
    monkeypatch.setitem(
        integrity.SCAN_PROFILES,
        "critical",
        ["/etc/passwd"],
    )

    assert not integrity._path_in_profile(
        "/tmp/unrelated.txt",
        "critical",
    )


def test_recursive_directory_file_allowed():
    assert integrity._path_in_profile(
        "/etc/ssh/sshd_config.d/custom.conf",
        "system",
    )


def test_directory_prefix_bypass_rejected():
    assert not integrity._path_in_profile(
        "/etc/ssh-malicious/config",
        "system",
    )


def test_user_profile_rejects_another_user(monkeypatch):
    monkeypatch.setitem(
        integrity.SCAN_PROFILES,
        "user",
        ["/home/analyst/.bashrc"],
    )

    assert not integrity._path_in_profile(
        "/home/other/.bashrc",
        "user",
    )


def test_unknown_profile_rejected():
    assert not integrity._path_in_profile(
        "/etc/passwd",
        "nonexistent",
    )


def test_non_normalized_path_rejected():
    assert not integrity._path_in_profile(
        "/etc/ssh/../shadow",
        "system",
    )


def test_create_baseline_rejects_unknown_profile_before_collection(monkeypatch):
    collect = Mock()
    write = Mock()
    report = Mock()
    monkeypatch.setattr(integrity, "_collect_targets", collect)
    monkeypatch.setattr(integrity, "write_private_json", write)
    monkeypatch.setattr(integrity, "clear_screen", lambda: None)
    monkeypatch.setattr(integrity, "pause_return", lambda: None)
    monkeypatch.setattr(integrity.console, "print", report)

    integrity.create_baseline("nonexistent")

    collect.assert_not_called()
    write.assert_not_called()
    report.assert_called_once()
    assert "Unknown integrity profile" in str(report.call_args.args[0])


def test_scan_and_validation_reject_unknown_profile_before_read(monkeypatch):
    read = Mock(side_effect=FileNotFoundError)
    monkeypatch.setattr(integrity, "open", read, raising=False)
    monkeypatch.setattr(integrity, "get_os", lambda: "Linux")

    monkeypatch.setattr(integrity, "clear_screen", lambda: None)
    monkeypatch.setattr(integrity, "pause_return", lambda: None)
    monkeypatch.setattr(integrity.console, "print", Mock())

    profile = "nonexistent[/]"
    result = integrity.check_baseline_integrity(profile)
    scan_result = integrity.scan_integrity(profile, silent=True)

    assert result["status"] == "error"
    assert result["tags"] == ["baseline_check_error"]
    assert result["details"] == [f"Unknown integrity profile: {profile!r}"]
    assert scan_result == result
    assert integrity.scan_integrity(profile) == result
    read.assert_not_called()
