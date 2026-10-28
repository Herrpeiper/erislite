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
