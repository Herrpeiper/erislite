from pathlib import Path

from erislite.security import import_guard


def test_pythonpath_unset_is_clean(monkeypatch):
    monkeypatch.delenv("PYTHONPATH", raising=False)

    issues = import_guard.check_pythonpath()

    assert issues == []


def test_pythonpath_set_is_flagged(monkeypatch):
    monkeypatch.setenv(
        "PYTHONPATH",
        "/tmp/malicious",
    )

    issues = import_guard.check_pythonpath()

    assert issues
    assert any(
        "PYTHONPATH is set" in issue
        for issue in issues
    )


def test_sys_path_tmp_is_flagged(monkeypatch):
    monkeypatch.setattr(
        import_guard.sys,
        "path",
        [
            "/usr/lib/python3",
            "/tmp/evil",
        ],
    )

    issues = import_guard.check_sys_path()

    assert issues
    assert any(
        "/tmp/evil" in issue
        for issue in issues
    )


def test_sys_path_dev_shm_is_flagged(monkeypatch):
    monkeypatch.setattr(
        import_guard.sys,
        "path",
        [
            "/usr/lib/python3",
            "/dev/shm/py",
        ],
    )

    issues = import_guard.check_sys_path()

    assert issues
    assert any(
        "/dev/shm/py" in issue
        for issue in issues
    )


def test_sys_path_normal_location_is_clean(monkeypatch):
    monkeypatch.setattr(
        import_guard.sys,
        "path",
        [
            "/usr/lib/python3",
            "/usr/local/lib/python3",
        ],
    )

    issues = import_guard.check_sys_path()

    assert issues == []


def test_shadow_file_is_detected(
    monkeypatch,
    tmp_path,
):
    fake_module = tmp_path / "psutil.py"
    fake_module.write_text(
        "# fake psutil module\n"
    )

    monkeypatch.chdir(tmp_path)

    issues = import_guard.check_shadow_files()

    assert issues
    assert any(
        "psutil.py" in issue
        for issue in issues
    )


def test_shadow_package_is_detected(
    monkeypatch,
    tmp_path,
):
    fake_package = tmp_path / "rich"
    fake_package.mkdir()

    monkeypatch.chdir(tmp_path)

    issues = import_guard.check_shadow_files()

    assert issues
    assert any(
        "rich" in issue
        for issue in issues
    )


def test_clean_cwd_has_no_shadow_files(
    monkeypatch,
    tmp_path,
):
    monkeypatch.chdir(tmp_path)

    issues = import_guard.check_shadow_files()

    assert issues == []


def test_project_root_skips_shadow_check(
    monkeypatch,
):
    monkeypatch.chdir(
        import_guard.PROJECT_ROOT
    )

    issues = import_guard.check_shadow_files()

    assert issues == []


def test_import_environment_clean(
    monkeypatch,
    tmp_path,
):
    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.chdir(tmp_path)

    monkeypatch.setattr(
        import_guard.sys,
        "path",
        [
            "/usr/lib/python3",
            "/usr/local/lib/python3",
        ],
    )

    result = import_guard.check_import_environment()

    assert result["status"] == "ok"
    assert result["details"] == []
    assert result["tags"] == []


def test_import_environment_suspicious(
    monkeypatch,
    tmp_path,
):
    fake_module = tmp_path / "psutil.py"
    fake_module.write_text(
        "# fake psutil module\n"
    )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(
        "PYTHONPATH",
        "/tmp/malicious",
    )
    monkeypatch.setattr(
        import_guard.sys,
        "path",
        [
            "/tmp/malicious",
        ],
    )

    result = import_guard.check_import_environment()

    assert result["status"] == "warning"
    assert (
        "import_environment_suspicious"
        in result["tags"]
    )
    assert result["details"]
