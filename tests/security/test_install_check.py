import os

from erislite.security import install_check


def _tree(tmp_path):
    root = tmp_path / "erislite_install"
    package = root / "erislite"
    package.mkdir(parents=True)
    (root / "main.py").write_text("")
    (package / "__init__.py").write_text("")
    return root


def test_non_root_is_never_blocked(tmp_path):
    root = _tree(tmp_path)

    assert install_check.find_unsafe_install_paths(root, euid=1000) == []


def test_foreign_owned_file_is_reported(monkeypatch, tmp_path):
    root = _tree(tmp_path)
    module = root / "erislite" / "__init__.py"
    real_lstat = os.lstat

    class Fake:
        def __init__(self, info):
            self._info = info

        def __getattr__(self, name):
            return getattr(self._info, name)

        st_uid = 1000

    def fake_lstat(path, *args, **kwargs):
        info = real_lstat(path, *args, **kwargs)
        return Fake(info) if os.fspath(path) == os.fspath(module) else info

    monkeypatch.setattr(install_check.os, "lstat", fake_lstat)
    monkeypatch.setattr(install_check, "_ancestor_issues", lambda root, uids: [])

    issues = install_check.find_unsafe_install_paths(root, euid=0)

    assert issues == [f"{module} is owned by uid 1000"]


def test_group_writable_code_is_reported(monkeypatch, tmp_path):
    root = _tree(tmp_path)
    module = root / "erislite" / "__init__.py"
    module.chmod(0o664)

    monkeypatch.setattr(install_check, "_ancestor_issues", lambda root, uids: [])
    monkeypatch.setattr(install_check, "_describe", _owner_agnostic(install_check._describe))

    issues = install_check.find_unsafe_install_paths(root, euid=0)

    assert any(str(module) in issue and "writable" in issue for issue in issues)


def test_clean_tree_has_no_issues(monkeypatch, tmp_path):
    root = _tree(tmp_path)
    for path in [root, root / "erislite", root / "main.py", root / "erislite" / "__init__.py"]:
        path.chmod(0o755 if path.is_dir() else 0o644)

    monkeypatch.setattr(install_check, "_ancestor_issues", lambda root, uids: [])
    monkeypatch.setattr(install_check, "_describe", _owner_agnostic(install_check._describe))

    assert install_check.find_unsafe_install_paths(root, euid=0) == []


def test_sticky_world_writable_ancestor_is_allowed():
    info = os.stat_result((0o41777, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    assert install_check._describe("/tmp", info, {0}) is None


def test_world_writable_ancestor_without_sticky_bit_is_reported():
    info = os.stat_result((0o40777, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    assert "writable" in install_check._describe("/srv", info, {0})


def _owner_agnostic(describe):
    """Treat the test runner's own files as root-owned."""

    def wrapper(path, info, trusted_uids):
        return describe(path, info, set(trusted_uids) | {info.st_uid})

    return wrapper
