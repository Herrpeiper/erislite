from types import SimpleNamespace

from erislite.accounts import users


def make_user(
    name,
    uid,
    home="/home/test",
    shell="/bin/bash",
):
    return SimpleNamespace(
        pw_name=name,
        pw_uid=uid,
        pw_dir=home,
        pw_shell=shell,
    )


def setup_linux(monkeypatch, accounts, valid_shells=None):
    monkeypatch.setattr(users, "get_os", lambda: "Linux")
    monkeypatch.setattr(users.pwd, "getpwall", lambda: accounts)

    monkeypatch.setattr(
        users,
        "_load_valid_shells",
        lambda: valid_shells or {
            "/bin/bash",
            "/bin/sh",
            "/usr/bin/zsh",
        },
    )


def test_normal_user_is_clean(monkeypatch):
    setup_linux(
        monkeypatch,
        [
            make_user(
                "alice",
                1000,
                "/home/alice",
                "/bin/bash",
            )
        ],
    )

    result = users.run_user_scan(silent=True)

    assert result == {
        "status": "ok",
        "details": [],
        "tags": [],
    }


def test_root_account_is_not_flagged(monkeypatch):
    setup_linux(
        monkeypatch,
        [
            make_user(
                "root",
                0,
                "/root",
                "/bin/bash",
            )
        ],
    )

    result = users.run_user_scan(silent=True)

    assert result["status"] == "ok"


def test_uid_zero_clone_is_flagged(monkeypatch):
    setup_linux(
        monkeypatch,
        [
            make_user(
                "evilroot",
                0,
                "/root2",
                "/bin/bash",
            )
        ],
    )

    result = users.run_user_scan(silent=True)

    assert result["status"] == "warning"
    assert "uid0_clone" in result["tags"]
    assert "suspicious_login" in result["tags"]


def test_low_uid_interactive_shell_is_flagged(monkeypatch):
    setup_linux(
        monkeypatch,
        [
            make_user(
                "serviceish",
                500,
                "/var/lib/serviceish",
                "/bin/bash",
            )
        ],
    )

    result = users.run_user_scan(silent=True)

    assert result["status"] == "warning"
    assert "low_uid_shell" in result["tags"]


def test_known_service_user_is_ignored(monkeypatch):
    setup_linux(
        monkeypatch,
        [
            make_user(
                "www-data",
                33,
                "/var/www",
                "/bin/bash",
            )
        ],
    )

    result = users.run_user_scan(silent=True)

    assert result["status"] == "ok"
    assert result["tags"] == []


def test_regular_user_without_valid_home_is_flagged(monkeypatch):
    setup_linux(
        monkeypatch,
        [
            make_user(
                "alice",
                1000,
                "/",
                "/bin/bash",
            )
        ],
    )

    result = users.run_user_scan(silent=True)

    assert result["status"] == "warning"
    assert "no_home_dir" in result["tags"]


def test_nonlogin_user_without_home_is_not_flagged(monkeypatch):
    setup_linux(
        monkeypatch,
        [
            make_user(
                "disabled",
                1000,
                "/",
                "/usr/sbin/nologin",
            )
        ],
    )

    result = users.run_user_scan(silent=True)

    assert result["status"] == "ok"


def test_python_shell_is_flagged(monkeypatch):
    setup_linux(
        monkeypatch,
        [
            make_user(
                "alice",
                1000,
                "/home/alice",
                "/usr/bin/python",
            )
        ],
        valid_shells={
            "/bin/bash",
            "/usr/bin/python",
        },
    )

    result = users.run_user_scan(silent=True)

    assert result["status"] == "warning"
    assert "code_shell" in result["tags"]


def test_nonstandard_shell_is_flagged(monkeypatch):
    setup_linux(
        monkeypatch,
        [
            make_user(
                "alice",
                1000,
                "/home/alice",
                "/opt/custom/shell",
            )
        ],
    )

    result = users.run_user_scan(silent=True)

    assert result["status"] == "warning"
    assert "nonstandard_shell" in result["tags"]


def test_nonlogin_shell_is_not_nonstandard(monkeypatch):
    setup_linux(
        monkeypatch,
        [
            make_user(
                "disabled",
                1000,
                "/home/disabled",
                "/bin/false",
            )
        ],
    )

    result = users.run_user_scan(silent=True)

    assert result["status"] == "ok"


def test_multiple_findings_for_same_account_count_once(monkeypatch):
    setup_linux(
        monkeypatch,
        [
            make_user(
                "evilroot",
                0,
                "/root2",
                "/usr/bin/python",
            )
        ],
        valid_shells={
            "/bin/bash",
            "/usr/bin/python",
        },
    )

    result = users.run_user_scan(silent=True)

    assert result["status"] == "warning"
    assert "account(s)" in result["details"][0]
    assert result["details"][0].endswith("1 account(s)")


def test_non_linux_returns_unsupported(monkeypatch):
    monkeypatch.setattr(users, "get_os", lambda: "Windows")

    result = users.run_user_scan(silent=True)

    assert result == {
        "status": "unsupported",
        "details": [],
        "tags": [],
    }
