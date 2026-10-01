from erislite.sweep import soc_mode


def _parsed_state(**overrides):
    state = {
        "failed_ssh": 0,
        "failed_ips_top": [],
        "ssh_success_count": 0,
        "ssh_success_raw": [],
        "root_ssh_success": 0,
        "root_ssh_details": [],
        "sudo_events": 0,
        "sudo_details": [],
        "sudo_to_root": 0,
        "sudo_to_root_details": [],
        "sudo_root_sessions": 0,
        "sudo_root_session_details": [],
        "su_to_root": 0,
        "su_to_root_details": [],
    }

    state.update(overrides)
    return state


def test_current_sudo_session_is_discounted():
    current = (
        "sudo: analyst : TTY=pts/0 ; PWD=/tmp ; USER=root ; "
        "COMMAND=/usr/bin/python3 main.py"
    )
    session = (
        "sudo: pam_unix(sudo:session): session opened for user root "
        "by analyst(uid=1000)"
    )

    parsed = _parsed_state(
        sudo_events=1,
        sudo_details=[current],
        sudo_to_root=1,
        sudo_to_root_details=[current],
        sudo_root_sessions=1,
        sudo_root_session_details=[session],
    )

    privilege = {
        "euid": 0,
        "is_root": True,
        "sudo_user": "analyst",
        "sudo_command": "/usr/bin/python3 main.py",
        "elevated_via_sudo": True,
    }

    result = soc_mode.discount_current_sudo_session(
        parsed,
        privilege,
    )

    assert result["sudo_events"] == 0
    assert result["sudo_details"] == []
    assert result["sudo_to_root"] == 0
    assert result["sudo_to_root_details"] == []
    assert result["sudo_root_sessions"] == 0
    assert result["sudo_root_session_details"] == []


def test_additional_sudo_activity_remains_visible():
    current = (
        "sudo: analyst : TTY=pts/0 ; PWD=/tmp ; USER=root ; "
        "COMMAND=/usr/bin/python3 main.py"
    )
    other = (
        "sudo: alice : TTY=pts/1 ; PWD=/tmp ; USER=root ; "
        "COMMAND=/usr/bin/systemctl restart ssh"
    )

    parsed = _parsed_state(
        sudo_events=2,
        sudo_details=[other, current],
        sudo_to_root=2,
        sudo_to_root_details=[other, current],
        sudo_root_sessions=0,
        sudo_root_session_details=[],
    )

    privilege = {
        "euid": 0,
        "is_root": True,
        "sudo_user": "analyst",
        "sudo_command": "/usr/bin/python3 main.py",
        "elevated_via_sudo": True,
    }

    result = soc_mode.discount_current_sudo_session(
        parsed,
        privilege,
    )

    assert result["sudo_events"] == 1
    assert result["sudo_details"] == [other]
    assert result["sudo_to_root"] == 1
    assert result["sudo_to_root_details"] == [other]


def test_non_sudo_session_is_unchanged():
    parsed = _parsed_state(
        sudo_events=1,
        sudo_to_root=1,
        sudo_root_sessions=1,
    )

    privilege = {
        "euid": 1000,
        "is_root": False,
        "sudo_user": None,
        "elevated_via_sudo": False,
    }

    result = soc_mode.discount_current_sudo_session(
        parsed,
        privilege,
    )

    assert result["sudo_events"] == 1
    assert result["sudo_to_root"] == 1
    assert result["sudo_root_sessions"] == 1


def test_discount_never_creates_negative_counts():
    parsed = _parsed_state()

    privilege = {
        "euid": 0,
        "is_root": True,
        "sudo_user": "analyst",
        "elevated_via_sudo": True,
    }

    result = soc_mode.discount_current_sudo_session(
        parsed,
        privilege,
    )

    assert result["sudo_events"] == 0
    assert result["sudo_to_root"] == 0
    assert result["sudo_root_sessions"] == 0


def test_sudo_discount_removes_current_invocation_and_details():
    current = (
        "sudo: mar : TTY=pts/0 ; PWD=/tmp ; USER=root ; "
        "COMMAND=/usr/bin/python3 main.py"
    )
    session = (
        "sudo: pam_unix(sudo:session): session opened for user root "
        "by mar(uid=1000)"
    )

    parsed = {
        "sudo_events": 1,
        "sudo_details": [current],
        "sudo_to_root": 1,
        "sudo_to_root_details": [current],
        "sudo_root_sessions": 1,
        "sudo_root_session_details": [session],
    }

    privilege = {
        "elevated_via_sudo": True,
        "sudo_user": "mar",
        "sudo_command": "/usr/bin/python3 main.py",
    }

    result = soc_mode.discount_current_sudo_session(parsed, privilege)

    assert result["sudo_events"] == 0
    assert result["sudo_details"] == []

    assert result["sudo_to_root"] == 0
    assert result["sudo_to_root_details"] == []

    assert result["sudo_root_sessions"] == 0
    assert result["sudo_root_session_details"] == []


def test_sudo_discount_does_nothing_when_current_command_not_in_window():
    other = (
        "sudo: alice : TTY=pts/1 ; PWD=/tmp ; USER=root ; "
        "COMMAND=/usr/bin/systemctl restart ssh"
    )

    parsed = {
        "sudo_events": 1,
        "sudo_details": [other],
        "sudo_to_root": 1,
        "sudo_to_root_details": [other],
        "sudo_root_sessions": 0,
        "sudo_root_session_details": [],
    }

    privilege = {
        "elevated_via_sudo": True,
        "sudo_user": "mar",
        "sudo_command": "/usr/bin/python3 main.py",
    }

    result = soc_mode.discount_current_sudo_session(parsed, privilege)

    assert result["sudo_events"] == 1
    assert result["sudo_details"] == [other]
    assert result["sudo_to_root"] == 1
    assert result["sudo_to_root_details"] == [other]


def test_sudo_discount_preserves_unrelated_activity():
    current = (
        "sudo: mar : TTY=pts/0 ; PWD=/tmp ; USER=root ; "
        "COMMAND=/usr/bin/python3 main.py"
    )
    other = (
        "sudo: alice : TTY=pts/1 ; PWD=/tmp ; USER=root ; "
        "COMMAND=/usr/bin/systemctl restart ssh"
    )

    parsed = {
        "sudo_events": 2,
        "sudo_details": [other, current],
        "sudo_to_root": 2,
        "sudo_to_root_details": [other, current],
        "sudo_root_sessions": 0,
        "sudo_root_session_details": [],
    }

    privilege = {
        "elevated_via_sudo": True,
        "sudo_user": "mar",
        "sudo_command": "/usr/bin/python3 main.py",
    }

    result = soc_mode.discount_current_sudo_session(parsed, privilege)

    assert result["sudo_events"] == 1
    assert result["sudo_details"] == [other]

    assert result["sudo_to_root"] == 1
    assert result["sudo_to_root_details"] == [other]