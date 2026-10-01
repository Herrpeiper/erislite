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
    parsed = _parsed_state(
        sudo_events=1,
        sudo_to_root=1,
        sudo_root_sessions=1,
    )

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


def test_additional_sudo_activity_remains_visible():
    parsed = _parsed_state(
        sudo_events=2,
        sudo_to_root=2,
        sudo_root_sessions=2,
    )

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

    assert result["sudo_events"] == 1
    assert result["sudo_to_root"] == 1
    assert result["sudo_root_sessions"] == 1

    assert soc_mode.compute_status(result, 0) == "ACTION REQUIRED"


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