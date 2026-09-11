from erislite.config.settings import DEFAULT_SWEEP_PROFILE, SWEEP_PROFILES


def test_default_sweep_profile_exists():
    assert DEFAULT_SWEEP_PROFILE in SWEEP_PROFILES


def test_expected_profiles_exist():
    assert set(SWEEP_PROFILES) == {
        "quick",
        "standard",
        "full",
    }


def test_quick_profile_contents():
    assert SWEEP_PROFILES["quick"] == (
        "listeners",
        "users",
        "login",
    )


def test_standard_profile_contents():
    assert SWEEP_PROFILES["standard"] == (
        "integrity",
        "listeners",
        "users",
        "login",
        "cve",
    )


def test_full_profile_contains_all_expected_modules():
    expected = {
        "integrity",
        "listeners",
        "users",
        "kernel",
        "sshkeys",
        "worldwritable",
        "cron",
        "login",
        "sshconfig",
        "docker",
        "suid",
        "processes",
        "hosts",
        "backdoor",
        "cve",
    }

    assert set(SWEEP_PROFILES["full"]) == expected


def test_profiles_do_not_contain_duplicates():
    for profile_name, modules in SWEEP_PROFILES.items():
        assert len(modules) == len(set(modules)), (
            f"{profile_name} contains duplicate modules"
        )


def test_full_profile_contains_suid():
    assert "suid" in SWEEP_PROFILES["full"]


def test_full_profile_contains_backdoor_detection():
    assert "backdoor" in SWEEP_PROFILES["full"]
