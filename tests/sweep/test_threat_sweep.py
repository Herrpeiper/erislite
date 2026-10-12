"""
ErisLITE Threat Sweep tests.

Tests deterministic risk-scoring behavior without invoking
host-level security checks.
"""

from erislite.sweep import threat_sweep
from erislite.sweep.threat_sweep import calculate_risk_score, compare_sweep_results


def test_empty_results_return_zero_score():
    score, breakdown, max_score = calculate_risk_score({})

    assert score == 0
    assert breakdown == {}
    assert max_score == 0


def test_ok_module_contributes_no_risk():
    results = {
        "integrity": {
            "status": "ok",
            "details": [],
            "tags": [],
        }
    }

    score, breakdown, max_score = calculate_risk_score(results)

    assert score == 0
    assert breakdown["integrity"] == 0
    assert max_score == 20


def test_warning_module_contributes_full_weight():
    results = {
        "listeners": {
            "status": "warning",
            "details": ["Suspicious listener detected"],
            "tags": ["suspicious_listener"],
        }
    }

    score, breakdown, max_score = calculate_risk_score(results)

    assert score == 15
    assert breakdown["listeners"] == 15
    assert max_score == 15


def test_issue_status_contributes_risk():
    results = {
        "users": {
            "status": "issue",
            "details": ["Suspicious account"],
            "tags": ["suspicious_login"],
        }
    }

    score, breakdown, max_score = calculate_risk_score(results)

    assert score == 15
    assert breakdown["users"] == 15
    assert max_score == 15


def test_error_status_contributes_risk():
    results = {
        "kernel": {
            "status": "error",
            "details": ["Kernel inspection failed"],
            "tags": [],
        }
    }

    score, breakdown, max_score = calculate_risk_score(results)

    assert score == 15
    assert breakdown["kernel"] == 15
    assert max_score == 15


def test_multiple_modules_are_scored_correctly():
    results = {
        "integrity": {"status": "warning"},
        "listeners": {"status": "ok"},
        "users": {"status": "issue"},
        "login": {"status": "ok"},
        "cve": {"status": "review"},
    }

    score, breakdown, max_score = calculate_risk_score(results)

    assert score == 35
    assert max_score == 60

    assert breakdown == {
        "integrity": 20,
        "listeners": 0,
        "users": 15,
        "login": 0,
    }


def test_unknown_module_is_ignored():
    results = {
        "not_a_real_module": {
            "status": "warning",
        }
    }

    score, breakdown, max_score = calculate_risk_score(results)

    assert score == 0
    assert breakdown == {}
    assert max_score == 0


def test_status_matching_is_case_insensitive():
    results = {
        "backdoor": {"status": "WARNING"},
        "hosts": {"status": "Issue"},
        "processes": {"status": "ERROR"},
    }

    score, breakdown, max_score = calculate_risk_score(results)

    assert score == 65
    assert max_score == 65

    assert breakdown == {
        "backdoor": 25,
        "hosts": 20,
        "processes": 20,
    }


def test_unsupported_module_does_not_add_risk():
    results = {
        "docker": {
            "status": "unsupported",
            "details": ["Docker is unavailable"],
        }
    }

    score, breakdown, max_score = calculate_risk_score(results)

    assert score == 0
    assert breakdown["docker"] == 0
    # A module that could not run must not inflate the denominator.
    assert max_score == 0


def test_review_status_does_not_add_risk():
    results = {
        "cve": {
            "status": "review",
            "details": [
                "1 version match detected"
            ],
            "tags": [
                "cve_version_match"
            ],
        }
    }

    score, breakdown, max_score = calculate_risk_score(results)

    assert score == 0
    assert "cve" not in breakdown
    # CVE matching is informational, so it adds nothing to the maximum.
    assert max_score == 0


def test_standard_profile_maximum_excludes_cve():
    results = {
        module: {"status": "ok", "details": [], "tags": []}
        for module in ("integrity", "listeners", "users", "login", "cve", "firewall")
    }

    _, _, max_score = calculate_risk_score(results)

    assert max_score == 75


def test_second_cron_job_is_reported_as_changed():
    previous = {
        "cron": {"status": "warning", "details": ["1 suspicious scheduled task(s) flagged"], "tags": ["suspicious_cron"]},
    }
    current = {
        "cron": {"status": "warning", "details": ["2 suspicious scheduled task(s) flagged"], "tags": ["suspicious_cron"]},
    }

    changes = compare_sweep_results(current, previous)

    assert changes["persisting"] == ["cron:suspicious_cron"]
    assert changes["changed"] == ["cron: 2 suspicious scheduled task(s) flagged"]


def test_identical_findings_are_not_changed():
    result = {"status": "warning", "details": ["x"], "tags": ["t"]}

    changes = compare_sweep_results({"cron": result}, {"cron": result})

    assert changes["changed"] == []


def test_run_module_check_isolates_crash():
    def boom():
        raise RuntimeError("kaboom")

    result = threat_sweep.run_module_check("cron", boom)

    assert result["status"] == "error"
    assert "kaboom" in result["details"][0]
    assert result["tags"] == ["cron_check_failed"]


def test_run_module_check_rejects_invalid_result():
    result = threat_sweep.run_module_check("cron", lambda: {"status": "fine"})

    assert result["status"] == "error"


def test_every_profile_module_has_a_check():
    from erislite.config.settings import SWEEP_PROFILES

    for modules in SWEEP_PROFILES.values():
        for module in modules:
            assert module in threat_sweep.SWEEP_CHECKS
