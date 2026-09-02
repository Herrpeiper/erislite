"""
ErisLITE Threat Sweep tests.

Tests deterministic risk-scoring behavior without invoking
host-level security checks.
"""

from erislite.sweep.threat_sweep import calculate_risk_score


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
        "cve": {"status": "warning"},
    }

    score, breakdown, max_score = calculate_risk_score(results)

    assert score == 55
    assert max_score == 80

    assert breakdown == {
        "integrity": 20,
        "listeners": 0,
        "users": 15,
        "login": 0,
        "cve": 20,
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
    assert max_score == 15
