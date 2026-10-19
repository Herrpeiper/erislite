# Project: ErisLITE
# Module: test_comparison_coverage.py
# Version: 1.6.0
# License: MIT
# Description: Historical comparison coverage regression tests.

from erislite.sweep.threat_sweep import compare_sweep_results


def result(status, tags=None, details=None):
    return {
        "status": status,
        "tags": tags if tags is not None else [],
        "details": details if details is not None else [],
    }


def suspicious_listener():
    return result(
        "warning",
        ["suspicious_listener"],
        ["1 suspicious listener detected"],
    )


def failed_listener():
    return result(
        "error",
        ["listener_check_failed"],
        ["Listener inspection could not be completed"],
    )


def test_persisting_listener():
    changes = compare_sweep_results(
        {"listeners": suspicious_listener()},
        {"listeners": suspicious_listener()},
    )

    assert changes["persisting"] == ["listeners:suspicious_listener"]
    assert changes["resolved"] == []


def test_clean_scan_resolves_listener():
    changes = compare_sweep_results(
        {"listeners": result("ok")},
        {"listeners": suspicious_listener()},
    )

    assert changes["resolved"] == ["listeners:suspicious_listener"]


def test_new_listener_after_clean_scan():
    changes = compare_sweep_results(
        {"listeners": suspicious_listener()},
        {"listeners": result("ok")},
    )

    assert changes["new"] == ["listeners:suspicious_listener"]


def test_failed_current_scan_does_not_resolve():
    changes = compare_sweep_results(
        {"listeners": failed_listener()},
        {"listeners": suspicious_listener()},
    )

    assert changes["resolved"] == []
    assert changes["new"] == []
    assert changes["unverified"] == ["listeners:suspicious_listener"]


def test_failed_previous_scan_does_not_claim_new():
    changes = compare_sweep_results(
        {"listeners": suspicious_listener()},
        {"listeners": failed_listener()},
    )

    assert changes["new"] == []
    assert changes["unverified"] == ["listeners:suspicious_listener"]


def test_unsupported_current_scan_is_unverified():
    changes = compare_sweep_results(
        {"listeners": result("unsupported")},
        {"listeners": suspicious_listener()},
    )

    assert changes["resolved"] == []
    assert changes["unverified"] == ["listeners:suspicious_listener"]


def test_missing_current_module_does_not_resolve():
    changes = compare_sweep_results(
        {},
        {"listeners": suspicious_listener()},
    )

    assert changes["resolved"] == []
    assert changes["unverified"] == ["listeners:suspicious_listener"]


def test_other_modules_remain_comparable():
    changes = compare_sweep_results(
        {
            "listeners": failed_listener(),
            "firewall": result(
                "warning",
                ["firewall_disabled"],
            ),
        },
        {
            "listeners": suspicious_listener(),
            "firewall": result("ok"),
        },
    )

    assert changes["new"] == ["firewall:firewall_disabled"]
    assert changes["resolved"] == []
    assert changes["unverified"] == ["listeners:suspicious_listener"]


def test_changed_details_preserved():
    changes = compare_sweep_results(
        {
            "listeners": result(
                "warning",
                ["suspicious_listener"],
                ["2 suspicious listeners"],
            )
        },
        {
            "listeners": result(
                "warning",
                ["suspicious_listener"],
                ["1 suspicious listener"],
            )
        },
    )

    assert changes["changed"] == ["listeners: 2 suspicious listeners"]
    assert changes["persisting"] == ["listeners:suspicious_listener"]


def test_normal_comparison_schema_unchanged():
    changes = compare_sweep_results(
        {"listeners": suspicious_listener()},
        {"listeners": result("ok")},
    )

    assert set(changes) == {
        "new",
        "changed",
        "persisting",
        "resolved",
    }


def test_missing_previous_module_does_not_claim_new():
    changes = compare_sweep_results(
        {"listeners": suspicious_listener()},
        {},
    )

    assert changes["new"] == []
    assert changes["unverified"] == ["listeners:suspicious_listener"]
