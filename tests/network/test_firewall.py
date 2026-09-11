from types import SimpleNamespace

import pytest

from erislite.network import firewall


def _result(
    stdout="",
    stderr="",
    returncode=0,
):
    return SimpleNamespace(
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
    )


def _runner(responses):
    def run(command):
        return responses.get(
            tuple(command),
            (None, "unavailable"),
        )

    return run


def test_active_ufw_returns_ok(monkeypatch):
    responses = {
        ("ufw", "status"): (
            _result(stdout="Status: active\n"),
            None,
        ),
    }

    monkeypatch.setattr(
        firewall,
        "_run_command",
        _runner(responses),
    )

    result = firewall.run_firewall_check(silent=True)

    assert result == {
        "status": "ok",
        "details": ["UFW is active"],
        "tags": [],
    }


def test_inactive_firewalld_is_not_classified_as_active(monkeypatch):
    responses = {
        ("systemctl", "is-active", "firewalld"): (
            _result(
                stdout="inactive\n",
                returncode=3,
            ),
            None,
        ),
    }

    monkeypatch.setattr(
        firewall,
        "_run_command",
        _runner(responses),
    )

    result = firewall.run_firewall_check(silent=True)

    assert result["status"] == "warning"
    assert result["tags"] == ["firewall_disabled"]


def test_permission_failure_has_distinct_tag(monkeypatch):
    responses = {
        ("iptables", "-S"): (
            _result(
                stderr="Permission denied (you must be root)",
                returncode=4,
            ),
            None,
        ),
    }

    monkeypatch.setattr(
        firewall,
        "_run_command",
        _runner(responses),
    )

    result = firewall.run_firewall_check(silent=True)

    assert result["status"] == "warning"
    assert result["tags"] == ["firewall_permission_denied"]


def test_empty_iptables_ruleset_is_warning(monkeypatch):
    responses = {
        ("iptables", "-S"): (
            _result(
                stdout=(
                    "-P INPUT ACCEPT\n"
                    "-P FORWARD ACCEPT\n"
                    "-P OUTPUT ACCEPT\n"
                )
            ),
            None,
        ),
    }

    monkeypatch.setattr(
        firewall,
        "_run_command",
        _runner(responses),
    )

    result = firewall.run_firewall_check(silent=True)

    assert result["status"] == "warning"
    assert result["tags"] == ["firewall_ip_empty"]


def test_failed_firewall_command_has_distinct_tag(monkeypatch):
    responses = {
        ("iptables", "-S"): (
            _result(
                stderr="Unexpected backend failure",
                returncode=1,
            ),
            None,
        ),
    }

    monkeypatch.setattr(
        firewall,
        "_run_command",
        _runner(responses),
    )

    result = firewall.run_firewall_check(silent=True)

    assert result["status"] == "error"
    assert result["tags"] == ["firewall_check_failed"]


@pytest.mark.parametrize(
    "output",
    [
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n",
        "-P INPUT DROP\n",
    ],
)
def test_iptables_meaningful_rules_are_detected(output):
    assert firewall._iptables_has_rules(output) is True


def test_default_accept_policies_are_not_meaningful_rules():
    output = (
        "-P INPUT ACCEPT\n"
        "-P FORWARD ACCEPT\n"
        "-P OUTPUT ACCEPT\n"
    )

    assert firewall._iptables_has_rules(output) is False


def test_nftables_rules_are_detected():
    output = """
table inet filter {
    chain input {
        type filter hook input priority 0;
        policy drop;
    }
}
"""

    assert firewall._nftables_has_rules(output) is True