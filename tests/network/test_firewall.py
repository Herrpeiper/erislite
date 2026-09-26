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

def test_detect_firewall_backend_prefers_active_ufw(monkeypatch):
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

    assert firewall.detect_firewall_backend() == "ufw"


def test_detect_firewall_backend_detects_firewalld(monkeypatch):
    responses = {
        ("systemctl", "is-active", "firewalld"): (
            _result(stdout="active\n"),
            None,
        ),
    }

    monkeypatch.setattr(
        firewall,
        "_run_command",
        _runner(responses),
    )

    assert firewall.detect_firewall_backend() == "firewalld"


def test_detect_firewall_backend_detects_nftables(monkeypatch):
    responses = {
        ("nft", "list", "ruleset"): (
            _result(
                stdout="""
table inet filter {
    chain output {
        type filter hook output priority 0;
        policy accept;
    }
}
"""
            ),
            None,
        ),
    }

    monkeypatch.setattr(
        firewall,
        "_run_command",
        _runner(responses),
    )

    assert firewall.detect_firewall_backend() == "nftables"


def test_detect_firewall_backend_detects_iptables(monkeypatch):
    responses = {
        ("iptables", "-S"): (
            _result(
                stdout="-A OUTPUT -p tcp --dport 443 -j ACCEPT\n"
            ),
            None,
        ),
    }

    monkeypatch.setattr(
        firewall,
        "_run_command",
        _runner(responses),
    )

    assert firewall.detect_firewall_backend() == "iptables"


def test_detect_firewall_backend_returns_none_when_unavailable(monkeypatch):
    monkeypatch.setattr(
        firewall,
        "_run_command",
        _runner({}),
    )

    assert firewall.detect_firewall_backend() is None


def test_build_ufw_block_commands():
    commands = firewall.build_ip_block_commands(
        "203.0.113.10",
        "ufw",
    )

    assert commands == {
        "apply": [
            "ufw",
            "deny",
            "out",
            "to",
            "203.0.113.10",
        ],
        "undo": [
            "ufw",
            "delete",
            "deny",
            "out",
            "to",
            "203.0.113.10",
        ],
    }


def test_build_firewalld_block_commands():
    commands = firewall.build_ip_block_commands(
        "203.0.113.10",
        "firewalld",
    )

    rule = (
        'rule family="ipv4" '
        'destination address="203.0.113.10" drop'
    )

    assert commands == {
        "apply": [
            "firewall-cmd",
            f"--add-rich-rule={rule}",
        ],
        "undo": [
            "firewall-cmd",
            f"--remove-rich-rule={rule}",
        ],
    }


def test_build_iptables_block_commands():
    commands = firewall.build_ip_block_commands(
        "203.0.113.10",
        "iptables",
    )

    assert commands == {
        "apply": [
            "iptables",
            "-A",
            "OUTPUT",
            "-d",
            "203.0.113.10",
            "-j",
            "DROP",
        ],
        "undo": [
            "iptables",
            "-D",
            "OUTPUT",
            "-d",
            "203.0.113.10",
            "-j",
            "DROP",
        ],
    }


def test_build_nftables_block_commands_refuses_unknown_chain():
    commands = firewall.build_ip_block_commands(
        "203.0.113.10",
        "nftables",
    )

    assert commands is None


@pytest.mark.parametrize(
    "invalid_ip",
    [
        "",
        "not-an-ip",
        "999.999.999.999",
        "203.0.113.10; rm -rf /",
    ],
)
def test_build_block_commands_rejects_invalid_ip(invalid_ip):
    assert (
        firewall.build_ip_block_commands(
            invalid_ip,
            "iptables",
        )
        is None
    )


def test_firewalld_rejects_ipv6():
    commands = firewall.build_ip_block_commands(
        "2001:db8::1",
        "firewalld",
    )

    assert commands is None