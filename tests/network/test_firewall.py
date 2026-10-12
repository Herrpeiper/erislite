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


def test_build_ufw_block_commands_insert_ahead_of_existing_rules():
    commands = firewall.build_ip_block_commands("203.0.113.10", "ufw")

    assert commands["apply"] == ["ufw", "insert", "1", "deny", "out", "to", "203.0.113.10"]
    assert commands["fallback"] == ["ufw", "deny", "out", "to", "203.0.113.10"]
    assert commands["undo"] == ["ufw", "delete", "deny", "out", "to", "203.0.113.10"]
    assert "ESTABLISHED" in commands["established_note"]


def test_build_firewalld_block_commands_use_direct_output_rule():
    commands = firewall.build_ip_block_commands("203.0.113.10", "firewalld")

    rule = ["ipv4", "filter", "OUTPUT", "0", "-d", "203.0.113.10", "-j", "DROP"]

    assert commands == {
        "apply": ["firewall-cmd", "--direct", "--add-rule", *rule],
        "undo": ["firewall-cmd", "--direct", "--remove-rule", *rule],
    }


def test_build_firewalld_block_commands_support_ipv6():
    commands = firewall.build_ip_block_commands("2001:db8::1", "firewalld")

    assert commands["apply"][3] == "ipv6"


def test_build_iptables_block_commands_insert_at_top():
    commands = firewall.build_ip_block_commands("203.0.113.10", "iptables")

    assert commands == {
        "apply": ["iptables", "-I", "OUTPUT", "1", "-d", "203.0.113.10", "-j", "DROP"],
        "undo": ["iptables", "-D", "OUTPUT", "-d", "203.0.113.10", "-j", "DROP"],
    }


def test_build_iptables_block_commands_use_ip6tables_for_ipv6():
    commands = firewall.build_ip_block_commands("2001:db8::1", "iptables")

    assert commands["apply"][0] == "ip6tables"
    assert commands["undo"][0] == "ip6tables"


def test_build_nftables_block_commands_use_erislite_set():
    commands = firewall.build_ip_block_commands("203.0.113.10", "nftables")

    assert commands["apply"] == [
        "nft", "add", "element", "inet", "erislite", "blocked4", "{ 203.0.113.10 }",
    ]
    assert commands["undo"] == [
        "nft", "delete", "element", "inet", "erislite", "blocked4", "{ 203.0.113.10 }",
    ]
    assert ["nft", "flush", "chain", "inet", "erislite", "output"] in commands["setup"]


def test_nftables_setup_flushes_before_adding_rules():
    setup = firewall.build_ip_block_commands("2001:db8::1", "nftables")["setup"]

    flush = setup.index(["nft", "flush", "chain", "inet", "erislite", "output"])
    rule_indexes = [index for index, command in enumerate(setup) if command[1:3] == ["add", "rule"]]

    assert rule_indexes and all(index > flush for index in rule_indexes)


def test_build_block_commands_normalizes_address():
    commands = firewall.build_ip_block_commands("2001:DB8:0::1", "iptables")

    assert "2001:db8::1" in commands["apply"]


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
