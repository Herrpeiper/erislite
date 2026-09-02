from pathlib import Path

import pytest

from erislite.network import hosts


def write_hosts_file(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "hosts"
    path.write_text(content, encoding="utf-8")
    return path


def test_parse_hosts_ignores_comments_and_blank_lines(tmp_path, monkeypatch):
    path = write_hosts_file(
        tmp_path,
        """
# comment

127.0.0.1 localhost
""",
    )

    monkeypatch.setattr(hosts, "HOSTS_PATH", str(path))

    entries, error = hosts.parse_hosts()

    assert error is None
    assert entries == [
        ("127.0.0.1", "localhost", "127.0.0.1 localhost", 4),
    ]


def test_parse_hosts_supports_multiple_hostnames_per_line(tmp_path, monkeypatch):
    path = write_hosts_file(
        tmp_path,
        "127.0.0.1 localhost localhost.localdomain\n",
    )

    monkeypatch.setattr(hosts, "HOSTS_PATH", str(path))

    entries, error = hosts.parse_hosts()

    assert error is None
    assert entries == [
        (
            "127.0.0.1",
            "localhost",
            "127.0.0.1 localhost localhost.localdomain",
            1,
        ),
        (
            "127.0.0.1",
            "localhost.localdomain",
            "127.0.0.1 localhost localhost.localdomain",
            1,
        ),
    ]


def test_parse_hosts_strips_inline_comments(tmp_path, monkeypatch):
    path = write_hosts_file(
        tmp_path,
        "10.0.0.5 server.internal # internal server\n",
    )

    monkeypatch.setattr(hosts, "HOSTS_PATH", str(path))

    entries, error = hosts.parse_hosts()

    assert error is None
    assert entries[0][0] == "10.0.0.5"
    assert entries[0][1] == "server.internal"


def test_parse_hosts_ignores_invalid_ip_addresses(tmp_path, monkeypatch):
    path = write_hosts_file(
        tmp_path,
        """
not-an-ip example.com
127.0.0.1 localhost
""",
    )

    monkeypatch.setattr(hosts, "HOSTS_PATH", str(path))

    entries, error = hosts.parse_hosts()

    assert error is None
    assert len(entries) == 1
    assert entries[0][1] == "localhost"


def test_parse_hosts_returns_error_for_missing_file(tmp_path, monkeypatch):
    path = tmp_path / "does-not-exist"

    monkeypatch.setattr(hosts, "HOSTS_PATH", str(path))

    entries, error = hosts.parse_hosts()

    assert entries == []
    assert error is not None


def test_normal_localhost_entry_is_not_flagged(tmp_path, monkeypatch):
    path = write_hosts_file(
        tmp_path,
        "127.0.0.1 localhost\n",
    )

    monkeypatch.setattr(hosts, "HOSTS_PATH", str(path))

    flagged, errors, tags = hosts.scan_hosts()

    assert flagged == []
    assert errors == []
    assert tags == []


def test_critical_domain_redirect_is_flagged(tmp_path, monkeypatch):
    path = write_hosts_file(
        tmp_path,
        "203.0.113.10 security.ubuntu.com\n",
    )

    monkeypatch.setattr(hosts, "HOSTS_PATH", str(path))

    flagged, errors, tags = hosts.scan_hosts()

    assert errors == []
    assert tags == []
    assert len(flagged) == 1

    finding = flagged[0]

    assert finding["hostname"] == "security.ubuntu.com"
    assert "hosts_critical_redirect" in finding["tags"]


def test_external_hostname_redirected_to_loopback_is_flagged(
    tmp_path,
    monkeypatch,
):
    path = write_hosts_file(
        tmp_path,
        "127.0.0.1 example.com\n",
    )

    monkeypatch.setattr(hosts, "HOSTS_PATH", str(path))

    flagged, _, _ = hosts.scan_hosts()

    assert len(flagged) == 1
    assert "hosts_loopback_redirect" in flagged[0]["tags"]


def test_local_hostname_on_loopback_is_not_flagged(tmp_path, monkeypatch):
    path = write_hosts_file(
        tmp_path,
        "127.0.0.1 service.local\n",
    )

    monkeypatch.setattr(hosts, "HOSTS_PATH", str(path))

    flagged, _, _ = hosts.scan_hosts()

    assert flagged == []


def test_external_hostname_mapped_to_private_ip_is_flagged(
    tmp_path,
    monkeypatch,
):
    path = write_hosts_file(
        tmp_path,
        "10.10.10.5 example.com\n",
    )

    monkeypatch.setattr(hosts, "HOSTS_PATH", str(path))

    flagged, _, _ = hosts.scan_hosts()

    assert len(flagged) == 1
    assert "hosts_private_redirect" in flagged[0]["tags"]


def test_internal_hostname_on_private_ip_is_not_flagged(
    tmp_path,
    monkeypatch,
):
    path = write_hosts_file(
        tmp_path,
        "10.10.10.5 app.internal\n",
    )

    monkeypatch.setattr(hosts, "HOSTS_PATH", str(path))

    flagged, _, _ = hosts.scan_hosts()

    assert flagged == []


def test_duplicate_non_loopback_mapping_is_flagged(
    tmp_path,
    monkeypatch,
):
    path = write_hosts_file(
        tmp_path,
        """
10.0.0.10 server.internal
10.0.0.11 server.internal
""",
    )

    monkeypatch.setattr(hosts, "HOSTS_PATH", str(path))

    flagged, _, _ = hosts.scan_hosts()

    duplicate_findings = [
        finding
        for finding in flagged
        if "hosts_duplicate_mapping" in finding["tags"]
    ]

    assert len(duplicate_findings) == 1
    assert duplicate_findings[0]["hostname"] == "server.internal"


def test_loopback_variants_do_not_trigger_duplicate_mapping(
    tmp_path,
    monkeypatch,
):
    path = write_hosts_file(
        tmp_path,
        """
127.0.0.1 localhost
::1 localhost
""",
    )

    monkeypatch.setattr(hosts, "HOSTS_PATH", str(path))

    flagged, _, _ = hosts.scan_hosts()

    assert not any(
        "hosts_duplicate_mapping" in finding["tags"]
        for finding in flagged
    )


def test_base64_like_hostname_is_flagged(tmp_path, monkeypatch):
    path = write_hosts_file(
        tmp_path,
        "192.0.2.10 QWxhZGRpbjpvcGVuIHNlc2FtZQ==\n",
    )

    monkeypatch.setattr(hosts, "HOSTS_PATH", str(path))

    flagged, _, _ = hosts.scan_hosts()

    assert len(flagged) == 1
    assert "hosts_suspicious_entry" in flagged[0]["tags"]
