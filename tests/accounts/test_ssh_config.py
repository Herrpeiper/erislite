from pathlib import Path

from erislite.accounts import ssh_config


def write_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "sshd_config"
    path.write_text(content, encoding="utf-8")
    return path


def test_parse_sshd_config_reads_known_settings(tmp_path):
    path = write_config(
        tmp_path,
        """
PermitRootLogin no
PasswordAuthentication no
UsePAM yes
""",
    )

    result = ssh_config.parse_sshd_config(str(path))

    assert result == {
        "PermitRootLogin": "no",
        "PasswordAuthentication": "no",
        "UsePAM": "yes",
    }


def test_parse_sshd_config_ignores_comments_and_blank_lines(tmp_path):
    path = write_config(
        tmp_path,
        """
# PermitRootLogin yes

PermitRootLogin no

# PasswordAuthentication yes
PasswordAuthentication no
""",
    )

    result = ssh_config.parse_sshd_config(str(path))

    assert result == {
        "PermitRootLogin": "no",
        "PasswordAuthentication": "no",
    }


def test_parse_sshd_config_ignores_unknown_directives(tmp_path):
    path = write_config(
        tmp_path,
        """
Port 22
ListenAddress 0.0.0.0
PermitRootLogin no
""",
    )

    result = ssh_config.parse_sshd_config(str(path))

    assert result == {
        "PermitRootLogin": "no",
    }


def test_parse_sshd_config_normalizes_values_to_lowercase(tmp_path):
    path = write_config(
        tmp_path,
        """
PermitRootLogin NO
UsePAM YES
""",
    )

    result = ssh_config.parse_sshd_config(str(path))

    assert result["PermitRootLogin"] == "no"
    assert result["UsePAM"] == "yes"


def test_parse_sshd_config_uses_last_explicit_value(tmp_path):
    path = write_config(
        tmp_path,
        """
PermitRootLogin yes
PermitRootLogin no
""",
    )

    result = ssh_config.parse_sshd_config(str(path))

    assert result["PermitRootLogin"] == "no"


def test_parse_sshd_config_returns_none_for_missing_file(tmp_path):
    path = tmp_path / "missing_sshd_config"

    result = ssh_config.parse_sshd_config(str(path))

    assert result is None


def test_secure_configuration_returns_ok(monkeypatch):
    monkeypatch.setattr(ssh_config, "get_os", lambda: "Linux")

    monkeypatch.setattr(
        ssh_config,
        "parse_sshd_config",
        lambda: dict(ssh_config.SECURE_DEFAULTS),
    )

    result = ssh_config.run_ssh_config_check(silent=True)

    assert result["status"] == "ok"
    assert result["details"] == []
    assert result["tags"] == []

    assert all(
        finding["status"] == "secure"
        for finding in result["findings"]
    )


def test_insecure_setting_returns_warning(monkeypatch):
    monkeypatch.setattr(ssh_config, "get_os", lambda: "Linux")

    config = dict(ssh_config.SECURE_DEFAULTS)
    config["PermitRootLogin"] = "yes"

    monkeypatch.setattr(
        ssh_config,
        "parse_sshd_config",
        lambda: config,
    )

    result = ssh_config.run_ssh_config_check(silent=True)

    assert result["status"] == "warning"
    assert "weak_ssh_config" in result["tags"]

    assert any(
        finding["setting"] == "PermitRootLogin"
        and finding["status"] == "insecure"
        for finding in result["findings"]
    )


def test_unset_setting_is_not_treated_as_insecure(monkeypatch):
    monkeypatch.setattr(ssh_config, "get_os", lambda: "Linux")

    config = dict(ssh_config.SECURE_DEFAULTS)
    del config["X11Forwarding"]

    monkeypatch.setattr(
        ssh_config,
        "parse_sshd_config",
        lambda: config,
    )

    result = ssh_config.run_ssh_config_check(silent=True)

    assert result["status"] == "ok"
    assert result["tags"] == []

    finding = next(
        finding
        for finding in result["findings"]
        if finding["setting"] == "X11Forwarding"
    )

    assert finding["status"] == "unset"
    assert finding["value"] == "Not Set"


def test_unreadable_config_returns_error(monkeypatch):
    monkeypatch.setattr(ssh_config, "get_os", lambda: "Linux")
    monkeypatch.setattr(
        ssh_config,
        "parse_sshd_config",
        lambda: None,
    )

    result = ssh_config.run_ssh_config_check(silent=True)

    assert result["status"] == "error"
    assert "ssh_config_unreadable" in result["tags"]
    assert result["findings"] == []


def test_non_linux_returns_unsupported(monkeypatch):
    monkeypatch.setattr(ssh_config, "get_os", lambda: "Windows")

    result = ssh_config.run_ssh_config_check(silent=True)

    assert result == {
        "status": "unsupported",
        "details": [],
        "tags": [],
    }


def test_all_baseline_settings_generate_findings(monkeypatch):
    monkeypatch.setattr(ssh_config, "get_os", lambda: "Linux")
    monkeypatch.setattr(
        ssh_config,
        "parse_sshd_config",
        lambda: {},
    )

    result = ssh_config.run_ssh_config_check(silent=True)

    assert len(result["findings"]) == len(
        ssh_config.SECURE_DEFAULTS
    )

    assert all(
        finding["status"] == "unset"
        for finding in result["findings"]
    )
