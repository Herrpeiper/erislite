from erislite.response.rapid_response import undo


def test_block_ip_undo_accepts_exact_iptables_command():
    entry = {
        "type": "block_ip",
        "data": {
            "remote_ip": "203.0.113.10",
            "firewall_backend": "iptables",
        },
    }

    args = [
        "iptables",
        "-D",
        "OUTPUT",
        "-d",
        "203.0.113.10",
        "-j",
        "DROP",
    ]

    assert (
        undo._validate_command_undo(
            entry,
            args,
        )
        is True
    )


def test_block_ip_undo_accepts_exact_ufw_command():
    entry = {
        "type": "block_ip",
        "data": {
            "remote_ip": "203.0.113.10",
            "firewall_backend": "ufw",
        },
    }

    args = [
        "ufw",
        "delete",
        "deny",
        "out",
        "to",
        "203.0.113.10",
    ]

    assert (
        undo._validate_command_undo(
            entry,
            args,
        )
        is True
    )


def test_block_ip_undo_accepts_exact_firewalld_command():
    entry = {
        "type": "block_ip",
        "data": {
            "remote_ip": "203.0.113.10",
            "firewall_backend": "firewalld",
        },
    }

    rule = 'rule family="ipv4" destination address="203.0.113.10" drop'

    args = [
        "firewall-cmd",
        f"--remove-rich-rule={rule}",
    ]

    assert (
        undo._validate_command_undo(
            entry,
            args,
        )
        is True
    )


def test_block_ip_undo_rejects_tampered_command():
    entry = {
        "type": "block_ip",
        "data": {
            "remote_ip": "203.0.113.10",
            "firewall_backend": "iptables",
        },
    }

    args = [
        "iptables",
        "-F",
    ]

    assert (
        undo._validate_command_undo(
            entry,
            args,
        )
        is False
    )


def test_block_ip_undo_rejects_missing_backend():
    entry = {
        "type": "block_ip",
        "data": {
            "remote_ip": "203.0.113.10",
        },
    }

    args = [
        "iptables",
        "-D",
        "OUTPUT",
        "-d",
        "203.0.113.10",
        "-j",
        "DROP",
    ]

    assert (
        undo._validate_command_undo(
            entry,
            args,
        )
        is False
    )


def test_block_ip_undo_rejects_unsupported_backend():
    entry = {
        "type": "block_ip",
        "data": {
            "remote_ip": "203.0.113.10",
            "firewall_backend": "nftables",
        },
    }

    args = [
        "nft",
        "delete",
        "rule",
    ]

    assert (
        undo._validate_command_undo(
            entry,
            args,
        )
        is False
    )


def _restore_entry(destination, source, mode=0o666):
    return {
        "type": "remove_cron",
        "data": {"path": str(destination)},
        "undo": {
            "type": "restore_file",
            "source": str(source),
            "destination": str(destination),
            "mode": mode,
            "uid": undo.os.geteuid(),
            "gid": undo.os.getegid(),
        },
    }


def test_restore_file_restores_without_world_write(monkeypatch, tmp_path):
    cron_dir = tmp_path / "cron.d"
    cron_dir.mkdir()
    quarantine = tmp_path / "quarantine"
    quarantine.mkdir()
    saved = quarantine / "etc_cron.d_job.1"
    saved.write_text("job\n")

    monkeypatch.setattr(undo, "CRON_DIRS", (str(cron_dir),))
    monkeypatch.setattr(undo.utils, "QUARANTINE_DIR", quarantine)

    destination = cron_dir / "job"
    entry = _restore_entry(destination, saved)

    success, detail = undo._restore_file(entry, entry["undo"])

    assert success is True, detail
    assert destination.read_text() == "job\n"
    assert destination.stat().st_mode & 0o777 == 0o664


def test_restore_file_rejects_source_outside_quarantine(monkeypatch, tmp_path):
    cron_dir = tmp_path / "cron.d"
    cron_dir.mkdir()
    planted = tmp_path / "planted"
    planted.write_text("* * * * * root /tmp/evil\n")

    monkeypatch.setattr(undo, "CRON_DIRS", (str(cron_dir),))
    monkeypatch.setattr(undo.utils, "QUARANTINE_DIR", tmp_path / "quarantine")

    entry = _restore_entry(cron_dir / "job", planted)

    success, detail = undo._restore_file(entry, entry["undo"])

    assert success is False
    assert "quarantine" in detail


def test_restore_file_rejects_destination_outside_cron_dirs(monkeypatch, tmp_path):
    quarantine = tmp_path / "quarantine"
    quarantine.mkdir()
    saved = quarantine / "x"
    saved.write_text("x")

    monkeypatch.setattr(undo, "CRON_DIRS", (str(tmp_path / "cron.d"),))
    monkeypatch.setattr(undo.utils, "QUARANTINE_DIR", quarantine)

    entry = _restore_entry(tmp_path / "etc" / "shadow", saved)

    success, detail = undo._restore_file(entry, entry["undo"])

    assert success is False
    assert "cron directory" in detail


def test_log_is_trusted_rejects_group_writable_log(tmp_path):
    log = tmp_path / "rapid_response_1.json"
    log.write_text("{}")
    log.chmod(0o664)

    trusted, reason = undo._log_is_trusted(log)

    assert trusted is False
    assert "writable by other users" in reason


def test_log_is_trusted_rejects_symlink(tmp_path):
    real = tmp_path / "real.json"
    real.write_text("{}")
    link = tmp_path / "rapid_response_1.json"
    link.symlink_to(real)

    trusted, _ = undo._log_is_trusted(link)

    assert trusted is False


def test_current_block_undo_commands_validate():
    for backend in ("ufw", "firewalld", "iptables", "nftables"):
        commands = undo.build_ip_block_commands("203.0.113.10", backend)
        entry = {
            "type": "block_ip",
            "data": {"remote_ip": "203.0.113.10", "firewall_backend": backend},
        }

        assert undo._validate_command_undo(entry, commands["undo"]) is True
