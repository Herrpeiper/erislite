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

    assert undo._validate_command_undo(
        entry,
        args,
    ) is True


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

    assert undo._validate_command_undo(
        entry,
        args,
    ) is True


def test_block_ip_undo_accepts_exact_firewalld_command():
    entry = {
        "type": "block_ip",
        "data": {
            "remote_ip": "203.0.113.10",
            "firewall_backend": "firewalld",
        },
    }

    rule = (
        'rule family="ipv4" '
        'destination address="203.0.113.10" drop'
    )

    args = [
        "firewall-cmd",
        f"--remove-rich-rule={rule}",
    ]

    assert undo._validate_command_undo(
        entry,
        args,
    ) is True


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

    assert undo._validate_command_undo(
        entry,
        args,
    ) is False


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

    assert undo._validate_command_undo(
        entry,
        args,
    ) is False


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

    assert undo._validate_command_undo(
        entry,
        args,
    ) is False