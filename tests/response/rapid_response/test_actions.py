from erislite.response.rapid_response import actions


def test_block_ip_uses_detected_backend(monkeypatch):
    log = []

    action = {
        "type": "block_ip",
        "data": {
            "remote_ip": "203.0.113.10",
        },
        "undo": None,
    }

    monkeypatch.setattr(
        actions,
        "detect_firewall_backend",
        lambda: "ufw",
    )

    monkeypatch.setattr(
        actions,
        "build_ip_block_commands",
        lambda ip, backend: {
            "apply": [
                "ufw",
                "deny",
                "out",
                "to",
                ip,
            ],
            "undo": [
                "ufw",
                "delete",
                "deny",
                "out",
                "to",
                ip,
            ],
        },
    )

    calls = []

    def fake_run_cmd(command):
        calls.append(command)
        return 0, "", ""

    monkeypatch.setattr(
        actions,
        "run_cmd",
        fake_run_cmd,
    )

    result = actions.execute_action(action, log)

    assert result is True
    assert calls == [
        [
            "ufw",
            "deny",
            "out",
            "to",
            "203.0.113.10",
        ]
    ]


def test_block_ip_stores_backend_and_undo(monkeypatch):
    log = []

    action = {
        "type": "block_ip",
        "data": {
            "remote_ip": "203.0.113.10",
        },
        "undo": None,
    }

    monkeypatch.setattr(
        actions,
        "detect_firewall_backend",
        lambda: "iptables",
    )

    monkeypatch.setattr(
        actions,
        "build_ip_block_commands",
        lambda ip, backend: {
            "apply": [
                "iptables",
                "-A",
                "OUTPUT",
                "-d",
                ip,
                "-j",
                "DROP",
            ],
            "undo": [
                "iptables",
                "-D",
                "OUTPUT",
                "-d",
                ip,
                "-j",
                "DROP",
            ],
        },
    )

    monkeypatch.setattr(
        actions,
        "run_cmd",
        lambda command: (0, "", ""),
    )

    result = actions.execute_action(action, log)

    assert result is True
    assert len(log) == 1
    assert log[0]["data"]["firewall_backend"] == "iptables"

    assert log[0]["undo"] == [
        "iptables",
        "-D",
        "OUTPUT",
        "-d",
        "203.0.113.10",
        "-j",
        "DROP",
    ]


def test_block_ip_logs_failure_when_no_backend(monkeypatch):
    log = []

    action = {
        "type": "block_ip",
        "data": {
            "remote_ip": "203.0.113.10",
        },
        "undo": None,
    }

    monkeypatch.setattr(
        actions,
        "detect_firewall_backend",
        lambda: None,
    )

    result = actions.execute_action(action, log)

    assert result is False
    assert len(log) == 1
    assert "no supported active firewall" in log[0]["result"]


def test_block_ip_refuses_unsupported_nftables_mutation(monkeypatch):
    log = []

    action = {
        "type": "block_ip",
        "data": {
            "remote_ip": "203.0.113.10",
        },
        "undo": None,
    }

    monkeypatch.setattr(
        actions,
        "detect_firewall_backend",
        lambda: "nftables",
    )

    monkeypatch.setattr(
        actions,
        "build_ip_block_commands",
        lambda ip, backend: None,
    )

    result = actions.execute_action(action, log)

    assert result is False
    assert len(log) == 1
    assert "cannot safely block" in log[0]["result"]


def test_block_ip_logs_failed_command(monkeypatch):
    log = []

    action = {
        "type": "block_ip",
        "data": {
            "remote_ip": "203.0.113.10",
        },
        "undo": None,
    }

    monkeypatch.setattr(
        actions,
        "detect_firewall_backend",
        lambda: "iptables",
    )

    monkeypatch.setattr(
        actions,
        "build_ip_block_commands",
        lambda ip, backend: {
            "apply": [
                "iptables",
                "-A",
                "OUTPUT",
                "-d",
                ip,
                "-j",
                "DROP",
            ],
            "undo": [
                "iptables",
                "-D",
                "OUTPUT",
                "-d",
                ip,
                "-j",
                "DROP",
            ],
        },
    )

    monkeypatch.setattr(
        actions,
        "run_cmd",
        lambda command: (
            1,
            "",
            "permission denied",
        ),
    )

    result = actions.execute_action(action, log)

    assert result is False
    assert len(log) == 1
    assert log[0]["result"] == "Failed: permission denied"

def test_lock_user_rejects_root(monkeypatch):
    log = []

    action = {
        "type": "lock_user",
        "data": {"username": "root"},
        "undo": [
            "usermod",
            "-U",
            "root",
        ],
    }

    result = actions.execute_action(action, log)

    assert result is False
    assert len(log) == 1
    assert "root account cannot be locked" in log[0]["result"]


def test_lock_user_rejects_current_operator(monkeypatch):
    log = []

    action = {
        "type": "lock_user",
        "data": {"username": "analyst"},
        "undo": [
            "usermod",
            "-U",
            "analyst",
        ],
    }

    class Account:
        pw_name = "analyst"
        pw_shell = "/bin/bash"

    monkeypatch.setattr(
        actions.pwd,
        "getpwnam",
        lambda username: Account(),
    )

    monkeypatch.setattr(
        actions.pwd,
        "getpwuid",
        lambda uid: Account(),
    )

    result = actions.execute_action(action, log)

    assert result is False
    assert len(log) == 1
    assert "current ErisLITE operator" in log[0]["result"]


def test_lock_user_rejects_nonexistent_user(monkeypatch):
    log = []

    action = {
        "type": "lock_user",
        "data": {"username": "ghostuser"},
        "undo": [
            "usermod",
            "-U",
            "ghostuser",
        ],
    }

    def fake_getpwnam(username):
        raise KeyError(username)

    monkeypatch.setattr(
        actions.pwd,
        "getpwnam",
        fake_getpwnam,
    )

    result = actions.execute_action(action, log)

    assert result is False
    assert len(log) == 1
    assert "user does not exist" in log[0]["result"]


def test_terminate_user_sessions_uses_loginctl(monkeypatch):
    calls = []

    monkeypatch.setattr(
        actions,
        "have",
        lambda command: command == "loginctl",
    )

    def fake_run_cmd(command):
        calls.append(command)
        return 0, "", ""

    monkeypatch.setattr(
        actions,
        "run_cmd",
        fake_run_cmd,
    )

    success, detail = actions._terminate_user_sessions(
        "suspicioususer"
    )

    assert success is True
    assert detail == "sessions terminated with loginctl"
    assert calls == [
        [
            "loginctl",
            "terminate-user",
            "suspicioususer",
        ]
    ]


def test_terminate_user_sessions_falls_back_to_pkill(monkeypatch):
    calls = []

    monkeypatch.setattr(
        actions,
        "have",
        lambda command: command in {"loginctl", "pkill"},
    )

    def fake_run_cmd(command):
        calls.append(command)

        if command[0] == "loginctl":
            return 1, "", "loginctl failed"

        return 0, "", ""

    monkeypatch.setattr(
        actions,
        "run_cmd",
        fake_run_cmd,
    )

    success, detail = actions._terminate_user_sessions(
        "suspicioususer"
    )

    assert success is True
    assert detail == "user processes terminated with pkill"

    assert calls == [
        [
            "loginctl",
            "terminate-user",
            "suspicioususer",
        ],
        [
            "pkill",
            "-KILL",
            "-u",
            "suspicioususer",
        ],
    ]


def test_lock_user_logs_partial_containment(monkeypatch):
    log = []

    action = {
        "type": "lock_user",
        "data": {"username": "suspicioususer"},
        "undo": [
            "usermod",
            "-U",
            "suspicioususer",
        ],
    }

    monkeypatch.setattr(
        actions,
        "_validate_lock_target",
        lambda username: (True, ""),
    )

    monkeypatch.setattr(
        actions,
        "have",
        lambda command: command == "usermod",
    )

    monkeypatch.setattr(
        actions,
        "run_cmd",
        lambda command: (0, "", ""),
    )

    monkeypatch.setattr(
        actions,
        "_terminate_user_sessions",
        lambda username: (
            False,
            "no supported session termination command available",
        ),
    )

    result = actions.execute_action(action, log)

    assert result is True
    assert len(log) == 1
    assert "Locked suspicioususer" in log[0]["result"]
    assert "session termination failed" in log[0]["result"]

def test_lock_user_rejects_service_account(monkeypatch):
    log = []

    action = {
        "type": "lock_user",
        "data": {"username": "daemonuser"},
        "undo": [
            "usermod",
            "-U",
            "daemonuser",
        ],
    }

    class ServiceAccount:
        pw_name = "daemonuser"
        pw_shell = "/usr/sbin/nologin"

    monkeypatch.setattr(
        actions.pwd,
        "getpwnam",
        lambda username: ServiceAccount(),
    )

    result = actions.execute_action(action, log)

    assert result is False
    assert len(log) == 1
    assert "service account" in log[0]["result"]