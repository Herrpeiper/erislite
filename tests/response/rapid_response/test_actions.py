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


class _Account:
    def __init__(self, name, uid, shell="/bin/bash"):
        self.pw_name = name
        self.pw_uid = uid
        self.pw_shell = shell


def _patch_single_account(monkeypatch, name="suspicioususer", uid=1500):
    account = _Account(name, uid)
    monkeypatch.setattr(actions.pwd, "getpwnam", lambda username: account)
    monkeypatch.setattr(actions.pwd, "getpwall", lambda: [_Account("root", 0), account])


def test_terminate_user_sessions_uses_loginctl(monkeypatch):
    calls = []
    _patch_single_account(monkeypatch)

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
    _patch_single_account(monkeypatch)

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
    assert "sessions not terminated" in log[0]["result"]

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
        pw_uid = 998
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


def test_terminate_user_sessions_refuses_uid0_clone(monkeypatch):
    calls = []
    _patch_single_account(monkeypatch, name="toor", uid=0)
    monkeypatch.setattr(actions, "have", lambda command: True)
    monkeypatch.setattr(actions, "run_cmd", lambda command: calls.append(command) or (0, "", ""))

    success, detail = actions._terminate_user_sessions("toor")

    # pkill -u toor would resolve to UID 0 and kill every root process.
    assert success is False
    assert "shares UID 0" in detail
    assert calls == []


def test_terminate_user_sessions_refuses_shared_uid(monkeypatch):
    first = _Account("alice", 1500)
    clone = _Account("alice2", 1500)
    monkeypatch.setattr(actions.pwd, "getpwnam", lambda username: clone)
    monkeypatch.setattr(actions.pwd, "getpwall", lambda: [first, clone])
    monkeypatch.setattr(actions, "have", lambda command: True)

    success, detail = actions._terminate_user_sessions("alice2")

    assert success is False
    assert "shares UID 1500" in detail


def test_operator_identity_uses_sudo_user(monkeypatch):
    monkeypatch.setenv("SUDO_USER", "liam")
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setattr(actions.os, "getuid", lambda: 0)
    monkeypatch.setattr(actions.os, "getlogin", lambda: (_ for _ in ()).throw(OSError()))
    monkeypatch.setattr(actions.pwd, "getpwuid", lambda uid: _Account({0: "root", 1000: "liam"}[uid], uid))

    names, uids = actions.operator_identity()

    assert "liam" in names
    assert uids == {0, 1000}


def test_lock_user_rejects_sudo_operator(monkeypatch):
    log = []
    monkeypatch.setenv("SUDO_USER", "liam")
    monkeypatch.setattr(actions.pwd, "getpwnam", lambda username: _Account("liam", 1000))

    result = actions.execute_action(
        {"type": "lock_user", "data": {"username": "liam"}, "undo": ["usermod", "-U", "liam"]},
        log,
    )

    assert result is False
    assert "current ErisLITE operator" in log[0]["result"]
    assert log[0]["undo"] is None


def test_kill_process_refuses_protected_pid(monkeypatch):
    log = []
    killed = []
    monkeypatch.setattr(actions.os, "kill", lambda pid, sig: killed.append(pid))

    result = actions.execute_action(
        {
            "type": "kill_process",
            "data": {"pid": actions.os.getpid(), "name": "python3", "exe": "/usr/bin/python3"},
            "undo": None,
        },
        log,
    )

    assert result is False
    assert killed == []
    assert log[0]["result"].startswith("Refused")


def test_kill_process_skips_reused_pid(monkeypatch):
    log = []
    killed = []
    monkeypatch.setattr(actions, "_protected_pids", lambda: {0, 1})
    monkeypatch.setattr(
        actions,
        "process_identity",
        lambda pid: {"pid": pid, "name": "nginx", "exe": "/usr/sbin/nginx", "create_time": 200.0},
    )
    monkeypatch.setattr(actions.os, "kill", lambda pid, sig: killed.append(pid))

    result = actions.execute_action(
        {
            "type": "kill_process",
            "data": {"pid": 4242, "name": "x", "exe": "/tmp/x", "create_time": 100.0},
            "undo": None,
        },
        log,
    )

    assert result is False
    assert killed == []
    assert "different process" in log[0]["result"]


def test_kill_process_kills_matching_process(monkeypatch):
    log = []
    killed = []
    monkeypatch.setattr(actions, "_protected_pids", lambda: {0, 1})
    monkeypatch.setattr(
        actions,
        "process_identity",
        lambda pid: {"pid": pid, "name": "x", "exe": "/tmp/x", "create_time": 100.0},
    )
    monkeypatch.setattr(actions.os, "kill", lambda pid, sig: killed.append(pid))

    result = actions.execute_action(
        {
            "type": "kill_process",
            "data": {"pid": 4242, "name": "x", "exe": "/tmp/x", "create_time": 100.0},
            "undo": None,
        },
        log,
    )

    assert result is True
    assert killed == [4242]


def test_block_ip_refuses_operator_ssh_source(monkeypatch):
    log = []
    monkeypatch.setattr(actions, "operator_source_ips", lambda: {"198.51.100.7"})
    monkeypatch.setattr(actions, "detect_firewall_backend", lambda: "iptables")

    result = actions.execute_action(
        {"type": "block_ip", "data": {"remote_ip": "198.51.100.7"}, "undo": None},
        log,
    )

    assert result is False
    assert "operator's SSH session" in log[0]["result"]


def test_block_ip_runs_setup_then_apply_for_nftables(monkeypatch):
    log = []
    calls = []
    monkeypatch.setattr(actions, "operator_source_ips", lambda: set())
    monkeypatch.setattr(actions, "detect_firewall_backend", lambda: "nftables")
    monkeypatch.setattr(actions, "run_cmd", lambda command: calls.append(command) or (0, "", ""))

    result = actions.execute_action(
        {"type": "block_ip", "data": {"remote_ip": "203.0.113.10"}, "undo": None},
        log,
    )

    assert result is True
    assert calls[0] == ["nft", "add", "table", "inet", "erislite"]
    assert calls[-1][:3] == ["nft", "add", "element"]
    assert log[0]["undo"][:3] == ["nft", "delete", "element"]


def test_block_ip_uses_ufw_fallback_when_insert_fails(monkeypatch):
    log = []
    calls = []
    monkeypatch.setattr(actions, "operator_source_ips", lambda: set())
    monkeypatch.setattr(actions, "detect_firewall_backend", lambda: "ufw")

    def fake_run_cmd(command):
        calls.append(command)
        if command[1] == "insert":
            return 1, "", "ERROR: Invalid position '1'"
        return 0, "", ""

    monkeypatch.setattr(actions, "run_cmd", fake_run_cmd)

    result = actions.execute_action(
        {"type": "block_ip", "data": {"remote_ip": "203.0.113.10"}, "undo": None},
        log,
    )

    assert result is True
    assert calls[-1] == ["ufw", "deny", "out", "to", "203.0.113.10"]
    assert "ESTABLISHED" in log[0]["result"]


def test_remove_cron_quarantines_outside_cron_dir(monkeypatch, tmp_path):
    cron_dir = tmp_path / "cron.d"
    cron_dir.mkdir()
    job = cron_dir / "evil"
    job.write_text("* * * * * root /tmp/x\n")
    job.chmod(0o666)
    quarantine = tmp_path / "quarantine"

    monkeypatch.setattr(actions, "CRON_DIRS", (str(cron_dir),))
    monkeypatch.setattr(actions.utils, "QUARANTINE_DIR", quarantine)
    log = []

    result = actions.execute_action(
        {"type": "remove_cron", "data": {"path": str(job)}, "undo": None},
        log,
    )

    assert result is True
    assert not job.exists()
    assert list(cron_dir.iterdir()) == []

    saved = list(quarantine.iterdir())
    assert len(saved) == 1
    assert saved[0].read_text() == "* * * * * root /tmp/x\n"
    assert saved[0].stat().st_mode & 0o777 == 0o600
    assert log[0]["undo"]["source"] == str(saved[0])
    assert log[0]["undo"]["mode"] == 0o666


def test_remove_cron_refuses_paths_outside_cron_dirs(monkeypatch, tmp_path):
    target = tmp_path / "passwd"
    target.write_text("x")
    log = []

    result = actions.execute_action(
        {"type": "remove_cron", "data": {"path": str(target)}, "undo": None},
        log,
    )

    assert result is False
    assert target.exists()


def test_build_action_plan_only_locks_uid0_accounts_given():
    plan = actions.build_action_plan([], [], ["toor"], [])

    assert [action["type"] for action in plan] == ["lock_user"]
    assert "UID 0" in plan[0]["label"]


def test_build_action_plan_adds_kill_for_shell_holding_connection(monkeypatch):
    monkeypatch.setattr(
        actions,
        "process_identity",
        lambda pid: {"pid": pid, "name": "bash", "exe": "/usr/bin/bash", "create_time": 1.0},
    )

    plan = actions.build_action_plan(
        [],
        [{"pid": 77, "proc": "bash", "laddr": "10.0.0.5:40000", "remote_ip": "203.0.113.10"}],
        [],
        [],
    )

    assert [action["type"] for action in plan] == ["block_ip", "kill_process"]
    assert plan[1]["data"]["pid"] == 77

