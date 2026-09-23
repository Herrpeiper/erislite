from erislite.system import security_audit


def test_format_result_ok():
    result = {
        "status": "ok",
        "details": [],
        "tags": [],
    }

    formatted = security_audit._format_result(
        result,
        "No issues detected",
    )

    assert formatted == "🟢 No issues detected"


def test_format_result_warning_uses_first_detail():
    result = {
        "status": "warning",
        "details": ["Review required"],
        "tags": ["example_tag"],
    }

    formatted = security_audit._format_result(
        result,
        "No issues detected",
    )

    assert formatted == "[yellow]⚠️ Review required[/]"


def test_format_result_warning_without_details():
    result = {
        "status": "warning",
        "details": [],
        "tags": [],
    }

    formatted = security_audit._format_result(
        result,
        "No issues detected",
    )

    assert formatted == "[yellow]⚠️ Review required[/]"


def test_format_result_unsupported():
    result = {
        "status": "unsupported",
        "details": [],
        "tags": [],
    }

    formatted = security_audit._format_result(
        result,
        "No issues detected",
    )

    assert formatted == "[yellow]Unsupported on this platform[/]"


def test_format_result_error_without_details():
    result = {
        "status": "error",
        "details": [],
        "tags": [],
    }

    formatted = security_audit._format_result(
        result,
        "No issues detected",
    )

    assert formatted == "⚠️ Error: inspection incomplete"


def test_run_uses_hardened_checks(monkeypatch):
    monkeypatch.setattr(security_audit, "clear_screen", lambda: None)
    monkeypatch.setattr(security_audit, "pause_return", lambda: None)

    monkeypatch.setattr(
        security_audit.console,
        "print",
        lambda *args, **kwargs: None,
    )

    monkeypatch.setattr(
        security_audit,
        "write_audit_log",
        lambda profile, findings: "/tmp/audit.log",
    )

    calls = []

    def fake_check(name, status="ok"):
        def _runner(silent=False):
            calls.append((name, silent))
            return {
                "status": status,
                "details": [],
                "tags": [],
            }

        return _runner

    monkeypatch.setattr(
        security_audit,
        "run_firewall_check",
        fake_check("firewall"),
    )
    monkeypatch.setattr(
        security_audit,
        "run_process_scan",
        fake_check("processes"),
    )
    monkeypatch.setattr(
        security_audit,
        "run_ssh_key_check",
        fake_check("ssh_keys"),
    )
    monkeypatch.setattr(
        security_audit,
        "run_world_writable_check",
        fake_check("world_writable"),
    )
    monkeypatch.setattr(
        security_audit,
        "run_login_audit",
        fake_check("login"),
    )

    security_audit.run(
        {
            "hostname": "test-host",
            "role": "workstation",
            "analyst_id": 1,
        }
    )

    assert calls == [
        ("firewall", True),
        ("processes", True),
        ("ssh_keys", True),
        ("world_writable", True),
        ("login", True),
    ]
