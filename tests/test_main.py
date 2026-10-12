import main


def test_show_import_warning_clean(monkeypatch):
    printed = []

    monkeypatch.setattr(
        main,
        "IMPORT_STATUS",
        {
            "status": "ok",
            "details": [],
            "tags": [],
        },
    )

    monkeypatch.setattr(
        main.console,
        "print",
        lambda *args, **kwargs: printed.append(args),
    )

    main._show_import_warning()

    assert printed == []


def test_show_import_warning_suspicious(monkeypatch):
    printed = []

    monkeypatch.setattr(
        main,
        "IMPORT_STATUS",
        {
            "status": "warning",
            "details": [
                "PYTHONPATH is set: /tmp/evil",
                "Suspicious import path: /tmp/evil",
            ],
            "tags": [
                "import_environment_suspicious",
            ],
        },
    )

    monkeypatch.setattr(
        main.console,
        "print",
        lambda *args, **kwargs: printed.append(args),
    )

    main._show_import_warning()

    rendered = "\n".join(str(item) for call in printed for item in call)

    assert "IMPORT ENVIRONMENT WARNING" in rendered
    assert "PYTHONPATH is set: /tmp/evil" in rendered
    assert "Suspicious import path: /tmp/evil" in rendered
    assert "will continue" in rendered


def test_main_runs_safety_check_before_cli(monkeypatch):
    events = []

    monkeypatch.setattr(
        main,
        "check_root_safety",
        lambda allow_unsafe: events.append(("check", allow_unsafe)) or True,
    )
    monkeypatch.setattr(main, "load_or_create_profile", lambda: {"hostname": "test-host"})
    monkeypatch.setattr(main, "show_splash", lambda profile: events.append("splash"))
    monkeypatch.setattr(main, "launch_cli", lambda profile: events.append("cli"))

    assert main.main([]) == 0
    assert events == [("check", False), "splash", "cli"]


def test_main_stops_when_safety_check_fails(monkeypatch):
    events = []

    monkeypatch.setattr(main, "check_root_safety", lambda allow_unsafe: False)
    monkeypatch.setattr(main, "launch_cli", lambda profile: events.append("cli"))

    assert main.main([]) == 1
    assert events == []


def test_main_passes_unsafe_override(monkeypatch):
    seen = []

    monkeypatch.setattr(main, "check_root_safety", lambda allow_unsafe: seen.append(allow_unsafe))

    main.main(["--allow-unsafe-install"])

    assert seen == [True]


def _quiet(monkeypatch):
    printed = []
    monkeypatch.setattr(main.console, "print", lambda *args, **kwargs: printed.append(args))
    return printed


CLEAN = {"status": "ok", "details": [], "tags": []}


def test_root_refuses_unsafe_install(monkeypatch):
    printed = _quiet(monkeypatch)
    monkeypatch.setattr(main, "IMPORT_STATUS", CLEAN)
    monkeypatch.setattr(main, "INSTALL_ISSUES", ["/home/liam is owned by uid 1000"])

    assert main.check_root_safety(False, euid=0) is False
    assert any("REFUSING TO RUN AS ROOT" in str(item) for call in printed for item in call)


def test_root_refuses_suspicious_import_environment(monkeypatch):
    _quiet(monkeypatch)
    monkeypatch.setattr(
        main,
        "IMPORT_STATUS",
        {"status": "warning", "details": ["PYTHONPATH is set: /tmp/evil"], "tags": []},
    )
    monkeypatch.setattr(main, "INSTALL_ISSUES", [])

    assert main.check_root_safety(False, euid=0) is False


def test_root_override_continues(monkeypatch):
    printed = _quiet(monkeypatch)
    monkeypatch.setattr(main, "IMPORT_STATUS", CLEAN)
    monkeypatch.setattr(main, "INSTALL_ISSUES", ["/home/liam is owned by uid 1000"])

    assert main.check_root_safety(True, euid=0) is True
    assert any("OVERRIDDEN" in str(item) for call in printed for item in call)


def test_root_with_safe_install_continues(monkeypatch):
    _quiet(monkeypatch)
    monkeypatch.setattr(main, "IMPORT_STATUS", CLEAN)
    monkeypatch.setattr(main, "INSTALL_ISSUES", [])

    assert main.check_root_safety(False, euid=0) is True


def test_non_root_only_warns(monkeypatch):
    printed = _quiet(monkeypatch)
    monkeypatch.setattr(
        main,
        "IMPORT_STATUS",
        {"status": "warning", "details": ["PYTHONPATH is set: /tmp/evil"], "tags": []},
    )
    monkeypatch.setattr(main, "INSTALL_ISSUES", ["ignored for non-root"])

    assert main.check_root_safety(False, euid=1000) is True
    assert any("IMPORT ENVIRONMENT WARNING" in str(item) for call in printed for item in call)
