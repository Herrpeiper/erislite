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

    rendered = "\n".join(
        str(item)
        for call in printed
        for item in call
    )

    assert "IMPORT ENVIRONMENT WARNING" in rendered
    assert "PYTHONPATH is set: /tmp/evil" in rendered
    assert "Suspicious import path: /tmp/evil" in rendered
    assert "will continue" in rendered


def test_main_runs_warning_before_cli(monkeypatch):
    events = []

    monkeypatch.setattr(
        main,
        "_show_import_warning",
        lambda: events.append("warning"),
    )

    monkeypatch.setattr(
        main,
        "load_or_create_profile",
        lambda: {
            "hostname": "test-host",
        },
    )

    monkeypatch.setattr(
        main,
        "show_splash",
        lambda profile: events.append("splash"),
    )

    monkeypatch.setattr(
        main,
        "launch_cli",
        lambda profile: events.append("cli"),
    )

    main.main()

    assert events == [
        "warning",
        "splash",
        "cli",
    ]
