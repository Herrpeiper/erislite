from erislite.ui import splash


def test_firewall_display_uses_detected_backend(monkeypatch):
    monkeypatch.setattr(
        splash,
        "run_firewall_check",
        lambda silent=True: {
            "status": "ok",
            "details": ["UFW is active"],
            "tags": [],
        },
    )

    assert splash.get_firewall_display() == "UFW"


def test_firewall_display_handles_no_backend(monkeypatch):
    monkeypatch.setattr(
        splash,
        "run_firewall_check",
        lambda silent=True: {
            "status": "warning",
            "details": ["No supported active firewall was detected"],
            "tags": ["firewall_disabled"],
        },
    )

    assert splash.get_firewall_display() == "None detected"


def test_firewall_display_handles_nftables(monkeypatch):
    monkeypatch.setattr(
        splash,
        "run_firewall_check",
        lambda silent=True: {
            "status": "ok",
            "details": ["nftables ruleset detected"],
            "tags": [],
        },
    )

    assert splash.get_firewall_display() == "nftables"


def test_firewall_display_handles_permission_denied(monkeypatch):
    monkeypatch.setattr(
        splash,
        "run_firewall_check",
        lambda silent=True: {
            "status": "warning",
            "details": [
                "Firewall state could not be fully inspected due to insufficient permissions"
            ],
            "tags": ["firewall_permission_denied"],
        },
    )

    assert splash.get_firewall_display() == "Unknown (permission denied)"


def test_firewall_display_handles_inspection_failure(monkeypatch):
    monkeypatch.setattr(
        splash,
        "run_firewall_check",
        lambda silent=True: {
            "status": "error",
            "details": ["Firewall inspection commands failed"],
            "tags": ["firewall_check_failed"],
        },
    )

    assert splash.get_firewall_display() == "Unknown (inspection failed)"