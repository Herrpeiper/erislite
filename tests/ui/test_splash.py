from erislite.ui import splash


def test_firewall_display_uses_detected_backend(monkeypatch):
    monkeypatch.setattr(
        splash,
        "detect_firewall_backend",
        lambda: "ufw",
    )

    assert splash.get_firewall_display() == "UFW"


def test_firewall_display_handles_no_backend(monkeypatch):
    monkeypatch.setattr(
        splash,
        "detect_firewall_backend",
        lambda: None,
    )

    assert splash.get_firewall_display() == "None detected"


def test_firewall_display_handles_nftables(monkeypatch):
    monkeypatch.setattr(
        splash,
        "detect_firewall_backend",
        lambda: "nftables",
    )

    assert splash.get_firewall_display() == "nftables"