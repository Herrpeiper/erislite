# Project: ErisLITE
# Module: guidance.py
# Author: Liam Piper-Brandon
# Version: 1.2.0
# License: MIT
# Created: 2025-06-01
# Last Updated: 2026-09-11
# Description: Analyst response guidance for threat findings.

DEFAULT_GUIDANCE = {
    "severity": "unknown",
    "summary": "No response guidance is currently available.",
    "investigate": [],
    "recommendation": (
        "Review the underlying module findings manually before making changes."
    ),
}


RESPONSE_GUIDANCE = {
    "uid0_clone": {
        "severity": "high",
        "summary": (
            "A non-root account has UID 0 and therefore has "
            "root-equivalent privileges."
        ),
        "investigate": [
            "awk -F: '$3 == 0 {print}' /etc/passwd",
            "getent passwd",
            "last",
        ],
        "recommendation": (
            "Verify whether the account is authorized before disabling "
            "or modifying it."
        ),
    },

    "backdoor_ld_preload": {
        "severity": "critical",
        "summary": (
            "/etc/ld.so.preload can force shared libraries into processes "
            "and may indicate persistence or rootkit activity."
        ),
        "investigate": [
            "cat /etc/ld.so.preload",
            "ls -l /etc/ld.so.preload",
            "ps auxf",
            "lsof | grep deleted",
        ],
        "recommendation": (
            "Verify every referenced library before removing or modifying "
            "the preload configuration."
        ),
    },

    "proc_deleted_exe": {
        "severity": "high",
        "summary": (
            "A running process is using an executable that has been deleted "
            "from disk, which can indicate stealth or post-exploitation activity."
        ),
        "investigate": [
            "ls -l /proc/*/exe 2>/dev/null | grep deleted",
            "ps auxf",
            "lsof +L1",
        ],
        "recommendation": (
            "Identify the process owner, parent process, and executable origin "
            "before terminating it."
        ),
    },

    "proc_root_suspicious_path": {
        "severity": "high",
        "summary": (
            "A root-owned process is executing from a high-risk location such "
            "as /tmp, /dev/shm, or a user home directory."
        ),
        "investigate": [
            "ps auxf",
            "ls -l /proc/<PID>/exe",
            "cat /proc/<PID>/cmdline",
        ],
        "recommendation": (
            "Validate the process and its parent chain before stopping it."
        ),
    },

    "suspicious_cron": {
        "severity": "high",
        "summary": (
            "A scheduled task contains patterns associated with persistence, "
            "payload retrieval, or command execution."
        ),
        "investigate": [
            "crontab -l",
            "ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly",
            "systemctl list-timers --all",
        ],
        "recommendation": (
            "Confirm the task owner and purpose before disabling or deleting it."
        ),
    },

    "unauthorized_key": {
        "severity": "high",
        "summary": (
            "An unexpected SSH authorized key may provide persistent remote access."
        ),
        "investigate": [
            "find /root /home -name authorized_keys -type f -print",
            "grep -R '' /root/.ssh /home/*/.ssh 2>/dev/null",
            "last",
        ],
        "recommendation": (
            "Verify the key owner and authorization before removing the key."
        ),
    },

    "firewall_disabled": {
        "severity": "medium",
        "summary": (
            "No active host firewall was detected, increasing network exposure."
        ),
        "investigate": [
            "ufw status verbose",
            "iptables -S",
            "nft list ruleset",
        ],
        "recommendation": (
            "Determine the intended firewall platform and policy before enabling "
            "or changing rules."
        ),
    },

    "hosts_critical_redirect": {
        "severity": "high",
        "summary": (
            "A critical domain has been redirected in /etc/hosts, which may "
            "interfere with updates, security tooling, or trust services."
        ),
        "investigate": [
            "cat /etc/hosts",
            "getent hosts <hostname>",
            "stat /etc/hosts",
        ],
        "recommendation": (
            "Validate the redirect against the expected system configuration "
            "before editing /etc/hosts."
        ),
    },
}


def get_guidance(tag: str) -> dict:
    return RESPONSE_GUIDANCE.get(
        tag,
        DEFAULT_GUIDANCE,
    )


def has_guidance(tag: str) -> bool:
    return tag in RESPONSE_GUIDANCE