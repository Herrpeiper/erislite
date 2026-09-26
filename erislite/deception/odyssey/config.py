# Project: ErisLITE
# Module: config.py
# Author: Liam Piper-Brandon
# Version: 1.4.0
# License: MIT
# Created: 2026-09-26
# Last Updated: 2026-09-26
# Description: Configuration and defaults for Odyssey Lite deception listeners.

from dataclasses import dataclass


@dataclass(frozen=True)
class ListenerConfig:
    """Configuration for a single Odyssey Lite TCP listener."""

    port: int
    service: str
    severity: str = "medium"
    enabled: bool = True


DEFAULT_LISTENERS = (
    ListenerConfig(port=2121, service="ftp-alt", severity="medium"),
    ListenerConfig(port=2323, service="telnet-alt", severity="high"),
    ListenerConfig(port=2222, service="ssh-alt", severity="high"),
    ListenerConfig(port=3389, service="rdp", severity="high"),
    ListenerConfig(port=8080, service="http-alt", severity="medium"),
)


def get_default_listeners() -> tuple[ListenerConfig, ...]:
    """Return the default Odyssey Lite listener configuration."""

    return DEFAULT_LISTENERS