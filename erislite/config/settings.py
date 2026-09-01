"""
ErisLITE v1.1
Application-wide settings and paths.
"""

from pathlib import Path


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

APP_NAME = "ErisLITE"
APP_VERSION = "1.1.0"
APP_DESCRIPTION = "Linux competition security and triage toolkit"


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
PROJECT_ROOT = PACKAGE_ROOT.parent

DATA_DIR = PROJECT_ROOT / "data"
LOG_DIR = DATA_DIR / "logs"
INTEGRITY_DIR = DATA_DIR / "integrity"

USER_DATA_DIR = Path.home() / ".erislite"

LAST_SWEEP_FILE = USER_DATA_DIR / "last_sweep.json"


# ---------------------------------------------------------------------------
# Runtime defaults
# ---------------------------------------------------------------------------

DEFAULT_COMMAND_TIMEOUT = 10
DEFAULT_NETWORK_TIMEOUT = 3

MAX_DISPLAY_FINDINGS = 50
MAX_LOG_FINDINGS = 500


# ---------------------------------------------------------------------------
# Sweep defaults
# ---------------------------------------------------------------------------

DEFAULT_SWEEP_PROFILE = "standard"

SWEEP_PROFILES = {
    "quick": (
        "listeners",
        "users",
        "login",
    ),
    "standard": (
        "integrity",
        "listeners",
        "users",
        "login",
        "cve",
    ),
    "full": (
        "integrity",
        "listeners",
        "users",
        "kernel",
        "sshkeys",
        "worldwritable",
        "cron",
        "login",
        "sshconfig",
        "docker",
        "suid",
        "processes",
        "hosts",
        "backdoor",
        "cve",
    ),
}


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

SUPPORTED_PLATFORM = "Linux"
ROOT_UID = 0


def ensure_runtime_directories() -> None:
    """Create ErisLITE runtime directories if they do not exist."""

    for directory in (
        DATA_DIR,
        LOG_DIR,
        INTEGRITY_DIR,
        USER_DATA_DIR,
    ):
        directory.mkdir(parents=True, exist_ok=True)