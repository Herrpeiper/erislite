# Project: ErisLITE
# Module: storage.py
# Author: Liam Piper-Brandon
# Version: 1.4.0
# License: MIT
# Created: 2026-09-26
# Last Updated: 2026-09-26
# Description: Persistent event storage for Odyssey Lite.

import json
from pathlib import Path

from erislite.deception.odyssey.events import OdysseyEvent

_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOG_DIR = _REPO_ROOT / "data" / "logs" / "odyssey"
DEFAULT_EVENT_LOG = DEFAULT_LOG_DIR / "odyssey_events.jsonl"


def append_event(
    event: OdysseyEvent,
    path: Path = DEFAULT_EVENT_LOG,
) -> None:
    """Append an Odyssey event to the persistent JSONL event log."""

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "a",
        encoding="utf-8",
    ) as file:
        json.dump(
            event.to_dict(),
            file,
            sort_keys=True,
        )
        file.write("\n")
