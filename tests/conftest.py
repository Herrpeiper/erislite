# Project: ErisLITE
# Module: conftest.py
# Author: Liam Piper-Brandon
# Version: 1.4.0
# License: MIT
# Created: 2026-09-30
# Last Updated: 2026-09-30
# Description: Shared pytest fixtures that keep tests from writing into the repository.

import pytest

from erislite.deception.odyssey import storage


@pytest.fixture(autouse=True)
def _isolate_odyssey_event_log(monkeypatch, tmp_path):
    """Redirect the default Odyssey event log into the test's temp directory.

    Without this, any test that records an event without patching storage
    writes into erislite/data/logs/odyssey/ in the working tree.
    """

    monkeypatch.setattr(
        storage,
        "DEFAULT_EVENT_LOG",
        tmp_path / "odyssey_logs" / "odyssey_events.jsonl",
    )
