# Project: ErisLITE
# Module: test_dedup.py
# Author: Liam Piper-Brandon
# Version: 1.4.0
# License: MIT
# Created: 2026-09-30
# Last Updated: 2026-09-30
# Description: Tests for bounded duplicate tracking and repeat summaries in Odyssey Lite.

"""Duplicate suppression must stay bounded and must not lose connections.

Suppressed repeats are counted and written to the event log as a
repeat_summary record when the source's window closes, when Odyssey stops
or when the in-session view is cleared.
"""

from datetime import datetime, timedelta, timezone

import pytest

from erislite.deception.odyssey import manager as manager_module
from erislite.deception.odyssey.events import OdysseyEvent
from erislite.deception.odyssey.manager import DUPLICATE_WINDOW_SECONDS, OdysseyManager

T0 = datetime(2026, 9, 30, 17, 0, tzinfo=timezone.utc)
WINDOW = timedelta(seconds=DUPLICATE_WINDOW_SECONDS)


def _event(source_ip="192.0.2.10", port=2323, at=T0) -> OdysseyEvent:
    return OdysseyEvent(
        source_ip=source_ip,
        source_port=50000,
        destination_port=port,
        service="telnet-alt",
        severity="high",
        timestamp=at,
    )


@pytest.fixture
def log(monkeypatch):
    """Capture everything the manager writes to the event log."""

    records = []
    monkeypatch.setattr(manager_module, "append_event", lambda e: records.append(e.to_dict()))
    monkeypatch.setattr(manager_module, "append_record", records.append)
    return records


def _summaries(records):
    return [record for record in records if record.get("record") == "repeat_summary"]


def _events(records):
    return [record for record in records if "record" not in record]


# ---------------------------------------------------------------------------
# Bounded tracking
# ---------------------------------------------------------------------------


def test_stale_sources_expire(log):
    manager = OdysseyManager(configs=())

    for index in range(100):
        manager._record_event(_event(source_ip=f"10.0.0.{index}"))

    manager._record_event(_event(source_ip="10.0.1.1", at=T0 + WINDOW + timedelta(seconds=1)))

    assert len(manager._tracked) == 1


def test_tracking_is_capped_under_flood(monkeypatch, log):
    monkeypatch.setattr(manager_module, "MAX_TRACKED_SOURCES", 50)
    manager = OdysseyManager(configs=())

    for index in range(500):
        manager._record_event(_event(source_ip=f"10.0.{index // 256}.{index % 256}"))

    assert len(manager._tracked) == 50
    assert len(_events(log)) == 500


def test_evicted_source_fails_open(monkeypatch, log):
    """An evicted source is logged again rather than silently suppressed."""

    monkeypatch.setattr(manager_module, "MAX_TRACKED_SOURCES", 1)
    manager = OdysseyManager(configs=())

    manager._record_event(_event(source_ip="10.0.0.1"))
    manager._record_event(_event(source_ip="10.0.0.2"))
    manager._record_event(_event(source_ip="10.0.0.1", at=T0 + timedelta(seconds=1)))

    assert [record["source_ip"] for record in _events(log)] == [
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.1",
    ]
    assert manager.suppressed_events == 0


# ---------------------------------------------------------------------------
# Repeat summaries
# ---------------------------------------------------------------------------


def test_summary_written_when_same_source_returns_after_window(log):
    manager = OdysseyManager(configs=())

    manager._record_event(_event(at=T0))
    manager._record_event(_event(at=T0 + timedelta(seconds=1)))
    manager._record_event(_event(at=T0 + timedelta(seconds=2)))
    manager._record_event(_event(at=T0 + WINDOW + timedelta(seconds=5)))

    (summary,) = _summaries(log)

    assert summary["repeat_count"] == 2
    assert summary["first_seen"] == T0.isoformat()
    assert summary["last_seen"] == (T0 + timedelta(seconds=2)).isoformat()
    assert summary["source_ip"] == "192.0.2.10"
    assert summary["destination_port"] == 2323
    assert len(_events(log)) == 2


def test_summary_written_when_window_expires_via_other_traffic(log):
    manager = OdysseyManager(configs=())

    manager._record_event(_event(source_ip="10.0.0.1", at=T0))
    manager._record_event(_event(source_ip="10.0.0.1", at=T0 + timedelta(seconds=1)))
    manager._record_event(_event(source_ip="10.0.0.2", at=T0 + WINDOW + timedelta(seconds=1)))

    (summary,) = _summaries(log)

    assert summary["source_ip"] == "10.0.0.1"
    assert summary["repeat_count"] == 1


def test_summary_written_on_stop(log):
    manager = OdysseyManager(configs=())

    manager._record_event(_event(at=T0))
    manager._record_event(_event(at=T0 + timedelta(seconds=1)))

    assert _summaries(log) == []

    manager.stop()

    assert _summaries(log)[0]["repeat_count"] == 1


def test_summary_written_before_clear(log):
    manager = OdysseyManager(configs=())

    manager._record_event(_event(at=T0))
    manager._record_event(_event(at=T0 + timedelta(seconds=1)))
    manager.clear_events()

    assert _summaries(log)[0]["repeat_count"] == 1
    assert manager.events == ()
    assert manager.suppressed_events == 0


def test_no_summary_without_repeats(log):
    manager = OdysseyManager(configs=())

    manager._record_event(_event())
    manager.stop()

    assert _summaries(log) == []


def test_flood_is_fully_accounted_for(log):
    manager = OdysseyManager(configs=())

    for index in range(2000):
        manager._record_event(_event(at=T0 + timedelta(milliseconds=index)))

    manager.stop()

    logged = len(_events(log))
    repeats = sum(summary["repeat_count"] for summary in _summaries(log))

    assert logged == 1
    assert logged + repeats == 2000


def test_summary_write_failure_is_reported(monkeypatch, log):
    manager = OdysseyManager(configs=())

    manager._record_event(_event(at=T0))
    manager._record_event(_event(at=T0 + timedelta(seconds=1)))

    def refuse(record):
        raise OSError("disk full")

    monkeypatch.setattr(manager_module, "append_record", refuse)
    manager.stop()

    assert manager.persistence_error == "disk full"
