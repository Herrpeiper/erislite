# Project: ErisLITE
# Module: manager.py
# Author: Liam Piper-Brandon
# Version: 1.4.0
# License: MIT
# Created: 2026-09-26
# Last Updated: 2026-09-30
# Description: Lifecycle and event management for Odyssey Lite.

from __future__ import annotations

import atexit
import threading
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from erislite.deception.odyssey.config import (
    ListenerConfig,
    get_default_listeners,
)
from erislite.deception.odyssey.events import OdysseyEvent, OdysseyRepeatSummary
from erislite.deception.odyssey.listeners import CanaryListener
from erislite.deception.odyssey.storage import append_event, append_record

MAX_IN_MEMORY_EVENTS = 1000
DUPLICATE_WINDOW_SECONDS = 5

# Upper bound on sources tracked for duplicate suppression. Entries expire
# once their window closes. The cap only matters when more distinct sources
# than this hit canaries within one window. Evicting a source fails open:
# its next connection is logged as a new event instead of being suppressed.
MAX_TRACKED_SOURCES = 4096


@dataclass
class _TrackedSource:
    """Duplicate suppression state for one source and canary."""

    event: OdysseyEvent
    repeats: int = 0
    last_seen: datetime | None = None


class OdysseyManager:
    """Manage Odyssey Lite canary listeners and observed events."""

    def __init__(
        self,
        configs: Iterable[ListenerConfig] | None = None,
        host: str = "0.0.0.0",
    ) -> None:
        if configs is None:
            configs = get_default_listeners()

        self.host = host
        self.configs = tuple(configs)

        self._events: deque[OdysseyEvent] = deque(
            maxlen=MAX_IN_MEMORY_EVENTS
        )
        # Insertion order tracks the time each source was last logged, so
        # the oldest entries are always at the front.
        self._tracked: dict[tuple[str, int, str], _TrackedSource] = {}
        self._suppressed_events = 0
        self._event_lock = threading.Lock()
        self._listeners: list[CanaryListener] = []
        self._failed_ports: list[int] = []
        self._persistence_error: str | None = None

    @property
    def running(self) -> bool:
        """Return whether any Odyssey listener is currently running."""

        return any(listener.running for listener in self._listeners)

    @property
    def events(self) -> tuple[OdysseyEvent, ...]:
        """Return a read-only snapshot of observed Odyssey events."""

        return tuple(self._events)

    @property
    def suppressed_events(self) -> int:
        """Return the number of duplicate events suppressed this session."""

        return self._suppressed_events

    @property
    def listeners(self) -> tuple[CanaryListener, ...]:
        """Return the currently configured listener objects."""

        return tuple(self._listeners)

    @property
    def failed_ports(self) -> tuple[int, ...]:
        """Return ports that failed to start during the latest start attempt."""

        return tuple(self._failed_ports)

    @property
    def persistence_error(self) -> str | None:
        """Return the latest event log write error, or None when writes succeed."""

        return self._persistence_error

    @property
    def callback_errors(self) -> int:
        """Return event handling failures across the current listeners."""

        return sum(listener.callback_errors for listener in self._listeners)

    def start(self) -> None:
        """Create and start enabled Odyssey listeners."""

        if self.running:
            return

        self._listeners = []
        self._failed_ports = []

        for config in self.configs:
            if not config.enabled:
                continue

            listener = CanaryListener(
                config=config,
                event_callback=self._record_event,
                host=self.host,
            )

            try:
                listener.start()
            except OSError:
                listener.stop()
                self._failed_ports.append(config.port)
                continue

            self._listeners.append(listener)

    def stop(self) -> None:
        """Stop all Odyssey listeners and write pending repeat summaries."""

        for listener in self._listeners:
            listener.stop()

        self.flush_repeat_summaries()

    def flush_repeat_summaries(self) -> None:
        """Write a summary for every source with suppressed repeats."""

        with self._event_lock:
            for key in list(self._tracked):
                self._forget_source(key)

    def clear_events(self) -> None:
        """Clear the in-session event view.

        Pending repeat summaries are written first. Clearing the view never
        removes information from the event log.
        """

        with self._event_lock:
            for key in list(self._tracked):
                self._forget_source(key)

            self._events.clear()
            self._suppressed_events = 0

    def _record_event(self, event: OdysseyEvent) -> None:
        """Store and persist an event generated by an Odyssey listener."""

        with self._event_lock:
            key = (
                event.source_ip,
                event.destination_port,
                event.service,
            )

            tracked = self._tracked.get(key)

            if tracked is not None:
                elapsed = (event.timestamp - tracked.event.timestamp).total_seconds()

                if 0 <= elapsed <= DUPLICATE_WINDOW_SECONDS:
                    tracked.repeats += 1
                    tracked.last_seen = event.timestamp
                    self._suppressed_events += 1
                    return

                self._forget_source(key)

            self._tracked[key] = _TrackedSource(event=event)
            self._events.append(event)
            self._persist(append_event, event)
            self._expire_tracked_sources(event.timestamp)

    def _expire_tracked_sources(self, now: datetime) -> None:
        """Drop sources whose window has closed, then enforce the size cap.

        Must be called with the event lock held.
        """

        while self._tracked:
            key = next(iter(self._tracked))
            age = (now - self._tracked[key].event.timestamp).total_seconds()

            if age <= DUPLICATE_WINDOW_SECONDS and len(self._tracked) <= MAX_TRACKED_SOURCES:
                break

            self._forget_source(key)

    def _forget_source(self, key: tuple[str, int, str]) -> None:
        """Stop tracking a source and log how many repeats were suppressed.

        Must be called with the event lock held.
        """

        tracked = self._tracked.pop(key)

        if not tracked.repeats:
            return

        summary = OdysseyRepeatSummary(
            source_ip=tracked.event.source_ip,
            destination_port=tracked.event.destination_port,
            service=tracked.event.service,
            severity=tracked.event.severity,
            first_seen=tracked.event.timestamp,
            last_seen=tracked.last_seen or tracked.event.timestamp,
            repeat_count=tracked.repeats,
        )

        self._persist(append_record, summary.to_dict())

    def _persist(self, write, item) -> None:
        """Write to the event log and record whether persistence is failing.

        The in-memory view is unaffected by write failures. The menu shows
        persistence_error so a refused or unwritable log is never silent.
        """

        try:
            write(item)
        except OSError as exc:
            self._persistence_error = str(exc)
        else:
            self._persistence_error = None


_shared_manager: OdysseyManager | None = None
_shared_lock = threading.Lock()


def get_manager() -> OdysseyManager:
    """Return the process-wide Odyssey manager, creating it on first use.

    The menu is entered and left many times per session, but the listeners
    and their bound ports live for the whole process. A single shared manager
    keeps the menu in sync with what is actually running.
    """

    global _shared_manager

    with _shared_lock:
        if _shared_manager is None:
            _shared_manager = OdysseyManager()
            atexit.register(_shared_manager.stop)

        return _shared_manager


def active_canary_ports() -> frozenset[int]:
    """Return ports bound by running Odyssey listeners in this process.

    Does not create the shared manager if Odyssey was never opened.
    """

    manager = _shared_manager

    if manager is None:
        return frozenset()

    return frozenset(
        listener.config.port
        for listener in manager.listeners
        if listener.running
    )
