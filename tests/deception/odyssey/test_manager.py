import socket
import threading
import time
from datetime import datetime, timedelta, timezone

from erislite.deception.odyssey import manager as manager_module
from erislite.deception.odyssey import manager
from erislite.deception.odyssey.config import ListenerConfig
from erislite.deception.odyssey.events import OdysseyEvent
from erislite.deception.odyssey.manager import OdysseyManager


def _get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_manager_starts_and_stops_multiple_listeners():
    configs = (
        ListenerConfig(
            port=_get_free_port(),
            service="canary-one",
        ),
        ListenerConfig(
            port=_get_free_port(),
            service="canary-two",
        ),
    )

    manager = OdysseyManager(
        configs=configs,
        host="127.0.0.1",
    )

    manager.start()

    try:
        assert manager.running is True
        assert len(manager.listeners) == 2
        assert all(listener.running for listener in manager.listeners)
    finally:
        manager.stop()

    assert manager.running is False


def test_manager_records_events(monkeypatch):
    monkeypatch.setattr(
        manager_module,
        "append_event",
        lambda event: None,
    )
        
    port = _get_free_port()

    manager = OdysseyManager(
        configs=(
            ListenerConfig(
                port=port,
                service="test-canary",
                severity="high",
            ),
        ),
        host="127.0.0.1",
    )

    manager.start()

    try:
        with socket.create_connection(
            ("127.0.0.1", port),
            timeout=2.0,
        ):
            pass

        deadline = time.monotonic() + 2.0

        while not manager.events and time.monotonic() < deadline:
            time.sleep(0.01)

        assert len(manager.events) == 1

        event = manager.events[0]

        assert event.destination_port == port
        assert event.service == "test-canary"
        assert event.severity == "high"
    finally:
        manager.stop()


def test_manager_skips_disabled_listeners():
    enabled_port = _get_free_port()
    disabled_port = _get_free_port()

    manager = OdysseyManager(
        configs=(
            ListenerConfig(
                port=enabled_port,
                service="enabled",
            ),
            ListenerConfig(
                port=disabled_port,
                service="disabled",
                enabled=False,
            ),
        ),
        host="127.0.0.1",
    )

    manager.start()

    try:
        assert len(manager.listeners) == 1
        assert manager.listeners[0].config.port == enabled_port
    finally:
        manager.stop()


def test_manager_clear_events(monkeypatch):
    monkeypatch.setattr(
        manager_module,
        "append_event",
        lambda event: None,
    )
    port = _get_free_port()

    manager = OdysseyManager(
        configs=(
            ListenerConfig(
                port=port,
                service="test-canary",
            ),
        ),
        host="127.0.0.1",
    )

    manager.start()

    try:
        with socket.create_connection(
            ("127.0.0.1", port),
            timeout=2.0,
        ):
            pass

        deadline = time.monotonic() + 2.0

        while not manager.events and time.monotonic() < deadline:
            time.sleep(0.01)

        assert len(manager.events) == 1

        manager.clear_events()

        assert manager.events == ()
    finally:
        manager.stop()


def test_manager_start_is_idempotent():
    port = _get_free_port()

    manager = OdysseyManager(
        configs=(
            ListenerConfig(
                port=port,
                service="test-canary",
            ),
        ),
        host="127.0.0.1",
    )

    manager.start()

    first_listeners = manager.listeners

    try:
        manager.start()

        assert manager.listeners == first_listeners
        assert len(manager.listeners) == 1
    finally:
        manager.stop()


def test_manager_reports_failed_ports_without_stopping_other_listeners():
    working_port = _get_free_port()

    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen()

    blocked_port = blocker.getsockname()[1]

    manager = OdysseyManager(
        configs=(
            ListenerConfig(
                port=working_port,
                service="working-canary",
            ),
            ListenerConfig(
                port=blocked_port,
                service="blocked-canary",
            ),
        ),
        host="127.0.0.1",
    )

    try:
        manager.start()

        assert manager.running is True
        assert working_port in {
            listener.config.port
            for listener in manager.listeners
        }
        assert blocked_port in manager.failed_ports

    finally:
        manager.stop()
        blocker.close()

def test_manager_persists_recorded_event(monkeypatch):
    persisted = []

    monkeypatch.setattr(
        manager_module,
        "append_event",
        persisted.append,
    )

    manager = OdysseyManager(configs=())

    event = OdysseyEvent(
        source_ip="192.0.2.10",
        source_port=54321,
        destination_port=2323,
        service="telnet-alt",
        severity="high",
    )

    manager._record_event(event)

    assert manager.events == (event,)
    assert persisted == [event]


def test_manager_keeps_event_when_persistence_fails(monkeypatch):
    def fail_write(event):
        raise OSError("disk unavailable")

    monkeypatch.setattr(
        manager_module,
        "append_event",
        fail_write,
    )

    manager = OdysseyManager(configs=())

    event = OdysseyEvent(
        source_ip="192.0.2.10",
        source_port=54321,
        destination_port=2323,
        service="telnet-alt",
        severity="high",
    )

    manager._record_event(event)

    assert manager.events == (event,)

def test_manager_bounds_in_memory_events(monkeypatch):
    monkeypatch.setattr(
        manager_module,
        "append_event",
        lambda event: None,
    )

    manager = OdysseyManager(configs=())

    timestamp = datetime(
        2026,
        9,
        30,
        18,
        0,
        tzinfo=timezone.utc,
    )

    for index in range(1001):
        event = OdysseyEvent(
            source_ip="192.0.2.10",
            source_port=10000 + index,
            destination_port=2323,
            service="telnet-alt",
            severity="high",
            timestamp=timestamp + timedelta(seconds=index * 6),
        )

        manager._record_event(event)

    assert len(manager.events) == 1000
    assert manager.events[0].source_port == 10001
    assert manager.events[-1].source_port == 11000


def test_manager_suppresses_duplicate_events(monkeypatch):
    persisted = []

    monkeypatch.setattr(
        manager_module,
        "append_event",
        persisted.append,
    )

    manager = OdysseyManager(configs=())

    timestamp = datetime(
        2026,
        9,
        30,
        18,
        0,
        tzinfo=timezone.utc,
    )

    first = OdysseyEvent(
        source_ip="192.0.2.10",
        source_port=50000,
        destination_port=2323,
        service="telnet-alt",
        severity="high",
        timestamp=timestamp,
    )

    duplicate = OdysseyEvent(
        source_ip="192.0.2.10",
        source_port=50001,
        destination_port=2323,
        service="telnet-alt",
        severity="high",
        timestamp=timestamp + timedelta(seconds=2),
    )

    manager._record_event(first)
    manager._record_event(duplicate)

    assert manager.events == (first,)
    assert persisted == [first]
    assert manager.suppressed_events == 1


def test_manager_records_duplicate_after_window(monkeypatch):
    persisted = []

    monkeypatch.setattr(
        manager_module,
        "append_event",
        persisted.append,
    )

    manager = OdysseyManager(configs=())

    timestamp = datetime(
        2026,
        9,
        30,
        18,
        0,
        tzinfo=timezone.utc,
    )

    first = OdysseyEvent(
        source_ip="192.0.2.10",
        source_port=50000,
        destination_port=2323,
        service="telnet-alt",
        severity="high",
        timestamp=timestamp,
    )

    later = OdysseyEvent(
        source_ip="192.0.2.10",
        source_port=50001,
        destination_port=2323,
        service="telnet-alt",
        severity="high",
        timestamp=timestamp + timedelta(seconds=6),
    )

    manager._record_event(first)
    manager._record_event(later)

    assert manager.events == (first, later)
    assert persisted == [first, later]
    assert manager.suppressed_events == 0

def test_manager_does_not_suppress_different_canary(monkeypatch):
    persisted = []

    monkeypatch.setattr(
        manager_module,
        "append_event",
        persisted.append,
    )

    manager = OdysseyManager(configs=())

    timestamp = datetime(
        2026,
        9,
        30,
        18,
        0,
        tzinfo=timezone.utc,
    )

    telnet_event = OdysseyEvent(
        source_ip="192.0.2.10",
        source_port=50000,
        destination_port=2323,
        service="telnet-alt",
        severity="high",
        timestamp=timestamp,
    )

    rdp_event = OdysseyEvent(
        source_ip="192.0.2.10",
        source_port=50001,
        destination_port=3389,
        service="rdp",
        severity="high",
        timestamp=timestamp + timedelta(seconds=1),
    )

    manager._record_event(telnet_event)
    manager._record_event(rdp_event)

    assert manager.events == (telnet_event, rdp_event)
    assert persisted == [telnet_event, rdp_event]
    assert manager.suppressed_events == 0

def test_manager_clear_events_resets_suppression_state(monkeypatch):
    monkeypatch.setattr(
        manager_module,
        "append_event",
        lambda event: None,
    )

    manager = OdysseyManager(configs=())

    timestamp = datetime(
        2026,
        9,
        30,
        18,
        0,
        tzinfo=timezone.utc,
    )

    first = OdysseyEvent(
        source_ip="192.0.2.10",
        source_port=50000,
        destination_port=2323,
        service="telnet-alt",
        severity="high",
        timestamp=timestamp,
    )

    duplicate = OdysseyEvent(
        source_ip="192.0.2.10",
        source_port=50001,
        destination_port=2323,
        service="telnet-alt",
        severity="high",
        timestamp=timestamp + timedelta(seconds=1),
    )

    manager._record_event(first)
    manager._record_event(duplicate)

    assert manager.suppressed_events == 1

    manager.clear_events()

    assert manager.events == ()
    assert manager.suppressed_events == 0

    manager._record_event(duplicate)

    assert manager.events == (duplicate,)

def test_manager_suppresses_concurrent_duplicates(monkeypatch):
    persisted = []

    monkeypatch.setattr(
        manager_module,
        "append_event",
        persisted.append,
    )

    manager = OdysseyManager(configs=())

    timestamp = datetime(
        2026,
        9,
        30,
        18,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        OdysseyEvent(
            source_ip="192.0.2.10",
            source_port=50000 + index,
            destination_port=2323,
            service="telnet-alt",
            severity="high",
            timestamp=timestamp,
        )
        for index in range(10)
    ]

    threads = [
        threading.Thread(
            target=manager._record_event,
            args=(event,),
        )
        for event in events
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert len(manager.events) == 1
    assert len(persisted) == 1
    assert manager.suppressed_events == 9

def test_manager_continues_when_one_port_is_occupied():
    open_port = _get_free_port()

    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen()

    blocked_port = blocker.getsockname()[1]

    manager = OdysseyManager(
        configs=(
            ListenerConfig(
                port=open_port,
                service="available-canary",
            ),
            ListenerConfig(
                port=blocked_port,
                service="blocked-canary",
            ),
        ),
        host="127.0.0.1",
    )

    try:
        manager.start()

        print(manager.listeners)
        for listener in manager.listeners:
            print(
                listener.config.port,
                listener.running,
                listener._thread,
            )

        running_ports = {
            listener.config.port
            for listener in manager.listeners
            if listener.running
        }

        assert open_port in running_ports
        assert blocked_port not in running_ports
        assert manager.failed_ports == (blocked_port,)
    finally:
        manager.stop()
        blocker.close()