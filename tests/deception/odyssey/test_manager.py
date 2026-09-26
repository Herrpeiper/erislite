import socket
import time

from erislite.deception.odyssey import manager as manager_module
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


def test_manager_cleans_up_after_start_failure():
    first_port = _get_free_port()

    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen()

    blocked_port = blocker.getsockname()[1]

    manager = OdysseyManager(
        configs=(
            ListenerConfig(
                port=first_port,
                service="first-canary",
            ),
            ListenerConfig(
                port=blocked_port,
                service="blocked-canary",
            ),
        ),
        host="127.0.0.1",
    )

    try:
        try:
            manager.start()
        except OSError:
            pass
        else:
            raise AssertionError("Expected Odyssey startup to fail")

        assert manager.running is False
        assert manager.listeners == ()
    finally:
        blocker.close()
        manager.stop()

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
