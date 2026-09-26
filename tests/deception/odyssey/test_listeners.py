import socket
import time

from erislite.deception.odyssey.config import ListenerConfig
from erislite.deception.odyssey.listeners import CanaryListener


def _get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_listener_starts_and_stops():
    events = []
    port = _get_free_port()

    config = ListenerConfig(
        port=port,
        service="test-canary",
    )

    listener = CanaryListener(
        config=config,
        event_callback=events.append,
        host="127.0.0.1",
    )

    listener.start()

    assert listener.running is True

    listener.stop()

    assert listener.running is False


def test_listener_generates_event_on_connection():
    events = []
    port = _get_free_port()

    config = ListenerConfig(
        port=port,
        service="test-canary",
        severity="high",
    )

    listener = CanaryListener(
        config=config,
        event_callback=events.append,
        host="127.0.0.1",
    )

    listener.start()

    try:
        with socket.create_connection(
            ("127.0.0.1", port),
            timeout=2.0,
        ):
            pass

        deadline = time.monotonic() + 2.0

        while not events and time.monotonic() < deadline:
            time.sleep(0.01)

        assert len(events) == 1

        event = events[0]

        assert event.source_ip == "127.0.0.1"
        assert event.source_port > 0
        assert event.destination_port == port
        assert event.service == "test-canary"
        assert event.severity == "high"
    finally:
        listener.stop()


def test_listener_start_is_idempotent():
    events = []
    port = _get_free_port()

    config = ListenerConfig(
        port=port,
        service="test-canary",
    )

    listener = CanaryListener(
        config=config,
        event_callback=events.append,
        host="127.0.0.1",
    )

    listener.start()

    first_thread = listener._thread

    try:
        listener.start()

        assert listener.running is True
        assert listener._thread is first_thread
    finally:
        listener.stop()