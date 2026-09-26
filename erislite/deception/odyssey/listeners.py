# Project: ErisLITE
# Module: listeners.py
# Author: Liam Piper-Brandon
# Version: 1.4.0
# License: MIT
# Created: 2026-09-26
# Last Updated: 2026-09-26
# Description: TCP canary listeners for Odyssey Lite.

import socket
import threading
from collections.abc import Callable

from erislite.deception.odyssey.config import ListenerConfig
from erislite.deception.odyssey.events import OdysseyEvent

EventCallback = Callable[[OdysseyEvent], None]


class CanaryListener:
    """Lightweight TCP canary listener for Odyssey Lite."""

    def __init__(
        self,
        config: ListenerConfig,
        event_callback: EventCallback,
        host: str = "0.0.0.0",
    ) -> None:
        self.config = config
        self.event_callback = event_callback
        self.host = host

        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    @property
    def running(self) -> bool:
        """Return whether the listener thread is currently active."""

        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        """Start the canary listener."""

        if self.running:
            return

        self._stop_event.clear()

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self.host, self.config.port))
        self._socket.listen()
        self._socket.settimeout(1.0)

        self._thread = threading.Thread(
            target=self._listen_loop,
            name=f"odyssey-{self.config.port}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the canary listener."""

        self._stop_event.set()

        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            finally:
                self._socket = None

        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _listen_loop(self) -> None:
        """Accept connections until the listener is stopped."""

        while not self._stop_event.is_set():
            try:
                if self._socket is None:
                    break

                connection, address = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                source_ip, source_port = address

                event = OdysseyEvent(
                    source_ip=source_ip,
                    source_port=source_port,
                    destination_port=self.config.port,
                    service=self.config.service,
                    severity=self.config.severity,
                )

                self.event_callback(event)
            finally:
                connection.close()