"""Common honeypot machinery (threaded server lifecycle)."""

from __future__ import annotations

import threading
from typing import Callable

from ..models import Event

EventSink = Callable[[Event], None]


class BaseHoneypot:
    """Base class handling the background-thread lifecycle for a sensor.

    Subclasses implement :meth:`_serve_forever` and :meth:`_shutdown`.
    """

    name = "base"

    def __init__(self, host: str, port: int, sink: EventSink) -> None:
        self.host = host
        self.port = port
        self.sink = sink
        self._thread: threading.Thread | None = None
        self._started = threading.Event()

    # -- lifecycle ------------------------------------------------------
    def start(self) -> "BaseHoneypot":
        if self._thread and self._thread.is_alive():
            return self
        self._thread = threading.Thread(target=self._run, name=f"honeypot-{self.name}", daemon=True)
        self._thread.start()
        self._started.wait(timeout=5)
        return self

    def _run(self) -> None:
        self._serve_forever()

    def stop(self) -> None:
        self._shutdown()
        if self._thread:
            self._thread.join(timeout=5)

    def __enter__(self) -> "BaseHoneypot":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- to be implemented by subclasses --------------------------------
    def _serve_forever(self) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    def _shutdown(self) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    # -- helpers --------------------------------------------------------
    def emit(self, event: Event) -> None:
        self.sink(event)
