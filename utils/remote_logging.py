"""Remote logging utilities for forwarding client logs to the controller.

This module exposes a thread-backed :class:`RemoteLogHandler` that collects
warning and error level log records from client roles and forwards them to the
controller once a network connection becomes available. Messages are enqueued
locally to avoid blocking the main application threads.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from typing import Callable, Optional


class RemoteLogHandler(logging.Handler):
    """Logging handler that forwards records to the controller asynchronously."""

    def __init__(self, *, source: str | None = None, sender: Optional[Callable[[dict], bool]] = None) -> None:
        super().__init__(level=logging.WARNING)
        self._queue: "queue.Queue[Optional[dict]]" = queue.Queue()
        self._stop_event = threading.Event()
        self._sender_lock = threading.Lock()
        self._sender: Optional[Callable[[dict], bool]] = sender
        self._source = source or ""
        self._worker = threading.Thread(target=self._process_queue, daemon=True, name="RemoteLogSender")
        self._worker.start()

    def emit(self, record: logging.LogRecord) -> None:  # pragma: no cover - logging integration
        try:
            payload = {
                "type": "remote_log",
                "level": record.levelname,
                "message": record.getMessage(),
                "source": self._source or record.name,
            }
            # Store a JSON snapshot for debugging requirements and enqueue the dict itself
            payload["json"] = json.dumps(
                {"type": "remote_log", "level": record.levelname, "message": record.getMessage(), "source": payload["source"]},
                ensure_ascii=False,
            )
            self._queue.put_nowait(payload)
        except Exception:
            # Never raise from logging; drop the record if we cannot enqueue.
            self.handleError(record)

    def set_source(self, source: str) -> None:
        with self._sender_lock:
            self._source = source

    def set_sender(self, sender: Optional[Callable[[dict], bool]]) -> None:
        with self._sender_lock:
            self._sender = sender

    def close(self) -> None:  # pragma: no cover - cleanup hook
        self._stop_event.set()
        self._queue.put_nowait(None)
        if self._worker.is_alive():
            self._worker.join(timeout=1.0)
        super().close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _process_queue(self) -> None:
        backlog: list[dict] = []
        while not self._stop_event.is_set():
            try:
                item = self._queue.get(timeout=0.5)
            except queue.Empty:
                item = None
            if item is None:
                if self._stop_event.is_set():
                    break
                item = None
            else:
                backlog.append(item)

            if not backlog:
                continue

            sender = self._current_sender()
            if sender is None:
                time.sleep(0.5)
                continue

            retry: list[dict] = []
            for payload in backlog:
                try:
                    if not sender(payload):
                        retry.append(payload)
                except Exception:
                    retry.append(payload)
            backlog = retry
            if backlog:
                time.sleep(0.5)

    def _current_sender(self) -> Optional[Callable[[dict], bool]]:
        with self._sender_lock:
            return self._sender


_global_handler: Optional[RemoteLogHandler] = None
_handler_lock = threading.Lock()


def get_remote_log_handler() -> RemoteLogHandler:
    """Return the shared remote log handler instance, creating it if needed."""

    global _global_handler
    with _handler_lock:
        if _global_handler is None:
            _global_handler = RemoteLogHandler()
        return _global_handler

