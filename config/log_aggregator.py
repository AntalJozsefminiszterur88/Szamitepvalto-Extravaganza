"""Remote log aggregation utilities for the controller role."""

from __future__ import annotations

import logging
import queue
import threading
from typing import Optional, Tuple


class LogAggregator:
    """Collect remote log messages and forward them to the central log file."""

    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        self._logger = logger or logging.getLogger("remote_logs")
        self._queue: "queue.Queue[Optional[Tuple[str, str, str]]]" = queue.Queue()
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._worker,
            name="LogAggregator",
            daemon=True,
        )

    def start(self) -> None:
        if self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._queue.put_nowait(None)
        if self._thread.is_alive():
            self._thread.join(timeout=1.0)

    def add_remote_log(self, source_client: str, level: str, message: str) -> None:
        self._queue.put_nowait((source_client, level, message))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _worker(self) -> None:
        while not self._stop_event.is_set():
            try:
                item = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if item is None:
                break
            source, level_name, message = item
            level = getattr(logging, level_name.upper(), logging.WARNING)
            try:
                self._logger.log(
                    level,
                    message,
                    extra={"remote_source": f"[{source}] - "},
                )
            except Exception:
                logging.getLogger(__name__).exception("Failed to aggregate remote log from %s", source)

