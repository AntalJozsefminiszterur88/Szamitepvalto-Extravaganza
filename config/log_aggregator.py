"""Remote log aggregation utilities for the controller role."""

from __future__ import annotations

import logging
import queue
import threading
from typing import Optional, Tuple


class LogAggregator:
    """Collect remote log messages and forward them to the central log file."""

    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        """Create a new aggregator that forwards remote logs to the controller.

        When *logger* is ``None`` we fall back to the root logger.  This makes
        sure that aggregated records end up in the exact same handler pipeline
        (and therefore the same rotating log file) that the controller already
        uses for its own events.  Relying on the root logger also means that the
        :class:`~utils.logging_setup.RemoteSourceFilter` installed on the root
        handlers will decorate the log line with the ``remote_source`` prefix so
        operators can clearly see which client produced a given message.
        """

        if logger is None:
            logger = logging.getLogger()
        self._logger = logger
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

