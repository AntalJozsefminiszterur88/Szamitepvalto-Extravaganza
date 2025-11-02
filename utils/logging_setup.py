"""Shared helpers for configuring the application's logging setup."""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import IO, Tuple

from config.constants import BRAND_NAME


LOG_FORMAT = "%(remote_source)s%(asctime)s - %(levelname)s - %(threadName)s - %(message)s"
LOG_FILENAME = "kvm_app.log"
LOG_SUBDIRECTORY = "Szamitepvalto-Extravaganza"
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 3


class RemoteSourceFilter(logging.Filter):
    """Ensure every record exposes a ``remote_source`` attribute."""

    def __init__(self, default_source: str = "") -> None:
        super().__init__()
        self._default_source = default_source

    def filter(self, record: logging.LogRecord) -> bool:  # pragma: no cover - logging integration
        current = getattr(record, "remote_source", None)
        if not current:
            record.remote_source = self._default_source
        return True


def _create_formatter() -> logging.Formatter:
    return logging.Formatter(LOG_FORMAT)


def create_stream_handler(
    stream: IO[str], *, default_remote_source: str = ""
) -> logging.Handler:
    """Create the default stream handler with filtering applied."""

    handler = logging.StreamHandler(stream)
    handler.setFormatter(_create_formatter())
    handler.addFilter(RemoteSourceFilter(default_remote_source))
    return handler


def create_controller_file_handler(
    log_file_path: str, *, default_remote_source: str = ""
) -> RotatingFileHandler:
    """Return a rotating file handler for the controller role."""

    os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
    handler = RotatingFileHandler(
        log_file_path,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setFormatter(_create_formatter())
    handler.addFilter(RemoteSourceFilter(default_remote_source))
    return handler


def ensure_controller_file_handler(
    log_file_path: str, *, default_remote_source: str = ""
) -> RotatingFileHandler:
    """Attach a controller file handler to the root logger if missing."""

    absolute_path = os.path.abspath(log_file_path)
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        if isinstance(handler, RotatingFileHandler):
            if os.path.abspath(getattr(handler, "baseFilename", "")) == absolute_path:
                return handler

    handler = create_controller_file_handler(
        absolute_path, default_remote_source=default_remote_source
    )
    root_logger.addHandler(handler)
    return handler


def resolve_log_paths(documents_dir: Path) -> Tuple[str, str]:
    """Return the controller log directory and log file path."""

    log_dir = os.path.join(str(documents_dir), BRAND_NAME, LOG_SUBDIRECTORY)
    log_file_path = os.path.join(log_dir, LOG_FILENAME)
    return log_dir, log_file_path

