"""Helper utilities for consistent console-visible logging."""

from __future__ import annotations

import logging
from typing import Any


def log_user_notice(message: str, *args: Any) -> None:
    """Log an informational message and mirror it to stdout if needed.

    The desktop controller is often executed in environments where the root
    logger is configured to emit only warnings. In that case the built-in
    logging output would hide user facing status updates, so we fall back to a
    direct ``print`` so operators still receive immediate feedback on the
    console.
    """

    root_logger = logging.getLogger()
    root_logger.info(message, *args)

    try:
        effective_level = root_logger.getEffectiveLevel()
    except Exception:
        effective_level = logging.NOTSET

    if effective_level > logging.INFO:
        try:
            formatted = message % args if args else message
        except Exception:
            formatted = message
        print(formatted, flush=True)
