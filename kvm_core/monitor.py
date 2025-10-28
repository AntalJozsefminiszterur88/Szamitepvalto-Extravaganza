"""Monitor control helpers for Számítógépváltó Extravaganza."""

from __future__ import annotations

import logging
from typing import Optional, Tuple

from monitorcontrol import get_monitors
from monitorcontrol.monitorcontrol import PowerMode


class MonitorController:
    """Encapsulates monitor control operations using ``monitorcontrol``."""

    def __init__(
        self,
        *,
        host_input: Optional[int] = None,
        client_input: Optional[int] = None,
    ) -> None:
        self.host_input = host_input
        self.client_input = client_input
        self._current_input: Optional[int] = None
        self._power_on: bool = True

    @property
    def current_input(self) -> Optional[int]:
        """Return the last successfully selected monitor input code."""
        return self._current_input

    @property
    def power_on(self) -> bool:
        """Return the cached power state of the primary monitor."""
        return self._power_on

    def switch_to_host(self) -> Tuple[bool, Optional[str]]:
        """Switch the primary monitor to the configured host input."""
        if self.host_input is None:
            message = "Host monitor input is not configured."
            logging.debug(message)
            return False, message
        return self.switch_to_input(self.host_input, label="host")

    def switch_to_client(self) -> Tuple[bool, Optional[str]]:
        """Switch the primary monitor to the configured client input."""
        if self.client_input is None:
            message = "Client monitor input is not configured."
            logging.debug(message)
            return False, message
        return self.switch_to_input(self.client_input, label="client")

    def switch_to_input(
        self, code: Optional[int], *, label: Optional[str] = None
    ) -> Tuple[bool, Optional[str]]:
        """Switch the primary monitor input source to *code*."""
        if code is None:
            message = "No monitor input code specified."
            logging.debug(message)
            return False, message

        monitor, error = self._get_primary_monitor()
        if monitor is None:
            return False, error

        display_label = label or code
        try:
            with monitor:
                monitor.set_input_source(code)
            self._current_input = code
            logging.info("Monitor input switched to %s", display_label)
            return True, None
        except Exception as exc:  # pragma: no cover - hardware dependent
            message = str(exc) or "monitor input switch failed"
            logging.error(
                "Failed to switch monitor input to %s: %s", display_label, exc, exc_info=True
            )
            return False, message

    def toggle_power(self) -> Tuple[bool, Optional[str]]:
        """Toggle the power state of the primary monitor."""
        monitor, error = self._get_primary_monitor()
        if monitor is None:
            return False, error

        try:
            with monitor:
                try:
                    current_mode = monitor.get_power_mode()
                    monitor_is_on = current_mode == PowerMode.on
                    self._power_on = monitor_is_on
                except Exception as exc:  # pragma: no cover - hardware dependent
                    monitor_is_on = self._power_on
                    logging.warning(
                        "Failed to query monitor power state, assuming cached value (%s): %s",
                        self._power_on,
                        exc,
                    )

                try:
                    if monitor_is_on:
                        monitor.set_power_mode(PowerMode.off_soft)
                        self._power_on = False
                        logging.info("Monitor power toggled OFF")
                    else:
                        monitor.set_power_mode(PowerMode.on)
                        self._power_on = True
                        logging.info("Monitor power toggled ON")
                    return True, None
                except Exception as exc:  # pragma: no cover - hardware dependent
                    message = str(exc) or "monitor power toggle failed"
                    logging.error("Failed to toggle monitor power state: %s", exc, exc_info=True)
                    return False, message
        except Exception as exc:  # pragma: no cover - hardware dependent
            message = str(exc) or "unexpected monitor power error"
            logging.error(
                "Unexpected error while toggling monitor power: %s", exc, exc_info=True
            )
            return False, message

    def _get_primary_monitor(self):
        """Return the primary monitor handle if available."""
        try:
            monitors = list(get_monitors())
        except Exception as exc:  # pragma: no cover - hardware dependent
            message = str(exc) or "failed to enumerate monitors"
            logging.error("Failed to enumerate monitors: %s", exc, exc_info=True)
            return None, message

        if not monitors:
            message = "No monitors detected."
            logging.warning(message)
            return None, message

        return monitors[0], None
