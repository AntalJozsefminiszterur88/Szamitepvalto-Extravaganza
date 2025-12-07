"""Input provider handling for local event capture using pynput."""

from __future__ import annotations

import ctypes
import logging
import os
import threading
import time
from typing import Callable, Iterable, Optional, Set

from pynput import keyboard, mouse


class InputProvider:
    """Capture local input events and forward them through a callback."""

    def __init__(
        self,
        send_callback: Callable[[dict], bool],
        *,
        is_running: Callable[[], bool],
        force_numpad_vk: Optional[Iterable[int]] = None,
    ) -> None:
        self._send_callback = send_callback
        self._is_running = is_running
        self._force_numpad_vk: Set[int] = set(force_numpad_vk or [])

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._aggregator_thread: Optional[threading.Thread] = None
        self._mouse_listener: Optional[mouse.Listener] = None
        self._keyboard_listener: Optional[keyboard.Listener] = None

        self._provider_pressed_keys: Set[tuple[str, int | str]] = set()
        self._host_mouse_controller: Optional[mouse.Controller] = None
        self._orig_mouse_pos: Optional[tuple[int, int]] = None

        self._movement_lock = threading.Lock()
        self._pending_move = {'dx': 0, 'dy': 0}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Start capturing local input."""
        if self.is_running():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="InputProviderStream",
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop capturing local input."""
        self._stop_event.set()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=1.5)
        self._thread = None

    def is_running(self) -> bool:
        thread = self._thread
        return bool(thread and thread.is_alive())

    @property
    def stop_event(self) -> threading.Event:
        return self._stop_event

    @property
    def thread(self) -> Optional[threading.Thread]:
        return self._thread

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _send_event(self, payload: dict) -> bool:
        try:
            result = self._send_callback(payload)
        except Exception as exc:  # pragma: no cover - defensive guard
            logging.error("Provider callback raised %s", exc, exc_info=True)
            return False
        return bool(result)

    def _aggregator_loop(self) -> None:
        while self._is_running() and not self._stop_event.is_set():
            time.sleep(0.01)
            with self._movement_lock:
                dx = self._pending_move['dx']
                dy = self._pending_move['dy']
                self._pending_move['dx'] = 0
                self._pending_move['dy'] = 0
            if dx or dy:
                if not self._send_event({'type': 'move_relative', 'dx': dx, 'dy': dy}):
                    self._stop_event.set()
                    break

    def _queue_relative_move(self, dx: int, dy: int) -> None:
        with self._movement_lock:
            self._pending_move['dx'] += dx
            self._pending_move['dy'] += dy

    def _run(self) -> None:
        controller = mouse.Controller()
        self._host_mouse_controller = controller
        self._orig_mouse_pos = controller.position

        try:
            if os.name == 'nt':
                user32 = ctypes.windll.user32
                width = user32.GetSystemMetrics(0)
                height = user32.GetSystemMetrics(1)
                center_x = width // 2
                center_y = height // 2
            else:
                center_x, center_y = 960, 540  # Fallback
        except Exception:
            center_x, center_y = 800, 600

        controller.position = (center_x, center_y)
        last_pos = {'x': center_x, 'y': center_y}
        is_warping = False

        self._aggregator_thread = threading.Thread(
            target=self._aggregator_loop,
            daemon=True,
            name="InputMoveAgg",
        )
        self._aggregator_thread.start()

        def on_move(x: int, y: int) -> Optional[bool]:
            nonlocal is_warping
            if self._stop_event.is_set():
                return False
            if is_warping:
                is_warping = False
                return None
            dx = x - last_pos['x']
            dy = y - last_pos['y']
            if dx or dy:
                self._queue_relative_move(dx, dy)
            is_warping = True
            try:
                controller.position = (center_x, center_y)
            except Exception:
                pass
            last_pos['x'] = center_x
            last_pos['y'] = center_y
            return None

        def on_click(x: int, y: int, button: mouse.Button, pressed: bool) -> Optional[bool]:
            if self._stop_event.is_set():
                return False
            self._send_event({'type': 'click', 'button': getattr(button, 'name', 'left'), 'pressed': pressed})
            return None

        def on_scroll(x: int, y: int, dx: int, dy: int) -> Optional[bool]:
            if self._stop_event.is_set():
                return False
            self._send_event({'type': 'scroll', 'dx': dx, 'dy': dy})
            return None

        def on_key(key: keyboard.Key | keyboard.KeyCode, pressed: bool) -> Optional[bool]:
            if self._stop_event.is_set():
                return False
            try:
                forced_vk = None
                if hasattr(key, 'vk') and key.vk in self._force_numpad_vk:
                    forced_vk = key.vk
                elif (
                    hasattr(key, 'value')
                    and hasattr(key.value, 'vk')
                    and key.value.vk in self._force_numpad_vk
                ):
                    forced_vk = key.value.vk

                if forced_vk is not None:
                    key_type = 'vk'
                    key_val = forced_vk
                elif hasattr(key, 'char') and key.char is not None:
                    key_type = 'char'
                    key_val = key.char
                elif hasattr(key, 'name') and key.name is not None:
                    key_type = 'special'
                    key_val = key.name
                elif hasattr(key, 'vk') and key.vk is not None:
                    key_type = 'vk'
                    key_val = key.vk
                else:
                    return True

                key_id = (key_type, key_val)
                if pressed:
                    self._provider_pressed_keys.add(key_id)
                else:
                    self._provider_pressed_keys.discard(key_id)
                self._send_event({'type': 'key', 'key_type': key_type, 'key': key_val, 'pressed': pressed})
            except Exception as exc:  # pragma: no cover - logging side effect
                logging.error("Error while handling provider key event: %s", exc, exc_info=True)
            return True

        self._mouse_listener = mouse.Listener(
            on_move=on_move,
            on_click=on_click,
            on_scroll=on_scroll,
            suppress=True,
        )
        self._keyboard_listener = keyboard.Listener(
            on_press=lambda k: on_key(k, True),
            on_release=lambda k: on_key(k, False),
            suppress=True,
        )

        self._mouse_listener.start()
        self._keyboard_listener.start()

        try:
            while self._is_running() and not self._stop_event.is_set():
                time.sleep(0.05)
        finally:
            if self._mouse_listener:
                self._mouse_listener.stop()
            if self._keyboard_listener:
                self._keyboard_listener.stop()

            agg_thread = self._aggregator_thread
            if agg_thread and agg_thread.is_alive():
                agg_thread.join(timeout=1.0)

            if self._provider_pressed_keys:
                for key_type, key_val in list(self._provider_pressed_keys):
                    if not self._send_event(
                        {
                            'type': 'key',
                            'key_type': key_type,
                            'key': key_val,
                            'pressed': False,
                        }
                    ):
                        break
                self._provider_pressed_keys.clear()

            if self._host_mouse_controller and self._orig_mouse_pos:
                try:
                    self._host_mouse_controller.position = self._orig_mouse_pos
                except Exception:
                    pass

            self._host_mouse_controller = None
            self._orig_mouse_pos = None
            self._stop_event.set()
            logging.info("Input provider stream loop exited")

        self._thread = None
        self._aggregator_thread = None
        self._mouse_listener = None
        self._keyboard_listener = None
