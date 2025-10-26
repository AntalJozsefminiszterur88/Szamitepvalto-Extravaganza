"""Input handling service for capturing and simulating keyboard/mouse events."""

from __future__ import annotations

import logging
import math
import threading
import time
import tkinter
from typing import Optional, Set, Tuple

from pynput import keyboard, mouse
from PySide6.QtCore import QObject, Signal


try:  # pragma: no cover - Windows specific behaviour
    import ctypes
    from ctypes import wintypes

    _USER32 = ctypes.windll.user32
    _SM_XVIRTUALSCREEN = 76
    _SM_YVIRTUALSCREEN = 77
    _SM_CXVIRTUALSCREEN = 78
    _SM_CYVIRTUALSCREEN = 79
except Exception:  # pragma: no cover - non Windows platforms
    _USER32 = None


STREAM_LOOP_DELAY = 0.05


class InputManager(QObject):
    """Manage local input capture and remote event simulation."""

    input_captured = Signal(dict)

    def __init__(self, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._mouse_controller = mouse.Controller()
        self._keyboard_controller = keyboard.Controller()
        self._win_mouse_fraction = [0.0, 0.0]
        self._simulated_pressed_keys: Set[object] = set()

        self._capture_active = threading.Event()
        self._capture_stop = threading.Event()
        self._movement_lock = threading.Lock()
        self._pending_move = {"dx": 0.0, "dy": 0.0}
        self._movement_thread: Optional[threading.Thread] = None
        self._mouse_listener: Optional[mouse.Listener] = None
        self._keyboard_listener: Optional[keyboard.Listener] = None
        self._host_mouse_controller: Optional[mouse.Controller] = None
        self._orig_mouse_pos: Optional[Tuple[float, float]] = None
        self._is_warping = False
        self._last_pos = {"x": 0.0, "y": 0.0}
        self._center_pos = (0.0, 0.0)
        self._captured_pressed_keys: Set[Tuple[str, object]] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def start_capturing(self) -> None:
        """Start capturing local mouse and keyboard input."""
        if self._capture_active.is_set():
            logging.debug("InputManager.start_capturing called while already active")
            return

        logging.info("InputManager: starting input capture")
        self._capture_active.set()
        self._capture_stop.clear()
        self._captured_pressed_keys.clear()

        host_mouse = mouse.Controller()
        self._host_mouse_controller = host_mouse
        self._orig_mouse_pos = host_mouse.position
        try:
            root = tkinter.Tk()
            root.withdraw()
            center_x = root.winfo_screenwidth() // 2
            center_y = root.winfo_screenheight() // 2
            root.destroy()
        except Exception:  # pragma: no cover - fallback when Tk unavailable
            center_x, center_y = 800, 600

        self._center_pos = (center_x, center_y)
        self._last_pos["x"], self._last_pos["y"] = center_x, center_y
        self._is_warping = False
        host_mouse.position = (center_x, center_y)

        self._movement_thread = threading.Thread(
            target=self._movement_aggregator,
            daemon=True,
            name="InputMovementAggregator",
        )
        self._movement_thread.start()

        self._mouse_listener = mouse.Listener(
            on_move=self._on_move,
            on_click=self._on_click,
            on_scroll=self._on_scroll,
            suppress=True,
        )
        self._keyboard_listener = keyboard.Listener(
            on_press=lambda key: self._on_key(key, True),
            on_release=lambda key: self._on_key(key, False),
            suppress=True,
        )

        self._mouse_listener.start()
        self._keyboard_listener.start()

        while self._capture_active.is_set() and not self._capture_stop.is_set():
            time.sleep(STREAM_LOOP_DELAY)

        self._teardown_capture()

    def stop_capturing(self) -> None:
        """Stop capturing the local input."""
        if not self._capture_active.is_set():
            return
        self._capture_stop.set()

    def simulate_event(self, data: dict) -> None:
        """Apply a remote input event on the local system."""
        msg_type = data.get("type")
        if msg_type == "move_relative":
            self._move_mouse_relative(data.get("dx", 0), data.get("dy", 0))
            return

        if msg_type == "click":
            button_name = data.get("button")
            button = getattr(mouse.Button, button_name, None)
            if button is None:
                extra_button = getattr(mouse.Button, "x1", None)
                if button_name == "x1" and extra_button is not None:
                    button = extra_button
            if button is None:
                logging.debug("InputManager: unknown click button %s", button_name)
                return
            if data.get("pressed"):
                self._mouse_controller.press(button)
                return
            self._mouse_controller.release(button)
            return

        if msg_type == "scroll":
            self._mouse_controller.scroll(data.get("dx", 0), data.get("dy", 0))
            return

        if msg_type == "key":
            key_event = self._decode_key_event(data)
            if key_event is None:
                logging.debug("InputManager: unhandled key event %s", data)
                return
            pressed, key_obj = key_event
            try:
                if pressed:
                    self._keyboard_controller.press(key_obj)
                    self._simulated_pressed_keys.add(key_obj)
                else:
                    self._keyboard_controller.release(key_obj)
                    self._simulated_pressed_keys.discard(key_obj)
            except Exception as exc:  # pragma: no cover - defensive logging
                logging.error("InputManager: key simulation failed: %s", exc, exc_info=True)
            return

        logging.debug("InputManager: unknown event type %s", msg_type)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def release_simulated_keys(self) -> None:
        """Release any keys that remain pressed during simulation."""
        for key_obj in list(self._simulated_pressed_keys):
            try:
                self._keyboard_controller.release(key_obj)
            except Exception:  # pragma: no cover - best effort release
                pass
        self._simulated_pressed_keys.clear()

    def _movement_aggregator(self) -> None:
        """Emit accumulated relative mouse movement at a steady rate."""
        while self._capture_active.is_set() and not self._capture_stop.is_set():
            time.sleep(0.015)
            with self._movement_lock:
                dx = self._pending_move["dx"]
                dy = self._pending_move["dy"]
                self._pending_move["dx"] = 0.0
                self._pending_move["dy"] = 0.0
            if dx != 0.0 or dy != 0.0:
                self.input_captured.emit({"type": "move_relative", "dx": dx, "dy": dy})

    def _on_move(self, x: float, y: float) -> None:
        if not self._capture_active.is_set() or self._is_warping:
            self._is_warping = False
            return
        dx = x - self._last_pos["x"]
        dy = y - self._last_pos["y"]
        if dx != 0 or dy != 0:
            with self._movement_lock:
                self._pending_move["dx"] += dx
                self._pending_move["dy"] += dy
        self._is_warping = True
        try:
            if self._host_mouse_controller:
                self._host_mouse_controller.position = self._center_pos
        finally:
            self._last_pos["x"], self._last_pos["y"] = self._center_pos

    def _on_click(self, x: float, y: float, button: mouse.Button, pressed: bool) -> None:
        if not self._capture_active.is_set():
            return
        self.input_captured.emit(
            {"type": "click", "button": getattr(button, "name", str(button)), "pressed": pressed}
        )

    def _on_scroll(self, x: float, y: float, dx: float, dy: float) -> None:
        if not self._capture_active.is_set():
            return
        self.input_captured.emit({"type": "scroll", "dx": dx, "dy": dy})

    def _on_key(self, key: keyboard.Key | keyboard.KeyCode, pressed: bool) -> None:
        if not self._capture_active.is_set():
            return
        key_type, key_value = self._identify_key(key)
        if key_type is None:
            logging.warning("InputManager: unknown key event %s", key)
            return

        if pressed:
            self._captured_pressed_keys.add((key_type, key_value))
        else:
            self._captured_pressed_keys.discard((key_type, key_value))

        event = {
            "type": "key",
            "key_type": key_type,
            "key": key_value,
            "pressed": pressed,
        }
        vk_code = self._extract_vk(key)
        if vk_code is not None:
            event["vk"] = vk_code
            if pressed and getattr(key, "_flags", None) == 0:
                event["numpad"] = True
            elif not pressed:
                event["numpad"] = False
        self.input_captured.emit(event)

    def _identify_key(self, key: keyboard.Key | keyboard.KeyCode) -> Tuple[Optional[str], Optional[object]]:
        if hasattr(key, "vk") and key.vk is not None:
            return "vk", int(key.vk)
        if hasattr(key, "char") and key.char is not None:
            return "char", key.char
        if hasattr(key, "name"):
            return "special", key.name
        return None, None

    def _extract_vk(self, key: keyboard.Key | keyboard.KeyCode) -> Optional[int]:
        try:
            if hasattr(key, "vk") and key.vk is not None:
                return int(key.vk)
            if hasattr(key, "value") and hasattr(key.value, "vk"):
                return int(key.value.vk)
        except Exception:  # pragma: no cover - best effort conversion
            return None
        return None

    def _decode_key_event(self, data: dict) -> Optional[Tuple[bool, object]]:
        pressed = bool(data.get("pressed"))
        key_type = data.get("key_type")
        key_value = data.get("key")
        try:
            if key_type == "char":
                return pressed, key_value
            if key_type == "special":
                key_obj = getattr(keyboard.Key, str(key_value), None)
                if key_obj is not None:
                    return pressed, key_obj
            if key_type == "vk":
                key_obj = keyboard.KeyCode.from_vk(int(key_value))
                return pressed, key_obj
        except Exception:  # pragma: no cover - graceful degradation
            return None
        return None

    def _move_mouse_relative(self, dx, dy) -> None:
        try:
            dx_val = float(dx) if dx is not None else 0.0
        except (TypeError, ValueError):
            dx_val = 0.0
        try:
            dy_val = float(dy) if dy is not None else 0.0
        except (TypeError, ValueError):
            dy_val = 0.0

        if dx_val == 0.0 and dy_val == 0.0:
            return

        if _USER32 is not None:
            try:
                point = wintypes.POINT()
                if not _USER32.GetCursorPos(ctypes.byref(point)):
                    raise ctypes.WinError(ctypes.get_last_error())

                total_dx = dx_val + self._win_mouse_fraction[0]
                total_dy = dy_val + self._win_mouse_fraction[1]
                frac_x, int_x = math.modf(total_dx)
                frac_y, int_y = math.modf(total_dy)

                move_x = int(int_x)
                move_y = int(int_y)

                self._win_mouse_fraction[0] = frac_x
                self._win_mouse_fraction[1] = frac_y

                target_x = point.x + move_x
                target_y = point.y + move_y

                width = _USER32.GetSystemMetrics(_SM_CXVIRTUALSCREEN)
                height = _USER32.GetSystemMetrics(_SM_CYVIRTUALSCREEN)
                if width and height:
                    left = _USER32.GetSystemMetrics(_SM_XVIRTUALSCREEN)
                    top = _USER32.GetSystemMetrics(_SM_YVIRTUALSCREEN)
                    max_x = left + width - 1
                    max_y = top + height - 1
                    if target_x < left:
                        target_x = left
                        self._win_mouse_fraction[0] = 0.0
                    elif target_x > max_x:
                        target_x = max_x
                        self._win_mouse_fraction[0] = 0.0
                    if target_y < top:
                        target_y = top
                        self._win_mouse_fraction[1] = 0.0
                    elif target_y > max_y:
                        target_y = max_y
                        self._win_mouse_fraction[1] = 0.0

                if (
                    move_x != 0
                    or move_y != 0
                    or target_x != point.x
                    or target_y != point.y
                ):
                    _USER32.SetCursorPos(int(target_x), int(target_y))
                return
            except Exception as exc:  # pragma: no cover - fallback to pynput
                logging.debug("Native cursor move failed (%s), falling back to pynput", exc)
                self._win_mouse_fraction[0] = 0.0
                self._win_mouse_fraction[1] = 0.0

        self._mouse_controller.move(dx_val, dy_val)

    def _teardown_capture(self) -> None:
        if self._keyboard_listener:
            try:
                self._keyboard_listener.stop()
            except Exception:  # pragma: no cover - defensive
                pass
        if self._mouse_listener:
            try:
                self._mouse_listener.stop()
            except Exception:  # pragma: no cover - defensive
                pass
        self._keyboard_listener = None
        self._mouse_listener = None

        if self._movement_thread and self._movement_thread.is_alive():
            self._movement_thread.join(timeout=0.2)
        self._movement_thread = None

        # Emit key releases for any keys still held down
        for key_type, key_val in list(self._captured_pressed_keys):
            release_event = {
                "type": "key",
                "key_type": key_type,
                "key": key_val,
                "pressed": False,
            }
            if key_type == "vk":
                release_event["vk"] = key_val
            self.input_captured.emit(release_event)
        self._captured_pressed_keys.clear()

        if self._host_mouse_controller and self._orig_mouse_pos:
            try:
                self._host_mouse_controller.position = self._orig_mouse_pos
            except Exception:  # pragma: no cover - best effort restore
                pass
        self._host_mouse_controller = None
        self._orig_mouse_pos = None

        self._capture_active.clear()
        self._capture_stop.clear()

