"""Input receiver that applies remote events locally using pynput."""

from __future__ import annotations

import logging
import math
import os

from pynput import keyboard, mouse

if os.name == 'nt':
    import ctypes
    from ctypes import wintypes

    _USER32 = ctypes.windll.user32
    _MOUSEEVENTF_MOVE = 0x0001
    _SM_XVIRTUALSCREEN = 76
    _SM_YVIRTUALSCREEN = 77
    _SM_CXVIRTUALSCREEN = 78
    _SM_CYVIRTUALSCREEN = 79
else:  # pragma: no cover - platform specific branch
    _USER32 = None
    _SM_XVIRTUALSCREEN = 0
    _SM_YVIRTUALSCREEN = 0
    _SM_CXVIRTUALSCREEN = 0
    _SM_CYVIRTUALSCREEN = 0


class InputReceiver:
    """Apply incoming input events to the local system."""

    def __init__(self) -> None:
        self.mouse_controller = mouse.Controller()
        self.keyboard_controller = keyboard.Controller()
        self._pressed_keys: set = set()
        self._win_mouse_fraction = [0.0, 0.0]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def apply_event(self, data: dict) -> None:
        """Apply a remote input event to the local controllers."""
        button_map = {
            'left': mouse.Button.left,
            'right': mouse.Button.right,
            'middle': mouse.Button.middle,
        }
        extra_button = getattr(mouse.Button, 'x1', None)
        if extra_button is not None:
            button_map['x1'] = extra_button
        msg_type = data.get('type')
        if msg_type == 'move_relative':
            self.move_mouse_relative(data.get('dx', 0), data.get('dy', 0))
        elif msg_type == 'click':
            btn = button_map.get(data.get('button'))
            if btn:
                (self.mouse_controller.press if data.get('pressed') else self.mouse_controller.release)(btn)
        elif msg_type == 'scroll':
            self.mouse_controller.scroll(data.get('dx', 0), data.get('dy', 0))
        elif msg_type == 'key':
            k_info = data.get('key')
            key_type = data.get('key_type')
            if key_type == 'char':
                k_press = k_info
            elif key_type == 'special':
                k_press = getattr(keyboard.Key, k_info, None)
            elif key_type == 'vk':
                try:
                    k_press = keyboard.KeyCode.from_vk(int(k_info))
                except Exception:
                    k_press = None
            else:
                k_press = None
            if k_press:
                if data.get('pressed'):
                    self.keyboard_controller.press(k_press)
                    self._pressed_keys.add(k_press)
                else:
                    self.keyboard_controller.release(k_press)
                    self._pressed_keys.discard(k_press)
        else:
            logging.debug("Unhandled local event type: %s", msg_type)

    def move_mouse_relative(self, dx, dy) -> None:
        """Move the cursor relative to its current position."""
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

                move_x = int(target_x - point.x)
                move_y = int(target_y - point.y)

                if move_x != 0 or move_y != 0:
                    _USER32.mouse_event(
                        _MOUSEEVENTF_MOVE,
                        int(move_x),
                        int(move_y),
                        0,
                        0,
                    )
                return
            except Exception as exc:
                logging.debug("Native cursor move failed (%s), falling back to pynput", exc)
                self._win_mouse_fraction[0] = 0.0
                self._win_mouse_fraction[1] = 0.0

        self.mouse_controller.move(dx_val, dy_val)

    def release_pressed_keys(self) -> None:
        """Release any tracked pressed keys."""
        for key in list(self._pressed_keys):
            try:
                self.keyboard_controller.release(key)
            except Exception:
                pass
        self._pressed_keys.clear()

    @property
    def pressed_keys(self) -> set:
        return self._pressed_keys
