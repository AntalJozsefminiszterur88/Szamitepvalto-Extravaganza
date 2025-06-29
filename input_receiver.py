import logging

from pynput import mouse, keyboard


class InputReceiver:
    """Process remote input events and replay them locally."""

    def __init__(self):
        self.mouse_controller = mouse.Controller()
        self.keyboard_controller = keyboard.Controller()
        self.button_map = {
            "left": mouse.Button.left,
            "right": mouse.Button.right,
            "middle": mouse.Button.middle,
        }
        self.pressed_keys = set()

    # ------------------------------------------------------------------
    def process_event(self, event_data):
        """Handle a single input event dictionary."""
        event_type = event_data.get("type")
        if event_type == "move_relative":
            dx = event_data.get("dx", 0)
            dy = event_data.get("dy", 0)
            self.mouse_controller.move(dx, dy)
        elif event_type == "click":
            button = self.button_map.get(event_data.get("button"))
            if button:
                if event_data.get("pressed"):
                    self.mouse_controller.press(button)
                else:
                    self.mouse_controller.release(button)
        elif event_type == "scroll":
            dx = event_data.get("dx", 0)
            dy = event_data.get("dy", 0)
            self.mouse_controller.scroll(dx, dy)
        elif event_type == "key":
            k_info = event_data.get("key")
            key_type = event_data.get("key_type")
            if key_type == "char":
                key = k_info
            elif key_type == "special":
                key = getattr(keyboard.Key, k_info, None)
            elif key_type == "vk":
                try:
                    key = keyboard.KeyCode.from_vk(int(k_info))
                except (TypeError, ValueError):
                    key = None
            else:
                key = None

            if key is not None:
                if event_data.get("pressed"):
                    try:
                        self.keyboard_controller.press(key)
                        self.pressed_keys.add(key)
                    except Exception as e:
                        logging.error("Failed to press key %s: %s", key, e)
                else:
                    try:
                        self.keyboard_controller.release(key)
                        self.pressed_keys.discard(key)
                    except Exception as e:
                        logging.error("Failed to release key %s: %s", key, e)

    def release_pressed_keys(self):
        """Release all currently pressed keys."""
        for k in list(self.pressed_keys):
            try:
                self.keyboard_controller.release(k)
            except Exception:
                pass
        self.pressed_keys.clear()
