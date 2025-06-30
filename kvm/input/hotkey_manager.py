import logging
from pynput import keyboard
from ..config import VK_LSHIFT, VK_RSHIFT, VK_NUMPAD0, VK_NUMPAD1, VK_NUMPAD2
from .key_combo_detector import KeyComboDetector, key_to_id


class HotkeyManager:
    """Global hotkey handler for switching control between machines."""

    def __init__(self, worker):
        self.worker = worker
        self.listener = None
        combos = [
            ([("key", keyboard.Key.shift), ("key", keyboard.Key.insert)], self._to_desktop),
            ([("key", keyboard.Key.shift_r), ("key", keyboard.Key.insert)], self._to_desktop),
            ([("vk", VK_LSHIFT), ("vk", VK_NUMPAD0)], self._to_desktop),
            ([("vk", VK_RSHIFT), ("vk", VK_NUMPAD0)], self._to_desktop),
            ([("key", keyboard.Key.shift), ("key", keyboard.Key.end)], self._to_laptop),
            ([("key", keyboard.Key.shift_r), ("key", keyboard.Key.end)], self._to_laptop),
            ([("vk", VK_LSHIFT), ("vk", VK_NUMPAD1)], self._to_laptop),
            ([("vk", VK_RSHIFT), ("vk", VK_NUMPAD1)], self._to_laptop),
            ([("key", keyboard.Key.shift), ("key", keyboard.Key.down)], self._to_elitedesk),
            ([("key", keyboard.Key.shift_r), ("key", keyboard.Key.down)], self._to_elitedesk),
            ([("vk", VK_LSHIFT), ("vk", VK_NUMPAD2)], self._to_elitedesk),
            ([("vk", VK_RSHIFT), ("vk", VK_NUMPAD2)], self._to_elitedesk),
        ]
        self.detector = KeyComboDetector(combos)

    def _to_desktop(self) -> None:
        logging.info("Hotkey to desktop")
        self.worker.deactivate_kvm(switch_monitor=True, reason="desktop hotkey")

    def _to_laptop(self) -> None:
        logging.info("Hotkey to laptop")
        self.worker.toggle_client_control("laptop", switch_monitor=False, release_keys=False)

    def _to_elitedesk(self) -> None:
        logging.info("Hotkey to elitedesk")
        self.worker.toggle_client_control("elitedesk", switch_monitor=True, release_keys=False)

    def _on_press(self, key):
        self.detector.press(key_to_id(key))

    def _on_release(self, key):
        self.detector.release(key_to_id(key))

    def start(self) -> None:
        if not self.listener:
            self.listener = keyboard.Listener(on_press=self._on_press, on_release=self._on_release)
            self.listener.start()
            logging.info("HotkeyManager started")

    def stop(self) -> None:
        if self.listener:
            self.listener.stop()
            self.listener = None
            logging.info("HotkeyManager stopped")
