import logging
from pynput import keyboard

from ..config import VK_LSHIFT, VK_RSHIFT, VK_NUMPAD0, VK_NUMPAD1, VK_NUMPAD2


class HotkeyManager:
    """Listen for global hotkeys that toggle client control."""

    def __init__(self, worker):
        self.worker = worker
        self.listener = None
        self.vk_codes = set()
        self.special_keys = set()
        self.pending_target = None

        # combinations when NumLock is off (using special keys)
        self._combo_desktop_special = {keyboard.Key.shift, keyboard.Key.insert}
        self._combo_laptop_special = {keyboard.Key.shift, keyboard.Key.end}
        self._combo_elitedesk_special = {keyboard.Key.shift, keyboard.KeyCode.from_vk(VK_NUMPAD2)}

        # combinations when NumLock is on (using vk codes)
        self._combo_desktop_vk = {VK_LSHIFT, VK_NUMPAD0}
        self._combo_laptop_vk = {VK_LSHIFT, VK_NUMPAD1}
        self._combo_elitedesk_vk = {VK_LSHIFT, VK_NUMPAD2}

    # ------------------------------------------------------------------
    def _on_press(self, key):
        try:
            self.vk_codes.add(key.vk)
        except AttributeError:
            self.special_keys.add(key)

        if (self._combo_desktop_special.issubset(self.special_keys)
                or self._combo_desktop_vk.issubset(self.vk_codes)
                or {keyboard.Key.shift_r, keyboard.Key.insert}.issubset(self.special_keys)
                or {VK_RSHIFT, VK_NUMPAD0}.issubset(self.vk_codes)):
            logging.info("Desktop hotkey detected")
            self.pending_target = "desktop"
        elif (self._combo_laptop_special.issubset(self.special_keys)
              or self._combo_laptop_vk.issubset(self.vk_codes)
              or {keyboard.Key.shift_r, keyboard.Key.end}.issubset(self.special_keys)
              or {VK_RSHIFT, VK_NUMPAD1}.issubset(self.vk_codes)):
            logging.info("Laptop hotkey detected")
            self.pending_target = "laptop"
        elif (self._combo_elitedesk_special.issubset(self.special_keys | {
                keyboard.Key.shift_r})
              or self._combo_elitedesk_vk.issubset(self.vk_codes)
              or {VK_RSHIFT, VK_NUMPAD2}.issubset(self.vk_codes)):
            logging.info("Elitedesk hotkey detected")
            self.pending_target = "elitedesk"

    def _on_release(self, key):
        try:
            self.vk_codes.discard(key.vk)
        except AttributeError:
            self.special_keys.discard(key)

        if self.pending_target and not self.vk_codes and not self.special_keys:
            if self.pending_target == "desktop":
                self.worker.deactivate_kvm(switch_monitor=True, reason="desktop hotkey")
            else:
                self.worker.toggle_client_control(
                    self.pending_target,
                    switch_monitor=(self.pending_target == "elitedesk"),
                    release_keys=False,
                )
            self.pending_target = None

    # ------------------------------------------------------------------
    def start(self):
        if not self.listener:
            self.listener = keyboard.Listener(on_press=self._on_press, on_release=self._on_release)
            self.listener.start()
            logging.info("Global hotkey listener started")

    def stop(self):
        if self.listener:
            try:
                self.listener.stop()
            finally:
                self.listener = None
                self.vk_codes.clear()
                self.special_keys.clear()
                self.pending_target = None
