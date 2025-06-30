import logging
from pynput import keyboard
from ..config import VK_LSHIFT, VK_RSHIFT, VK_NUMPAD0, VK_NUMPAD1, VK_NUMPAD2


class HotkeyManager:
    """Manages global hotkeys for app control using the robust two-set detection method."""

    def __init__(self, worker):
        self.worker = worker
        self.listener = None

        # --- Define hotkeys for BOTH NumLock states ---

        # NumLock OFF state (uses pynput Key objects for Numpad keys)
        self.hotkey_desktop_l_numoff = {keyboard.Key.shift, keyboard.Key.insert}
        self.hotkey_desktop_r_numoff = {keyboard.Key.shift_r, keyboard.Key.insert}
        self.hotkey_laptop_l_numoff = {keyboard.Key.shift, keyboard.Key.end}
        self.hotkey_laptop_r_numoff = {keyboard.Key.shift_r, keyboard.Key.end}
        self.hotkey_elitdesk_l_numoff = {keyboard.Key.shift, keyboard.Key.down}  # Common for Numpad 2
        self.hotkey_elitdesk_r_numoff = {keyboard.Key.shift_r, keyboard.Key.down}

        # NumLock ON state (uses VK codes for Numpad keys)
        self.hotkey_desktop_l_numon = {VK_LSHIFT, VK_NUMPAD0}
        self.hotkey_desktop_r_numon = {VK_RSHIFT, VK_NUMPAD0}
        self.hotkey_laptop_l_numon = {VK_LSHIFT, VK_NUMPAD1}
        self.hotkey_laptop_r_numon = {VK_RSHIFT, VK_NUMPAD1}
        self.hotkey_elitdesk_l_numon = {VK_LSHIFT, VK_NUMPAD2}
        self.hotkey_elitdesk_r_numon = {VK_RSHIFT, VK_NUMPAD2}

        # --- State tracking with two separate sets ---
        self.current_pressed_vk_codes = set()
        self.current_pressed_special_keys = set()
        self.pending_client = None

    def _on_press(self, key):
        try:
            # Try to get a VK code first
            self.current_pressed_vk_codes.add(key.vk)
        except AttributeError:
            # If no VK code, it's a special key; store the object
            self.current_pressed_special_keys.add(key)

        logging.debug(
            "HotkeyManager Press: VKs=%s, Specials=%s",
            self.current_pressed_vk_codes,
            self.current_pressed_special_keys,
        )

        # --- Check both NumLock ON and OFF hotkeys ---
        if (
            self.hotkey_desktop_l_numoff.issubset(self.current_pressed_special_keys)
            or self.hotkey_desktop_r_numoff.issubset(self.current_pressed_special_keys)
            or self.hotkey_desktop_l_numon.issubset(self.current_pressed_vk_codes)
            or self.hotkey_desktop_r_numon.issubset(self.current_pressed_vk_codes)
        ):
            self.pending_client = "desktop"
        elif (
            self.hotkey_laptop_l_numoff.issubset(self.current_pressed_special_keys)
            or self.hotkey_laptop_r_numoff.issubset(self.current_pressed_special_keys)
            or self.hotkey_laptop_l_numon.issubset(self.current_pressed_vk_codes)
            or self.hotkey_laptop_r_numon.issubset(self.current_pressed_vk_codes)
        ):
            self.pending_client = "laptop"
        elif (
            self.hotkey_elitdesk_l_numoff.issubset(self.current_pressed_special_keys)
            or self.hotkey_elitdesk_r_numoff.issubset(self.current_pressed_special_keys)
            or self.hotkey_elitdesk_l_numon.issubset(self.current_pressed_vk_codes)
            or self.hotkey_elitdesk_r_numon.issubset(self.current_pressed_vk_codes)
        ):
            self.pending_client = "elitedesk"

    def _on_release(self, key):
        try:
            self.current_pressed_vk_codes.discard(key.vk)
        except AttributeError:
            self.current_pressed_special_keys.discard(key)

        logging.debug(
            "HotkeyManager Release: VKs=%s, Specials=%s",
            self.current_pressed_vk_codes,
            self.current_pressed_special_keys,
        )

        if self.pending_client and not self.current_pressed_vk_codes and not self.current_pressed_special_keys:
            logging.info(f"Hotkey action executed: {self.pending_client}")
            if self.pending_client == "desktop":
                self.worker.deactivate_kvm(switch_monitor=True, reason="desktop hotkey")
            else:
                self.worker.toggle_client_control(
                    self.pending_client,
                    switch_monitor=(self.pending_client == "elitedesk"),
                    release_keys=False
                )
            self.pending_client = None

    def start(self):
        if self.listener is None:
            self.listener = keyboard.Listener(on_press=self._on_press, on_release=self._on_release)
            self.listener.start()
            logging.info("HotkeyManager started.")

    def stop(self):
        if self.listener:
            self.listener.stop()
            self.listener = None
            logging.info("HotkeyManager stopped.")
