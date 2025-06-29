import logging
from pynput import keyboard

from config import (
    VK_LSHIFT,
    VK_RSHIFT,
    VK_NUMPAD0,
    VK_NUMPAD1,
    VK_NUMPAD2,
)


class HotkeyManager:
    """Manage global application hotkeys using pynput."""

    def __init__(self, worker):
        self.worker = worker
        self.listener = None

        # Hotkey definitions when NumLock is off
        self.hotkey_desktop_l_numoff = {keyboard.Key.shift, keyboard.Key.insert}
        self.hotkey_desktop_r_numoff = {keyboard.Key.shift_r, keyboard.Key.insert}
        self.hotkey_laptop_l_numoff = {keyboard.Key.shift, keyboard.Key.end}
        self.hotkey_laptop_r_numoff = {keyboard.Key.shift_r, keyboard.Key.end}
        self.hotkey_elitdesk_l_numoff = {keyboard.Key.shift, VK_NUMPAD2}
        self.hotkey_elitdesk_r_numoff = {keyboard.Key.shift_r, VK_NUMPAD2}

        # Hotkey definitions when NumLock is on (VK codes)
        self.hotkey_desktop_l_numon = {VK_LSHIFT, VK_NUMPAD0}
        self.hotkey_desktop_r_numon = {VK_RSHIFT, VK_NUMPAD0}
        self.hotkey_laptop_l_numon = {VK_LSHIFT, VK_NUMPAD1}
        self.hotkey_laptop_r_numon = {VK_RSHIFT, VK_NUMPAD1}
        self.hotkey_elitdesk_l_numon = {VK_LSHIFT, VK_NUMPAD2}
        self.hotkey_elitdesk_r_numon = {VK_RSHIFT, VK_NUMPAD2}

        # Track currently pressed keys
        self.current_pressed_vk_codes = set()
        self.current_pressed_special_keys = set()
        self.pending_client = None

    def _on_press(self, key):
        try:
            self.current_pressed_vk_codes.add(key.vk)
        except AttributeError:
            self.current_pressed_special_keys.add(key)

        logging.debug(
            "Key pressed: %s. VKs: %s, Specials: %s",
            key,
            self.current_pressed_vk_codes,
            self.current_pressed_special_keys,
        )

        if (
            self.hotkey_desktop_l_numoff.issubset(self.current_pressed_special_keys)
            or self.hotkey_desktop_r_numoff.issubset(self.current_pressed_special_keys)
        ) or (
            self.hotkey_desktop_l_numon.issubset(self.current_pressed_vk_codes)
            or self.hotkey_desktop_r_numon.issubset(self.current_pressed_vk_codes)
        ):
            logging.info("!!! Asztal gyorsbillentyű észlelve! Visszaváltás... !!!")
            self.pending_client = "desktop"
        elif (
            self.hotkey_laptop_l_numoff.issubset(self.current_pressed_special_keys)
            or self.hotkey_laptop_r_numoff.issubset(self.current_pressed_special_keys)
        ) or (
            self.hotkey_laptop_l_numon.issubset(self.current_pressed_vk_codes)
            or self.hotkey_laptop_r_numon.issubset(self.current_pressed_vk_codes)
        ):
            logging.info("!!! Laptop gyorsbillentyű észlelve! Váltás... !!!")
            self.pending_client = "laptop"
        elif (
            self.hotkey_elitdesk_l_numoff.issubset(
                self.current_pressed_special_keys.union(self.current_pressed_vk_codes)
            )
            or self.hotkey_elitdesk_r_numoff.issubset(
                self.current_pressed_special_keys.union(self.current_pressed_vk_codes)
            )
        ) or (
            self.hotkey_elitdesk_l_numon.issubset(self.current_pressed_vk_codes)
            or self.hotkey_elitdesk_r_numon.issubset(self.current_pressed_vk_codes)
        ):
            logging.info("!!! ElitDesk gyorsbillentyű észlelve! Váltás... !!!")
            self.pending_client = "elitedesk"

    def _on_release(self, key):
        try:
            self.current_pressed_vk_codes.discard(key.vk)
        except AttributeError:
            self.current_pressed_special_keys.discard(key)

        logging.debug(
            "Key released: %s. VKs: %s, Specials: %s",
            key,
            self.current_pressed_vk_codes,
            self.current_pressed_special_keys,
        )

        if (
            self.pending_client
            and not self.current_pressed_vk_codes
            and not self.current_pressed_special_keys
        ):
            logging.info("Hotkey action executed: %s", self.pending_client)
            if self.pending_client == "desktop":
                self.worker.deactivate_kvm(switch_monitor=True, reason="desktop hotkey")
            else:
                self.worker.toggle_client_control(
                    self.pending_client,
                    switch_monitor=(self.pending_client == "elitedesk"),
                    release_keys=False,
                )
            self.pending_client = None

    def start(self):
        """Start listening for global hotkeys."""
        if not self.listener:
            self.listener = keyboard.Listener(on_press=self._on_press, on_release=self._on_release)
            self.listener.start()
            logging.info("Gyorsbillentyű figyelő elindítva.")

    def stop(self):
        """Stop listening for global hotkeys."""
        if self.listener:
            try:
                self.listener.stop()
            finally:
                self.listener = None
                # Clear pressed states
                self.current_pressed_vk_codes.clear()
                self.current_pressed_special_keys.clear()
                self.pending_client = None
