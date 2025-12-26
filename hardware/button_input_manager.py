"""Button input manager for handling host hotkeys and Pico button events."""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Dict, Optional

import serial
from serial.tools import list_ports
from pynput import keyboard
from pynput.keyboard import Controller, Key

from config.settings import PICO_SERIAL_PORT

class ButtonInputManager:
    """Coordinate host F-key hotkeys and Pico button messages."""

    BAUD_RATE = 115200
    SERIAL_TIMEOUT = 1

    def __init__(self, worker: "KVMOrchestrator") -> None:
        self.worker = worker
        self._running = threading.Event()
        self._serial_thread: Optional[threading.Thread] = None
        self._keyboard_listener: Optional[keyboard.Listener] = None
        self._keyboard_controller = Controller()
        self._synthetic_keys: set[Key] = set()
        self._current_pressed_vk: set[int] = set()
        self._numpad_pressed_vk: set[int] = set()
        self._serial_action_map: Dict[str, Callable[[], None]] = {}
        self._keyboard_action_map: Dict[Key, Callable[[], None]] = {}
        self._initialise_action_maps()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Start listening for hotkeys and Pico serial messages."""
        if self._running.is_set():
            return
        self._running.set()
        self._start_keyboard_listener()
        self._serial_thread = threading.Thread(
            target=self._serial_loop,
            daemon=True,
            name="PicoSerialButtons",
        )
        self._serial_thread.start()
        logging.info("ButtonInputManager started")

    def stop(self) -> None:
        """Stop the listeners gracefully."""
        self._running.clear()
        if self._keyboard_listener:
            try:
                self._keyboard_listener.stop()
            except Exception:
                pass
            self._keyboard_listener = None
        if self._serial_thread and self._serial_thread.is_alive():
            self._serial_thread.join(timeout=2)
        self._serial_thread = None
        logging.info("ButtonInputManager stopped")

    # ------------------------------------------------------------------
    # Setup helpers
    # ------------------------------------------------------------------
    def _initialise_action_maps(self) -> None:
        """Prepare lookup tables for both keyboard and serial events."""

        self._keyboard_action_map = {
            Key.f13: lambda: self._handle_asztal("keyboard F13"),
            Key.f14: lambda: self._handle_laptop("keyboard F14"),
            Key.f15: lambda: self._handle_elitedesk("keyboard F15"),
            Key.f16: lambda: self._handle_hdmi1("keyboard F16"),
            Key.f17: lambda: self._handle_hdmi2("keyboard F17"),
            Key.f21: lambda: self._handle_monitor_toggle("keyboard F21"),
            Key.f22: lambda: self._forward_or_emit_host_key(Key.f22, "keyboard F22"),
        }
        self._serial_action_map = {
            "KEY_Asztal": lambda: self._handle_asztal("pico KEY_Asztal"),
            "KEY_Laptop": lambda: self._handle_laptop("pico KEY_Laptop"),
            "KEY_EliteDesk": lambda: self._handle_elitedesk("pico KEY_EliteDesk"),
            "KEY_HDMI_1": lambda: self._handle_hdmi1("pico KEY_HDMI_1"),
            "KEY_HDMI_2": lambda: self._handle_hdmi2("pico KEY_HDMI_2"),
            "KEY_Monitor_OnOff": lambda: self._handle_monitor_toggle("pico KEY_Monitor_OnOff"),
            "KEY_Hang_1": lambda: self._forward_or_emit_host_key(Key.f18, "pico KEY_Hang_1"),
            "KEY_Hang_2": lambda: self._forward_or_emit_host_key(Key.f19, "pico KEY_Hang_2"),
            "KEY_Hang_3": lambda: self._forward_or_emit_host_key(Key.f20, "pico KEY_Hang_3"),
            "KEY_Nemitas": lambda: self._forward_or_emit_host_key(Key.f22, "pico KEY_Nemitas"),
            # Legacy numeric protocol compatibility
            "1": lambda: self._handle_asztal("pico legacy 1"),
            "2": lambda: self._handle_laptop("pico legacy 2"),
            "3": lambda: self._handle_elitedesk("pico legacy 3"),
            "4": lambda: self._handle_hdmi1("pico legacy 4"),
        }

    def _start_keyboard_listener(self) -> None:
        if self._keyboard_listener:
            return

        def on_press(key: keyboard.Key) -> None:
            if key in self._synthetic_keys:
                return
            action = self._keyboard_action_map.get(key)
            if action:
                action()
                return

            vk = getattr(key, "vk", None)
            if vk is None:
                return
            self._current_pressed_vk.add(vk)
            if getattr(key, "_flags", 0) == 0:
                self._numpad_pressed_vk.add(vk)
            self._check_modifier_hotkeys()

        def on_release(key: keyboard.Key) -> None:
            vk = getattr(key, "vk", None)
            if vk is not None:
                self._current_pressed_vk.discard(vk)
                self._numpad_pressed_vk.discard(vk)

        self._keyboard_listener = keyboard.Listener(
            on_press=on_press,
            on_release=on_release,
        )
        self._keyboard_listener.start()
        logging.info("Global keyboard listener started")

    # ------------------------------------------------------------------
    # Action handlers
    # ------------------------------------------------------------------
    def _handle_asztal(self, source: str) -> None:
        logging.info("Host switch requested by %s", source)
        self.worker.deactivate_kvm(switch_monitor=True, reason=source)

    def _handle_laptop(self, source: str) -> None:
        logging.info("Laptop switch requested by %s", source)
        self.worker.toggle_client_control("laptop", switch_monitor=False, release_keys=False)

    def _handle_elitedesk(self, source: str) -> None:
        logging.info("EliteDesk switch requested by %s", source)
        self.worker.toggle_client_control("elitedesk", switch_monitor=True, release_keys=False)

    def _handle_hdmi1(self, source: str) -> None:
        logging.info("Monitor HDMI-1 input requested by %s", source)
        self.worker.switch_monitor_input(17)

    def _handle_hdmi2(self, source: str) -> None:
        logging.info("Monitor HDMI-2 input requested by %s", source)
        self.worker.switch_monitor_input(18)

    def _handle_monitor_toggle(self, source: str) -> None:
        logging.info("Monitor power toggle requested by %s", source)
        self.worker.toggle_monitor_power()

    def _forward_or_emit_host_key(self, key: Key, source: str) -> None:
        """Try forwarding the key press to the desktop provider, fall back locally."""
        logging.info("Audio hotkey %s triggered by %s", key, source)
        try:
            forwarded = self.worker.send_provider_function_key(key, source=source)
        except AttributeError:
            forwarded = False
        if forwarded:
            return
        logging.info("Falling back to local key simulation for %s due to %s", key, source)
        self._emit_host_key(key, source)

    def _emit_host_key(self, key: Key, source: str) -> None:
        logging.info("Simulating %s due to %s", key, source)
        self._synthetic_keys.add(key)
        try:
            self._keyboard_controller.press(key)
            time.sleep(0.05)
            self._keyboard_controller.release(key)
        finally:
            # Delay clearing to ensure release is processed
            time.sleep(0.01)
            self._synthetic_keys.discard(key)

    # ------------------------------------------------------------------
    # Modifier combinations
    # ------------------------------------------------------------------
    def _check_modifier_hotkeys(self) -> None:
        VK_LSHIFT = 0xA0
        VK_RSHIFT = 0xA1
        VK_NUMPAD0 = 0x60
        VK_NUMPAD1 = 0x61
        VK_NUMPAD2 = 0x62
        VK_INSERT = 0x2D
        VK_END = 0x23
        VK_DOWN = 0x28

        is_shift_pressed = VK_LSHIFT in self._current_pressed_vk or VK_RSHIFT in self._current_pressed_vk
        if not is_shift_pressed:
            return

        if (
            VK_NUMPAD0 in self._current_pressed_vk
            or (VK_INSERT in self._current_pressed_vk and VK_INSERT in self._numpad_pressed_vk)
        ):
            self._handle_asztal("keyboard Shift+Num0")
        elif (
            VK_NUMPAD1 in self._current_pressed_vk
            or (VK_END in self._current_pressed_vk and VK_END in self._numpad_pressed_vk)
        ):
            self._handle_laptop("keyboard Shift+Num1")
        elif (
            VK_NUMPAD2 in self._current_pressed_vk
            or (VK_DOWN in self._current_pressed_vk and VK_DOWN in self._numpad_pressed_vk)
        ):
            self._handle_elitedesk("keyboard Shift+Num2")

    # ------------------------------------------------------------------
    # Pico serial handling
    # ------------------------------------------------------------------
    def _find_pico_port(self) -> Optional[str]:
        ports = list(list_ports.comports())
        forced_port = (PICO_SERIAL_PORT or "").strip()
        if forced_port:
            if any(port.device == forced_port for port in ports):
                return forced_port
            logging.warning(
                "Configured PICO_SERIAL_PORT %s not found, falling back to auto-detection",
                forced_port,
            )

        keywords = ("pico", "circuitpython")
        data_candidate = None
        for port in ports:
            try:
                desc_raw = port.description or ""
                manuf_raw = getattr(port, "manufacturer", "") or ""
                iface_raw = getattr(port, "interface", "") or ""
                desc = desc_raw.lower()
                manuf = manuf_raw.lower()
                iface = iface_raw.lower()
                vid = getattr(port, "vid", None)
                matched = False
                if vid in (0x2E8A, 0x239A) or any(k in desc for k in keywords) or any(
                    k in manuf for k in keywords
                ):
                    matched = True
                    if "data" in iface or "data" in desc:
                        return port.device
                    if not data_candidate:
                        data_candidate = port.device
                if not matched:
                    logging.debug(
                        "Port not matched: %s VID=%s DESC='%s' MANUF='%s'",
                        port.device,
                        f"0x{vid:04X}" if vid else "None",
                        desc_raw,
                        manuf_raw,
                    )
            except Exception:
                continue
        return data_candidate

    def _serial_loop(self) -> None:
        while self._running.is_set():
            port_name = self._find_pico_port()
            if not port_name:
                for _ in range(5):
                    if not self._running.is_set():
                        return
                    time.sleep(1)
                continue

            logging.info("Pico serial device detected on %s", port_name)
            try:
                with serial.Serial(port_name, self.BAUD_RATE, timeout=self.SERIAL_TIMEOUT) as ser:
                    ser.reset_input_buffer()
                    logging.info("Listening for Pico button messages")
                    while self._running.is_set():
                        try:
                            line = ser.readline()
                        except Exception:
                            logging.warning("Serial read failed, retrying...")
                            time.sleep(2)
                            continue
                        if not line:
                            continue
                        try:
                            message = line.decode("utf-8", errors="ignore").strip()
                        except Exception:
                            continue
                        if not message:
                            continue
                        action = self._serial_action_map.get(message)
                        if action:
                            action()
                        else:
                            logging.debug("Unknown Pico message: %s", message)
            except serial.SerialException as exc:
                logging.info("Unable to open Pico serial device %s: %s", port_name, exc)
                time.sleep(1)
        logging.info("Pico serial listener terminated")
