"""Hardware management services for monitor control and button inputs."""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Dict, Optional

from monitorcontrol import get_monitors
from monitorcontrol.monitorcontrol import PowerMode
from pynput import keyboard
from pynput.keyboard import Controller, Key
from PySide6.QtCore import QObject, Signal
from serial.tools import list_ports
import serial

from config import PICO_SERIAL_PORT


class HardwareManager(QObject):
    """Coordinate monitor control and local input devices."""

    switch_requested = Signal(str, str)
    monitor_input_requested = Signal(int)
    monitor_power_toggle_requested = Signal()
    function_key_requested = Signal(object, str)

    def __init__(self) -> None:
        super().__init__()
        self._button_manager: Optional[ButtonInputManager] = None
        self._function_key_handler: Optional[Callable[[Key, str], bool]] = None
        self.monitor_power_on: bool = True

        self.monitor_input_requested.connect(self.switch_monitor_input)
        self.monitor_power_toggle_requested.connect(self.toggle_monitor_power)

    def start(self) -> None:
        """Start listening for button inputs."""
        if self._button_manager is None:
            self._button_manager = ButtonInputManager(self)
        self._button_manager.start()

    def stop(self) -> None:
        """Stop listening for button inputs."""
        if self._button_manager:
            self._button_manager.stop()

    def set_function_key_handler(self, handler: Optional[Callable[[Key, str], bool]]) -> None:
        """Set the callback used to forward audio hotkeys to a provider."""
        self._function_key_handler = handler

    def handle_function_key_request(self, key: Key, source: str) -> bool:
        """Forward the audio key request to the handler if available."""
        self.function_key_requested.emit(key, source)
        if not self._function_key_handler:
            return False
        try:
            return bool(self._function_key_handler(key, source))
        except Exception:  # pragma: no cover - defensive logging only
            logging.exception("Failed to forward function key %s triggered by %s", key, source)
            return False

    def switch_monitor_input(self, input_code: int) -> None:
        """Switch the primary monitor to the given input source."""
        try:
            with list(get_monitors())[0] as monitor:
                monitor.set_input_source(input_code)
                logging.info("Monitor input switched to %s", input_code)
        except Exception as exc:  # pragma: no cover - hardware access
            logging.error("Failed to switch monitor input: %s", exc)

    def toggle_monitor_power(self) -> None:
        """Toggle the primary monitor power state between on and soft off."""
        try:
            monitors = list(get_monitors())
            if not monitors:
                logging.warning("No monitors detected for power toggle (F21).")
                return

            with monitors[0] as monitor:
                try:
                    current_mode = monitor.get_power_mode()
                    monitor_is_on = current_mode == PowerMode.on
                    self.monitor_power_on = monitor_is_on
                except Exception as exc:
                    logging.warning(
                        "Failed to query monitor power state, assuming current value (%s): %s",
                        self.monitor_power_on,
                        exc,
                    )
                    monitor_is_on = self.monitor_power_on

                try:
                    if monitor_is_on:
                        monitor.set_power_mode(PowerMode.off_soft)
                        self.monitor_power_on = False
                        logging.info("Monitor power toggled OFF via hotkey.")
                    else:
                        monitor.set_power_mode(PowerMode.on)
                        self.monitor_power_on = True
                        logging.info("Monitor power toggled ON via hotkey.")
                except Exception as exc:
                    logging.error("Failed to toggle monitor power state: %s", exc, exc_info=True)
        except Exception as exc:
            logging.error("Unexpected error while toggling monitor power: %s", exc, exc_info=True)


class ButtonInputManager:
    """Coordinate host F-key hotkeys and Pico button messages."""

    BAUD_RATE = 115200
    SERIAL_TIMEOUT = 1

    def __init__(self, hardware_manager: HardwareManager) -> None:
        self.hardware_manager = hardware_manager
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
            except Exception:  # pragma: no cover - defensive
                pass
            self._keyboard_listener = None
        if self._serial_thread and self._serial_thread.is_alive():
            self._serial_thread.join(timeout=2)
        self._serial_thread = None
        logging.info("ButtonInputManager stopped")

    def _initialise_action_maps(self) -> None:
        """Prepare lookup tables for both keyboard and serial events."""

        self._keyboard_action_map = {
            Key.f13: lambda: self._handle_switch("desktop", "keyboard F13"),
            Key.f14: lambda: self._handle_switch("laptop", "keyboard F14"),
            Key.f15: lambda: self._handle_switch("elitedesk", "keyboard F15"),
            Key.f16: lambda: self._handle_monitor_input(17, "keyboard F16"),
            Key.f17: lambda: self._handle_monitor_input(18, "keyboard F17"),
            Key.f21: lambda: self._handle_monitor_toggle("keyboard F21"),
        }
        self._serial_action_map = {
            "KEY_Asztal": lambda: self._handle_switch("desktop", "pico KEY_Asztal"),
            "KEY_Laptop": lambda: self._handle_switch("laptop", "pico KEY_Laptop"),
            "KEY_EliteDesk": lambda: self._handle_switch("elitedesk", "pico KEY_EliteDesk"),
            "KEY_HDMI_1": lambda: self._handle_monitor_input(17, "pico KEY_HDMI_1"),
            "KEY_HDMI_2": lambda: self._handle_monitor_input(18, "pico KEY_HDMI_2"),
            "KEY_Monitor_OnOff": lambda: self._handle_monitor_toggle("pico KEY_Monitor_OnOff"),
            "KEY_Hang_1": lambda: self._handle_function_key(Key.f18, "pico KEY_Hang_1"),
            "KEY_Hang_2": lambda: self._handle_function_key(Key.f19, "pico KEY_Hang_2"),
            "KEY_Hang_3": lambda: self._handle_function_key(Key.f20, "pico KEY_Hang_3"),
            "KEY_Nemitas": lambda: self._handle_function_key(Key.f22, "pico KEY_Nemitas"),
            # Legacy numeric protocol compatibility
            "1": lambda: self._handle_switch("desktop", "pico legacy 1"),
            "2": lambda: self._handle_switch("laptop", "pico legacy 2"),
            "3": lambda: self._handle_switch("elitedesk", "pico legacy 3"),
            "4": lambda: self._handle_monitor_input(17, "pico legacy 4"),
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

    def _handle_switch(self, target: str, source: str) -> None:
        logging.info("Switch requested to %s by %s", target, source)
        self.hardware_manager.switch_requested.emit(target, source)

    def _handle_monitor_input(self, input_code: int, source: str) -> None:
        logging.info("Monitor input %s requested by %s", input_code, source)
        self.hardware_manager.monitor_input_requested.emit(input_code)

    def _handle_monitor_toggle(self, source: str) -> None:
        logging.info("Monitor power toggle requested by %s", source)
        self.hardware_manager.monitor_power_toggle_requested.emit()

    def _handle_function_key(self, key: Key, source: str) -> None:
        logging.info("Audio hotkey %s triggered by %s", key, source)
        forwarded = self.hardware_manager.handle_function_key_request(key, source)
        if forwarded:
            return
        logging.info("Falling back to local key simulation for %s due to %s", key, source)
        self._emit_host_key(key)

    def _emit_host_key(self, key: Key) -> None:
        self._synthetic_keys.add(key)
        try:
            self._keyboard_controller.press(key)
            time.sleep(0.05)
            self._keyboard_controller.release(key)
        finally:
            time.sleep(0.01)
            self._synthetic_keys.discard(key)

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
            self._handle_switch("desktop", "keyboard Shift+Num0")
        elif (
            VK_NUMPAD1 in self._current_pressed_vk
            or (VK_END in self._current_pressed_vk and VK_END in self._numpad_pressed_vk)
        ):
            self._handle_switch("laptop", "keyboard Shift+Num1")
        elif (
            VK_NUMPAD2 in self._current_pressed_vk
            or (VK_DOWN in self._current_pressed_vk and VK_DOWN in self._numpad_pressed_vk)
        ):
            self._handle_switch("elitedesk", "keyboard Shift+Num2")

    def _find_pico_port(self) -> Optional[str]:
        forced_port = (PICO_SERIAL_PORT or "").strip()
        if forced_port:
            return forced_port
        keywords = ("pico", "circuitpython")
        data_candidate = None
        for port in list_ports.comports():
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
                        except serial.SerialException:
                            logging.info("Serial read failed, attempting reconnect")
                            break
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
