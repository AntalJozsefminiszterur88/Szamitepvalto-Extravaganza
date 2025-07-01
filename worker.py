"""Definitive KVM worker using the 'Two Permanent Listeners' architecture for maximum stability."""

import socket
import time
import threading
import struct
import logging
from typing import Optional
import tkinter

import msgpack
import pyperclip
from pynput import mouse, keyboard
from zeroconf import Zeroconf, ServiceBrowser
from connection_utils import ConnectionMixin
from file_transfer import FileTransferMixin
from monitorcontrol import get_monitors
from PySide6.QtCore import QObject, Signal, QSettings
from config import (
    SERVICE_TYPE, SERVICE_NAME_PREFIX, APP_NAME, ORG_NAME,
    VK_NUMPAD0, VK_NUMPAD1, VK_NUMPAD2, VK_LSHIFT, VK_RSHIFT
)


def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80)); return s.getsockname()[0]
    except Exception: return socket.gethostbyname(socket.gethostname())


class KVMWorker(FileTransferMixin, ConnectionMixin, QObject):
    __slots__ = (
        'settings', '_running', 'kvm_active', 'client_sockets', 'client_infos',
        'active_client', 'zeroconf', 'local_ip', 'server_ip', 'connection_thread',
        'device_name', 'clipboard_thread', 'last_clipboard', 'server_socket',
        'network_file_clipboard', '_cancel_transfer', 'last_server_ip',
        'clipboard_lock', '_input_listeners'
    )
    finished = Signal()
    status_update = Signal(str)
    # ... other signals ...

    def __init__(self, settings):
        super().__init__()
        self.settings = settings
        self._running = True
        self.kvm_active = False
        # ... other initializations ...
        self.client_sockets, self.client_infos, self.active_client = [], {}, None
        self.zeroconf = Zeroconf()
        self.local_ip = get_local_ip()
        self.server_ip, self.connection_thread = None, None
        settings_store = QSettings(ORG_NAME, APP_NAME)
        self.last_server_ip = settings_store.value('network/last_server_ip', None)
        self.device_name = settings.get('device_name', socket.gethostname())
        self.clipboard_thread, self.last_clipboard, self.clipboard_lock = None, "", threading.Lock()
        self.server_socket, self.network_file_clipboard, self._cancel_transfer = None, None, threading.Event()
        self._input_listeners = []

    def release_all_keys(self):
        # ... (unchanged)
        kc = keyboard.Controller()
        keys = [keyboard.Key.shift, keyboard.Key.ctrl, keyboard.Key.alt,
                keyboard.KeyCode.from_vk(VK_NUMPAD0), keyboard.KeyCode.from_vk(VK_NUMPAD1), keyboard.KeyCode.from_vk(VK_NUMPAD2)]
        for key in keys:
            try: kc.release(key)
            except: pass

    def _input_handler(self):
        """Initializes and runs the two permanent input listeners."""
        logging.info("--- INITIALIZING PERMANENT LISTENERS ---")

        # --- Listener 1: Suppressing Listener (for active KVM) ---
        pressed_keys_forwarded = set()
        try:
            root = tkinter.Tk(); root.withdraw()
            center_x, center_y = (root.winfo_screenwidth() // 2, root.winfo_screenheight() // 2)
            root.destroy()
        except: center_x, center_y = 800, 600
        is_warping = False
        mouse_controller = mouse.Controller()

        def send(data):
            if not self.active_client: return
            try:
                packed = msgpack.packb(data, use_bin_type=True)
                message = struct.pack('!I', len(packed)) + packed
                self.active_client.sendall(message)
            except (OSError, ConnectionResetError):
                self._remove_client(self.active_client, "send failed")

        def on_move_suppress(x, y):
            nonlocal is_warping
            if not self.kvm_active: return
            if is_warping: is_warping = False; return
            dx, dy = x - mouse_controller.position[0], y - mouse_controller.position[1]
            if dx != 0 or dy != 0: send({'type': 'move_relative', 'dx': dx, 'dy': dy})
            is_warping = True; mouse_controller.position = (center_x, center_y)

        def on_click_suppress(x, y, button, pressed):
            if not self.kvm_active: return
            send({'type': 'click', 'button': button.name, 'pressed': pressed})

        def on_scroll_suppress(x, y, dx, dy):
            if not self.kvm_active: return
            send({'type': 'scroll', 'dx': dx, 'dy': dy})

        def on_press_suppress(key):
            if not self.kvm_active: return
            # Key forwarding logic
            if hasattr(key, "char") and key.char: key_type, key_val = "char", key.char
            elif hasattr(key, "name"): key_type, key_val = "special", key.name
            elif hasattr(key, "vk"): key_type, key_val = "vk", key.vk
            else: return
            key_id = (key_type, key_val)
            if key_id not in pressed_keys_forwarded:
                pressed_keys_forwarded.add(key_id)
                send({"type": "key", "key_type": key_type, "key": key_val, "pressed": True})

        def on_release_suppress(key):
            if not self.kvm_active: return
            # Key release logic
            if hasattr(key, "char") and key.char: key_type, key_val = "char", key.char
            elif hasattr(key, "name"): key_type, key_val = "special", key.name
            elif hasattr(key, "vk"): key_type, key_val = "vk", key.vk
            else: return
            key_id = (key_type, key_val)
            if key_id in pressed_keys_forwarded:
                pressed_keys_forwarded.discard(key_id)
                send({"type": "key", "key_type": key_type, "key": key_val, "pressed": False})

        # --- Listener 2: Non-Suppressing Listener (for idle KVM) ---
        idle_vks, idle_special, pending_client = set(), set(), None
        hotkey_map = {
            'desktop': ({VK_LSHIFT, VK_NUMPAD0}, {keyboard.Key.shift, keyboard.Key.insert}),
            'laptop': ({VK_LSHIFT, VK_NUMPAD1}, {keyboard.Key.shift, keyboard.Key.end}),
            'elitedesk': ({VK_LSHIFT, VK_NUMPAD2}, {keyboard.Key.shift, VK_NUMPAD2}),
        }

        def on_press_idle(key):
            nonlocal pending_client
            if self.kvm_active: return
            try: idle_vks.add(key.vk)
            except AttributeError: idle_special.add(key)
            for target, (vk_set, key_set) in hotkey_map.items():
                if vk_set.issubset(idle_vks) or key_set.issubset(idle_special):
                    pending_client = target
                    break

        def on_release_idle(key):
            nonlocal pending_client
            if self.kvm_active: return
            try: idle_vks.discard(key.vk)
            except AttributeError: idle_special.discard(key)
            if pending_client and not idle_vks and not idle_special:
                logging.info(f"IDLE HOTKEY ACTION: {pending_client}")
                self.toggle_client_control(pending_client)
                pending_client = None

        # --- Start both listeners ---
        suppressing_mouse = mouse.Listener(on_move=on_move_suppress, on_click=on_click_suppress, on_scroll=on_scroll_suppress, suppress=True)
        suppressing_keyboard = keyboard.Listener(on_press=on_press_suppress, on_release=on_release_suppress, suppress=True)
        idle_keyboard = keyboard.Listener(on_press=on_press_idle, on_release=on_release_idle, suppress=False)

        self._input_listeners.extend([suppressing_mouse, suppressing_keyboard, idle_keyboard])
        suppressing_mouse.start(); suppressing_keyboard.start(); idle_keyboard.start()

        suppressing_mouse.join(); suppressing_keyboard.join(); idle_keyboard.join()
        logging.info("--- PERMANENT LISTENERS SHUT DOWN ---")

    def set_active_client_by_name(self, name):
        # ... (unchanged)
        for sock, cname in self.client_infos.items():
            if cname.lower().startswith(name.lower()): self.active_client = sock; return True
        return False

    def toggle_client_control(self, name: str, *, switch_monitor: bool = True):
        current_client_name = self.client_infos.get(self.active_client, "").lower()
        target_name = name.lower()
        is_desktop_target = target_name == 'desktop'

        if self.kvm_active:
            if current_client_name.startswith(target_name) or is_desktop_target:
                self.deactivate_kvm(reason=f"toggle for {name}", switch_monitor=True)
            else:
                self.deactivate_kvm(reason=f"switching to {name}", switch_monitor=False)
                if self.set_active_client_by_name(name):
                    self.activate_kvm(switch_monitor=switch_monitor)
        else: # KVM is inactive
            if not is_desktop_target and self.set_active_client_by_name(name):
                self.activate_kvm(switch_monitor=switch_monitor)

    def activate_kvm(self, switch_monitor=True):
        if not self.active_client: self.status_update.emit("Hiba: Nincs kliens a váltáshoz!"); return
        if self.kvm_active: return

        if switch_monitor:
            try:
                with list(get_monitors())[0] as monitor: monitor.set_input_source(self.settings['monitor_codes']['client'])
            except Exception as e: self.status_update.emit(f"Monitor hiba: {e}")

        self.kvm_active = True # IMPORTANT: Set active AFTER monitor switch
        client_name = self.client_infos.get(self.active_client, "ismeretlen")
        self.status_update.emit(f"Állapot: Aktív - {client_name}")
        logging.info(f"KVM activated. Target: {client_name}")

    def deactivate_kvm(self, switch_monitor=True, *, reason: Optional[str] = None):
        if not self.kvm_active: return

        if switch_monitor:
            try:
                with list(get_monitors())[0] as monitor: monitor.set_input_source(self.settings['monitor_codes']['host'])
            except Exception as e: self.status_update.emit(f"Monitor hiba: {e}")

        self.kvm_active = False # IMPORTANT: Set inactive AFTER monitor switch
        self.release_all_keys()
        self.active_client = None
        self.status_update.emit("Állapot: Inaktív. Várakozás...")
        logging.info("KVM deactivated. Reason: %s", reason or "unknown")

    def stop(self):
        self._running = False
        if self.kvm_active: self.deactivate_kvm(switch_monitor=False, reason="stop() called")
        for listener in self._input_listeners:
            try: listener.stop()
            except: pass
        # ... (rest of stop logic is fine)
        try: self.zeroconf.close()
        except: pass
        for sock in list(self.client_sockets): self._remove_client(sock, "stopping")
        self.finished.emit()

    def run(self):
        if self.settings['role'] == 'ado':
            input_thread = threading.Thread(target=self._input_handler, daemon=True, name="InputHandler")
            input_thread.start()
            self.run_server()
        else:
            self.run_client()

    # ... other methods are delegated to mixins ...

