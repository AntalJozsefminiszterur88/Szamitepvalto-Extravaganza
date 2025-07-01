"""Single-Listener, bomb-proof KVM worker logic."""

import socket
import time
import threading
import struct
import logging
from typing import Optional

import msgpack
import pyperclip
import tkinter
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
    """Return the local IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return socket.gethostbyname(socket.gethostname())


class KVMWorker(FileTransferMixin, ConnectionMixin, QObject):
    """Background worker handling KVM state and networking."""

    __slots__ = (
        'settings', '_running', 'kvm_active', 'client_sockets', 'client_infos',
        'active_client', 'zeroconf', 'local_ip', 'server_ip', 'connection_thread',
        'device_name', 'clipboard_thread', 'last_clipboard', 'server_socket',
        'network_file_clipboard', '_cancel_transfer', 'last_server_ip',
        'clipboard_lock', '_input_listeners'
    )

    finished = Signal()
    status_update = Signal(str)
    update_progress_display = Signal(int, str)
    file_transfer_error = Signal(str)
    incoming_upload_started = Signal(str, int)
    request_deactivation = Signal(str)

    def __init__(self, settings):
        super().__init__()
        self.settings = settings
        self._running = True
        self.kvm_active = False
        self.client_sockets = []
        self.client_infos = {}
        self.active_client = None
        self.zeroconf = Zeroconf()
        self.local_ip = get_local_ip()
        self.server_ip = None
        self.connection_thread = None

        settings_store = QSettings(ORG_NAME, APP_NAME)
        self.last_server_ip = settings_store.value('network/last_server_ip', None)
        self.device_name = settings.get('device_name', socket.gethostname())

        self.clipboard_thread = None
        self.last_clipboard = ""
        self.clipboard_lock = threading.Lock()
        self.server_socket = None
        self.network_file_clipboard = None
        self._cancel_transfer = threading.Event()
        self._input_listeners = []

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------
    def release_all_keys(self):
        """Ensure that modifier and numpad keys are released."""
        kc = keyboard.Controller()
        keys = [
            keyboard.Key.shift, keyboard.Key.shift_l, keyboard.Key.shift_r,
            keyboard.Key.ctrl, keyboard.Key.ctrl_l, keyboard.Key.ctrl_r,
            keyboard.Key.alt, keyboard.Key.alt_l, keyboard.Key.alt_r,
            keyboard.KeyCode.from_vk(VK_NUMPAD0),
            keyboard.KeyCode.from_vk(VK_NUMPAD1),
            keyboard.KeyCode.from_vk(VK_NUMPAD2),
        ]
        for key in keys:
            try:
                kc.release(key)
            except Exception:
                pass


    def _input_loop(self):
        """The single, permanent input listener loop."""
        logging.info("--- PERMANENT INPUT LOOP STARTED ---")

        hotkey_desktop = ({VK_LSHIFT, VK_NUMPAD0}, {keyboard.Key.shift, keyboard.Key.insert})
        hotkey_laptop = ({VK_LSHIFT, VK_NUMPAD1}, {keyboard.Key.shift, keyboard.Key.end})
        hotkey_elitedesk = ({VK_LSHIFT, VK_NUMPAD2}, {keyboard.Key.shift, VK_NUMPAD2})

        current_vks, current_special = set(), set()
        pressed_keys_forwarded = set()

        try:
            root = tkinter.Tk(); root.withdraw()
            center_x, center_y = (root.winfo_screenwidth() // 2, root.winfo_screenheight() // 2)
            root.destroy()
        except Exception:
            center_x, center_y = 800, 600
        is_warping = False

        mouse_controller = mouse.Controller()

        def send(data):
            if not self.kvm_active or not self.active_client:
                return
            try:
                packed = msgpack.packb(data, use_bin_type=True)
                message = struct.pack('!I', len(packed)) + packed
                self.active_client.sendall(message)
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                logging.error("Send failed, client disconnected: %s", e)
                self._remove_client(self.active_client, "send failed")
            except Exception as e:
                logging.error("Unexpected send error: %s", e)

        def on_move(x, y):
            nonlocal is_warping
            if self.kvm_active:
                if is_warping:
                    is_warping = False
                    return
                dx, dy = x - mouse_controller.position[0], y - mouse_controller.position[1]
                if dx != 0 or dy != 0:
                    send({'type': 'move_relative', 'dx': dx, 'dy': dy})
                is_warping = True
                mouse_controller.position = (center_x, center_y)

        def on_click(x, y, button, pressed):
            if self.kvm_active:
                send({'type': 'click', 'button': button.name, 'pressed': pressed})

        def on_scroll(x, y, dx, dy):
            if self.kvm_active:
                send({'type': 'scroll', 'dx': dx, 'dy': dy})

        def handle_hotkey_check():
            for vk_set, key_set in [hotkey_desktop, hotkey_laptop, hotkey_elitedesk]:
                if vk_set.issubset(current_vks) or key_set.issubset(current_special):
                    if vk_set == hotkey_desktop[0]:
                        target = 'desktop'
                    elif vk_set == hotkey_laptop[0]:
                        target = 'laptop'
                    else:
                        target = 'elitedesk'

                    if self.kvm_active:
                        logging.info(f"STREAMING HOTKEY: Deactivating for target {target}")
                        send_release_for_pressed()
                        self.toggle_client_control(target)
                    else:
                        logging.info(f"IDLE HOTKEY: Activating for target {target}")
                        self.toggle_client_control(target)
                    return True
            return False

        def send_release_for_pressed():
            for key_type, key_val in list(pressed_keys_forwarded):
                send({"type": "key", "key_type": key_type, "key": key_val, "pressed": False})
            pressed_keys_forwarded.clear()

        def on_press(key):
            try:
                vk = key.vk
                current_vks.add(vk)
            except AttributeError:
                current_special.add(key)

            if handle_hotkey_check():
                return

            if self.kvm_active:
                if hasattr(key, "char") and key.char:
                    key_type, key_val = "char", key.char
                elif hasattr(key, "name"):
                    key_type, key_val = "special", key.name
                elif hasattr(key, "vk"):
                    key_type, key_val = "vk", key.vk
                else:
                    return

                key_id = (key_type, key_val)
                if key_id not in pressed_keys_forwarded:
                    pressed_keys_forwarded.add(key_id)
                    send({"type": "key", "key_type": key_type, "key": key_val, "pressed": True})

        def on_release(key):
            try:
                vk = key.vk
                current_vks.discard(vk)
            except AttributeError:
                current_special.discard(key)

            if self.kvm_active:
                if hasattr(key, "char") and key.char:
                    key_type, key_val = "char", key.char
                elif hasattr(key, "name"):
                    key_type, key_val = "special", key.name
                elif hasattr(key, "vk"):
                    key_type, key_val = "vk", key.vk
                else:
                    return

                key_id = (key_type, key_val)
                if key_id in pressed_keys_forwarded:
                    pressed_keys_forwarded.discard(key_id)
                    send({"type": "key", "key_type": key_type, "key": key_val, "pressed": False})

        m_listener = mouse.Listener(on_move=on_move, on_click=on_click, on_scroll=on_scroll, suppress=self.kvm_active)
        k_listener = keyboard.Listener(on_press=on_press, on_release=on_release, suppress=self.kvm_active)
        self._input_listeners.extend([m_listener, k_listener])
        m_listener.start(); k_listener.start()

        while self._running:
            suppress = self.kvm_active
            if m_listener.suppress != suppress:
                m_listener.suppress = suppress
            if k_listener.suppress != suppress:
                k_listener.suppress = suppress
            time.sleep(0.1)

        logging.info("--- PERMANENT INPUT LOOP STOPPED ---")
        m_listener.stop(); k_listener.stop()

    # ------------------------------------------------------------------
    # Networking helpers
    # ------------------------------------------------------------------
    def _remove_client(self, sock, reason: str = ""):
        if sock is None:
            return
        client_name = self.client_infos.get(sock, "<unknown>")
        logging.warning("Kliens eltávolítva: %s. Ok: %s", client_name, reason)
        try:
            sock.close()
        except Exception:
            pass
        if sock in self.client_sockets:
            self.client_sockets.remove(sock)
        if sock in self.client_infos:
            del self.client_infos[sock]
        if sock == self.active_client:
            if self.kvm_active:
                logging.debug(f"Active client {client_name} disconnected, requesting deactivation.")
                self.request_deactivation.emit(f"aktív kliens ({client_name}) lecsatlakozott")
            self.active_client = None

    def _set_clipboard(self, text: str):
        with self.clipboard_lock:
            try:
                pyperclip.copy(text)
            except Exception:
                pass

    def _get_clipboard(self) -> str:
        with self.clipboard_lock:
            try:
                return pyperclip.paste()
            except Exception:
                return ""

    def _send_message(self, sock, data):
        try:
            packed = msgpack.packb(data, use_bin_type=True)
            sock.sendall(struct.pack('!I', len(packed)) + packed)
            return True
        except Exception:
            return False

    def _broadcast_message(self, data, exclude=None):
        to_remove = []
        message = struct.pack('!I', len(msgpack.packb(data, use_bin_type=True))) + msgpack.packb(data, use_bin_type=True)
        for s in list(self.client_sockets):
            if s is exclude:
                continue
            try:
                s.sendall(message)
            except Exception:
                to_remove.append(s)
        for s in to_remove:
            self._remove_client(s, "broadcast failed")

    # ------------------------------------------------------------------
    # Clipboard loops
    # ------------------------------------------------------------------
    def _clipboard_loop_server(self):
        while self._running:
            time.sleep(1.0)
            try:
                current_text = self._get_clipboard()
                with self.clipboard_lock:
                    if current_text and current_text != self.last_clipboard:
                        self.last_clipboard = current_text
                        self._broadcast_message({'type': 'clipboard_text', 'text': current_text})
            except Exception:
                pass

    def _clipboard_loop_client(self, sock):
        while self._running and self.server_socket is sock:
            time.sleep(1.0)
            try:
                current_text = self._get_clipboard()
                with self.clipboard_lock:
                    if current_text and current_text != self.last_clipboard:
                        self.last_clipboard = current_text
                        self._send_message(sock, {'type': 'clipboard_text', 'text': current_text})
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Client management
    # ------------------------------------------------------------------
    def set_active_client_by_name(self, name):
        for sock, cname in self.client_infos.items():
            if cname.lower().startswith(name.lower()):
                self.active_client = sock
                logging.info(f"Active client set to {cname}")
                return True
        return False

    def toggle_client_control(self, name: str, *, switch_monitor: bool = True):
        """Switch control to the named client or deactivate if already active."""
        logging.debug(f"--- TOGGLE CONTROL. Target: {name}, KVM Active: {self.kvm_active} ---")

        current_client_name = self.client_infos.get(self.active_client, "").lower()
        target_name = name.lower()

        if self.kvm_active and current_client_name.startswith(target_name):
            logging.debug("Toggle target is same as active client. Deactivating.")
            self.deactivate_kvm(reason="toggle same client")
            return

        if self.kvm_active:
            logging.debug("KVM is active, but target is different. Deactivating first.")
            self.deactivate_kvm(reason="switching client")

        logging.debug(f"Attempting to set and activate new client: {name}")
        if self.set_active_client_by_name(name):
            self.activate_kvm(switch_monitor=switch_monitor)
        else:
            logging.error(f"Failed to set active client to {name}, client not found.")
            self.status_update.emit(f"Hiba: A(z) '{name}' kliens nem található.")

    # ------------------------------------------------------------------
    # Lifecycle management
    # ------------------------------------------------------------------
    def stop(self):
        logging.info("--- WORKER STOPPING ---")
        self._running = False
        if self.kvm_active:
            self.deactivate_kvm(switch_monitor=False, reason="stop() called")
        for listener in self._input_listeners:
            try:
                listener.stop()
            except Exception:
                pass
        try:
            self.zeroconf.close()
        except Exception:
            pass
        sockets_to_close = list(self.client_sockets)
        for sock in sockets_to_close:
            self._remove_client(sock, "application stopping")
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        self.finished.emit()

    def run(self):
        logging.info(f"Worker starting in '{self.settings['role']}' mode.")
        if self.settings['role'] == 'ado':
            input_thread = threading.Thread(target=self._input_loop, daemon=True, name="InputLoop")
            input_thread.start()
            self.run_server()
        else:
            self.run_client()
        logging.info("Worker run loop finished.")

    def activate_kvm(self, switch_monitor=True):
        logging.debug(f"--- ACTIVATE KVM. Target: {self.client_infos.get(self.active_client, 'N/A')} ---")
        if not self.active_client:
            self.status_update.emit("Hiba: Nincs aktív kliens a váltáshoz!")
            logging.error("activate_kvm called with no active_client.")
            return

        if self.kvm_active:
            return
        self.kvm_active = True
        client_name = self.client_infos.get(self.active_client, "ismeretlen")
        self.status_update.emit(f"Állapot: Aktív - {client_name}")
        logging.info(f"KVM activated. Target: {client_name}")

        if switch_monitor:
            try:
                with list(get_monitors())[0] as monitor:
                    monitor.set_input_source(self.settings['monitor_codes']['client'])
            except Exception as e:
                self.status_update.emit(f"Monitor hiba: {e}")

    def deactivate_kvm(self, switch_monitor=True, *, reason: Optional[str] = None):
        logging.info("KVM deactivated. Reason: %s", reason or "unknown")
        if not self.kvm_active:
            return

        self.kvm_active = False

        if switch_monitor:
            try:
                with list(get_monitors())[0] as monitor:
                    monitor.set_input_source(self.settings['monitor_codes']['host'])
            except Exception as e:
                self.status_update.emit(f"Monitor hiba: {e}")

        self.release_all_keys()
        self.active_client = None
        self.status_update.emit("Állapot: Inaktív. Várakozás gyorsbillentyűre.")

    # Additional methods for network/file transfer remain unchanged.

