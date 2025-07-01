# worker.py - FINAL STRUCTURAL FIX
# Decouples background threads from state changes using a signal.

import socket
import time
import threading
import logging
import tkinter
from typing import Optional
import struct
import msgpack
import pyperclip
from pynput import keyboard
from zeroconf import Zeroconf, ServiceBrowser
from input_streaming import stream_inputs
from connection_utils import ConnectionMixin
from file_transfer import FileTransferMixin
from monitorcontrol import get_monitors
from PySide6.QtCore import QObject, Signal, QSettings
from config import (
    SERVICE_TYPE,
    SERVICE_NAME_PREFIX,
    APP_NAME,
    ORG_NAME,
    VK_NUMPAD0,
    VK_NUMPAD1,
    VK_NUMPAD2,
    VK_LSHIFT,
    VK_RSHIFT,
)


def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return socket.gethostbyname(socket.gethostname())


class KVMWorker(FileTransferMixin, ConnectionMixin, QObject):
    __slots__ = (
        'settings', '_running', 'kvm_active', 'client_sockets', 'client_infos',
        'active_client', 'pynput_listeners', 'zeroconf', 'streaming_thread',
        'switch_monitor', 'local_ip', 'server_ip', 'connection_thread',
        'device_name', 'clipboard_thread', 'last_clipboard', 'server_socket',
        'network_file_clipboard', '_cancel_transfer', 'last_server_ip',
        'clipboard_lock', 'hotkey_listener'
    )

    finished = Signal()
    status_update = Signal(str)
    update_progress_display = Signal(int, str)
    file_transfer_error = Signal(str)
    incoming_upload_started = Signal(str, int)
    request_deactivation = Signal(str)  # NEW SIGNAL

    def __init__(self, settings):
        super().__init__()
        self.settings = settings
        self._running = True
        self.kvm_active = False
        self.client_sockets = []
        self.client_infos = {}
        self.active_client = None
        self.pynput_listeners = []
        self.zeroconf = Zeroconf()
        self.streaming_thread = None
        self.switch_monitor = True
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
        self._host_mouse_controller = None
        self._orig_mouse_pos = None
        self.hotkey_listener = None

    def release_hotkey_keys(self):
        kc = keyboard.Controller()
        keys = [
            keyboard.Key.shift_l, keyboard.Key.shift_r,
            keyboard.KeyCode.from_vk(VK_NUMPAD0),
            keyboard.KeyCode.from_vk(VK_NUMPAD1),
            keyboard.KeyCode.from_vk(VK_NUMPAD2),
        ]
        for k in keys:
            try:
                kc.release(k)
            except Exception:
                pass

    def _start_hotkey_listener(self):
        if self.hotkey_listener is not None:
            return
        # Hotkey definitions...
        hotkey_desktop_l_numoff = {keyboard.Key.shift, keyboard.Key.insert}
        hotkey_desktop_r_numoff = {keyboard.Key.shift_r, keyboard.Key.insert}
        hotkey_laptop_l_numoff = {keyboard.Key.shift, keyboard.Key.end}
        hotkey_laptop_r_numoff = {keyboard.Key.shift_r, keyboard.Key.end}
        hotkey_elitdesk_l_numoff = {keyboard.Key.shift, VK_NUMPAD2}
        hotkey_elitdesk_r_numoff = {keyboard.Key.shift_r, VK_NUMPAD2}
        hotkey_desktop_l_numon = {VK_LSHIFT, VK_NUMPAD0}
        hotkey_desktop_r_numon = {VK_RSHIFT, VK_NUMPAD0}
        hotkey_laptop_l_numon = {VK_LSHIFT, VK_NUMPAD1}
        hotkey_laptop_r_numon = {VK_RSHIFT, VK_NUMPAD1}
        hotkey_elitdesk_l_numon = {VK_LSHIFT, VK_NUMPAD2}
        hotkey_elitdesk_r_numon = {VK_RSHIFT, VK_NUMPAD2}

        current_pressed_vk_codes, current_pressed_special_keys, pending_client = set(), set(), None

        def on_press(key):
            nonlocal pending_client
            try:
                current_pressed_vk_codes.add(key.vk)
            except AttributeError:
                current_pressed_special_keys.add(key)

            if any([
                hotkey_desktop_l_numoff.issubset(current_pressed_special_keys),
                hotkey_desktop_r_numoff.issubset(current_pressed_special_keys),
                hotkey_desktop_l_numon.issubset(current_pressed_vk_codes),
                hotkey_desktop_r_numon.issubset(current_pressed_vk_codes),
            ]):
                pending_client = 'desktop'
            elif any([
                hotkey_laptop_l_numoff.issubset(current_pressed_special_keys),
                hotkey_laptop_r_numoff.issubset(current_pressed_special_keys),
                hotkey_laptop_l_numon.issubset(current_pressed_vk_codes),
                hotkey_laptop_r_numon.issubset(current_pressed_vk_codes),
            ]):
                pending_client = 'laptop'
            elif any([
                hotkey_elitdesk_l_numoff.issubset(current_pressed_special_keys.union(current_pressed_vk_codes)),
                hotkey_elitdesk_r_numoff.issubset(current_pressed_special_keys.union(current_pressed_vk_codes)),
                hotkey_elitdesk_l_numon.issubset(current_pressed_vk_codes),
                hotkey_elitdesk_r_numon.issubset(current_pressed_vk_codes),
            ]):
                pending_client = 'elitedesk'

        def on_release(key):
            nonlocal pending_client
            try:
                current_pressed_vk_codes.discard(key.vk)
            except AttributeError:
                current_pressed_special_keys.discard(key)
            if pending_client and not current_pressed_vk_codes and not current_pressed_special_keys:
                if pending_client == 'desktop':
                    self.deactivate_kvm(switch_monitor=True, reason="desktop hotkey")
                else:
                    self.toggle_client_control(pending_client, switch_monitor=(pending_client == 'elitedesk'))
                pending_client = None

        self.hotkey_listener = keyboard.Listener(on_press=on_press, on_release=on_release)
        self.pynput_listeners.append(self.hotkey_listener)
        self.hotkey_listener.start()
        logging.info("Tétlen gyorsbillentyű figyelő elindítva.")

    def _stop_hotkey_listener(self):
        if self.hotkey_listener:
            try:
                self.hotkey_listener.stop()
            except Exception:
                pass
            if self.hotkey_listener in self.pynput_listeners:
                self.pynput_listeners.remove(self.hotkey_listener)
            self.hotkey_listener = None
            logging.info("Tétlen gyorsbillentyű figyelő leállítva.")

    def _set_clipboard(self, text: str):
        # ... (no change)
        with self.clipboard_lock:
            try:
                pyperclip.copy(text)
                self.last_clipboard = text
            except Exception as e:
                logging.debug("Vágólap írási hiba: %s", e)

    def _get_clipboard(self) -> str:
        # ... (no change)
        with self.clipboard_lock:
            try:
                return pyperclip.paste()
            except Exception as e:
                logging.debug("Vágólap olvasási hiba: %s", e)
                return self.last_clipboard

    def _send_message(self, sock, data):
        # ... (no change)
        try:
            packed = msgpack.packb(data, use_bin_type=True)
            sock.sendall(struct.pack('!I', len(packed)) + packed)
            return True
        except Exception:
            return False

    def _broadcast_message(self, data, exclude=None):
        # ... (no change)
        to_remove = []
        packed = msgpack.packb(data, use_bin_type=True)
        message = struct.pack('!I', len(packed)) + packed
        for s in list(self.client_sockets):
            if s is exclude:
                continue
            try:
                s.sendall(message)
            except Exception:
                to_remove.append(s)
        for s in to_remove:
            self._remove_client(s, "broadcast failed")

    def _remove_client(self, sock, reason: str = ""):
        # STRUCTURAL CHANGE: Emits signal instead of calling deactivate_kvm
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
            self.active_client = None
            if self.kvm_active:
                self.request_deactivation.emit(f"aktív kliens ({client_name}) lecsatlakozott")

    def _clipboard_loop_server(self):
        # ... (no change)
        while self._running:
            time.sleep(0.5)
            text_to_send = None
            try:
                current_text = self._get_clipboard()
                with self.clipboard_lock:
                    if current_text and current_text != self.last_clipboard:
                        self.last_clipboard = current_text
                        text_to_send = current_text
                if text_to_send:
                    self._broadcast_message({'type': 'clipboard_text', 'text': text_to_send})
            except Exception:
                pass

    def _clipboard_loop_client(self, sock):
        # ... (no change)
        while self._running and self.server_socket is sock:
            time.sleep(0.5)
            text_to_send = None
            try:
                current_text = self._get_clipboard()
                with self.clipboard_lock:
                    if current_text and current_text != self.last_clipboard:
                        self.last_clipboard = current_text
                        text_to_send = current_text
                if text_to_send:
                    self._send_message(sock, {'type': 'clipboard_text', 'text': text_to_send})
            except Exception:
                pass

    def set_active_client_by_name(self, name):
        for sock, cname in self.client_infos.items():
            if cname.lower().startswith(name.lower()):
                self.active_client = sock
                logging.info(f"Aktív kliens beállítva: {cname}")
                return True
        logging.warning(f"Nincs kliens '{name}' névvel")
        return False

    def toggle_client_control(self, name: str, *, switch_monitor: bool = True):
        current = self.client_infos.get(self.active_client, "").lower()
        if self.kvm_active and current.startswith(name.lower()):
            self.deactivate_kvm(reason="toggle same client")
            return
        if self.kvm_active:
            self.deactivate_kvm(reason="switching client")
        if self.set_active_client_by_name(name):
            self.activate_kvm(switch_monitor=switch_monitor)

    def stop(self):
        self._running = False
        if self.kvm_active:
            self.deactivate_kvm(switch_monitor=False, reason="stop() called")
        else:
            self._stop_hotkey_listener()

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
        if self.settings['role'] == 'ado':
            self.run_server()
        else:
            self.run_client()
        logging.info("Worker futása befejeződött.")

    def activate_kvm(self, switch_monitor=True):
        if not self.active_client:
            self.status_update.emit("Hiba: Nincs aktív kliens a váltáshoz!")
            return

        self._stop_hotkey_listener()
        self.kvm_active = True
        client_name = self.client_infos.get(self.active_client, "ismeretlen")
        self.status_update.emit(f"Állapot: Aktív - {client_name}")

        self.switch_monitor = switch_monitor
        self.streaming_thread = threading.Thread(target=stream_inputs, args=(self,), daemon=True, name="StreamingThread")
        self.streaming_thread.start()

    def deactivate_kvm(self, switch_monitor=None, *, reason: Optional[str] = None):
        if not self.kvm_active:
            return
        self.kvm_active = False
        logging.info("KVM deaktiválása. Ok: %s", reason or "ismeretlen")
        self._stop_hotkey_listener()  # Stop any hotkey listeners
        if self.streaming_thread and self.streaming_thread.is_alive():
            self.streaming_thread.join(timeout=0.5)

        switch = switch_monitor if switch_monitor is not None else self.switch_monitor
        if switch:
            time.sleep(0.2)
            try:
                with list(get_monitors())[0] as monitor:
                    monitor.set_input_source(self.settings['monitor_codes']['host'])
            except Exception as e:
                self.status_update.emit(f"Monitor hiba: {e}")

        self.release_hotkey_keys()
        self.active_client = None
        self.status_update.emit("Állapot: Inaktív. Várakozás gyorsbillentyűre.")
        if self._running:
            self._start_hotkey_listener()
