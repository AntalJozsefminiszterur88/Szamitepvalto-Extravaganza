# worker.py - FINAL REFACTORED VERSION
# Fixes: Listener conflict, "sticky key" bug, race conditions, client disconnects, and clipboard thread-safety.

import socket
import time
import threading
import logging
import tkinter
import queue
import struct
import os
from typing import Optional
import msgpack
import pyperclip
from pynput import keyboard
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser
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
    BRAND_NAME,
    VK_NUMPAD0,
    VK_NUMPAD1,
    VK_NUMPAD2,
    VK_LSHIFT,
    VK_RSHIFT,
)


def get_local_ip() -> str:
    """Return the primary local IP address."""
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
    update_progress_display = Signal(int, str)  # percentage, label text
    file_transfer_error = Signal(str)
    incoming_upload_started = Signal(str, int)

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
        """Release potential stuck hotkey keys without generating input."""
        kc = keyboard.Controller()
        keys = [
            keyboard.Key.shift_l,
            keyboard.Key.shift_r,
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
        """Start the idle hotkey listener for client switching."""
        if self.hotkey_listener is not None:
            return

        # Definitions for NumLock OFF state based on diagnostic results
        hotkey_desktop_l_numoff = {keyboard.Key.shift, keyboard.Key.insert}
        hotkey_desktop_r_numoff = {keyboard.Key.shift_r, keyboard.Key.insert}
        hotkey_laptop_l_numoff = {keyboard.Key.shift, keyboard.Key.end}
        hotkey_laptop_r_numoff = {keyboard.Key.shift_r, keyboard.Key.end}
        hotkey_elitdesk_l_numoff = {keyboard.Key.shift, VK_NUMPAD2}
        hotkey_elitdesk_r_numoff = {keyboard.Key.shift_r, VK_NUMPAD2}

        # Definitions for NumLock ON state (fallback using VK codes)
        hotkey_desktop_l_numon = {VK_LSHIFT, VK_NUMPAD0}
        hotkey_desktop_r_numon = {VK_RSHIFT, VK_NUMPAD0}
        hotkey_laptop_l_numon = {VK_LSHIFT, VK_NUMPAD1}
        hotkey_laptop_r_numon = {VK_RSHIFT, VK_NUMPAD1}
        hotkey_elitdesk_l_numon = {VK_LSHIFT, VK_NUMPAD2}
        hotkey_elitdesk_r_numon = {VK_RSHIFT, VK_NUMPAD2}

        current_pressed_vk_codes = set()
        current_pressed_special_keys = set()
        pending_client = None

        def on_press(key):
            nonlocal pending_client
            try:
                current_pressed_vk_codes.add(key.vk)
            except AttributeError:
                current_pressed_special_keys.add(key)

            logging.debug(
                f"Key pressed: {key}. VKs: {current_pressed_vk_codes}, Specials: {current_pressed_special_keys}"
            )

            if (
                hotkey_desktop_l_numoff.issubset(current_pressed_special_keys)
                or hotkey_desktop_r_numoff.issubset(current_pressed_special_keys)
            ) or (
                hotkey_desktop_l_numon.issubset(current_pressed_vk_codes)
                or hotkey_desktop_r_numon.issubset(current_pressed_vk_codes)
            ):
                logging.info("!!! Asztal gyorsbillentyű észlelve! Visszaváltás... !!!")
                pending_client = 'desktop'
            elif (
                hotkey_laptop_l_numoff.issubset(current_pressed_special_keys)
                or hotkey_laptop_r_numoff.issubset(current_pressed_special_keys)
            ) or (
                hotkey_laptop_l_numon.issubset(current_pressed_vk_codes)
                or hotkey_laptop_r_numon.issubset(current_pressed_vk_codes)
            ):
                logging.info("!!! Laptop gyorsbillentyű észlelve! Váltás... !!!")
                pending_client = 'laptop'
            elif (
                hotkey_elitdesk_l_numoff.issubset(
                    current_pressed_special_keys.union(current_pressed_vk_codes)
                )
                or hotkey_elitdesk_r_numoff.issubset(
                    current_pressed_special_keys.union(current_pressed_vk_codes)
                )
            ) or (
                hotkey_elitdesk_l_numon.issubset(current_pressed_vk_codes)
                or hotkey_elitdesk_r_numon.issubset(current_pressed_vk_codes)
            ):
                logging.info("!!! ElitDesk gyorsbillentyű észlelve! Váltás... !!!")
                pending_client = 'elitedesk'

        def on_release(key):
            nonlocal pending_client
            try:
                current_pressed_vk_codes.discard(key.vk)
            except AttributeError:
                current_pressed_special_keys.discard(key)

            logging.debug(
                f"Key released: {key}. VKs: {current_pressed_vk_codes}, Specials: {current_pressed_special_keys}"
            )

            if pending_client and not current_pressed_vk_codes and not current_pressed_special_keys:
                logging.info(f"Hotkey action executed: {pending_client}")
                if pending_client == 'desktop':
                    self.deactivate_kvm(switch_monitor=True, reason="desktop hotkey")
                else:
                    self.toggle_client_control(
                        pending_client,
                        switch_monitor=(pending_client == 'elitedesk'),
                        release_keys=False,
                    )
                pending_client = None

        self.hotkey_listener = keyboard.Listener(on_press=on_press, on_release=on_release)
        self.pynput_listeners.append(self.hotkey_listener)
        self.hotkey_listener.start()
        logging.info("Tétlen gyorsbillentyű figyelő elindítva.")

    def _stop_hotkey_listener(self):
        """Stop the idle hotkey listener if running."""
        listener = self.hotkey_listener
        if listener is not None:
            try:
                listener.stop()
            except Exception:
                pass
            if listener in self.pynput_listeners:
                self.pynput_listeners.remove(listener)
            self.hotkey_listener = None
            self.release_hotkey_keys()
            logging.info("Tétlen gyorsbillentyű figyelő leállítva.")

    def _set_clipboard(self, text: str) -> None:
        """Safely set the system clipboard."""
        with self.clipboard_lock:
            try:
                pyperclip.copy(text)
                self.last_clipboard = text
            except Exception as e:
                logging.error("Failed to set clipboard: %s", e)

    def _get_clipboard(self) -> str:
        """Safely read the system clipboard."""
        with self.clipboard_lock:
            try:
                return pyperclip.paste()
            except Exception as e:
                logging.error("Failed to read clipboard: %s", e)
                return self.last_clipboard

    def _send_message(self, sock, data) -> bool:
        """Send a msgpack message through the given socket."""
        try:
            packed = msgpack.packb(data, use_bin_type=True)
            sock.sendall(struct.pack('!I', len(packed)) + packed)
            return True
        except Exception:
            # Error is logged by the caller if needed
            return False

    def _broadcast_message(self, data, exclude=None) -> None:
        """Broadcast a message to all connected clients."""
        to_remove = []
        packed = msgpack.packb(data, use_bin_type=True)
        for s in list(self.client_sockets):
            if s is exclude:
                continue
            if not self._send_message(s, data):
                 to_remove.append(s)

        for s in to_remove:
            self._remove_client(s, reason="broadcast failed")

    def _remove_client(self, sock, reason: str = "") -> None:
        """Safely remove a client socket and update state."""
        client_name = self.client_infos.get(sock, "<unknown>")
        logging.warning("Kliens eltávolítva: %s. Ok: %s", client_name, reason or "kapcsolat bontva")
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
                self.deactivate_kvm(reason="aktív kliens lecsatlakozott")

    def _clipboard_loop_server(self) -> None:
        while self._running:
            text_to_send = None
            try:
                current_text = self._get_clipboard()
                with self.clipboard_lock:
                    if current_text != self.last_clipboard:
                        self.last_clipboard = current_text
                        text_to_send = current_text
            except Exception as e:
                logging.error("Hiba a szerver vágólap olvasásakor: %s", e)

            if text_to_send is not None:
                self._broadcast_message({'type': 'clipboard_text', 'text': text_to_send})
            time.sleep(0.5)

    def _clipboard_loop_client(self, sock) -> None:
        while self._running and self.server_socket is sock:
            text_to_send = None
            try:
                current_text = self._get_clipboard()
                with self.clipboard_lock:
                    if current_text != self.last_clipboard:
                        self.last_clipboard = current_text
                        text_to_send = current_text
            except Exception as e:
                logging.error("Hiba a kliens vágólap olvasásakor: %s", e)

            if text_to_send is not None:
                self._send_message(sock, {'type': 'clipboard_text', 'text': text_to_send})
            time.sleep(0.5)


    def set_active_client_by_name(self, name):
        """Select a connected client by name as the active target."""
        for sock, cname in self.client_infos.items():
            if cname.lower().startswith(name.lower()):
                self.active_client = sock
                logging.info(f"Aktív kliens beállítva: {cname}")
                return True
        logging.warning(f"Nincs kliens '{name}' névvel")
        return False

    def toggle_client_control(self, name: str, *, switch_monitor: bool = True, release_keys: bool = True) -> None:
        """Activate or deactivate control for a specific client."""
        current = self.client_infos.get(self.active_client, "").lower()
        target = name.lower()

        if self.kvm_active and current.startswith(target):
            logging.debug("Cél ugyanaz, mint az aktív kliens -> deaktiválás")
            self.deactivate_kvm(release_keys=release_keys, reason="toggle same client")
            return
        if self.kvm_active:
            logging.debug("Váltás előtt a jelenlegi KVM session deaktiválása")
            self.deactivate_kvm(release_keys=release_keys, reason="switching client")

        if self.set_active_client_by_name(name):
            logging.debug("KVM aktiválása a(z) %s kliensnek", name)
            self.activate_kvm(switch_monitor=switch_monitor)

    def stop(self):
        logging.info("stop() metódus meghívva.")
        self._running = False
        if self.kvm_active:
            self.deactivate_kvm(switch_monitor=False, reason="stop() called")
        else:
            self._stop_hotkey_listener()
        
        try:
            self.zeroconf.close()
        except:
            pass
        
        # Close all sockets
        for sock in list(self.client_sockets):
            self._remove_client(sock, "application stopping")
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        
        if self.connection_thread and self.connection_thread.is_alive():
            self.connection_thread.join(timeout=1)
        if self.clipboard_thread and self.clipboard_thread.is_alive():
            self.clipboard_thread.join(timeout=1)
        
        self.release_hotkey_keys()
        self._clear_network_file_clipboard()
        self.finished.emit()


    def run(self):
        logging.info(f"Worker elindítva {self.settings['role']} módban.")
        self.release_hotkey_keys()
        if self.settings['role'] == 'ado':
            self.run_server()
        else:
            self.run_client()
        logging.info("Worker futása befejeződött.")

    def activate_kvm(self, switch_monitor=True):
        if not self.active_client:
            self.status_update.emit("Hiba: Nincs aktív kliens a váltáshoz!")
            logging.warning("Váltási kísérlet aktív kliens nélkül.")
            return

        logging.info("KVM aktiválása. Cél: %s", self.client_infos.get(self.active_client, "ismeretlen"))
        self._stop_hotkey_listener() # <-- KEY CHANGE
        
        self.switch_monitor = switch_monitor
        self.kvm_active = True
        self.status_update.emit(f"Állapot: Aktív - {self.client_infos.get(self.active_client)}")
        
        self.streaming_thread = threading.Thread(target=self._streaming_loop, daemon=True, name="StreamingThread")
        self.streaming_thread.start()

    def _streaming_loop(self):
        """Keep streaming active and restart if it stops unexpectedly."""
        while self.kvm_active and self._running:
            stream_inputs(self)
            if self.kvm_active and self._running:
                logging.warning("Input streaming megszakadt, újraindítás...")
                time.sleep(0.5)

    def deactivate_kvm(
        self,
        switch_monitor=None,
        *,
        release_keys: bool = True,
        reason: Optional[str] = None,
    ):
        logging.info("KVM deaktiválása. Ok: %s", reason or "ismeretlen")
        self.kvm_active = False

        if self.streaming_thread and self.streaming_thread.is_alive():
            logging.debug("Várakozás a streaming szál leállására...")
            self.streaming_thread.join(timeout=1.0)
        self.streaming_thread = None

        switch = switch_monitor if switch_monitor is not None else self.switch_monitor
        if switch:
            time.sleep(0.2)
            try:
                with list(get_monitors())[0] as monitor:
                    monitor.set_input_source(self.settings['monitor_codes']['host'])
                    logging.info("Monitor sikeresen visszaváltva a hosztra.")
            except Exception as e:
                msg = f"Monitor hiba: {e}"
                self.status_update.emit(msg)
                logging.error(msg, exc_info=True)

        if release_keys:
            self.release_hotkey_keys()

        if hasattr(self, '_host_mouse_controller') and self._host_mouse_controller:
            try:
                if self._orig_mouse_pos:
                    self._host_mouse_controller.position = self._orig_mouse_pos
            except Exception: pass
            self._host_mouse_controller = None
            self._orig_mouse_pos = None

        self.status_update.emit("Állapot: Inaktív. Várakozás gyorsbillentyűre.")
        
        if self._running:
            self._start_hotkey_listener() # <-- KEY CHANGE
        
        self.active_client = None
