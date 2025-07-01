# worker.py - VÉGLEGES JAVÍTOTT VERZIÓ
# Javítva: Streaming listener `AttributeError`, "sticky key" hiba, visszaváltási logika, egér-akadás.

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
        'clipboard_lock'
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
        # Active client connections (multiple receivers can connect)
        self.client_sockets = []
        # Mapping from socket to human readable client name
        self.client_infos = {}
        # Currently selected client to forward events to
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
        logging.debug("Network file clipboard cleared")
        self._cancel_transfer = threading.Event()
        self._host_mouse_controller = None
        self._orig_mouse_pos = None

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

    # ------------------------------------------------------------------
    # Clipboard utilities
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # Network helpers
    # ------------------------------------------------------------------
    def _send_message(self, sock, data) -> bool:
        """Send a msgpack message through the given socket."""
        try:
            packed = msgpack.packb(data, use_bin_type=True)
            sock.sendall(struct.pack('!I', len(packed)) + packed)
            return True
        except Exception as e:
            logging.error("Failed to send message: %s", e, exc_info=True)
            return False

    def _broadcast_message(self, data, exclude=None) -> None:
        """Broadcast a message to all connected clients."""
        packed = msgpack.packb(data, use_bin_type=True)
        for s in list(self.client_sockets):
            if s is exclude:
                continue
            try:
                s.sendall(struct.pack('!I', len(packed)) + packed)
            except Exception as e:
                logging.error("Failed to broadcast message: %s", e)

    # ------------------------------------------------------------------
    # Clipboard synchronization
    # ------------------------------------------------------------------
    def _clipboard_loop_server(self) -> None:
        while self._running:
            text = self._get_clipboard()
            send_needed = False
            with self.clipboard_lock:
                if text != self.last_clipboard:
                    self.last_clipboard = text
                    send_needed = True
            if send_needed:
                self._broadcast_message({'type': 'clipboard_text', 'text': text})
            time.sleep(0.5)

    def _clipboard_loop_client(self, sock) -> None:
        while self._running and self.server_socket is sock:
            text = self._get_clipboard()
            send_needed = False
            with self.clipboard_lock:
                if text != self.last_clipboard:
                    self.last_clipboard = text
                    send_needed = True
            if send_needed:
                self._send_message(sock, {'type': 'clipboard_text', 'text': text})
            time.sleep(0.5)


    def set_active_client_by_name(self, name):
        """Select a connected client by name as the active target."""
        logging.debug(f"set_active_client_by_name called with name={name}")
        for sock, cname in self.client_infos.items():
            if cname.lower().startswith(name.lower()):
                self.active_client = sock
                logging.info(f"Active client set to {cname}")
                return True
        logging.warning(f"No client matching '{name}' found")
        return False

    def toggle_client_control(self, name: str, *, switch_monitor: bool = True, release_keys: bool = True) -> None:
        """Activate or deactivate control for a specific client."""
        current = self.client_infos.get(self.active_client, "").lower()
        target = name.lower()
        logging.info(
            "toggle_client_control start: target=%s current=%s kvm_active=%s switch_monitor=%s",
            target,
            current,
            self.kvm_active,
            switch_monitor,
        )
        if self.kvm_active and current.startswith(target):
            logging.debug("Deactivating KVM because active client matches target")
            self.deactivate_kvm(release_keys=release_keys, reason="toggle_client_control same client")
            self.active_client = None
            return
        if self.kvm_active:
            logging.debug("Deactivating current KVM session before switching client")
            self.deactivate_kvm(release_keys=release_keys, reason="toggle_client_control switch")
            self.active_client = None
        if self.set_active_client_by_name(name):
            logging.debug("Activating KVM for client %s", name)
            self.activate_kvm(switch_monitor=switch_monitor)
        logging.info("toggle_client_control end")

    def stop(self):
        logging.info("stop() metódus meghívva.")
        self._running = False
        if self.kvm_active:
            self.deactivate_kvm(switch_monitor=False, reason="stop() called")  # Leállításkor ne váltson monitort
        try:
            self.zeroconf.close()
        except:
            pass
        for listener in self.pynput_listeners:
            try:
                listener.stop()
            except:
                pass
        for sock in list(getattr(self, 'client_sockets', [])):
            try:
                sock.close()
            except Exception:
                pass
        self.client_infos.clear()
        self.active_client = None
        if self.connection_thread and self.connection_thread.is_alive():
            self.connection_thread.join(timeout=1)
        if self.clipboard_thread and self.clipboard_thread.is_alive():
            self.clipboard_thread.join(timeout=1)
        # Extra safety to avoid stuck modifier keys on exit
        self.release_hotkey_keys()
        self._clear_network_file_clipboard()

    def run(self):
        logging.info(f"Worker elindítva {self.settings['role']} módban.")
        # Ensure no stuck modifier keys remain from a previous run
        self.release_hotkey_keys()
        if self.settings['role'] == 'ado':
            self.run_server()
        else:
            self.run_client()
        self.finished.emit()

    def toggle_kvm_active(self, switch_monitor=True):
        """Toggle KVM state with optional monitor switching."""
        logging.info(
            "toggle_kvm_active called. current_state=%s switch_monitor=%s active_client=%s",
            self.kvm_active,
            switch_monitor,
            self.client_infos.get(self.active_client),
        )
        if self.active_client is None:
            logging.warning("toggle_kvm_active invoked with no active_client")
        if not self.kvm_active:
            self.activate_kvm(switch_monitor=switch_monitor)
        else:
            self.deactivate_kvm(switch_monitor=switch_monitor, reason="toggle_kvm_active")
        self.release_hotkey_keys()

    def activate_kvm(self, switch_monitor=True):
        logging.info(
            "activate_kvm called. switch_monitor=%s active_client=%s",
            switch_monitor,
            self.client_infos.get(self.active_client, "unknown"),
        )
        if not self.client_sockets:
            self.status_update.emit("Hiba: Nincs csatlakozott kliens a váltáshoz!")
            logging.warning("Váltási kísérlet kliens kapcsolat nélkül.")
            return

        self.switch_monitor = switch_monitor
        self.kvm_active = True
        self.status_update.emit("Állapot: Aktív...")
        logging.info("KVM aktiválva.")
        self.streaming_thread = threading.Thread(target=self._streaming_loop, daemon=True, name="StreamingThread")
        self.streaming_thread.start()
        logging.debug("Streaming thread started")

    def _streaming_loop(self):
        """Keep streaming active and restart if it stops unexpectedly."""
        while self.kvm_active and self._running:
            stream_inputs(self)
            if self.kvm_active and self._running:
                logging.warning("Egér szinkronizáció megszakadt, újraindítás...")
                time.sleep(1)

    def deactivate_kvm(
        self,
        switch_monitor=None,
        *,
        release_keys: bool = True,
        reason: Optional[str] = None,
    ):
        if reason:
            logging.info(
                "deactivate_kvm called. reason=%s switch_monitor=%s kvm_active=%s active_client=%s",
                reason,
                switch_monitor,
                self.kvm_active,
                self.client_infos.get(self.active_client),
            )
        else:
            logging.info(
                "deactivate_kvm called. switch_monitor=%s kvm_active=%s active_client=%s",
                switch_monitor,
                self.kvm_active,
                self.client_infos.get(self.active_client),
            )
        self.kvm_active = False
        self.status_update.emit("Állapot: Inaktív...")
        logging.info("KVM deaktiválva.")

        # A monitor visszaváltást a toggle metódus végzi, miután a streaming szál leállt
        switch = switch_monitor if switch_monitor is not None else getattr(self, 'switch_monitor', True)
        if switch:
            # Itt egy kis időt adunk a streaming szálnak a leállásra, mielőtt váltunk
            time.sleep(0.2)
            try:
                with list(get_monitors())[0] as monitor:
                    monitor.set_input_source(self.settings['monitor_codes']['host'])
                    logging.info("Monitor sikeresen visszaváltva a hosztra.")
            except Exception as e:
                self.status_update.emit(f"Monitor hiba: {e}")
                logging.error(f"Monitor hiba: {e}", exc_info=True)
        # Ensure hotkey keys are released when deactivating if requested
        if release_keys:
            self.release_hotkey_keys()

        if hasattr(self, '_host_mouse_controller') and hasattr(self, '_orig_mouse_pos'):
            try:
                self._host_mouse_controller.position = self._orig_mouse_pos
            except Exception as e:
                logging.error(f"Failed to restore mouse position: {e}", exc_info=True)
            self._host_mouse_controller = None
            self._orig_mouse_pos = None

        # Connection state handling is now performed by toggle_client_control
