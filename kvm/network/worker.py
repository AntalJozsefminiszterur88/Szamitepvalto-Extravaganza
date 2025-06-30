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
import shutil
import tempfile
import zipfile
from typing import Optional
import msgpack
import pyperclip
from pynput import mouse, keyboard
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser
from .networking import accept_connections, KVMServiceListener, set_worker_reference
from monitorcontrol import get_monitors
from PySide6.QtCore import QObject, Signal, QSettings
from ..input.hotkey_manager import HotkeyManager
from ..input.input_streamer import InputStreamer
from .file_sender import FileSender
from ..input.input_receiver import InputReceiver
from ..config import (
    SERVICE_TYPE,
    SERVICE_NAME_PREFIX,
    APP_NAME,
    ORG_NAME,
    BRAND_NAME,
    TEMP_DIR_PARTS,
    VK_CTRL,
    VK_CTRL_R,
    VK_NUMPAD0,
    VK_NUMPAD1,
    VK_NUMPAD2,
    VK_F12,
    VK_LSHIFT,
    VK_RSHIFT,
)

# Delay between iterations in the streaming loop to lower CPU usage
STREAM_LOOP_DELAY = 0.05
# Maximum number of events queued for sending before old ones are dropped
SEND_QUEUE_MAXSIZE = 200
# File transfer chunk size
FILE_CHUNK_SIZE = 65536
# Socket timeout (seconds) during file transfers
TRANSFER_TIMEOUT = 30
# Minimum delay between progress updates
PROGRESS_UPDATE_INTERVAL = 0.5


def get_local_ip() -> str:
    """Return the primary local IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return socket.gethostbyname(socket.gethostname())


class KVMWorker(QObject):
    __slots__ = (
        'settings', '_running', 'kvm_active', 'client_sockets', 'client_infos',
        'active_client', 'pynput_listeners', 'zeroconf', 'input_streamer',
        'switch_monitor', 'local_ip', 'server_ip',
        'device_name', 'clipboard_thread', 'last_clipboard', 'server_socket',
        'network_file_clipboard', '_cancel_transfer', 'last_server_ip',
        'hotkey_manager', 'file_sender', 'input_receiver'
    )

    finished = Signal()
    status_update = Signal(str)
    update_progress_display = Signal(int, str)  # percentage, label text
    file_transfer_error = Signal(str)

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
        self.input_streamer = InputStreamer(self)
        self.file_sender = FileSender(self)
        self.input_receiver = InputReceiver()
        self.switch_monitor = True
        self.local_ip = get_local_ip()
        self.server_ip = None
        settings_store = QSettings(ORG_NAME, APP_NAME)
        self.last_server_ip = settings_store.value('network/last_server_ip', None)
        self.device_name = settings.get('device_name', socket.gethostname())
        self.clipboard_thread = None
        self.last_clipboard = ""
        self.server_socket = None
        self.network_file_clipboard = None
        logging.debug("Network file clipboard cleared")
        self._cancel_transfer = threading.Event()
        self._host_mouse_controller = None
        self._orig_mouse_pos = None
        set_worker_reference(self)
        self.hotkey_manager = HotkeyManager(self)

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
        try:
            pyperclip.copy(text)
            self.last_clipboard = text
        except Exception as e:
            logging.error("Failed to set clipboard: %s", e)

    def _get_clipboard(self) -> str:
        """Safely read the system clipboard."""
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
            if text != self.last_clipboard:
                self.last_clipboard = text
                self._broadcast_message({'type': 'clipboard_text', 'text': text})
            time.sleep(0.5)

    def _clipboard_loop_client(self, sock) -> None:
        while self._running and self.server_socket is sock:
            text = self._get_clipboard()
            if text != self.last_clipboard:
                self.last_clipboard = text
                self._send_message(sock, {'type': 'clipboard_text', 'text': text})
            time.sleep(0.5)

    # ------------------------------------------------------------------
    # File transfer helpers
    # ------------------------------------------------------------------
    def _get_temp_dir(self) -> str:
        """
        Creates and returns the path to a dedicated temporary directory for the app.
        Uses the custom path from settings if available, otherwise the system default.
        """
        base_path = self.settings.get('temp_path') or tempfile.gettempdir()

        # Construct the root path for all temporary files using the configured
        # drive and the constant directory structure.
        app_temp_path = os.path.join(base_path, *TEMP_DIR_PARTS)

        try:
            os.makedirs(app_temp_path, exist_ok=True)
            transfer_temp_dir = tempfile.mkdtemp(dir=app_temp_path)
            logging.info(f"Using temporary directory: {transfer_temp_dir}")
            return transfer_temp_dir
        except OSError as e:
            logging.error(
                f"Could not create temporary directory at {app_temp_path}: {e}. Falling back to system default."
            )
            return tempfile.mkdtemp()


    def _safe_extract_archive(self, archive_path, dest_dir):
        """Extract archive to dest_dir and cleanup on failure."""
        temp_extract = tempfile.mkdtemp(dir=dest_dir)
        logging.debug("Created temporary extract dir %s", temp_extract)
        try:
            with zipfile.ZipFile(archive_path, 'r') as zf:
                zf.extractall(temp_extract)
            if self._cancel_transfer.is_set():
                raise RuntimeError('transfer canceled')
            for name in os.listdir(temp_extract):
                source_path = os.path.join(temp_extract, name)
                target_path_base = os.path.join(dest_dir, name)

                # --- START NEW FILENAME CONFLICT LOGIC ---
                final_target_path = target_path_base
                counter = 2
                base, ext = os.path.splitext(name)

                while os.path.exists(final_target_path):
                    if ext:
                        new_name = f"{base} ({counter}){ext}"
                    else:
                        new_name = f"{name} ({counter})"
                    final_target_path = os.path.join(dest_dir, new_name)
                    counter += 1

                if final_target_path != target_path_base:
                    logging.info(
                        f"Filename conflict: '{target_path_base}' exists. Renaming to '{final_target_path}'"
                    )
                # --- END NEW FILENAME CONFLICT LOGIC ---

                shutil.move(source_path, final_target_path)
        except Exception:
            shutil.rmtree(temp_extract, ignore_errors=True)
            logging.debug("Extraction failed, removed %s", temp_extract)
            raise
        else:
            shutil.rmtree(temp_extract, ignore_errors=True)
            logging.debug("Extraction complete, removed %s", temp_extract)


    def _clear_network_file_clipboard(self):
        """Remove any stored temporary archive and clear the clipboard info."""
        if self.network_file_clipboard and self.network_file_clipboard.get('archive'):
            try:
                os.remove(self.network_file_clipboard['archive'])
                logging.debug(
                    "Removed temporary archive %s", self.network_file_clipboard['archive']
                )
            except FileNotFoundError:
                pass
            except Exception as e:
                logging.error(
                    "Failed to remove temporary archive %s: %s",
                    self.network_file_clipboard['archive'],
                    e,
                )
        self.network_file_clipboard = None
        logging.debug("Network file clipboard cleared")

    def cancel_file_transfer(self):
        """Signal ongoing file transfer loops to cancel."""
        self._cancel_transfer.set()
        logging.debug("File transfer cancel signal set")

    # ------------------------------------------------------------------
    # Public API used by the GUI
    # ------------------------------------------------------------------
    def share_files(self, paths, operation='copy') -> None:
        threading.Thread(target=self._share_files_thread, args=(paths, operation), daemon=True).start()

    def _share_files_thread(self, paths, operation):
        self._cancel_transfer.clear()
        logging.debug(
            "Entering _share_files_thread. Cancel flag: %s",
            self._cancel_transfer.is_set(),
        )
        logging.debug("Cancel flag cleared at start of _share_files_thread")
        if self.settings['role'] != 'ado':
            sock = self.server_socket
            if not sock:
                logging.warning('No server connection for file share')
                self.file_transfer_error.emit("Nincs kapcsolat a szerverrel a küldéshez.")
                return
            self.file_sender.send_files(paths, operation, sock)
            return
        timeout = self.settings.get('archive_timeout_seconds', 900)
        cancel_evt = threading.Event()
        result = {}
        temp_archive_dir = None

        def run_archiving():
            result['archive'] = self.file_sender._create_archive(paths, cancel_event=cancel_evt)

        arch_thread = threading.Thread(target=run_archiving, daemon=True)
        arch_thread.start()
        arch_thread.join(timeout)
        if arch_thread.is_alive():
            cancel_evt.set()
            arch_thread.join(5)
            logging.critical(
                "Archiving of %s timed out after %.1f minutes.",
                paths,
                timeout / 60,
            )
            self.file_transfer_error.emit("Archiv\xe1l\xe1s id\u0151t\xfall\xe9p\xe9s (t\xfal nagy f\xe1jl?)")
            if result.get('archive'):
                shutil.rmtree(os.path.dirname(result['archive']), ignore_errors=True)
            return
        archive = result.get('archive')
        try:
            if not archive:
                self._clear_network_file_clipboard()
                logging.debug("Archive creation failed, exiting _share_files_thread")
                return

            temp_archive_dir = os.path.dirname(archive)
            if self.settings['role'] == 'ado':
                self._clear_network_file_clipboard()
                self.network_file_clipboard = {
                    'paths': paths,
                    'operation': operation,
                    'archive': archive,
                    'source_id': self.device_name,
                }
                logging.debug(
                    "Network file clipboard set: %s", self.network_file_clipboard
                )
                self._broadcast_message({
                    'type': 'network_clipboard_set',
                    'source_id': self.device_name,
                    'operation': operation,
                })
            else:
                pass  # client-side handled earlier
        finally:
            if temp_archive_dir and self.settings['role'] != 'ado':
                logging.info(f"Client-side cleanup: Removing temporary archive directory {temp_archive_dir}")
                shutil.rmtree(temp_archive_dir, ignore_errors=True)
            self._cancel_transfer.clear()
            logging.debug(
                "Exiting _share_files_thread. Network clipboard: %s",
                self.network_file_clipboard,
            )

    def request_paste(self, dest_dir) -> None:
        self._cancel_transfer.clear()
        logging.debug(
            "request_paste called. role=%s cancel=%s",
            self.settings['role'],
            self._cancel_transfer.is_set(),
        )
        logging.debug("Cancel flag cleared at start of request_paste")
        if self.settings['role'] == 'ado':
            if not self.network_file_clipboard or not self.network_file_clipboard.get('archive'):
                logging.warning('No shared files to paste')
                return
            try:
                archive_name = os.path.basename(self.network_file_clipboard['archive']) if self.network_file_clipboard and self.network_file_clipboard.get('archive') else "archívum"
                logging.info("[WORKER_DEBUG] Starting server-side paste (extraction) for: %s", archive_name)
                self.update_progress_display.emit(0, f"Kibontás: {archive_name}")
                self._safe_extract_archive(self.network_file_clipboard['archive'], dest_dir)
                logging.info("[WORKER_DEBUG] Server-side paste (extraction) COMPLETED for: %s", archive_name)
                self.update_progress_display.emit(100, f"{archive_name}: Feldolgozás kész!")
            except Exception as e:
                logging.error('Extraction failed: %s', e, exc_info=True)
                logging.error('[WORKER_DEBUG] Server-side paste (extraction) FAILED for: %s. Error: %s', archive_name, e)
                self.file_transfer_error.emit(f"Kibontási hiba: {e}")
                return
            if self.network_file_clipboard.get('operation') == 'cut':
                src_id = self.network_file_clipboard.get('source_id')
                if src_id == self.device_name:
                    for pth in self.network_file_clipboard.get('paths', []):
                        try:
                            if os.path.isdir(pth):
                                shutil.rmtree(pth)
                            else:
                                os.remove(pth)
                        except Exception as e:
                            logging.error('Failed to delete %s: %s', pth, e)
                    self._clear_network_file_clipboard()
                else:
                    for s, name in self.client_infos.items():
                        if name == src_id:
                            self._send_message(s, {'type': 'delete_source', 'paths': self.network_file_clipboard.get('paths', [])})
                            break
                    self._clear_network_file_clipboard()
        else:
            sock = self.server_socket
            if sock:
                logging.debug("Sending paste_request to server")
                self._send_message(sock, {'type': 'paste_request', 'destination': dest_dir})
        logging.debug("request_paste completed. cancel=%s", self._cancel_transfer.is_set())
        self._cancel_transfer.clear()
        logging.debug("Cancel flag cleared at end of request_paste")

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
            return
        if self.kvm_active:
            logging.debug("Deactivating current KVM session before switching client")
            self.deactivate_kvm(release_keys=release_keys, reason="toggle_client_control switch")
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
        # Stop global hotkey listener
        try:
            self.hotkey_manager.stop()
        except Exception:
            pass
        for sock in list(getattr(self, 'client_sockets', [])):
            try:
                sock.close()
            except Exception:
                pass
        self.client_infos.clear()
        self.active_client = None
        if self.clipboard_thread and self.clipboard_thread.is_alive():
            self.clipboard_thread.join(timeout=1)
        # Extra safety to avoid stuck modifier keys on exit
        self.release_hotkey_keys()
        self._clear_network_file_clipboard()
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None

    def run(self):
        logging.info(f"Worker elindítva {self.settings['role']} módban.")
        if self.settings['role'] == 'ado':
            self.run_server()
        else:
            self.run_client()
        self.finished.emit()

    def run_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.server_socket.bind(('', self.settings['port']))
        self.server_socket.listen(5)
        logging.info(f"TCP szerver elindítva a {self.settings['port']} porton.")

        accept_thread = threading.Thread(
            target=accept_connections,
            args=(self.server_socket,),
            daemon=True,
            name="AcceptThread"
        )
        accept_thread.start()

        self.clipboard_thread = threading.Thread(
            target=self._clipboard_loop_server, daemon=True, name="ClipboardSrv"
        )
        self.clipboard_thread.start()
        
        info = ServiceInfo(
            SERVICE_TYPE,
            f"{SERVICE_NAME_PREFIX}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(self.local_ip)],
            port=self.settings['port']
        )
        self.zeroconf.register_service(info)
        self.status_update.emit(
            "Adó szolgáltatás regisztrálva. Gyorsbillentyűk: "
            "Asztal - Shift + Numpad 0, Laptop - Shift + Numpad 1, "
            "ElitDesk - Shift + Numpad 2"
        )
        logging.info("Zeroconf szolgáltatás regisztrálva.")

        # Start global hotkey monitoring
        self.hotkey_manager.start()

        while self._running:
            time.sleep(0.5)
        
        logging.info("Adó szolgáltatás leállt.")

    def accept_connections(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                server_socket.bind(('', self.settings['port']))
                server_socket.listen(5)
                logging.info(f"TCP szerver elindítva a {self.settings['port']} porton.")

                while self._running:
                    client_sock, addr = server_socket.accept()
                    client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    self.client_sockets.append(client_sock)
                    if self.active_client is None:
                        self.active_client = client_sock
                    logging.info(f"Kliens csatlakozva: {addr}.")
                    self.status_update.emit(f"Kliens csatlakozva: {addr}. Várakozás gyorsbillentyűre.")

                    threading.Thread(target=self.monitor_client, args=(client_sock, addr), daemon=True).start()
        except Exception as e:
            if self._running:
                logging.error(f"Hiba a kliens fogadásakor: {e}", exc_info=True)

    def monitor_client(self, sock, addr):
        """Monitor a single client connection, handle commands and remove it on disconnect."""
        sock.settimeout(30.0)
        buffer = b''

        def recv_all(s, n):
            data = b''
            while len(data) < n:
                chunk = s.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
            return data

        # Expect an initial handshake with the client name
        client_name = str(addr)
        try:
            raw_len = recv_all(sock, 4)
            if raw_len:
                msg_len = struct.unpack('!I', raw_len)[0]
                payload = recv_all(sock, msg_len)
                if payload:
                    hello = msgpack.unpackb(payload, raw=False)
                    client_name = hello.get('device_name', client_name)
        except Exception:
            pass
        self.client_infos[sock] = client_name
        logging.info(f"Client connected: {client_name} ({addr})")
        logging.debug(
            "monitor_client start for %s cancel=%s",
            client_name,
            self._cancel_transfer.is_set(),
        )
        # send current clipboard to newly connected client
        if self.last_clipboard:
            try:
                self._send_message(sock, {'type': 'clipboard_text', 'text': self.last_clipboard})
            except Exception:
                pass
        upload_info = None

        try:
            last_log = time.time()
            while self._running:
                if time.time() - last_log >= 10:
                    logging.debug(
                        "monitor_client main loop. cancel=%s received=%d",
                        self._cancel_transfer.is_set(),
                        upload_info['received'] if upload_info else 0,
                    )
                    last_log = time.time()
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buffer += chunk
                    while len(buffer) >= 4:
                        msg_len = struct.unpack('!I', buffer[:4])[0]
                        if len(buffer) < 4 + msg_len:
                            break
                        payload = buffer[4:4 + msg_len]
                        buffer = buffer[4 + msg_len:]
                        try:
                            data = msgpack.unpackb(payload, raw=False)
                            cmd = data.get('command')
                            if cmd == 'switch_elitedesk':
                                self.toggle_client_control('elitedesk', switch_monitor=True)
                            elif cmd == 'switch_laptop':
                                self.toggle_client_control('laptop', switch_monitor=False)
                            elif data.get('type') == 'clipboard_text':
                                text = data.get('text', '')
                                if text != self.last_clipboard:
                                    self._set_clipboard(text)
                                    self._broadcast_message(data, exclude=sock)
                            elif data.get('type') == 'paste_request':
                                dest = data.get('destination')
                                if self.network_file_clipboard and self.network_file_clipboard.get('archive'):
                                    self._cancel_transfer.clear()
                                    logging.debug("Cancel flag cleared for paste_request")
                                    self.file_sender._send_archive(sock, self.network_file_clipboard['archive'], dest)
                            elif data.get('type') == 'file_metadata':
                                logging.info("[WORKER_DEBUG] Received 'upload_file_start' from client: %s (size: %s)", data.get('name'), data.get('size'))
                                temp_dir_for_download = self._get_temp_dir()
                                incoming_path = os.path.join(temp_dir_for_download, data['name'])
                                self._clear_network_file_clipboard()
                                try:
                                    incoming_file = open(incoming_path, 'wb')
                                except Exception as e:
                                    logging.error('Failed to open incoming file: %s', e, exc_info=True)
                                    self.file_transfer_error.emit(str(e))
                                    self._clear_network_file_clipboard()
                                    break
                                self._cancel_transfer.clear()
                                logging.debug("Receiving upload, cancel flag cleared")
                                sock.settimeout(TRANSFER_TIMEOUT)
                                upload_info = {
                                    'file': incoming_file,
                                    'path': incoming_path,
                                    'temp_dir': temp_dir_for_download,
                                    'paths': data.get('paths', []),
                                    'operation': data.get('operation', 'copy'),
                                    'size': data.get('size', 0),
                                    'name': data.get('name'),
                                    'source_id': data.get('source_id', client_name),
                                    'received': 0,
                                    'start_time': time.time(),
                                }
                                last_percentage = -1
                                last_emit_time = time.time()
                                # Start progress display at 0% using the safe signal
                                self.update_progress_display.emit(0, f"{upload_info['name']}: 0MB / {upload_info['size']/1024/1024:.1f}MB")
                            elif data.get('type') == 'file_chunk':
                                if upload_info:
                                    try:
                                        upload_info['file'].write(data['data'])
                                        upload_info['received'] += len(data['data'])
                                        if time.time() - last_emit_time >= PROGRESS_UPDATE_INTERVAL:
                                            current_percentage = int((upload_info['received'] / upload_info['size']) * 100) if upload_info['size'] > 0 else 0

                                            # --- Speed and ETR Calculation ---
                                            elapsed_time = time.time() - upload_info['start_time']
                                            speed_mbps = (upload_info['received'] / (1024*1024)) / elapsed_time if elapsed_time > 0 else 0
                                            remaining_bytes = upload_info['size'] - upload_info['received']
                                            etr_seconds = int(remaining_bytes / (speed_mbps * 1024 * 1024)) if speed_mbps > 0 else 0
                                            etr_str = time.strftime('%M:%S', time.gmtime(etr_seconds)) if etr_seconds < 3600 else time.strftime('%H:%M:%S', time.gmtime(etr_seconds))

                                            label = f"{upload_info['name']}: {upload_info['received']/1024/1024:.1f}MB / {upload_info['size']/1024/1024:.1f}MB\n"
                                            label += f"Sebesség: {speed_mbps:.1f} MB/s | Hátralévő idő: {etr_str}"

                                            self.update_progress_display.emit(current_percentage, label)
                                            last_percentage = current_percentage
                                            last_emit_time = time.time()
                                        if self._cancel_transfer.is_set():
                                            break
                                    except Exception as e:
                                        logging.error('Error writing chunk: %s', e, exc_info=True)
                                        self.file_transfer_error.emit(str(e))
                                        self._clear_network_file_clipboard()
                                        self._cancel_transfer.set()
                                        break
                            elif data.get('type') == 'file_end':
                                if upload_info:
                                    logging.info(
                                        "[WORKER_DEBUG] Received 'upload_file_end' for: %s",
                                        upload_info['name'],
                                    )
                                    upload_info['file'].close()
                                    final_label = f"{upload_info['name']}: Kész! ({upload_info['size']/1024/1024:.1f}MB)"
                                    self.update_progress_display.emit(100, final_label)
                                    self._clear_network_file_clipboard()
                                    self.network_file_clipboard = {
                                        'paths': upload_info['paths'],
                                        'operation': upload_info['operation'],
                                        'archive': upload_info['path'],
                                        'source_id': upload_info.get('source_id', client_name),
                                    }
                                    logging.debug(
                                        "Network file clipboard set: %s", self.network_file_clipboard
                                    )
                                    self._broadcast_message({
                                        'type': 'network_clipboard_set',
                                        'source_id': upload_info.get('source_id', client_name),
                                        'operation': upload_info['operation'],
                                    }, exclude=sock)
                                    upload_info = None
                                    sock.settimeout(1.0)
                                    self._cancel_transfer.clear()
                                    logging.debug("Upload finished, cancel flag cleared")
                            elif data.get('type') == 'paste_success':
                                src = data.get('source_id')
                                if (
                                    self.network_file_clipboard
                                    and self.network_file_clipboard.get('operation') == 'cut'
                                    and self.network_file_clipboard.get('source_id') == src
                                ):
                                    if src == self.device_name:
                                        for pth in self.network_file_clipboard.get('paths', []):
                                            try:
                                                if os.path.isdir(pth):
                                                    shutil.rmtree(pth)
                                                else:
                                                    os.remove(pth)
                                            except Exception as e:
                                                logging.error("Failed to delete %s: %s", pth, e)
                                        self._clear_network_file_clipboard()
                                    else:
                                        for s2, n2 in self.client_infos.items():
                                            if n2 == src:
                                                self._send_message(s2, {
                                                    'type': 'delete_source',
                                                    'paths': self.network_file_clipboard.get('paths', []),
                                                })
                                                break
                                        self._clear_network_file_clipboard()
                            if self._cancel_transfer.is_set():
                                if upload_info:
                                    try:
                                        upload_info['file'].close()
                                        os.remove(upload_info['path'])
                                    except Exception:
                                        pass
                                    upload_info = None
                                self._clear_network_file_clipboard()
                                sock.settimeout(1.0)
                                self._cancel_transfer.clear()
                                logging.debug("Upload canceled or finished, cancel flag cleared")
                        except Exception:
                            logging.warning("Hibas parancs a klienstol")
                except socket.timeout:
                    continue
                except (socket.error, BrokenPipeError):
                    break
        finally:
            logging.warning(f"Kliens lecsatlakozott: {addr}.")
            try:
                sock.close()
            except Exception:
                pass
            if upload_info and upload_info.get('temp_dir'):
                logging.warning("Cleaning up incomplete download directory: %s", upload_info['temp_dir'])
                try:
                    upload_info['file'].close()
                except Exception:
                    pass
                shutil.rmtree(upload_info['temp_dir'], ignore_errors=True)
            upload_info = None
            self._cancel_transfer.clear()
            self._clear_network_file_clipboard()
            if sock in self.client_sockets:
                self.client_sockets.remove(sock)
            if sock in self.client_infos:
                del self.client_infos[sock]
            if sock == self.active_client:
                self.active_client = None
            if self.kvm_active and not self.client_sockets:
                self.deactivate_kvm(reason="all clients disconnected")
            logging.debug("monitor_client exit for %s", client_name)

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
        self.input_streamer.start()
        logging.debug("Streaming started")


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

        # Stop input streaming listeners
        self.input_streamer.stop()

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

        if self.active_client not in self.client_sockets:
            if self.active_client is not None:
                logging.warning("Active client disconnected during deactivation")
            else:
                logging.debug("No active client set after deactivation")
            if self.client_sockets:
                self.active_client = self.client_sockets[0]
                logging.info("Reselected active client: %s", self.client_infos.get(self.active_client))
            else:
                self.active_client = None
    

    def run_client(self):
        listener = KVMServiceListener(self)
        ServiceBrowser(self.zeroconf, SERVICE_TYPE, listener)
        self.status_update.emit("Vevő mód: Keresem az Adó szolgáltatást...")
        while self._running:
            time.sleep(1)

    def connect_to_server(self, ip, port):
        hk_listener = None

        hb_thread = None  # Ensure heartbeat thread variable is always defined

        logging.debug(
            "connect_to_server attempting to connect to %s:%s cancel=%s",
            ip,
            port,
            self._cancel_transfer.is_set(),
        )

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    s.settimeout(5.0)
                    logging.info(f"Connecting to {ip}:{self.settings['port']}")
                    s.connect((ip, self.settings['port']))
                    s.settimeout(None)
                    self.server_socket = s
                    settings_store = QSettings(ORG_NAME, APP_NAME)
                    settings_store.setValue('network/last_server_ip', ip)
                    self.last_server_ip = ip
                    incoming_info = None
                    self._cancel_transfer.clear()
                    logging.debug("Connected to server, cancel flag cleared")
                    logging.debug("Cancel flag state at connect: %s", self._cancel_transfer.is_set())

                    try:
                        hello = msgpack.packb({'device_name': self.device_name}, use_bin_type=True)
                        s.sendall(struct.pack('!I', len(hello)) + hello)
                        logging.debug("Handshake sent to server")
                    except Exception as e:
                        logging.error(f"Failed to send handshake: {e}")

                    self.clipboard_thread = threading.Thread(
                        target=self._clipboard_loop_client, args=(s,), daemon=True, name="ClipboardCli"
                    )
                    self.clipboard_thread.start()

                    logging.info("TCP kapcsolat sikeres.")
                    self.status_update.emit("Csatlakozva. Irányítás átvéve.")

                    def send_command(cmd):
                        try:
                            packed = msgpack.packb({'command': cmd}, use_bin_type=True)
                            s.sendall(struct.pack('!I', len(packed)) + packed)
                            logging.info(f"Command sent to server: {cmd}")
                        except Exception:
                            logging.error("Nem sikerult parancsot kuldeni", exc_info=True)

                    hotkey_cmd_l = {keyboard.Key.shift, keyboard.KeyCode.from_vk(VK_F12)}
                    hotkey_cmd_r = {keyboard.Key.shift_r, keyboard.KeyCode.from_vk(VK_F12)}

                    client_pressed_special_keys = set()
                    client_pressed_vk_codes = set()

                    def hk_press(key):
                        try:
                            client_pressed_vk_codes.add(key.vk)
                        except AttributeError:
                            client_pressed_special_keys.add(key)

                        combined_pressed = client_pressed_special_keys.union(
                            {keyboard.KeyCode.from_vk(vk) for vk in client_pressed_vk_codes}
                        )

                        if hotkey_cmd_l.issubset(combined_pressed) or hotkey_cmd_r.issubset(combined_pressed):
                            logging.info("Client hotkey (Shift+F12) detected, requesting switch_elitedesk")
                            send_command('switch_elitedesk')

                    def hk_release(key):
                        try:
                            client_pressed_vk_codes.discard(key.vk)
                        except AttributeError:
                            client_pressed_special_keys.discard(key)

                    hk_listener = keyboard.Listener(on_press=hk_press, on_release=hk_release)
                    hk_listener.start()

                    last_event_time = time.time()
                    last_warning = 0
                    hb_thread = None

                    def heartbeat():
                        nonlocal last_warning
                        while self._running and self.server_socket is s:
                            if time.time() - last_event_time > 2:
                                if time.time() - last_warning > 2:
                                    logging.warning("No input events received for over 2 seconds")
                                    last_warning = time.time()
                            time.sleep(1)

                    hb_thread = threading.Thread(target=heartbeat, daemon=True, name="HeartbeatThread")
                    hb_thread.start()

                    def recv_all(sock, n):
                        data = b''
                        while len(data) < n:
                            chunk = sock.recv(n - len(data))
                            if not chunk:
                                return None
                            data += chunk
                        return data

                    while self._running and self.server_socket is s:
                        logging.debug(
                            "connect_to_server recv loop. cancel=%s received=%d",
                            self._cancel_transfer.is_set(),
                            incoming_info['received'] if incoming_info else 0,
                        )
                        raw_len = recv_all(s, 4)
                        if not raw_len:
                            break
                        msg_len = struct.unpack('!I', raw_len)[0]
                        payload = recv_all(s, msg_len)
                        if payload is None:
                            break
                        try:
                            data = msgpack.unpackb(payload, raw=False)
                            last_event_time = time.time()
                            event_type = data.get('type')
                            if event_type in ('move_relative', 'click', 'scroll', 'key'):
                                self.input_receiver.process_event(data)
                            elif event_type == 'clipboard_text':
                                text = data.get('text', '')
                                if text != self.last_clipboard:
                                    self._set_clipboard(text)
                            elif event_type == 'file_metadata':
                                temp_dir_for_download = self._get_temp_dir()
                                incoming_tmp = os.path.join(temp_dir_for_download, data['name'])
                                self._cancel_transfer.clear()
                                logging.debug("Receiving file, cancel flag cleared")
                                try:
                                    incoming_file = open(incoming_tmp, 'wb')
                                except Exception as e:
                                    logging.error('Failed to open receive file: %s', e, exc_info=True)
                                    self.file_transfer_error.emit(str(e))
                                    break
                                s.settimeout(TRANSFER_TIMEOUT)
                                incoming_info = {
                                    'path': incoming_tmp,
                                    'dest': data['dest'],
                                    'size': data['size'],
                                    'name': data['name'],
                                    'file': incoming_file,
                                    'received': 0,
                                    'source_id': data.get('source_id', self.device_name),
                                    'temp_dir': temp_dir_for_download,
                                    'start_time': time.time(),
                                }
                                last_percentage = -1
                                last_emit_time = time.time()
                                self.update_progress_display.emit(0, f"{incoming_info['name']}: 0MB / {incoming_info['size']/1024/1024:.1f}MB")
                            elif event_type == 'file_chunk':
                                if incoming_info:
                                    try:
                                        incoming_info['file'].write(data['data'])
                                        incoming_info['received'] += len(data['data'])
                                        current_percentage = int((incoming_info['received'] / incoming_info['size']) * 100) if incoming_info['size'] > 0 else 0
                                        if current_percentage > last_percentage or time.time() - last_emit_time > PROGRESS_UPDATE_INTERVAL:
                                            elapsed_time = time.time() - incoming_info['start_time']
                                            speed_mbps = (incoming_info['received'] / (1024*1024)) / elapsed_time if elapsed_time > 0 else 0
                                            remaining_bytes = incoming_info['size'] - incoming_info['received']
                                            etr_seconds = int(remaining_bytes / (speed_mbps * 1024 * 1024)) if speed_mbps > 0 else 0
                                            etr_str = time.strftime('%M:%S', time.gmtime(etr_seconds)) if etr_seconds < 3600 else time.strftime('%H:%M:%S', time.gmtime(etr_seconds))

                                            label = f"{incoming_info['name']}: {incoming_info['received']/1024/1024:.1f}MB / {incoming_info['size']/1024/1024:.1f}MB\n"
                                            label += f"Sebesség: {speed_mbps:.1f} MB/s | Hátralévő idő: {etr_str}"
                                            self.update_progress_display.emit(current_percentage, label)
                                            last_percentage = current_percentage
                                            last_emit_time = time.time()
                                        if self._cancel_transfer.is_set():
                                            break
                                    except Exception as e:
                                        logging.error('Receive error: %s', e, exc_info=True)
                                        self.file_transfer_error.emit(str(e))
                                        self._cancel_transfer.set()
                                        break
                            elif event_type == 'file_end':
                                if incoming_info:
                                    incoming_info['file'].close()
                                    try:
                                        self._safe_extract_archive(incoming_info['path'], incoming_info['dest'])
                                    finally:
                                        shutil.rmtree(incoming_info['temp_dir'], ignore_errors=True)
                                    self._send_message(s, {'type': 'paste_success', 'source_id': incoming_info.get('source_id')})
                                    s.settimeout(None)
                                    final_label = f"{incoming_info['name']}: Kész! ({incoming_info['size']/1024/1024:.1f}MB)"
                                    self.update_progress_display.emit(100, final_label)
                                    incoming_info = None
                                    self._cancel_transfer.clear()
                                    logging.debug("Download finished, cancel flag cleared")
                            elif event_type == 'delete_source':
                                for pth in data.get('paths', []):
                                    try:
                                        if os.path.isdir(pth):
                                            shutil.rmtree(pth)
                                        else:
                                            os.remove(pth)
                                    except Exception as e:
                                        logging.error('Failed to delete %s: %s', pth, e)
                        except Exception:
                            logging.warning("Hibás adatcsomag")

                        if self._cancel_transfer.is_set():
                            if incoming_info:
                                try:
                                    incoming_info['file'].close()
                                except Exception:
                                    pass
                                if incoming_info.get('temp_dir'):
                                    shutil.rmtree(incoming_info['temp_dir'], ignore_errors=True)
                                incoming_info = None
                            s.settimeout(None)
                            self._cancel_transfer.clear()
                            logging.debug("Download canceled or finished, cancel flag cleared")

        except Exception as e:
            if self._running:
                logging.error(f"Csatlakozás sikertelen: {e}", exc_info=True)
                self.status_update.emit(f"Kapcsolat sikertelen: {e}.")

        finally:
            logging.info("Connection to server closed")
            if hb_thread is not None:
                try:
                    hb_thread.join(timeout=0.1)
                except Exception:
                    pass
            if self.clipboard_thread is not None:
                try:
                    self.clipboard_thread.join(timeout=0.1)
                except Exception:
                    pass
            self.input_receiver.release_pressed_keys()
            if hk_listener is not None:
                try:
                    hk_listener.stop()
                except Exception:
                    pass
            self.release_hotkey_keys()
            if incoming_info and incoming_info.get('temp_dir'):
                logging.warning(
                    "Cleaning up incomplete download directory: %s",
                    incoming_info['temp_dir'],
                )
                try:
                    incoming_info['file'].close()
                except Exception:
                    pass
                shutil.rmtree(incoming_info['temp_dir'], ignore_errors=True)
            incoming_info = None
            self._cancel_transfer.clear()
            self.server_socket = None
            logging.debug("connect_to_server finished")
