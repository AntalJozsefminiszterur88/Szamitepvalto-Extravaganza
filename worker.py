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
from pynput import keyboard
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser
from input_streaming import stream_inputs
from connection_utils import ConnectionMixin
from monitorcontrol import get_monitors
from PySide6.QtCore import QObject, Signal, QSettings
from config import (
    SERVICE_TYPE,
    SERVICE_NAME_PREFIX,
    APP_NAME,
    ORG_NAME,
    BRAND_NAME,
    TEMP_DIR_PARTS,
    VK_NUMPAD0,
    VK_NUMPAD1,
    VK_NUMPAD2,
)

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


class KVMWorker(ConnectionMixin, QObject):
    __slots__ = (
        'settings', '_running', 'kvm_active', 'client_sockets', 'client_infos',
        'active_client', 'pynput_listeners', 'zeroconf', 'streaming_thread',
        'switch_monitor', 'local_ip', 'server_ip', 'connection_thread',
        'device_name', 'clipboard_thread', 'last_clipboard', 'server_socket',
        'network_file_clipboard', '_cancel_transfer', 'last_server_ip'
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

    def _create_archive(self, paths, cancel_event: Optional[threading.Event] = None):
        temp_dir = self._get_temp_dir()
        archive = os.path.join(temp_dir, 'share.zip')
        logging.debug("Created temp archive dir %s", temp_dir)
        # Log available space in the temporary directory which will hold the archive
        try:
            usage = shutil.disk_usage(temp_dir)
            logging.debug(
                "Temp dir disk usage - total: %s, used: %s, free: %s",
                usage.total,
                usage.used,
                usage.free,
            )
        except Exception as e:
            logging.debug("Failed to query temp dir disk usage: %s", e)
        start_time = time.time()
        try:
            # Pre-scan all paths to determine total number of files
            total_files = 0
            for p in paths:
                if os.path.isdir(p):
                    for _, _, files in os.walk(p):
                        total_files += len(files)
                else:
                    total_files += 1

            archived_files = 0
            with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
                def _write_with_progress(src_path, arcname, ctype):
                    file_size = os.path.getsize(src_path)
                    if cancel_event and cancel_event.is_set():
                        raise RuntimeError('archive canceled')

                    last_percentage = -1
                    last_emit_time = time.time()
                    start_time = time.time()

                    if file_size > 1_000_000_000:
                        info = zipfile.ZipInfo(arcname, date_time=time.localtime(time.time())[:6])
                        info.compress_type = ctype
                        with open(src_path, 'rb') as src_file, zf.open(info, 'w', force_zip64=True) as dest:
                            sent = 0
                            while True:
                                if cancel_event and cancel_event.is_set():
                                    raise RuntimeError('archive canceled')
                                chunk = src_file.read(FILE_CHUNK_SIZE)
                                if not chunk:
                                    break
                                dest.write(chunk)
                                sent += len(chunk)

                                current_percentage = int((sent / file_size) * 100)
                                if current_percentage > last_percentage or time.time() - last_emit_time > PROGRESS_UPDATE_INTERVAL:
                                    # --- Speed and ETR Calculation ---
                                    elapsed_time = time.time() - start_time
                                    speed_mbps = (sent / (1024*1024)) / elapsed_time if elapsed_time > 0 else 0
                                    remaining_bytes = file_size - sent
                                    etr_seconds = int(remaining_bytes / (speed_mbps * 1024 * 1024)) if speed_mbps > 0 else 0
                                    etr_str = time.strftime('%M:%S', time.gmtime(etr_seconds)) if etr_seconds < 3600 else time.strftime('%H:%M:%S', time.gmtime(etr_seconds))

                                    label = f"{os.path.basename(src_path)}: {sent/1024/1024:.1f}MB / {file_size/1024/1024:.1f}MB\n"
                                    label += f"Sebesség: {speed_mbps:.1f} MB/s | Hátralévő idő: {etr_str}"

                                    self.update_progress_display.emit(current_percentage, label)
                                    last_percentage = current_percentage
                                    last_emit_time = time.time()
                        final_label = f"{os.path.basename(src_path)}: Kész! ({file_size/1024/1024:.1f}MB)"
                        self.update_progress_display.emit(100, final_label)
                    else:
                        zf.write(src_path, arcname, compress_type=ctype)
                for p in paths:
                    if os.path.isdir(p):
                        base = os.path.basename(p.rstrip(os.sep))
                        for root, _, files in os.walk(p):
                            for f in files:
                                full = os.path.join(root, f)
                                rel = os.path.join(base, os.path.relpath(full, p))
                                file_size = os.path.getsize(full)
                                if file_size > 1_000_000_000:
                                    logging.info(
                                        "Adding large file %s (%d bytes) to archive",
                                        full,
                                        file_size,
                                    )
                                try:
                                    compress_type = zipfile.ZIP_DEFLATED
                                    ext = os.path.splitext(f)[1].lower()
                                    if file_size > 1_000_000_000 or ext in {'.mkv', '.mp4', '.mov'}:
                                        compress_type = zipfile.ZIP_STORED
                                    _write_with_progress(full, rel, compress_type)
                                    logging.debug("Archived %s", full)
                                    if cancel_event and cancel_event.is_set():
                                        raise RuntimeError('archive canceled')
                                except MemoryError:
                                    msg = (
                                        f"Archiv\xe1l\xe1si hiba: Kev\xe9s a mem\xf3ria a(z) {os.path.basename(full)} t\xf6m\xf6r\xedt\xe9s\xe9hez."
                                    )
                                    logging.error(msg, exc_info=True)
                                    self.file_transfer_error.emit(msg)
                                    return None
                                except (IOError, OSError) as e:
                                    msg = f"Archiv\xe1l\xe1si hiba: Nincs el\xe9g hely vagy IO probl\xe9ma ({e})."
                                    logging.error(msg, exc_info=True)
                                    self.file_transfer_error.emit(msg)
                                    return None
                                except zipfile.LargeZipFile as e:
                                    msg = f"Archiv\xe1l\xe1si hiba: {e}"
                                    logging.error(msg, exc_info=True)
                                    self.file_transfer_error.emit(msg)
                                    return None
                                archived_files += 1
                                percentage = int(archived_files / total_files * 100) if total_files else 0
                                label = f"Tömörítés: {os.path.basename(full)} ({archived_files}/{total_files} fájl)"
                                self.update_progress_display.emit(percentage, label)
                    else:
                        file_size = os.path.getsize(p)
                        if file_size > 1_000_000_000:
                            logging.info(
                                "Adding large file %s (%d bytes) to archive",
                                p,
                                file_size,
                            )
                        try:
                            compress_type = zipfile.ZIP_DEFLATED
                            ext = os.path.splitext(p)[1].lower()
                            if file_size > 1_000_000_000 or ext in {'.mkv', '.mp4', '.mov'}:
                                compress_type = zipfile.ZIP_STORED
                            _write_with_progress(p, os.path.basename(p), compress_type)
                            logging.debug("Archived %s", p)
                            if cancel_event and cancel_event.is_set():
                                raise RuntimeError('archive canceled')
                        except MemoryError:
                            msg = (
                                f"Archiv\xe1l\xe1si hiba: Kev\xe9s a mem\xf3ria a(z) {os.path.basename(p)} t\xf6m\xf6r\xedt\xe9s\xe9hez."
                            )
                            logging.error(msg, exc_info=True)
                            self.file_transfer_error.emit(msg)
                            return None
                        except (IOError, OSError) as e:
                            msg = f"Archiv\xe1l\xe1si hiba: Nincs el\xe9g hely vagy IO probl\xe9ma ({e})."
                            logging.error(msg, exc_info=True)
                            self.file_transfer_error.emit(msg)
                            return None
                        except zipfile.LargeZipFile as e:
                            msg = f"Archiv\xe1l\xe1si hiba: {e}"
                            logging.error(msg, exc_info=True)
                            self.file_transfer_error.emit(msg)
                            return None
                        archived_files += 1
                        percentage = int(archived_files / total_files * 100) if total_files else 0
                        label = f"Tömörítés: {os.path.basename(p)} ({archived_files}/{total_files} fájl)"
                        self.update_progress_display.emit(percentage, label)
            label = f"Tömörítés kész. ({os.path.basename(archive)})"
            self.update_progress_display.emit(100, label)
        except Exception as e:
            logging.error("Failed to create archive: %s", e, exc_info=True)
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception as cleanup_err:
                logging.error("Failed to cleanup temp dir %s: %s", temp_dir, cleanup_err)
            self.file_transfer_error.emit(f"Archive creation failed: {e}")
            return None
        duration = time.time() - start_time
        if duration > 600:
            logging.warning("Archive creation took %.1f seconds", duration)
        logging.debug("Archive created at %s", archive)
        return archive

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

    def _send_archive(self, sock, archive_path, dest_dir):
        self._cancel_transfer.clear()
        logging.debug(
            "Entering _send_archive. cancel=%s dest=%s",
            self._cancel_transfer.is_set(),
            dest_dir,
        )
        logging.debug("Cancel flag cleared at start of _send_archive")
        prev_to = sock.gettimeout()
        sock.settimeout(TRANSFER_TIMEOUT)
        try:
            size = os.path.getsize(archive_path)
            name = os.path.basename(archive_path)
            meta = {
                'type': 'file_metadata',
                'name': name,
                'size': size,
                'dest': dest_dir,
                'source_id': self.network_file_clipboard.get('source_id') if self.network_file_clipboard else self.device_name,
            }
            if not self._send_message(sock, meta):
                return
            sent = 0
            last_percentage = -1
            last_emit_time = time.time()
            start_time = time.time()  # For average speed calculation

            with open(archive_path, 'rb') as f:
                while not self._cancel_transfer.is_set():
                    chunk = f.read(FILE_CHUNK_SIZE)
                    if not chunk:
                        break
                    if not self._send_message(sock, {'type': 'file_chunk', 'data': chunk}):
                        raise IOError('send failed')
                    sent += len(chunk)

                    # Throttle the UI update
                    if time.time() - last_emit_time >= PROGRESS_UPDATE_INTERVAL:
                        current_percentage = int((sent / size) * 100) if size > 0 else 0

                        # --- Speed and ETR Calculation ---
                        elapsed_time = time.time() - start_time
                        speed_mbps = (sent / (1024*1024)) / elapsed_time if elapsed_time > 0 else 0
                        remaining_bytes = size - sent
                        etr_seconds = int(remaining_bytes / (speed_mbps * 1024 * 1024)) if speed_mbps > 0 else 0
                        etr_str = time.strftime('%M:%S', time.gmtime(etr_seconds)) if etr_seconds < 3600 else time.strftime('%H:%M:%S', time.gmtime(etr_seconds))

                        label = f"{name}: {sent/1024/1024:.1f}MB / {size/1024/1024:.1f}MB\n"
                        label += f"Sebesség: {speed_mbps:.1f} MB/s | Hátralévő idő: {etr_str}"

                        self.update_progress_display.emit(current_percentage, label)
                        last_emit_time = time.time()
            if self._cancel_transfer.is_set():
                self._send_message(sock, {'type': 'transfer_canceled'})
                return
            final_label = f"{name}: Kész! ({size/1024/1024:.1f}MB)"
            self.update_progress_display.emit(100, final_label)
            self._send_message(sock, {'type': 'file_end'})
            logging.debug(
                "WORKER EMITTING update_progress_display: %s %d/%d",
                name,
                size,
                size,
            )
            logging.debug("_send_archive loop completed. cancel=%s", self._cancel_transfer.is_set())
        except Exception as e:
            logging.error('Error sending archive: %s', e, exc_info=True)
            self.file_transfer_error.emit(str(e))
        finally:
            sock.settimeout(prev_to)
            self._cancel_transfer.clear()
            logging.debug("Archive send finished, cancel flag cleared")
            logging.debug("Exiting _send_archive")

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
        timeout = self.settings.get('archive_timeout_seconds', 900)
        cancel_evt = threading.Event()
        result = {}
        temp_archive_dir = None

        def run_archiving():
            result['archive'] = self._create_archive(paths, cancel_event=cancel_evt)

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
            else:  # This is the client-side sending logic
                sock = self.server_socket
                if not sock:
                    logging.warning('No server connection for file share')
                    self.file_transfer_error.emit("Nincs kapcsolat a szerverrel a küldéshez.")
                    return

                # Use the robust _send_archive method for sending.
                # The 'dest' parameter for _send_archive is not used on the sending side,
                # but the method expects it. We can pass an empty string.
                self._send_archive(sock, archive, dest_dir="")
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
    

