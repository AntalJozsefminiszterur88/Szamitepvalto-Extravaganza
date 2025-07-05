import os
import shutil
import socket
import struct
import tempfile
import threading
import queue
import time
import zipfile
import logging
from typing import Optional
import msgpack

from config import TEMP_DIR_PARTS

# Constants duplicated from worker for standalone operation
FILE_CHUNK_SIZE = 65536
# Socket timeout (seconds) during file transfers. Increased
# from 30 to 90 seconds to better tolerate slower connections.
TRANSFER_TIMEOUT = 90
PROGRESS_UPDATE_INTERVAL = 0.5


class FileTransferHandler:
    """Handle file transfer related operations for KVMWorker."""

    def __init__(self, worker):
        self.worker = worker
        self.settings = worker.settings
        self.device_name = worker.device_name
        self.network_file_clipboard = None
        self._cancel_transfer = threading.Event()
        self.current_uploads = {}
        self.current_downloads = {}

    def _cleanup_transfer_info(self, info: dict) -> None:
        """Release resources associated with a transfer info dictionary."""
        if not info:
            return
        try:
            f = info.get('file')
            if f:
                f.close()
        except Exception:
            pass
        writer = info.get('writer_thread')
        if writer:
            try:
                info.get('queue', queue.Queue()).put(None)
            except Exception:
                pass
            writer.join(timeout=1)
        if info.get('temp_dir'):
            shutil.rmtree(info['temp_dir'], ignore_errors=True)

    # --------------------------------------------------------------
    # Utility helpers
    # --------------------------------------------------------------
    def _get_temp_dir(self) -> str:
        base_path = self.settings.get('temp_path') or tempfile.gettempdir()
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
                    start_time_local = time.time()
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
                                    elapsed_time = time.time() - start_time_local
                                    speed_mbps = (sent / (1024*1024)) / elapsed_time if elapsed_time > 0 else 0
                                    remaining_bytes = file_size - sent
                                    etr_seconds = int(remaining_bytes / (speed_mbps * 1024 * 1024)) if speed_mbps > 0 else 0
                                    etr_str = time.strftime('%M:%S', time.gmtime(etr_seconds)) if etr_seconds < 3600 else time.strftime('%H:%M:%S', time.gmtime(etr_seconds))
                                    label = f"{os.path.basename(src_path)}: {sent/1024/1024:.1f}MB / {file_size/1024/1024:.1f}MB\n"
                                    label += f"Sebesség: {speed_mbps:.1f} MB/s | Hátralévő idő: {etr_str}"
                                    self.worker.update_progress_display.emit(current_percentage, label)
                                    last_percentage = current_percentage
                                    last_emit_time = time.time()
                        final_label = f"{os.path.basename(src_path)}: Kész! ({file_size/1024/1024:.1f}MB)"
                        self.worker.update_progress_display.emit(100, final_label)
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
                                    msg = f"Archiválási hiba: Kevés a memória a(z) {os.path.basename(full)} tömörítéséhez."
                                    logging.error(msg, exc_info=True)
                                    self.worker.file_transfer_error.emit(msg)
                                    return None
                                except (IOError, OSError) as e:
                                    msg = f"Archiválási hiba: Nincs elég hely vagy IO probléma ({e})."
                                    logging.error(msg, exc_info=True)
                                    self.worker.file_transfer_error.emit(msg)
                                    return None
                                except zipfile.LargeZipFile as e:
                                    msg = f"Archiválási hiba: {e}"
                                    logging.error(msg, exc_info=True)
                                    self.worker.file_transfer_error.emit(msg)
                                    return None
                                archived_files += 1
                                percentage = int(archived_files / total_files * 100) if total_files else 0
                                label = f"Tömörítés: {os.path.basename(full)} ({archived_files}/{total_files} fájl)"
                                self.worker.update_progress_display.emit(percentage, label)
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
                            msg = f"Archiválási hiba: Kevés a memória a(z) {os.path.basename(p)} tömörítéséhez."
                            logging.error(msg, exc_info=True)
                            self.worker.file_transfer_error.emit(msg)
                            return None
                        except (IOError, OSError) as e:
                            msg = f"Archiválási hiba: Nincs elég hely vagy IO probléma ({e})."
                            logging.error(msg, exc_info=True)
                            self.worker.file_transfer_error.emit(msg)
                            return None
                        except zipfile.LargeZipFile as e:
                            msg = f"Archiválási hiba: {e}"
                            logging.error(msg, exc_info=True)
                            self.worker.file_transfer_error.emit(msg)
                            return None
                        archived_files += 1
                        percentage = int(archived_files / total_files * 100) if total_files else 0
                        label = f"Tömörítés: {os.path.basename(p)} ({archived_files}/{total_files} fájl)"
                        self.worker.update_progress_display.emit(percentage, label)
            label = f"Tömörítés kész. ({os.path.basename(archive)})"
            self.worker.update_progress_display.emit(100, label)
        except Exception as e:
            logging.error("Failed to create archive: %s", e, exc_info=True)
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception as cleanup_err:
                logging.error("Failed to cleanup temp dir %s: %s", temp_dir, cleanup_err)
            self.worker.file_transfer_error.emit(f"Archive creation failed: {e}")
            return None
        duration = time.time() - start_time
        if duration > 600:
            logging.warning("Archive creation took %.1f seconds", duration)
        logging.debug("Archive created at %s", archive)
        return archive

    def _safe_extract_archive(self, archive_path, dest_dir):
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
                shutil.move(source_path, final_target_path)
        finally:
            shutil.rmtree(temp_extract, ignore_errors=True)
            logging.debug("Removed temporary extract dir %s", temp_extract)

    def _send_archive(self, sock, archive_path, dest_dir):
        self._cancel_transfer.clear()
        prev_to = sock.gettimeout()
        sock.settimeout(TRANSFER_TIMEOUT)
        try:
            size = os.path.getsize(archive_path)
            name = os.path.basename(archive_path)
            logging.info(
                "Starting archive send: %s (%d bytes) to %s",
                name,
                size,
                sock.getpeername() if hasattr(sock, 'getpeername') else 'server',
            )
            meta = {
                'type': 'file_metadata',
                'name': name,
                'size': size,
                'dest': dest_dir,
                'source_id': self.network_file_clipboard.get('source_id') if self.network_file_clipboard else self.device_name,
            }
            if not self.worker._send_message(sock, meta):
                logging.error("Failed to send metadata for archive %s", name)
                return
            sent = 0
            last_percentage = -1
            last_emit_time = time.time()
            with open(archive_path, 'rb') as f:
                while True:
                    chunk = f.read(FILE_CHUNK_SIZE)
                    if not chunk:
                        break
                    logging.debug(
                        "Sending chunk of %d bytes for %s at offset %d",
                        len(chunk),
                        name,
                        sent,
                    )
                    if not self.worker._send_message(sock, {'type': 'file_chunk', 'data': chunk}):
                        logging.error(
                            "Failed to send file chunk at offset %d for %s. Aborting transfer.",
                            sent,
                            name,
                        )
                        return
                    sent += len(chunk)
                    if time.time() - last_emit_time >= PROGRESS_UPDATE_INTERVAL:
                        current_percentage = int((sent / size) * 100) if size > 0 else 0
                        elapsed_time = time.time() - (last_emit_time if last_percentage != -1 else time.time())
                        speed_mbps = (sent / (1024*1024)) / elapsed_time if elapsed_time > 0 else 0
                        remaining_bytes = size - sent
                        etr_seconds = int(remaining_bytes / (speed_mbps * 1024 * 1024)) if speed_mbps > 0 else 0
                        etr_str = time.strftime('%M:%S', time.gmtime(etr_seconds)) if etr_seconds < 3600 else time.strftime('%H:%M:%S', time.gmtime(etr_seconds))
                        label = f"{name}: {sent/1024/1024:.1f}MB / {size/1024/1024:.1f}MB\n"
                        label += f"Sebesség: {speed_mbps:.1f} MB/s | Hátralévő idő: {etr_str}"
                        self.worker.update_progress_display.emit(current_percentage, label)
                        last_percentage = current_percentage
                        last_emit_time = time.time()
                    if self._cancel_transfer.is_set():
                        self.worker._send_message(sock, {'type': 'transfer_canceled'})
                        return
            final_label = f"{name}: Kész! ({size/1024/1024:.1f}MB)"
            self.worker.update_progress_display.emit(100, final_label)
            self.worker._send_message(sock, {'type': 'file_end'})
        except Exception as e:
            logging.error('Error sending archive: %s', e, exc_info=True)
            self.worker.file_transfer_error.emit(str(e))
        finally:
            sock.settimeout(prev_to)
            self._cancel_transfer.clear()
            logging.info(
                "Finished archive send: %s (%d bytes sent)",
                name,
                sent if 'sent' in locals() else 0,
            )
            logging.debug("Archive send finished")

    def _clear_network_file_clipboard(self):
        if self.network_file_clipboard and self.network_file_clipboard.get('archive'):
            try:
                os.remove(self.network_file_clipboard['archive'])
                logging.debug("Removed temporary archive %s", self.network_file_clipboard['archive'])
            except FileNotFoundError:
                pass
            except Exception as e:
                logging.error("Failed to remove temporary archive %s: %s", self.network_file_clipboard['archive'], e)
        self.network_file_clipboard = None
        logging.debug("Network file clipboard cleared")

    def cancel_file_transfer(self):
        self._cancel_transfer.set()
        logging.debug("File transfer cancel signal set")

    def _file_writer_thread(self, info: dict):
        """Background thread that writes queued chunks to disk."""
        logging.debug("file writer thread started for %s", info.get('name'))
        try:
            while True:
                chunk = info['queue'].get()
                if chunk is None:
                    break
                info['file'].write(chunk)
                logging.debug(
                    "file writer wrote %d bytes for %s",
                    len(chunk),
                    info.get('name'),
                )
        except Exception as e:
            logging.error(
                "file writer error for %s: %s", info.get('name'), e, exc_info=True
            )
            self._cancel_transfer.set()
        finally:
            logging.debug("file writer thread exiting for %s", info.get('name'))

    def _cleanup_failed_transfer(self, info):
        """Internal helper to clean up a failed incoming transfer."""
        self._cleanup_transfer_info(info)

    def handle_transfer_timeout(self, sock):
        """Handle cleanup when a file transfer times out."""
        logging.error("File transfer timeout occurred")
        self.worker.file_transfer_error.emit(
            "Fájlátvitel időtúllépés. A kapcsolat megszakadt.")
        self.on_client_disconnected(sock)

    # --------------------------------------------------------------
    # Public API used by worker
    # --------------------------------------------------------------
    def share_files(self, paths, operation='copy') -> None:
        threading.Thread(target=self._share_files_thread, args=(paths, operation), daemon=True).start()

    def _share_files_thread(self, paths, operation):
        self._cancel_transfer.clear()
        logging.info(
            "share_files_thread started: %s files, operation=%s", len(paths), operation
        )
        timeout = self.settings.get('archive_timeout_seconds', 900)
        cancel_evt = threading.Event()
        result = {}
        temp_archive_dir = None
        try:
            def run_archiving():
                result['archive'] = self._create_archive(paths, cancel_event=cancel_evt)

            arch_thread = threading.Thread(target=run_archiving, daemon=True)
            arch_thread.start()
            arch_thread.join(timeout)
            if arch_thread.is_alive():
                cancel_evt.set()
                arch_thread.join(5)
                logging.critical(
                    "Archiving of %s timed out after %.1f minutes.", paths, timeout / 60
                )
                self.worker.file_transfer_error.emit("Archiválás időtúllépés (túl nagy fájl?)")
                if result.get('archive'):
                    temp_archive_dir = os.path.dirname(result['archive'])
                return

            archive = result.get('archive')
            if not archive:
                self._clear_network_file_clipboard()
                return

            temp_archive_dir = os.path.dirname(archive)
            logging.info("Archive ready at %s", archive)
            if self.settings['role'] == 'ado':
                self._clear_network_file_clipboard()
                self.network_file_clipboard = {
                    'paths': paths,
                    'operation': operation,
                    'archive': archive,
                    'source_id': self.device_name,
                }
                logging.debug("Network file clipboard set: %s", self.network_file_clipboard)
                self.worker._broadcast_message(
                    {'type': 'network_clipboard_set', 'source_id': self.device_name, 'operation': operation}
                )
            else:
                sock = self.worker.server_socket
                if not sock:
                    logging.warning('No server connection for file share')
                    self.worker.file_transfer_error.emit("Nincs kapcsolat a szerverrel a küldéshez.")
                    return
                self._send_archive(sock, archive, dest_dir="")
        finally:
            if temp_archive_dir and self.settings['role'] != 'ado':
                shutil.rmtree(temp_archive_dir, ignore_errors=True)
            self._cancel_transfer.clear()
            logging.info("share_files_thread finished")

    def request_paste(self, dest_dir) -> None:
        self._cancel_transfer.clear()
        if self.settings['role'] == 'ado':
            if not self.network_file_clipboard or not self.network_file_clipboard.get('archive'):
                logging.warning('No shared files to paste')
                return
            try:
                archive_name = os.path.basename(self.network_file_clipboard['archive']) if self.network_file_clipboard and self.network_file_clipboard.get('archive') else "archívum"
                self.worker.update_progress_display.emit(0, f"Kibontás: {archive_name}")
                self._safe_extract_archive(self.network_file_clipboard['archive'], dest_dir)
                self.worker.update_progress_display.emit(100, f"{archive_name}: Feldolgozás kész!")
            except Exception as e:
                logging.error('Extraction failed: %s', e, exc_info=True)
                self.worker.file_transfer_error.emit(f"Kibontási hiba: {e}")
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
                    for s, name in self.worker.client_infos.items():
                        if name == src_id:
                            self.worker._send_message(s, {'type': 'delete_source', 'paths': self.network_file_clipboard.get('paths', [])})
                            break
                    self._clear_network_file_clipboard()
        else:
            sock = self.worker.server_socket
            if sock:
                self.worker._send_message(sock, {'type': 'paste_request', 'destination': dest_dir})
        self._cancel_transfer.clear()

    # --------------------------------------------------------------
    # Network message handling
    # --------------------------------------------------------------
    def handle_network_message(self, data: dict, sock: socket.socket):
        msg_type = data.get('type')
        logging.debug("handle_network_message received type '%s'", msg_type)
        if msg_type == 'paste_request':
            dest = data.get('destination')
            if self.network_file_clipboard and self.network_file_clipboard.get('archive'):
                self._cancel_transfer.clear()
                self._send_archive(sock, self.network_file_clipboard['archive'], dest)
            return
        if msg_type == 'file_metadata':
            temp_dir = self._get_temp_dir()
            incoming_path = os.path.join(temp_dir, data['name'])
            self._clear_network_file_clipboard()
            try:
                incoming_file = open(incoming_path, 'wb')
            except Exception as e:
                logging.error('Failed to open incoming file: %s', e, exc_info=True)
                self.worker.file_transfer_error.emit(str(e))
                self._clear_network_file_clipboard()
                return
            if self.settings['role'] == 'ado':
                source_id = data.get('source_id', self.worker.client_infos.get(sock))
            else:
                source_id = data.get('source_id', self.device_name)
            info = {
                'file': incoming_file,
                'path': incoming_path,
                'temp_dir': temp_dir,
                'paths': data.get('paths', []),
                'operation': data.get('operation', 'copy'),
                'size': data.get('size', 0),
                'name': data.get('name'),
                'source_id': source_id,
                'received': 0,
                'start_time': time.time(),
                'last_percentage': -1,
                'last_emit_time': time.time(),
                'queue': queue.Queue(),
            }
            writer_thread = threading.Thread(
                target=self._file_writer_thread,
                args=(info,),
                daemon=True,
            )
            info['writer_thread'] = writer_thread
            writer_thread.start()
            if self.settings['role'] == 'ado':
                self.current_uploads[sock] = info
            else:
                self.current_downloads[sock] = info
            self.worker.update_progress_display.emit(0, f"{info['name']}: 0MB / {info['size']/1024/1024:.1f}MB")
            if self.settings['role'] == 'ado':
                self.worker.incoming_upload_started.emit(data.get('name'), data.get('size', 0))
            sock.settimeout(TRANSFER_TIMEOUT)
            return
        if msg_type == 'file_chunk':
            info = self.current_uploads.get(sock) if self.settings['role'] == 'ado' else self.current_downloads.get(sock)
            if info:
                try:
                    logging.debug(
                        "Received chunk of %d bytes for %s", len(data['data']), info.get('name')
                    )
                    info['queue'].put(data['data'])
                    info['received'] += len(data['data'])
                    if time.time() - info['last_emit_time'] >= PROGRESS_UPDATE_INTERVAL:
                        current_percentage = int((info['received'] / info['size']) * 100) if info['size'] > 0 else 0
                        elapsed_time = time.time() - info['start_time']
                        speed_mbps = (info['received'] / (1024*1024)) / elapsed_time if elapsed_time > 0 else 0
                        remaining_bytes = info['size'] - info['received']
                        etr_seconds = int(remaining_bytes / (speed_mbps * 1024 * 1024)) if speed_mbps > 0 else 0
                        etr_str = time.strftime('%M:%S', time.gmtime(etr_seconds)) if etr_seconds < 3600 else time.strftime('%H:%M:%S', time.gmtime(etr_seconds))
                        label = f"{info['name']}: {info['received']/1024/1024:.1f}MB / {info['size']/1024/1024:.1f}MB\n"
                        label += f"Sebesség: {speed_mbps:.1f} MB/s | Hátralévő idő: {etr_str}"
                        self.worker.update_progress_display.emit(current_percentage, label)
                        info['last_percentage'] = current_percentage
                        info['last_emit_time'] = time.time()
                except Exception as e:
                    logging.error('Transfer chunk error: %s', e, exc_info=True)
                    self.worker.file_transfer_error.emit(str(e))
                    self._cancel_transfer.set()
            return
        if msg_type == 'file_end':
            info = self.current_uploads.pop(sock, None) if self.settings['role'] == 'ado' else self.current_downloads.pop(sock, None)
            if info:
                info['queue'].put(None)
                info['writer_thread'].join()
                info['file'].close()
                logging.debug(
                    "File transfer completed for %s", info.get('name')
                )
                if self.settings['role'] == 'ado':
                    final_label = f"{info['name']}: Kész! ({info['size']/1024/1024:.1f}MB)"
                    self.worker.update_progress_display.emit(100, final_label)
                    self._clear_network_file_clipboard()
                    self.network_file_clipboard = {
                        'paths': info['paths'],
                        'operation': info['operation'],
                        'archive': info['path'],
                        'source_id': info.get('source_id'),
                    }
                    self.worker._broadcast_message({'type': 'network_clipboard_set', 'source_id': info.get('source_id'), 'operation': info['operation']}, exclude=sock)
                    sock.settimeout(1.0)
                    self._cancel_transfer.clear()
                else:
                    try:
                        self._safe_extract_archive(info['path'], info['dest'])
                    finally:
                        shutil.rmtree(info['temp_dir'], ignore_errors=True)
                    self.worker._send_message(sock, {'type': 'paste_success', 'source_id': info.get('source_id')})
                    sock.settimeout(None)
                    final_label = f"{info['name']}: Kész! ({info['size']/1024/1024:.1f}MB)"
                    self.worker.update_progress_display.emit(100, final_label)
                    self._cancel_transfer.clear()
            return
        if msg_type == 'paste_success' and self.settings['role'] == 'ado':
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
                            logging.error('Failed to delete %s: %s', pth, e)
                    self._clear_network_file_clipboard()
                else:
                    for s2, n2 in self.worker.client_infos.items():
                        if n2 == src:
                            self.worker._send_message(s2, {'type': 'delete_source', 'paths': self.network_file_clipboard.get('paths', [])})
                            break
                    self._clear_network_file_clipboard()
            return
        if msg_type == 'delete_source' and self.settings['role'] != 'ado':
            for pth in data.get('paths', []):
                try:
                    if os.path.isdir(pth):
                        shutil.rmtree(pth)
                    else:
                        os.remove(pth)
                except Exception as e:
                    logging.error('Failed to delete %s: %s', pth, e)
            return

    def on_client_disconnected(self, sock: socket.socket):
        info = self.current_uploads.pop(sock, None)
        if info:
            self._cleanup_transfer_info(info)
        info = self.current_downloads.pop(sock, None)
        if info:
            self._cleanup_transfer_info(info)
        self._cancel_transfer.clear()
        self._clear_network_file_clipboard()

    def cleanup(self):
        for info in list(self.current_uploads.values()):
            self._cleanup_transfer_info(info)
        self.current_uploads.clear()
        for info in list(self.current_downloads.values()):
            self._cleanup_transfer_info(info)
        self.current_downloads.clear()
        self._cancel_transfer.clear()
        self._clear_network_file_clipboard()
