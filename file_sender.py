import os
import shutil
import tempfile
import time
import zipfile
import logging
import threading
from typing import Optional

FILE_CHUNK_SIZE = 65536
TRANSFER_TIMEOUT = 30
PROGRESS_UPDATE_INTERVAL = 0.5


class FileSender:
    """Handle archiving and sending files over a socket."""

    def __init__(self, worker):
        self.worker = worker

    def _create_archive(self, paths, cancel_event: Optional[threading.Event] = None):
        temp_dir = self.worker._get_temp_dir()
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
                    start_time_inner = time.time()

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
                                    elapsed_time = time.time() - start_time_inner
                                    speed_mbps = (sent / (1024 * 1024)) / elapsed_time if elapsed_time > 0 else 0
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
                                    msg = (
                                        f"Archiválási hiba: Kevés a memória a(z) {os.path.basename(full)} tömörítéséhez."
                                    )
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
                            msg = (
                                f"Archiválási hiba: Kevés a memória a(z) {os.path.basename(p)} tömörítéséhez."
                            )
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

    def _send_archive(self, sock, archive_path, dest_dir):
        self.worker._cancel_transfer.clear()
        logging.debug(
            "Entering _send_archive. cancel=%s dest=%s",
            self.worker._cancel_transfer.is_set(),
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
                'source_id': self.worker.network_file_clipboard.get('source_id') if self.worker.network_file_clipboard else self.worker.device_name,
            }
            if not self.worker._send_message(sock, meta):
                return
            sent = 0
            last_percentage = -1
            last_emit_time = time.time()
            start_time = time.time()
            with open(archive_path, 'rb') as f:
                while not self.worker._cancel_transfer.is_set():
                    chunk = f.read(FILE_CHUNK_SIZE)
                    if not chunk:
                        break
                    if not self.worker._send_message(sock, {'type': 'file_chunk', 'data': chunk}):
                        raise IOError('send failed')
                    sent += len(chunk)
                    if time.time() - last_emit_time >= PROGRESS_UPDATE_INTERVAL:
                        current_percentage = int((sent / size) * 100) if size > 0 else 0
                        elapsed_time = time.time() - start_time
                        speed_mbps = (sent / (1024 * 1024)) / elapsed_time if elapsed_time > 0 else 0
                        remaining_bytes = size - sent
                        etr_seconds = int(remaining_bytes / (speed_mbps * 1024 * 1024)) if speed_mbps > 0 else 0
                        etr_str = time.strftime('%M:%S', time.gmtime(etr_seconds)) if etr_seconds < 3600 else time.strftime('%H:%M:%S', time.gmtime(etr_seconds))
                        label = f"{name}: {sent/1024/1024:.1f}MB / {size/1024/1024:.1f}MB\n"
                        label += f"Sebesség: {speed_mbps:.1f} MB/s | Hátralévő idő: {etr_str}"
                        self.worker.update_progress_display.emit(current_percentage, label)
                        last_emit_time = time.time()
            if self.worker._cancel_transfer.is_set():
                self.worker._send_message(sock, {'type': 'transfer_canceled'})
                return
            final_label = f"{name}: Kész! ({size/1024/1024:.1f}MB)"
            self.worker.update_progress_display.emit(100, final_label)
            self.worker._send_message(sock, {'type': 'file_end'})
            logging.debug(
                "WORKER EMITTING update_progress_display: %s %d/%d",
                name,
                size,
                size,
            )
            logging.debug("_send_archive loop completed. cancel=%s", self.worker._cancel_transfer.is_set())
        except Exception as e:
            logging.error('Error sending archive: %s', e, exc_info=True)
            self.worker.file_transfer_error.emit(str(e))
        finally:
            sock.settimeout(prev_to)
            self.worker._cancel_transfer.clear()
            logging.debug("Archive send finished, cancel flag cleared")
            logging.debug("Exiting _send_archive")

    def send_files(self, paths, operation, sock):
        archive = self._create_archive(paths)
        if not archive:
            return
        temp_dir = os.path.dirname(archive)
        try:
            self._send_archive(sock, archive, dest_dir="")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            self.worker._cancel_transfer.clear()
