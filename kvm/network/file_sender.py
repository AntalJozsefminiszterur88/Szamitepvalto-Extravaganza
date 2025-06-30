import logging
import os
import shutil
import tempfile
import threading
import time
import zipfile

FILE_CHUNK_SIZE = 65536
PROGRESS_UPDATE_INTERVAL = 0.5


class FileSender:
    """Create and send zip archives over a socket."""

    def __init__(self, worker):
        self.worker = worker

    # ------------------------------------------------------------------
    def _create_archive(self, paths, cancel_event=None):
        temp_dir = self.worker._get_temp_dir()
        archive_path = os.path.join(temp_dir, "share.zip")
        total_size = 0
        for p in paths:
            if os.path.isdir(p):
                for root, _, files in os.walk(p):
                    for f in files:
                        total_size += os.path.getsize(os.path.join(root, f))
            else:
                total_size += os.path.getsize(p)

        written = 0
        last_emit = time.time()
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for p in paths:
                if os.path.isdir(p):
                    base = os.path.basename(p.rstrip(os.sep))
                    for root, _, files in os.walk(p):
                        for f in files:
                            src = os.path.join(root, f)
                            arcname = os.path.join(base, os.path.relpath(src, p))
                            zf.write(src, arcname)
                            written += os.path.getsize(src)
                            if cancel_event and cancel_event.is_set():
                                raise RuntimeError("archive canceled")
                            if time.time() - last_emit >= PROGRESS_UPDATE_INTERVAL and total_size:
                                pct = int((written / total_size) * 100)
                                self.worker.update_progress_display.emit(pct, f"Archiválás {pct}%")
                                last_emit = time.time()
                else:
                    zf.write(p, os.path.basename(p))
                    written += os.path.getsize(p)
                    if cancel_event and cancel_event.is_set():
                        raise RuntimeError("archive canceled")
                    if time.time() - last_emit >= PROGRESS_UPDATE_INTERVAL and total_size:
                        pct = int((written / total_size) * 100)
                        self.worker.update_progress_display.emit(pct, f"Archiválás {pct}%")
                        last_emit = time.time()
        self.worker.update_progress_display.emit(100, "Archiválás kész")
        return archive_path

    # ------------------------------------------------------------------
    def _send_archive(self, sock, archive_path, dest_dir=""):
        size = os.path.getsize(archive_path)
        name = os.path.basename(archive_path)
        meta = {
            "type": "file_metadata",
            "name": name,
            "size": size,
            "dest": dest_dir,
            "source_id": self.worker.device_name,
        }
        if not self.worker._send_message(sock, meta):
            return
        sent = 0
        last_emit = time.time()
        start = time.time()
        with open(archive_path, "rb") as f:
            while not self.worker._cancel_transfer.is_set():
                chunk = f.read(FILE_CHUNK_SIZE)
                if not chunk:
                    break
                if not self.worker._send_message(sock, {"type": "file_chunk", "data": chunk}):
                    raise IOError("send failed")
                sent += len(chunk)
                if time.time() - last_emit >= PROGRESS_UPDATE_INTERVAL and size:
                    pct = int((sent / size) * 100)
                    self.worker.update_progress_display.emit(pct, f"Küldés {pct}%")
                    last_emit = time.time()
        if self.worker._cancel_transfer.is_set():
            self.worker._send_message(sock, {"type": "transfer_canceled"})
            return
        self.worker._send_message(sock, {"type": "file_end"})
        self.worker.update_progress_display.emit(100, "Küldés kész")
        logging.debug("Archive send finished in %.1fs", time.time() - start)

    # ------------------------------------------------------------------
    def send_files(self, paths, operation, sock):
        cancel_evt = threading.Event()
        result = {}

        def run_archive():
            result["archive"] = self._create_archive(paths, cancel_event=cancel_evt)

        arch_thread = threading.Thread(target=run_archive, daemon=True)
        arch_thread.start()
        arch_thread.join(self.worker.settings.get("archive_timeout_seconds", 900))
        if arch_thread.is_alive():
            cancel_evt.set()
            arch_thread.join()
            self.worker.file_transfer_error.emit("Archiválás időtúllépés")
            if result.get("archive"):
                shutil.rmtree(os.path.dirname(result["archive"]), ignore_errors=True)
            return

        archive = result.get("archive")
        if not archive:
            return
        temp_dir = os.path.dirname(archive)
        try:
            self._send_archive(sock, archive, dest_dir="")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            self.worker._cancel_transfer.clear()
