import http.server
import logging
import os
import shutil
import threading
import time
import uuid
import urllib.parse
from typing import Optional

from config.constants import BRAND_NAME
from utils.logging_setup import LOG_SUBDIRECTORY
from utils.path_helpers import resolve_documents_directory

CENTRAL_CLIPBOARD_PORT = 54321
CLIPBOARD_STORAGE_DIRNAME = "SharedClipboard"
CLIPBOARD_MAX_AGE_SECONDS = 24 * 60 * 60


class CentralClipboardServer:
    """Centralized HTTP server for shared clipboard payloads."""

    def __init__(self, host: str = "0.0.0.0", port: int = CENTRAL_CLIPBOARD_PORT) -> None:
        self._host = host
        self._port = port
        self._server: Optional[http.server.ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.storage_dir = self._resolve_storage_dir()

    def _resolve_storage_dir(self) -> str:
        documents_dir = resolve_documents_directory()
        base_dir = os.path.join(
            str(documents_dir),
            BRAND_NAME,
            LOG_SUBDIRECTORY,
            CLIPBOARD_STORAGE_DIRNAME,
        )
        os.makedirs(base_dir, exist_ok=True)
        return base_dir

    def cleanup_old_files(self) -> None:
        now = time.time()
        try:
            entries = os.listdir(self.storage_dir)
        except OSError as exc:
            logging.warning("Failed to list clipboard storage directory %s: %s", self.storage_dir, exc)
            return

        for entry in entries:
            path = os.path.join(self.storage_dir, entry)
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                continue
            if now - mtime < CLIPBOARD_MAX_AGE_SECONDS:
                continue
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=False)
                else:
                    os.remove(path)
            except Exception as exc:
                logging.warning("Failed to remove old clipboard file %s: %s", path, exc)

    def _build_handler(self) -> type[http.server.BaseHTTPRequestHandler]:
        server = self

        class _RequestHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args) -> None:  # noqa: A003 - match base
                logging.debug("CentralClipboardServer: " + format, *args)

            def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
                if not self.path.startswith("/download/"):
                    self.send_error(404, "Unsupported endpoint.")
                    return

                request_path = urllib.parse.urlparse(self.path).path
                filename = request_path[len("/download/") :]
                filename = urllib.parse.unquote(filename)
                filename = os.path.basename(filename)
                if not filename:
                    self.send_error(400, "Missing filename.")
                    return

                target_path = os.path.join(server.storage_dir, filename)
                target_path = os.path.abspath(target_path)
                if not target_path.startswith(os.path.abspath(server.storage_dir)):
                    self.send_error(403, "Invalid filename.")
                    return

                if not os.path.exists(target_path):
                    self.send_error(404, "File not found.")
                    return

                try:
                    file_size = os.path.getsize(target_path)
                except OSError:
                    self.send_error(404, "File missing.")
                    return

                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(file_size))
                self.send_header(
                    "Content-Disposition",
                    f'attachment; filename="{os.path.basename(target_path)}"',
                )
                self.end_headers()

                with open(target_path, "rb") as handle:
                    shutil.copyfileobj(handle, self.wfile)

            def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
                if self.path != "/upload":
                    self.send_error(404, "Unsupported endpoint.")
                    return

                content_type = self.headers.get("Content-Type", "")
                content_length = self.headers.get("Content-Length")
                try:
                    length = int(content_length) if content_length else None
                except ValueError:
                    length = None

                file_data: Optional[bytes] = None
                original_name: Optional[str] = None

                if content_type.startswith("multipart/form-data"):
                    import cgi

                    form = cgi.FieldStorage(
                        fp=self.rfile,
                        headers=self.headers,
                        environ={
                            "REQUEST_METHOD": "POST",
                            "CONTENT_TYPE": content_type,
                        },
                    )
                    if form.list:
                        for field in form.list:
                            if field.filename:
                                original_name = field.filename
                                file_data = field.file.read()
                                break
                    if file_data is None:
                        self.send_error(400, "No file uploaded.")
                        return
                else:
                    if length is None:
                        self.send_error(411, "Missing Content-Length.")
                        return
                    file_data = self.rfile.read(length)
                    original_name = self.headers.get("X-Filename")

                if file_data is None:
                    self.send_error(400, "Empty payload.")
                    return

                _, ext = os.path.splitext(original_name or "")
                unique_name = f"{int(time.time())}_{uuid.uuid4().hex[:8]}{ext}"
                target_path = os.path.join(server.storage_dir, unique_name)

                try:
                    with open(target_path, "wb") as handle:
                        handle.write(file_data)
                except Exception as exc:
                    logging.error("Failed to save clipboard upload %s: %s", target_path, exc)
                    self.send_error(500, "Failed to save upload.")
                    return

                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(unique_name.encode("utf-8"))

        return _RequestHandler

    def start(self) -> None:
        with self._lock:
            if self._server is not None:
                return
            self.cleanup_old_files()
            handler = self._build_handler()
            self._server = http.server.ThreadingHTTPServer((self._host, self._port), handler)
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                name="CentralClipboardServer",
                daemon=True,
            )
            self._thread.start()
        logging.info(
            "Central clipboard server started on %s:%s (storage: %s)",
            self._host,
            self._port,
            self.storage_dir,
        )

    def stop(self) -> None:
        with self._lock:
            if self._server is None:
                return
            self._server.shutdown()
            self._server.server_close()
            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=1)
            self._server = None
            self._thread = None
        logging.info("Central clipboard server stopped.")
