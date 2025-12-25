from __future__ import annotations

import contextlib
import http.server
import logging
import mimetypes
import os
import socket
import threading
import urllib.parse
import urllib.request


def get_lan_ip() -> str:
    """Return the LAN IP address using a UDP socket trick."""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except Exception:
        return "127.0.0.1"


class ClipboardHTTPServer:
    """Serve clipboard payloads over a local HTTP sidecar."""

    def __init__(self, host: str = "0.0.0.0") -> None:
        self._host = host
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._file_path: str | None = None
        self._url_path: str | None = None
        self.base_url: str | None = None
        self._lock = threading.Lock()
        self._download_event = threading.Event()

    @property
    def has_downloaded(self) -> bool:
        return self._download_event.is_set()

    def _build_handler(self) -> type[http.server.BaseHTTPRequestHandler]:
        server = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args) -> None:  # noqa: A003 - match base
                logging.debug("ClipboardHTTPServer: " + format, *args)

            def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
                file_path = server._file_path
                url_path = server._url_path
                if not file_path or not url_path:
                    self.send_error(404, "No clipboard payload available.")
                    return

                request_path = urllib.parse.urlparse(self.path).path
                if request_path != f"/{url_path}":
                    self.send_error(404, "Clipboard payload not found.")
                    return

                server._download_event.set()

                try:
                    file_size = os.path.getsize(file_path)
                except OSError:
                    self.send_error(404, "Clipboard payload missing.")
                    return

                mime_type, _ = mimetypes.guess_type(file_path)
                self.send_response(200)
                self.send_header("Content-Type", mime_type or "application/octet-stream")
                self.send_header("Content-Length", str(file_size))
                self.send_header(
                    "Content-Disposition", f'attachment; filename="{os.path.basename(file_path)}"'
                )
                self.end_headers()

                with open(file_path, "rb") as handle:
                    while True:
                        chunk = handle.read(64 * 1024)
                        if not chunk:
                            break
                        self.wfile.write(chunk)

        return _Handler

    def start(self, file_path: str) -> str:
        """Start the sidecar server and expose the given file."""

        if not os.path.isfile(file_path):
            raise FileNotFoundError(file_path)

        with self._lock:
            self._file_path = file_path
            self._url_path = urllib.parse.quote(os.path.basename(file_path))
            if self._server is None:
                handler = self._build_handler()
                self._server = http.server.ThreadingHTTPServer((self._host, 0), handler)
                self._thread = threading.Thread(
                    target=self._server.serve_forever,
                    name="ClipboardHTTPServer",
                    daemon=True,
                )
                self._thread.start()
            host, port = self._server.server_address[:2]
            self.base_url = f"http://{get_lan_ip()}:{port}/{self._url_path}"
            self._download_event.clear()

        if self.base_url is None:
            raise RuntimeError("Clipboard HTTP server failed to start.")

        return self.base_url

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
            self._file_path = None
            self._url_path = None
            self.base_url = None
            self._download_event.clear()


def download_file(url: str, target_path: str, *, chunk_size: int = 64 * 1024) -> bool:
    """Download a file to disk using streaming chunks."""

    os.makedirs(os.path.dirname(target_path) or ".", exist_ok=True)
    try:
        with urllib.request.urlopen(url) as response, open(target_path, "wb") as handle:
            while True:
                chunk = response.read(chunk_size)
                if not chunk:
                    break
                handle.write(chunk)
    except Exception as exc:
        logging.error("Failed to download clipboard file from %s: %s", url, exc)
        with contextlib.suppress(Exception):
            if os.path.exists(target_path):
                os.remove(target_path)
        return False
    return True
