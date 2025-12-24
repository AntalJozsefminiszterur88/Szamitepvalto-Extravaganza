from __future__ import annotations

import http.server
import logging
import os
import tempfile
import threading
import urllib.parse
import urllib.request


class ClipboardHTTPServer:
    """Serve clipboard payloads over a local HTTP sidecar."""

    def __init__(self, host: str = "127.0.0.1") -> None:
        self._host = host
        self._base_dir = tempfile.gettempdir()
        handler = self._build_handler()
        self._server = http.server.ThreadingHTTPServer((self._host, 0), handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="ClipboardHTTPServer",
            daemon=True,
        )
        self._thread.start()

    def _build_handler(self) -> type[http.server.SimpleHTTPRequestHandler]:
        base_dir = self._base_dir

        class _Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
                super().__init__(*args, directory=base_dir, **kwargs)

            def log_message(self, format: str, *args) -> None:  # noqa: A003 - match base
                logging.debug("ClipboardHTTPServer: " + format, *args)

        return _Handler

    def serve_file(self, file_path: str) -> str:
        """Expose ``file_path`` through the sidecar and return a download URL."""

        if not os.path.isfile(file_path):
            raise FileNotFoundError(file_path)

        relative = os.path.relpath(file_path, self._base_dir)
        if relative.startswith(os.pardir):
            raise ValueError("File must be located inside the temp directory.")

        url_path = urllib.parse.quote(relative.replace(os.sep, "/"))
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/{url_path}"

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread.is_alive():
            self._thread.join(timeout=1)


def download_file(url: str, target_path: str, *, chunk_size: int = 256 * 1024) -> threading.Thread:
    """Download a file in the background without blocking the caller."""

    def _worker() -> None:
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
            try:
                if os.path.exists(target_path):
                    os.remove(target_path)
            except Exception:
                pass

    thread = threading.Thread(target=_worker, name="ClipboardHTTPDownload", daemon=True)
    thread.start()
    return thread
