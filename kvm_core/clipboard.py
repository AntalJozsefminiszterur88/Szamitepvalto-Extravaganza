import io
import logging
import os
import shutil
import threading
import time
import zipfile
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any, Callable, Iterable, Optional

from PySide6.QtCore import QStandardPaths

from config.constants import BRAND_NAME
from utils.clipboard_sync import (
    clear_clipboard,
    clipboard_items_equal,
    normalize_clipboard_item,
    read_clipboard_content,
    write_clipboard_content,
)

CLIPBOARD_STORAGE_DIRNAME = "SharedClipboard"
CLIPBOARD_CLEANUP_INTERVAL_SECONDS = 24 * 60 * 60


class ClipboardManager:
    """Encapsulates shared clipboard synchronisation logic."""

    def __init__(
        self,
        settings: dict,
        send_message_callback: Callable[[dict, Optional[Iterable[Any]]], None],
        *,
        send_to_peer_callback: Callable[[Any, dict], bool],
        get_server_socket: Callable[[], Any],
        send_to_provider_callback: Optional[Callable[[dict], bool]] = None,
        get_input_provider_socket: Optional[Callable[[], Any]] = None,
        get_client_sockets: Optional[Callable[[], Iterable[Any]]] = None,
    ) -> None:
        self.settings = settings
        self._broadcast_callback = send_message_callback
        self._send_to_peer_callback = send_to_peer_callback
        self._get_server_socket = get_server_socket
        self._send_to_provider_callback = send_to_provider_callback or (lambda payload: False)
        self._get_input_provider_socket = get_input_provider_socket or (lambda: None)
        self._get_client_sockets = get_client_sockets or (lambda: [])

        self._thread: Optional[threading.Thread] = None
        self._running = threading.Event()
        self._running.clear()

        self.clipboard_lock = threading.Lock()
        self.last_clipboard_item: Optional[dict] = None
        self.shared_clipboard_item: Optional[dict] = None
        self.clipboard_expiry_seconds = 12 * 60 * 60
        self._ignore_next_clipboard_change = threading.Event()

        self.clipboard_storage_dir: Optional[str] = None
        self._clipboard_cleanup_marker: Optional[str] = None
        self._clipboard_last_cleanup: float = 0.0
        self._clipboard_last_persisted_digest: Optional[tuple[str, str]] = None

        if self.settings.get('role') == 'ado':
            self._initialize_clipboard_storage()

    # ------------------------------------------------------------------
    # Lifecycle helpers
    # ------------------------------------------------------------------
    @property
    def thread(self) -> Optional[threading.Thread]:
        return self._thread

    @property
    def storage_dir(self) -> Optional[str]:
        return self.clipboard_storage_dir

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        self._running.set()
        role = self.settings.get('role')
        if role == 'ado':
            target = self._clipboard_loop_server
            name = "ClipboardSrv"
        else:
            target = self._clipboard_loop_client
            name = "ClipboardCli"
        self._thread = threading.Thread(target=target, daemon=True, name=name)
        self._thread.start()

    def stop(self) -> None:
        self._running.clear()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1)
        self._thread = None

    # ------------------------------------------------------------------
    # External interface
    # ------------------------------------------------------------------
    def handle_network_message(self, peer: Any, data: dict) -> bool:
        msg_type = data.get('type')
        if msg_type == 'clipboard_data':
            self._handle_clipboard_data_message(peer, data)
            return True
        if msg_type == 'clipboard_clear':
            self._handle_clipboard_clear_message(peer)
            return True
        return False

    def ensure_storage_cleanup(self, *, force: bool = False) -> None:
        self._ensure_clipboard_storage_cleanup(force=force)

    # ------------------------------------------------------------------
    # Clipboard utilities
    # ------------------------------------------------------------------
    def _initialize_clipboard_storage(self) -> None:
        documents_dir = QStandardPaths.writableLocation(QStandardPaths.DocumentsLocation)
        if not documents_dir:
            documents_dir = os.path.join(os.path.expanduser("~"), "Documents")
            logging.debug(
                "Qt did not return a Documents path; using fallback %s for clipboard storage.",
                documents_dir,
            )

        base_dir = os.path.join(
            documents_dir,
            BRAND_NAME,
            "Szamitepvalto-Extravaganza",
            CLIPBOARD_STORAGE_DIRNAME,
        )
        try:
            os.makedirs(base_dir, exist_ok=True)
        except Exception as exc:
            logging.error(
                "Unable to create shared clipboard directory %s: %s",
                base_dir,
                exc,
                exc_info=True,
            )
            return

        self.clipboard_storage_dir = base_dir
        self._clipboard_cleanup_marker = os.path.join(base_dir, ".last_cleanup")
        logging.info("Shared clipboard storage initialised at %s", base_dir)
        self._ensure_clipboard_storage_cleanup()

    def _ensure_clipboard_storage_cleanup(self, *, force: bool = False) -> None:
        directory = self.clipboard_storage_dir
        marker = self._clipboard_cleanup_marker
        if not directory or not marker:
            return

        now = time.time()
        last_cleanup = self._clipboard_last_cleanup or 0.0

        marker_timestamp: Optional[float] = None
        if os.path.exists(marker):
            try:
                with open(marker, "r", encoding="utf-8") as handle:
                    content = handle.read().strip()
                if content:
                    marker_timestamp = float(content)
            except Exception as exc:
                logging.debug(
                    "Failed to read clipboard cleanup marker %s: %s",
                    marker,
                    exc,
                )
                marker_timestamp = None
            if marker_timestamp is None:
                try:
                    marker_timestamp = os.path.getmtime(marker)
                except OSError:
                    marker_timestamp = None

        if marker_timestamp:
            last_cleanup = marker_timestamp
            self._clipboard_last_cleanup = last_cleanup

        if not force and last_cleanup and now - last_cleanup < CLIPBOARD_CLEANUP_INTERVAL_SECONDS:
            return

        logging.info(
            "Performing daily cleanup of shared clipboard storage at %s",
            directory,
        )

        try:
            entries = os.listdir(directory)
        except Exception as exc:
            logging.warning(
                "Failed to list clipboard storage directory %s: %s",
                directory,
                exc,
            )
            entries = []

        for entry in entries:
            path = os.path.join(directory, entry)
            try:
                if marker and os.path.abspath(path) == os.path.abspath(marker):
                    continue
            except OSError:
                if marker and path == marker:
                    continue
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=False)
                else:
                    os.remove(path)
            except FileNotFoundError:
                continue
            except Exception as exc:
                logging.warning(
                    "Failed to remove clipboard artifact %s: %s",
                    path,
                    exc,
                )

        try:
            with open(marker, "w", encoding="utf-8") as handle:
                handle.write(str(now))
            os.utime(marker, (now, now))
        except Exception as exc:
            logging.warning(
                "Failed to update clipboard cleanup marker %s: %s",
                marker,
                exc,
            )
        else:
            self._clipboard_last_cleanup = now

    def _build_unique_storage_name(
        self, base_name: str, *, extension: Optional[str] = None
    ) -> str:
        directory = self.clipboard_storage_dir
        if not directory:
            return base_name

        safe_base = base_name.replace(os.sep, "_")
        if os.altsep:
            safe_base = safe_base.replace(os.altsep, "_")
        candidate = safe_base
        counter = 1

        def _target(name: str) -> str:
            if extension:
                return os.path.join(directory, f"{name}{extension}")
            return os.path.join(directory, name)

        while os.path.exists(_target(candidate)):
            counter += 1
            candidate = f"{safe_base}_{counter:02d}"

        return candidate

    def _persist_clipboard_item(self, item: dict) -> None:
        if self.settings.get('role') != 'ado':
            return

        directory = self.clipboard_storage_dir
        if not directory:
            logging.debug("Clipboard storage directory is not initialised; skipping persistence.")
            return

        fmt = item.get('format')
        if fmt not in {'image', 'files'}:
            return

        digest = item.get('digest')
        key: Optional[tuple[str, str]] = None
        if digest:
            key = (fmt, str(digest))
            if key == self._clipboard_last_persisted_digest:
                logging.debug(
                    "Skipping clipboard persistence for duplicate %s payload (digest=%s).",
                    fmt,
                    digest,
                )
                return

        raw_data = item.get('data')
        if isinstance(raw_data, bytes):
            payload = raw_data
        elif isinstance(raw_data, bytearray):
            payload = bytes(raw_data)
        elif isinstance(raw_data, memoryview):
            payload = raw_data.tobytes()
        else:
            logging.debug(
                "Clipboard item in format %s does not provide raw bytes; skipping persistence.",
                fmt,
            )
            return

        self._ensure_clipboard_storage_cleanup()

        digest_fragment = str(item.get('digest') or 'nohash')[:12]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_name = f"{timestamp}_{fmt}_{digest_fragment}"

        if fmt == 'image':
            encoding = str(item.get('encoding') or 'dib').lower()
            extension = '.png' if encoding == 'png' else '.dib'
            unique_name = self._build_unique_storage_name(base_name, extension=extension)
            target_path = os.path.join(directory, f"{unique_name}{extension}")
            try:
                with open(target_path, 'wb') as handle:
                    handle.write(payload)
            except Exception as exc:
                logging.error(
                    "Failed to persist clipboard image to %s: %s",
                    target_path,
                    exc,
                    exc_info=True,
                )
                return

            logging.info(
                "Clipboard image saved to %s (%d bytes, encoding=%s).",
                target_path,
                len(payload),
                encoding,
            )
            if key:
                self._clipboard_last_persisted_digest = key
            return

        if fmt != 'files':
            return

        unique_name = self._build_unique_storage_name(base_name)

        extracted_files = []
        skipped_members = 0
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue

                    normalized = PurePosixPath(info.filename.replace("\\", "/"))
                    parts = [
                        part
                        for part in normalized.parts
                        if part not in {"", ".", ".."}
                    ]
                    if not parts:
                        skipped_members += 1
                        continue

                    original_name = parts[-1]
                    stem, extension = os.path.splitext(original_name)

                    prefix = "_".join(parts[:-1])
                    if prefix:
                        stem = f"{prefix}_{stem}" if stem else prefix

                    candidate_base = f"{unique_name}_{stem}" if stem else unique_name
                    safe_base = self._build_unique_storage_name(
                        candidate_base,
                        extension=extension if extension else None,
                    )
                    if extension:
                        target_path = os.path.join(directory, f"{safe_base}{extension}")
                    else:
                        target_path = os.path.join(directory, safe_base)

                    try:
                        with archive.open(info, "r") as source, open(
                            target_path, "wb"
                        ) as destination:
                            shutil.copyfileobj(source, destination)
                    except Exception as exc:
                        logging.warning(
                            "Failed to extract clipboard file %s: %s",
                            info.filename,
                            exc,
                        )
                        try:
                            os.remove(target_path)
                        except OSError:
                            pass
                        continue

                    extracted_files.append(target_path)
        except zipfile.BadZipFile as exc:
            logging.error(
                "Clipboard file payload is not a valid archive: %s",
                exc,
            )
            return
        except Exception as exc:
            logging.error(
                "Failed to unpack clipboard files into %s: %s",
                directory,
                exc,
                exc_info=True,
            )
            for path in extracted_files:
                try:
                    os.remove(path)
                except OSError:
                    pass
            return

        if not extracted_files:
            logging.info(
                "Clipboard file payload did not contain any extractable files (skipped %d members).",
                skipped_members,
            )
            return

        file_count = item.get('file_count')
        if not file_count and item.get('entries'):
            file_count = len(item['entries'])
        try:
            file_count_int = int(file_count) if file_count is not None else None
        except (TypeError, ValueError):
            file_count_int = None

        logging.info(
            "Clipboard files saved into %s (%s item%s, %d bytes payload, %d skipped).",
            directory,
            file_count_int if file_count_int is not None else 'unknown',
            '' if file_count_int == 1 else 's',
            len(payload),
            skipped_members,
        )
        if key:
            self._clipboard_last_persisted_digest = key

    def _remember_last_clipboard(self, item: Optional[dict]) -> None:
        self.last_clipboard_item = item.copy() if item else None

    def _apply_system_clipboard(self, item: dict) -> None:
        if not item:
            return
        try:
            self._ignore_next_clipboard_change.set()
            write_clipboard_content(item)
            logging.debug("System clipboard updated from shared data.")
        except Exception as exc:
            logging.error("Failed to set clipboard: %s", exc, exc_info=True)

    def _store_shared_clipboard(self, item: dict, *, timestamp: Optional[float] = None) -> dict:
        stored = item.copy()
        stored['timestamp'] = float(timestamp if timestamp is not None else time.time())
        with self.clipboard_lock:
            self.shared_clipboard_item = stored
        if self.settings.get('role') == 'ado':
            try:
                self._persist_clipboard_item(stored)
            except Exception as exc:
                logging.error(
                    "Failed to persist clipboard payload locally: %s",
                    exc,
                    exc_info=True,
                )
        return stored

    def _build_clipboard_payload(self, item: dict, *, timestamp: Optional[float] = None) -> dict:
        ts = float(timestamp if timestamp is not None else item.get('timestamp', time.time()))
        payload = {
            'type': 'clipboard_data',
            'format': item['format'],
            'encoding': item.get('encoding'),
            'size': item.get('size'),
            'digest': item.get('digest'),
            'timestamp': ts,
            'data': item['data'],
        }
        if 'length' in item:
            payload['length'] = item['length']
        if 'width' in item:
            payload['width'] = item['width']
        if 'height' in item:
            payload['height'] = item['height']
        if 'bits_per_pixel' in item:
            payload['bits_per_pixel'] = item['bits_per_pixel']
        if 'entries' in item:
            payload['entries'] = item['entries']
        if 'file_count' in item:
            payload['file_count'] = item['file_count']
        if 'total_size' in item:
            payload['total_size'] = item['total_size']
        return payload

    def _apply_clipboard_clear(self) -> None:
        self._ignore_next_clipboard_change.set()
        try:
            clear_clipboard()
        except Exception as exc:
            logging.error("Failed to clear clipboard: %s", exc, exc_info=True)
        self._remember_last_clipboard(None)
        with self.clipboard_lock:
            self.shared_clipboard_item = None

    def _clear_shared_clipboard(self, *, broadcast: bool = False) -> None:
        logging.info("Clearing shared clipboard contents.")
        self._apply_clipboard_clear()
        if broadcast and self.settings.get('role') == 'ado':
            payload = {'type': 'clipboard_clear', 'timestamp': time.time()}
            provider = self._get_input_provider_socket()
            exclude: set[Any] = set()
            if provider:
                if not self._send_to_provider_callback(payload):
                    logging.warning("Failed to notify input provider about clipboard clear.")
                exclude.add(provider)
            clients = list(self._get_client_sockets())
            if clients:
                self._broadcast_callback(payload, exclude)

    def _check_clipboard_expiration(self) -> None:
        if self.settings.get('role') != 'ado':
            return
        with self.clipboard_lock:
            item = self.shared_clipboard_item
        if not item:
            return
        timestamp = item.get('timestamp')
        if not timestamp:
            return
        if time.time() - float(timestamp) >= self.clipboard_expiry_seconds:
            logging.info(
                "Shared clipboard entry expired after %.0f seconds.",
                self.clipboard_expiry_seconds,
            )
            self._clear_shared_clipboard(broadcast=True)

    def _get_shared_clipboard_payload(self) -> Optional[dict]:
        with self.clipboard_lock:
            item = self.shared_clipboard_item
        if not item:
            return None
        timestamp = item.get('timestamp')
        if timestamp and time.time() - float(timestamp) >= self.clipboard_expiry_seconds:
            return None
        return self._build_clipboard_payload(item)

    def _handle_clipboard_data_message(self, sock, data: dict, *, from_local: bool = False) -> None:
        item = normalize_clipboard_item(data)
        if not item:
            logging.debug("Ignoring invalid clipboard payload from %s", sock)
            return
        timestamp = data.get('timestamp')
        if from_local or timestamp is None:
            timestamp = time.time()
        role = self.settings.get('role')
        if role == 'ado':
            stored = self._store_shared_clipboard(item, timestamp=timestamp)
            if not from_local and not clipboard_items_equal(item, self.last_clipboard_item):
                self._apply_system_clipboard(item)
            self._remember_last_clipboard(item)
            payload = self._build_clipboard_payload(stored)
            provider = self._get_input_provider_socket()
            exclude: set[Any] = set()
            if sock:
                exclude.add(sock)
            if provider:
                if provider is not sock:
                    if not self._send_to_provider_callback(payload):
                        logging.warning("Failed to forward clipboard update to input provider.")
                    exclude.add(provider)
                else:
                    exclude.add(provider)
            clients = list(self._get_client_sockets())
            if clients:
                self._broadcast_callback(payload, exclude)
        else:
            if not clipboard_items_equal(item, self.last_clipboard_item):
                self._apply_system_clipboard(item)
            self._remember_last_clipboard(item)
            if timestamp is not None:
                stored = item.copy()
                stored['timestamp'] = float(timestamp)
                with self.clipboard_lock:
                    self.shared_clipboard_item = stored

    def _handle_clipboard_clear_message(self, sock) -> None:
        role = self.settings.get('role')
        if role == 'ado':
            self._clear_shared_clipboard(broadcast=True)
        else:
            self._apply_clipboard_clear()

    # ------------------------------------------------------------------
    # Clipboard synchronisation loops
    # ------------------------------------------------------------------
    def _clipboard_loop_server(self) -> None:
        logging.info("Clipboard server loop started.")
        while self._running.is_set():
            if self._ignore_next_clipboard_change.is_set():
                self._ignore_next_clipboard_change.clear()
                time.sleep(0.5)
                continue

            item = read_clipboard_content()
            if item and not clipboard_items_equal(item, self.last_clipboard_item):
                self._remember_last_clipboard(item)
                stored = self._store_shared_clipboard(item)
                payload = self._build_clipboard_payload(stored)
                provider = self._get_input_provider_socket()
                exclude: set[Any] = set()
                if provider:
                    if not self._send_to_provider_callback(payload):
                        logging.warning("Failed to forward clipboard update to input provider.")
                    exclude.add(provider)
                clients = list(self._get_client_sockets())
                if clients:
                    self._broadcast_callback(payload, exclude)
            self._check_clipboard_expiration()
            time.sleep(0.3)
        logging.info("Clipboard server loop stopped.")

    def _clipboard_loop_client(self) -> None:
        logging.info("Clipboard client loop started.")
        while self._running.is_set():
            if self._ignore_next_clipboard_change.is_set():
                self._ignore_next_clipboard_change.clear()
                time.sleep(0.5)
                continue

            item = read_clipboard_content()
            if item and not clipboard_items_equal(item, self.last_clipboard_item):
                self._remember_last_clipboard(item)
                sock = self._get_server_socket()
                if sock:
                    payload = self._build_clipboard_payload(item)
                    if not self._send_to_peer_callback(sock, payload):
                        logging.warning("Failed to send clipboard update to server.")
            time.sleep(0.3)
        logging.info("Clipboard client loop stopped.")
