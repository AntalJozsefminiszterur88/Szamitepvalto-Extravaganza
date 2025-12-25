import io
import logging
import os
import shutil
import tempfile
import threading
import time
import zipfile
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any, Callable, Iterable, Optional

from config.constants import BRAND_NAME
from kvm_core.clipboard_server import CentralClipboardServer, CENTRAL_CLIPBOARD_PORT
from utils.path_helpers import resolve_documents_directory
from utils.clipboard_sync import (
    clear_clipboard,
    clipboard_items_equal,
    _compute_digest,
    _compute_file_payload_digest,
    get_clipboard_sequence_number,
    get_clipboard_metadata,
    normalize_clipboard_item,
    pack_files_to_zip,
    read_clipboard_content,
    set_clipboard_from_file,
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
        self._last_clipboard_metadata: Optional[dict] = None
        self.shared_clipboard_item: Optional[dict] = None
        self.remote_clipboard_metadata: Optional[dict] = None
        self.clipboard_expiry_seconds = 12 * 60 * 60
        self._ignore_next_clipboard_change = threading.Event()
        self._last_clipboard_sequence: Optional[int] = None

        self.clipboard_storage_dir: Optional[str] = None
        self._clipboard_cleanup_marker: Optional[str] = None
        self._clipboard_last_cleanup: float = 0.0
        self._clipboard_last_persisted_digest: Optional[tuple[str, str]] = None
        self._persisted_payloads: dict[tuple[str, str], list[str]] = {}
        self._last_processed_clipboard_sequence: Optional[int] = None
        self._last_clipboard_write_time: float = 0.0
        self._internal_update_flag = False
        self._last_injected_digest: Optional[str] = None
        self._central_clipboard_server: Optional[CentralClipboardServer] = None
        self._last_uploaded_filename: Optional[str] = None

        if self.settings.get('role') == 'ado':
            self._central_clipboard_server = CentralClipboardServer()
            self._central_clipboard_server.start()
            self.clipboard_storage_dir = self._central_clipboard_server.storage_dir

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
        self._last_clipboard_sequence = None
        self._last_processed_clipboard_sequence = None
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
        logging.info(f"Stopping {self.__class__.__name__}...")
        self._running.clear()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1)
        self._thread = None
        self._last_clipboard_sequence = None
        self._last_processed_clipboard_sequence = None
        if self._central_clipboard_server:
            self._central_clipboard_server.stop()
        logging.info(f"{self.__class__.__name__} stopped.")

    # ------------------------------------------------------------------
    # External interface
    # ------------------------------------------------------------------
    def handle_network_message(self, peer: Any, data: dict) -> bool:
        msg_type = data.get('type')
        if msg_type == 'clipboard_notify':
            self._handle_clipboard_notify_message(peer, data)
            return True
        if msg_type == 'clipboard_clear':
            self._handle_clipboard_clear_message(peer)
            return True
        return False

    def ensure_storage_cleanup(self, *, force: bool = False) -> None:
        self._ensure_clipboard_storage_cleanup(force=force)

    def get_shared_clipboard_snapshot(self) -> Optional[dict]:
        """Return a serialisable snapshot of the shared clipboard state."""

        with self.clipboard_lock:
            if not self.shared_clipboard_item:
                return None
            item = self.shared_clipboard_item.copy()

        snapshot: dict[str, Any] = {
            'format': item.get('format'),
            'timestamp': float(item.get('timestamp')) if item.get('timestamp') else None,
        }

        if snapshot['format'] == 'files':
            entries: list[dict[str, Any]] = []
            raw_entries = item.get('entries')
            if isinstance(raw_entries, Iterable):
                for entry in raw_entries:
                    if not isinstance(entry, dict):
                        continue
                    entries.append(
                        {
                            'name': str(entry.get('name', '')),
                            'is_dir': bool(entry.get('is_dir', False)),
                            'size': entry.get('size'),
                        }
                    )
            snapshot['entries'] = entries
            snapshot['file_count'] = item.get('file_count') or len(entries)
            snapshot['total_size'] = item.get('total_size')
            snapshot['size'] = item.get('size')

        return snapshot

    def clear_shared_clipboard(self, *, broadcast: bool = False) -> bool:
        """Clear the shared clipboard contents if present."""

        with self.clipboard_lock:
            has_item = self.shared_clipboard_item is not None
        if not has_item:
            return False

        self._clear_shared_clipboard(broadcast=broadcast)
        return True

    def purge_shared_clipboard_artifacts(self) -> int:
        """Remove persisted files related to the active shared clipboard entry."""

        directory = self.clipboard_storage_dir
        if not directory:
            return 0

        with self.clipboard_lock:
            item = self.shared_clipboard_item

        if not item:
            return 0

        fmt = item.get('format')
        digest = item.get('digest')
        if not digest or not fmt:
            return 0

        key = (fmt, str(digest))
        stored_paths = self._persisted_payloads.pop(key, [])
        removed = 0
        for path in stored_paths:
            try:
                if os.path.exists(path):
                    os.remove(path)
                    removed += 1
            except Exception as exc:  # pragma: no cover - best-effort cleanup
                logging.debug(
                    "Failed to remove persisted clipboard artifact %s: %s",
                    path,
                    exc,
                    exc_info=True,
                )

        if key == self._clipboard_last_persisted_digest:
            self._clipboard_last_persisted_digest = None

        return removed

    # ------------------------------------------------------------------
    # Clipboard utilities
    # ------------------------------------------------------------------
    def _initialize_clipboard_storage(self) -> None:
        documents_dir = resolve_documents_directory()
        if not documents_dir.exists():
            try:
                documents_dir.mkdir(parents=True, exist_ok=True)
            except Exception as exc:
                logging.error(
                    "Unable to create base documents directory %s: %s",
                    documents_dir,
                    exc,
                    exc_info=True,
                )
                return

        base_dir = os.path.join(
            str(documents_dir),
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
        if self._central_clipboard_server:
            self._central_clipboard_server.cleanup_old_files()
            return

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

        performed_cleanup = False
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
            else:
                performed_cleanup = True

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
            if performed_cleanup:
                self._persisted_payloads.clear()

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

        self._ensure_clipboard_storage_cleanup()

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
            stored_paths = self._persisted_payloads.get(key)
            if stored_paths and all(os.path.exists(path) for path in stored_paths):
                logging.debug(
                    "Reusing existing persisted %s payload for digest %s (paths=%s).",
                    fmt,
                    digest,
                    stored_paths,
                )
                self._clipboard_last_persisted_digest = key
                return
            if stored_paths:
                self._persisted_payloads.pop(key, None)

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
                self._persisted_payloads[key] = [target_path]
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
            self._persisted_payloads[key] = extracted_files

    def _remember_last_clipboard(self, item: Optional[dict]) -> None:
        self.last_clipboard_item = item.copy() if item else None

    def _compute_item_digest(self, item: dict) -> Optional[str]:
        digest = item.get('digest')
        if isinstance(digest, str) and digest:
            return digest
        fmt = item.get('format')
        if fmt in {'text', 'html'}:
            data = item.get('data')
            if data is None:
                return None
            if isinstance(data, (bytes, bytearray, memoryview)):
                raw = bytes(data)
            else:
                raw = str(data).encode('utf-8')
            return _compute_digest(fmt, 'utf-8', raw)
        if fmt == 'image':
            data = item.get('data')
            if data is None:
                return None
            if not isinstance(data, (bytes, bytearray, memoryview)):
                return None
            encoding = str(item.get('encoding') or 'dib')
            return _compute_digest('image', encoding, bytes(data))
        if fmt == 'files':
            data = item.get('data')
            if isinstance(data, (bytes, bytearray, memoryview)):
                try:
                    return _compute_file_payload_digest(bytes(data))
                except Exception:
                    return None
        return None

    def _is_self_injected(self, item: dict) -> bool:
        digest = self._compute_item_digest(item)
        if digest and digest == self._last_injected_digest:
            logging.info("Ignored self-injected clipboard content (hash match).")
            return True
        return False

    def _apply_system_clipboard(self, item: dict) -> None:
        if not item:
            return
        try:
            self._ignore_next_clipboard_change.set()
            write_clipboard_content(item)
            self._last_clipboard_write_time = time.time()
            digest = self._compute_item_digest(item)
            if digest:
                self._last_injected_digest = digest
            logging.debug("System clipboard updated from shared data.")
        except Exception as exc:
            logging.error("Failed to set clipboard: %s", exc, exc_info=True)

    def _store_shared_clipboard(self, item: dict, *, timestamp: Optional[float] = None) -> dict:
        stored = item.copy()
        stored['timestamp'] = float(timestamp if timestamp is not None else time.time())
        with self.clipboard_lock:
            self.shared_clipboard_item = stored
        if self.settings.get('role') == 'ado' and self._central_clipboard_server is None:
            try:
                self._persist_clipboard_item(stored)
            except Exception as exc:
                logging.error(
                    "Failed to persist clipboard payload locally: %s",
                    exc,
                    exc_info=True,
                )
        return stored

    def _store_shared_clipboard_metadata(
        self, metadata: dict, *, timestamp: Optional[float] = None
    ) -> dict:
        stored = metadata.copy()
        stored['timestamp'] = float(timestamp if timestamp is not None else time.time())
        with self.clipboard_lock:
            self.shared_clipboard_item = stored
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

    def _build_clipboard_notify_payload(
        self,
        filename: str,
        fmt: str,
        metadata: Optional[dict] = None,
        *,
        timestamp: Optional[float] = None,
    ) -> dict:
        ts = float(timestamp if timestamp is not None else time.time())
        payload = {
            'type': 'clipboard_notify',
            'filename': filename,
            'format': fmt,
            'timestamp': ts,
        }
        if metadata:
            for key in (
                'encoding',
                'size',
                'digest',
                'entries',
                'file_count',
                'total_size',
            ):
                if key in metadata:
                    payload[key] = metadata[key]
        return payload

    def _resolve_central_server_host(self) -> Optional[str]:
        if self.settings.get('role') == 'ado':
            return "127.0.0.1"
        sock = self._get_server_socket()
        if sock:
            try:
                return sock.getpeername()[0]
            except OSError:
                return None
        return self.settings.get('server_ip')

    def _upload_clipboard_file(self, file_path: str) -> Optional[str]:
        host = self._resolve_central_server_host()
        if not host:
            logging.warning("Cannot upload clipboard data: missing server host.")
            return None

        url = f"http://{host}:{CENTRAL_CLIPBOARD_PORT}/upload"
        try:
            with open(file_path, "rb") as handle:
                payload = handle.read()
        except Exception as exc:
            logging.error("Failed to read clipboard file %s: %s", file_path, exc)
            return None

        request = urllib.request.Request(url, data=payload, method="POST")
        request.add_header("Content-Type", "application/octet-stream")
        request.add_header("Content-Length", str(len(payload)))
        request.add_header("X-Filename", os.path.basename(file_path))

        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                filename = response.read().decode("utf-8").strip()
        except Exception as exc:
            logging.error("Failed to upload clipboard data to %s: %s", url, exc)
            return None

        if not filename:
            logging.error("Clipboard upload did not return a filename.")
            return None
        return filename

    def _download_clipboard_file(self, filename: str) -> Optional[str]:
        host = self._resolve_central_server_host()
        if not host:
            logging.warning("Cannot download clipboard data: missing server host.")
            return None

        url = f"http://{host}:{CENTRAL_CLIPBOARD_PORT}/download/{urllib.parse.quote(filename)}"
        temp_dir = tempfile.mkdtemp(prefix="clipboard_download_")
        target_path = os.path.join(temp_dir, filename)

        try:
            with urllib.request.urlopen(url, timeout=10) as response, open(
                target_path, "wb"
            ) as handle:
                shutil.copyfileobj(response, handle)
        except Exception as exc:
            logging.error("Failed to download clipboard data from %s: %s", url, exc)
            try:
                if os.path.exists(target_path):
                    os.remove(target_path)
            except OSError:
                pass
            return None

        return target_path

    def _prepare_clipboard_upload(self, item: dict, fmt: str) -> Optional[tuple[str, dict, list[str]]]:
        metadata: dict[str, Any] = {}
        cleanup_paths: list[str] = []

        if fmt == 'files':
            paths = item.get('paths') or item.get('data')
            if not paths:
                return None
            packaged = pack_files_to_zip(paths)
            if not packaged:
                return None
            file_path = packaged['path']
            cleanup_paths.append(os.path.dirname(file_path))
            metadata.update(
                {
                    'encoding': packaged.get('encoding'),
                    'size': packaged.get('size'),
                    'digest': packaged.get('digest'),
                    'entries': packaged.get('entries'),
                    'file_count': packaged.get('file_count'),
                    'total_size': packaged.get('total_size'),
                }
            )
            return file_path, metadata, cleanup_paths

        if fmt == 'image':
            raw = item.get('data')
            if raw is None:
                return None
            if isinstance(raw, (bytearray, memoryview)):
                raw_bytes = bytes(raw)
            elif isinstance(raw, bytes):
                raw_bytes = raw
            else:
                return None
            encoding = str(item.get('encoding') or 'png').lower()
            extension = ".png" if encoding == "png" else ".dib"
            temp_dir = tempfile.mkdtemp(prefix="clipboard_image_")
            file_path = os.path.join(temp_dir, f"clipboard_image{extension}")
            with open(file_path, "wb") as handle:
                handle.write(raw_bytes)
            cleanup_paths.append(temp_dir)
            metadata.update(
                {
                    'encoding': encoding,
                    'size': len(raw_bytes),
                    'digest': _compute_digest('image', encoding, raw_bytes),
                }
            )
            return file_path, metadata, cleanup_paths

        if fmt in {'text', 'html'}:
            raw_text = item.get('data', '')
            if isinstance(raw_text, (bytes, bytearray, memoryview)):
                raw_bytes = bytes(raw_text)
            else:
                raw_bytes = str(raw_text).encode('utf-8')
            extension = ".html" if fmt == "html" else ".txt"
            temp_dir = tempfile.mkdtemp(prefix="clipboard_text_")
            file_path = os.path.join(temp_dir, f"clipboard_payload{extension}")
            with open(file_path, "wb") as handle:
                handle.write(raw_bytes)
            cleanup_paths.append(temp_dir)
            metadata.update(
                {
                    'size': len(raw_bytes),
                    'digest': _compute_digest(fmt, 'utf-8', raw_bytes),
                }
            )
            return file_path, metadata, cleanup_paths

        return None

    def _cleanup_clipboard_upload(self, paths: list[str]) -> None:
        for path in paths:
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
                elif os.path.exists(path):
                    os.remove(path)
            except Exception:
                continue

    def _dispatch_clipboard_notify(
        self, payload: dict, *, exclude: Optional[Iterable[Any]] = None
    ) -> None:
        role = self.settings.get('role')
        if role == 'ado':
            provider = self._get_input_provider_socket()
            exclude_set = set(exclude or [])
            if provider:
                if not self._send_to_provider_callback(payload):
                    logging.warning("Failed to forward clipboard notify to input provider.")
                exclude_set.add(provider)
            clients = list(self._get_client_sockets())
            if clients:
                self._broadcast_callback(payload, exclude_set)
        else:
            sock = self._get_server_socket()
            if sock and not self._send_to_peer_callback(sock, payload):
                logging.warning("Failed to send clipboard notify to server.")

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

    def _handle_clipboard_notify_message(self, sock, data: dict) -> None:
        filename = data.get('filename')
        if not isinstance(filename, str) or not filename:
            logging.debug("Missing filename in clipboard notify payload from %s", sock)
            return
        if filename == self._last_uploaded_filename:
            logging.info("Ignoring clipboard notify for recently uploaded payload.")
            return

        fmt = data.get('format') or 'text'
        timestamp = data.get('timestamp')
        try:
            ts_value = float(timestamp) if timestamp is not None else time.time()
        except (TypeError, ValueError):
            ts_value = time.time()

        metadata = {
            key: data.get(key)
            for key in ('encoding', 'size', 'digest', 'entries', 'file_count', 'total_size')
            if key in data
        }
        metadata['format'] = fmt
        metadata['timestamp'] = ts_value

        def _apply_download() -> None:
            target_path = self._download_clipboard_file(filename)
            if not target_path:
                return

            digest: Optional[str] = None
            try:
                self._internal_update_flag = True
                self._ignore_next_clipboard_change.set()
                set_clipboard_from_file(target_path, fmt if fmt == 'files' else None)
                self._last_clipboard_write_time = time.time()
                try:
                    with open(target_path, "rb") as handle:
                        raw = handle.read()
                    if fmt in {'text', 'html'}:
                        digest = _compute_digest(fmt, 'utf-8', raw)
                    elif fmt == 'image':
                        _, extension = os.path.splitext(target_path)
                        encoding = "png" if extension.lower() == ".png" else "dib"
                        digest = _compute_digest("image", encoding, raw)
                    elif fmt == 'files':
                        digest = _compute_file_payload_digest(raw)
                except Exception:
                    digest = metadata.get('digest')
                self._last_injected_digest = digest
            except Exception as exc:
                logging.error("Failed to apply downloaded clipboard payload: %s", exc, exc_info=True)
                return
            finally:
                self._internal_update_flag = False

            stored = metadata.copy()
            if digest:
                stored['digest'] = digest
            self._remember_last_clipboard(stored)
            self._last_clipboard_metadata = stored.copy()
            with self.clipboard_lock:
                self.shared_clipboard_item = stored

        threading.Thread(
            target=_apply_download, name="ClipboardCentralApply", daemon=True
        ).start()

        if self.settings.get('role') == 'ado':
            payload = self._build_clipboard_notify_payload(
                filename, fmt, metadata, timestamp=ts_value
            )
            provider = self._get_input_provider_socket()
            exclude: set[Any] = set()
            if sock:
                exclude.add(sock)
            if provider:
                if not self._send_to_provider_callback(payload):
                    logging.warning("Failed to forward clipboard notify to input provider.")
                exclude.add(provider)
            clients = list(self._get_client_sockets())
            if clients:
                self._broadcast_callback(payload, exclude)

    def _extract_single_file_from_zip(self, zip_path: str) -> Optional[str]:
        try:
            with zipfile.ZipFile(zip_path) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    extract_dir = tempfile.mkdtemp(prefix="clipboard_extract_")
                    return archive.extract(info, path=extract_dir)
        except zipfile.BadZipFile:
            logging.error("Received invalid clipboard archive; refusing to apply.")
        except Exception as exc:
            logging.error("Failed to extract clipboard payload: %s", exc, exc_info=True)
        return None

    def _handle_clipboard_clear_message(self, sock) -> None:
        role = self.settings.get('role')
        if role == 'ado':
            self._clear_shared_clipboard(broadcast=True)
        else:
            self._apply_clipboard_clear()
        self.remote_clipboard_metadata = None

    # ------------------------------------------------------------------
    # Clipboard synchronisation loops
    # ------------------------------------------------------------------
    def _clipboard_loop_server(self) -> None:
        logging.info("Clipboard server loop started.")
        while self._running.is_set():
            if self._internal_update_flag or time.time() - self._last_clipboard_write_time < 1:
                time.sleep(0.1)
                continue
            if self._ignore_next_clipboard_change.is_set():
                self._ignore_next_clipboard_change.clear()
                self._refresh_clipboard_sequence_marker()
                time.sleep(0.5)
                continue

            sequence = get_clipboard_sequence_number()
            if sequence is not None:
                if self._last_clipboard_sequence == sequence:
                    self._check_clipboard_expiration()
                    time.sleep(0.3)
                    continue
                previous_sequence = self._last_clipboard_sequence
                self._last_clipboard_sequence = sequence
                logging.info("Local clipboard changed. Checking for duplicates...")

            metadata = get_clipboard_metadata()
            if metadata:
                fmt = metadata.get('format')
                if fmt == 'text':
                    item = read_clipboard_content()
                    if item:
                        if self._is_self_injected(item):
                            continue
                        now = time.time()
                        item['timestamp'] = now
                        self._last_clipboard_metadata = None
                        is_duplicate = clipboard_items_equal(item, self.last_clipboard_item)
                        if (
                            is_duplicate
                            and sequence is not None
                            and sequence != self._last_processed_clipboard_sequence
                        ):
                            is_duplicate = False
                        if not is_duplicate:
                            prepared = self._prepare_clipboard_upload(item, fmt)
                            if not prepared:
                                logging.debug("Failed to package clipboard payload for %s.", fmt)
                                continue
                            file_path, upload_metadata, cleanup_paths = prepared
                            try:
                                filename = self._upload_clipboard_file(file_path)
                            finally:
                                self._cleanup_clipboard_upload(cleanup_paths)
                            if not filename:
                                continue
                            self._last_uploaded_filename = filename
                            stored_metadata = {
                                'format': fmt,
                                'timestamp': now,
                                **upload_metadata,
                            }
                            self._store_shared_clipboard_metadata(stored_metadata, timestamp=now)
                            self._remember_last_clipboard(item)
                            if sequence is not None:
                                self._last_processed_clipboard_sequence = sequence
                            payload = self._build_clipboard_notify_payload(
                                filename, fmt, upload_metadata, timestamp=now
                            )
                            logging.info(
                                "Broadcasting new clipboard content (format: %s).",
                                fmt,
                            )
                            self._dispatch_clipboard_notify(payload)
                        else:
                            logging.info("Ignored duplicate clipboard content.")
                elif fmt in {'image', 'files', 'html'}:
                    now = time.time()
                    metadata['timestamp'] = now
                    if self._is_self_injected(metadata):
                        continue
                    is_duplicate = metadata == self._last_clipboard_metadata
                    if (
                        is_duplicate
                        and sequence is not None
                        and sequence != self._last_processed_clipboard_sequence
                    ):
                        is_duplicate = False
                    if not is_duplicate:
                        item = read_clipboard_content()
                        if not item:
                            logging.debug("Clipboard read produced no data for %s.", fmt)
                            continue
                        item['timestamp'] = now
                        if fmt == 'image' and self._is_self_injected(item):
                            continue
                        prepared = self._prepare_clipboard_upload(item, fmt)
                        if not prepared:
                            logging.debug("Failed to package clipboard payload for %s.", fmt)
                            continue
                        file_path, upload_metadata, cleanup_paths = prepared
                        try:
                            filename = self._upload_clipboard_file(file_path)
                        finally:
                            self._cleanup_clipboard_upload(cleanup_paths)
                        if not filename:
                            continue
                        self._last_uploaded_filename = filename
                        stored_metadata = metadata.copy()
                        stored_metadata.update(upload_metadata)
                        self._store_shared_clipboard_metadata(stored_metadata, timestamp=now)
                        self._last_clipboard_metadata = stored_metadata.copy()
                        if sequence is not None:
                            self._last_processed_clipboard_sequence = sequence
                        payload = self._build_clipboard_notify_payload(
                            filename, fmt, stored_metadata, timestamp=now
                        )
                        logging.info(
                            "Broadcasting new clipboard content (format: %s).",
                            fmt,
                        )
                        self._dispatch_clipboard_notify(payload)
                    else:
                        logging.info("Ignored duplicate clipboard content.")
            self._check_clipboard_expiration()
            time.sleep(0.3)
        logging.info("Clipboard server loop stopped.")

    def _clipboard_loop_client(self) -> None:
        logging.info("Clipboard client loop started.")
        while self._running.is_set():
            if self._internal_update_flag or time.time() - self._last_clipboard_write_time < 1:
                time.sleep(0.1)
                continue
            if self._ignore_next_clipboard_change.is_set():
                self._ignore_next_clipboard_change.clear()
                self._refresh_clipboard_sequence_marker()
                time.sleep(0.5)
                continue

            sequence = get_clipboard_sequence_number()
            if sequence is not None:
                if self._last_clipboard_sequence == sequence:
                    time.sleep(0.3)
                    continue
                previous_sequence = self._last_clipboard_sequence
                self._last_clipboard_sequence = sequence
                logging.info("Local clipboard changed. Checking for duplicates...")

            metadata = get_clipboard_metadata()
            if metadata:
                fmt = metadata.get('format')
                if fmt == 'text':
                    item = read_clipboard_content()
                    if item:
                        if self._is_self_injected(item):
                            continue
                        now = time.time()
                        item['timestamp'] = now
                        self._last_clipboard_metadata = None
                        is_duplicate = clipboard_items_equal(item, self.last_clipboard_item)
                        if (
                            is_duplicate
                            and sequence is not None
                            and sequence != self._last_processed_clipboard_sequence
                        ):
                            is_duplicate = False
                        if not is_duplicate:
                            prepared = self._prepare_clipboard_upload(item, fmt)
                            if not prepared:
                                logging.debug("Failed to package clipboard payload for %s.", fmt)
                                continue
                            file_path, upload_metadata, cleanup_paths = prepared
                            try:
                                filename = self._upload_clipboard_file(file_path)
                            finally:
                                self._cleanup_clipboard_upload(cleanup_paths)
                            if not filename:
                                continue
                            self._last_uploaded_filename = filename
                            stored_metadata = {
                                'format': fmt,
                                'timestamp': now,
                                **upload_metadata,
                            }
                            self._store_shared_clipboard_metadata(stored_metadata, timestamp=now)
                            self._remember_last_clipboard(item)
                            if sequence is not None:
                                self._last_processed_clipboard_sequence = sequence
                            payload = self._build_clipboard_notify_payload(
                                filename, fmt, upload_metadata, timestamp=now
                            )
                            logging.info(
                                "Broadcasting new clipboard content (format: %s).",
                                fmt,
                            )
                            self._dispatch_clipboard_notify(payload)
                        else:
                            logging.info("Ignored duplicate clipboard content.")
                elif fmt in {'image', 'files', 'html'}:
                    now = time.time()
                    metadata['timestamp'] = now
                    if self._is_self_injected(metadata):
                        continue
                    is_duplicate = metadata == self._last_clipboard_metadata
                    if (
                        is_duplicate
                        and sequence is not None
                        and sequence != self._last_processed_clipboard_sequence
                    ):
                        is_duplicate = False
                    if not is_duplicate:
                        item = read_clipboard_content()
                        if not item:
                            logging.debug("Clipboard read produced no data for %s.", fmt)
                            continue
                        item['timestamp'] = now
                        if fmt == 'image' and self._is_self_injected(item):
                            continue
                        prepared = self._prepare_clipboard_upload(item, fmt)
                        if not prepared:
                            logging.debug("Failed to package clipboard payload for %s.", fmt)
                            continue
                        file_path, upload_metadata, cleanup_paths = prepared
                        try:
                            filename = self._upload_clipboard_file(file_path)
                        finally:
                            self._cleanup_clipboard_upload(cleanup_paths)
                        if not filename:
                            continue
                        self._last_uploaded_filename = filename
                        stored_metadata = metadata.copy()
                        stored_metadata.update(upload_metadata)
                        self._store_shared_clipboard_metadata(stored_metadata, timestamp=now)
                        self._last_clipboard_metadata = stored_metadata.copy()
                        if sequence is not None:
                            self._last_processed_clipboard_sequence = sequence
                        payload = self._build_clipboard_notify_payload(
                            filename, fmt, stored_metadata, timestamp=now
                        )
                        logging.info(
                            "Broadcasting new clipboard content (format: %s).",
                            fmt,
                        )
                        self._dispatch_clipboard_notify(payload)
                    else:
                        logging.info("Ignored duplicate clipboard content.")
            time.sleep(0.3)
        logging.info("Clipboard client loop stopped.")

    def _refresh_clipboard_sequence_marker(self) -> None:
        """Update the cached clipboard sequence number if available."""

        sequence = get_clipboard_sequence_number()
        if sequence is not None:
            self._last_clipboard_sequence = sequence
