"""Clipboard synchronisation service used by the KVM orchestrator."""

from __future__ import annotations

import io
import logging
import os
import shutil
import threading
import time
import zipfile
from datetime import datetime
from pathlib import PurePosixPath
from typing import Callable, Optional

from PySide6.QtCore import QObject, Signal, QStandardPaths

from core.config import BRAND_NAME
from utils.clipboard_sync import (
    clear_clipboard,
    clipboard_items_equal,
    normalize_clipboard_item,
    read_clipboard_content,
    write_clipboard_content,
)


CLIPBOARD_STORAGE_DIRNAME = "SharedClipboard"
CLIPBOARD_CLEANUP_INTERVAL_SECONDS = 24 * 60 * 60


class ClipboardManager(QObject):
    """Encapsulates clipboard state handling and persistence."""

    clipboard_update_captured = Signal(dict)

    def __init__(
        self,
        settings: dict,
        *,
        stability_monitor=None,
        monitor_prefix: Optional[str] = None,
    ) -> None:
        super().__init__()
        self.settings = settings
        self.stability_monitor = stability_monitor
        self.monitor_prefix = (monitor_prefix or "clipboard").rstrip("/")

        self.role: Optional[str] = settings.get("role")

        self.clipboard_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._monitor_active = threading.Event()

        self.last_clipboard_item: Optional[dict] = None
        self.shared_clipboard_item: Optional[dict] = None
        self.clipboard_lock = threading.Lock()
        self.clipboard_expiry_seconds = 12 * 60 * 60
        self._ignore_next_clipboard_change = threading.Event()

        self.clipboard_storage_dir: Optional[str] = None
        self._clipboard_cleanup_marker: Optional[str] = None
        self._clipboard_last_cleanup: float = 0.0
        self._clipboard_last_persisted_digest: Optional[tuple[str, str]] = None

        self._storage_directory_registered = False
        self._cleanup_task_name: Optional[str] = None

        if self.role == "ado":
            self._initialize_clipboard_storage()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def start_monitoring(self, role: Optional[str]) -> None:
        """Start clipboard monitoring loop for the specified role."""

        self.role = role or self.role or self.settings.get("role")

        if self.clipboard_thread and self.clipboard_thread.is_alive():
            logging.debug("ClipboardManager.start_monitoring called while active")
            return

        if self.role == "ado" and not self.clipboard_storage_dir:
            self._initialize_clipboard_storage()

        self._stop_event.clear()
        self._monitor_active.set()

        target: Callable[[], None]
        name: str
        if self.role == "ado":
            target = self._clipboard_loop_server
            name = "ClipboardSrv"
        else:
            target = self._clipboard_loop_client
            name = "ClipboardCli"

        self.clipboard_thread = threading.Thread(
            target=target,
            daemon=True,
            name=name,
        )
        self.clipboard_thread.start()

    def stop_monitoring(self) -> None:
        """Stop the clipboard monitoring loop."""

        self._monitor_active.clear()
        self._stop_event.set()
        thread = self.clipboard_thread
        if thread and thread.is_alive():
            if threading.current_thread() is not thread:
                thread.join(timeout=1)
        self.clipboard_thread = None

    def handle_remote_update(self, data: dict) -> Optional[dict]:
        """Process an incoming clipboard message from the network."""

        msg_type = data.get("type")
        if msg_type == "clipboard_data":
            return self._handle_clipboard_data_message(data)
        if msg_type == "clipboard_clear":
            return self._handle_clipboard_clear_message(data)
        logging.debug("ClipboardManager: unknown message type %s", msg_type)
        return None

    def check_clipboard_expiration(self) -> None:
        """Ensure that stored clipboard data does not outlive its TTL."""

        self._check_clipboard_expiration()

    def get_shared_clipboard_payload(self) -> Optional[dict]:
        """Return the currently shared clipboard payload, if still valid."""

        return self._get_shared_clipboard_payload()

    def ensure_clipboard_storage_cleanup(self, *, force: bool = False) -> None:
        """Expose cleanup so orchestrator can trigger it on demand."""

        self._ensure_clipboard_storage_cleanup(force=force)

    @property
    def monitor_thread(self) -> Optional[threading.Thread]:
        """Provide access to the monitoring thread for diagnostics."""

        return self.clipboard_thread

    def unregister_storage_monitoring(self) -> None:
        """Remove stability monitor registrations created by the manager."""

        monitor = self.stability_monitor
        if not monitor:
            return
        if self._storage_directory_registered and self.clipboard_storage_dir:
            try:
                monitor.remove_directory_quota(os.path.abspath(self.clipboard_storage_dir))
            except Exception:
                logging.exception("Failed to remove clipboard directory quota")
        self._storage_directory_registered = False
        if self._cleanup_task_name:
            try:
                monitor.remove_periodic_task(self._cleanup_task_name)
            except Exception:
                logging.exception("Failed to remove clipboard cleanup task")
        self._cleanup_task_name = None

    # ------------------------------------------------------------------
    # Clipboard handling helpers
    # ------------------------------------------------------------------
    def _clipboard_loop_server(self) -> None:
        logging.info("ClipboardManager server loop started")
        while self._monitor_active.is_set() and not self._stop_event.is_set():
            try:
                if self._ignore_next_clipboard_change.is_set():
                    self._ignore_next_clipboard_change.clear()
                    time.sleep(0.1)
                    continue
                item = read_clipboard_content()
                if item and not clipboard_items_equal(item, self.last_clipboard_item):
                    self._remember_last_clipboard(item)
                    stored = self._store_shared_clipboard(item)
                    payload = self._build_clipboard_payload(stored)
                    logging.debug("ClipboardManager emitting local clipboard update")
                    self.clipboard_update_captured.emit(payload)
            except Exception as exc:
                logging.debug("ClipboardManager server loop iteration failed: %s", exc, exc_info=True)
            finally:
                try:
                    self._check_clipboard_expiration()
                except Exception:
                    logging.exception("Clipboard expiration check failed")
            time.sleep(0.5)
        logging.info("ClipboardManager server loop stopped")

    def _clipboard_loop_client(self) -> None:
        logging.info("ClipboardManager client loop started")
        while self._monitor_active.is_set() and not self._stop_event.is_set():
            try:
                if self._ignore_next_clipboard_change.is_set():
                    self._ignore_next_clipboard_change.clear()
                    time.sleep(0.1)
                    continue
                item = read_clipboard_content()
                if item and not clipboard_items_equal(item, self.last_clipboard_item):
                    self._remember_last_clipboard(item)
                    payload = self._build_clipboard_payload(item)
                    logging.debug("ClipboardManager emitting client clipboard update")
                    self.clipboard_update_captured.emit(payload)
            except Exception as exc:
                logging.debug("ClipboardManager client loop iteration failed: %s", exc, exc_info=True)
            time.sleep(0.5)
        logging.info("ClipboardManager client loop stopped")

    def _handle_clipboard_data_message(self, data: dict) -> Optional[dict]:
        item = normalize_clipboard_item(data)
        if not item:
            logging.debug("ClipboardManager: invalid clipboard payload %s", data)
            return None

        timestamp = data.get("timestamp")
        if timestamp is None:
            timestamp = time.time()
        else:
            try:
                timestamp = float(timestamp)
            except (TypeError, ValueError):
                timestamp = time.time()

        if self.role == "ado":
            stored = self._store_shared_clipboard(item, timestamp=timestamp)
            if not clipboard_items_equal(item, self.last_clipboard_item):
                self._apply_system_clipboard(item)
            self._remember_last_clipboard(item)
            payload = self._build_clipboard_payload(stored, timestamp=timestamp)
            return payload

        if not clipboard_items_equal(item, self.last_clipboard_item):
            self._apply_system_clipboard(item)
        self._remember_last_clipboard(item)
        stored = item.copy()
        stored["timestamp"] = float(timestamp)
        with self.clipboard_lock:
            self.shared_clipboard_item = stored
        return None

    def _handle_clipboard_clear_message(self, data: dict) -> Optional[dict]:
        if self.role == "ado":
            self._clear_shared_clipboard(broadcast=False)
            payload = {
                "type": "clipboard_clear",
                "timestamp": data.get("timestamp", time.time()),
            }
            return payload

        self._apply_clipboard_clear()
        return None

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
        self._register_clipboard_monitoring()

    def _register_clipboard_monitoring(self) -> None:
        monitor = self.stability_monitor
        directory = self.clipboard_storage_dir
        if not monitor or not directory:
            return

        abs_directory = os.path.abspath(directory)
        if not self._storage_directory_registered:
            try:
                monitor.add_directory_quota(abs_directory, max_mb=512, min_free_mb=256)
                self._storage_directory_registered = True
            except Exception:
                logging.exception("Failed to register clipboard directory quota")

        task_name = f"{self.monitor_prefix}/clipboard_cleanup"
        if not self._cleanup_task_name:
            try:
                monitor.add_periodic_task(
                    task_name,
                    max(3600.0, CLIPBOARD_CLEANUP_INTERVAL_SECONDS / 2),
                    lambda: self._ensure_clipboard_storage_cleanup(force=True),
                )
                self._cleanup_task_name = task_name
            except Exception:
                logging.exception("Failed to register clipboard cleanup task")

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

        candidate = base_name
        suffix = extension or ""
        index = 1
        while True:
            path = os.path.join(directory, f"{candidate}{suffix}")
            if not os.path.exists(path):
                return candidate
            candidate = f"{base_name}_{index}"
            index += 1

    def _persist_clipboard_item(self, item: dict) -> None:
        if self.role != "ado":
            return

        directory = self.clipboard_storage_dir
        if not directory:
            logging.debug("Clipboard storage directory is not initialised; skipping persistence.")
            return

        fmt = item.get("format")
        if fmt not in {"image", "files"}:
            return

        digest = item.get("digest")
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

        raw_data = item.get("data")
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

        digest_fragment = str(item.get("digest") or "nohash")[:12]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"{timestamp}_{fmt}_{digest_fragment}"

        if fmt == "image":
            encoding = str(item.get("encoding") or "dib").lower()
            extension = ".png" if encoding == "png" else ".dib"
            unique_name = self._build_unique_storage_name(base_name, extension=extension)
            target_path = os.path.join(directory, f"{unique_name}{extension}")
            try:
                with open(target_path, "wb") as handle:
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
                        except Exception:
                            pass
                        continue

                    extracted_files.append(target_path)
        except zipfile.BadZipFile as exc:
            logging.error("Invalid clipboard file payload: %s", exc, exc_info=True)
            return
        except Exception as exc:
            logging.error("Failed to unpack clipboard files: %s", exc, exc_info=True)
            return

        file_count = len(extracted_files)
        logging.info(
            "Persisted clipboard fileset '%s' with %d file%s (%d skipped)",
            unique_name,
            file_count,
            "" if file_count == 1 else "s",
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
        stored["timestamp"] = float(timestamp if timestamp is not None else time.time())
        with self.clipboard_lock:
            self.shared_clipboard_item = stored
        if self.role == "ado":
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
        ts = float(timestamp if timestamp is not None else item.get("timestamp", time.time()))
        payload = {
            "type": "clipboard_data",
            "format": item["format"],
            "encoding": item.get("encoding"),
            "size": item.get("size"),
            "digest": item.get("digest"),
            "timestamp": ts,
            "data": item["data"],
        }
        if "length" in item:
            payload["length"] = item["length"]
        if "width" in item:
            payload["width"] = item["width"]
        if "height" in item:
            payload["height"] = item["height"]
        if "bits_per_pixel" in item:
            payload["bits_per_pixel"] = item["bits_per_pixel"]
        if "entries" in item:
            payload["entries"] = item["entries"]
        if "file_count" in item:
            payload["file_count"] = item["file_count"]
        if "total_size" in item:
            payload["total_size"] = item["total_size"]
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
        if broadcast:
            payload = {"type": "clipboard_clear", "timestamp": time.time()}
            self.clipboard_update_captured.emit(payload)

    def _check_clipboard_expiration(self) -> None:
        if self.role != "ado":
            return
        with self.clipboard_lock:
            item = self.shared_clipboard_item
        if not item:
            return
        timestamp = item.get("timestamp")
        if not timestamp:
            return
        try:
            ts = float(timestamp)
        except (TypeError, ValueError):
            return
        if time.time() - ts >= self.clipboard_expiry_seconds:
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
        timestamp = item.get("timestamp")
        if timestamp and time.time() - float(timestamp) >= self.clipboard_expiry_seconds:
            return None
        return self._build_clipboard_payload(item)

