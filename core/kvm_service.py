# kvm_service.py - Refactored KVM worker core service

import socket
import time
import threading
import logging
import tkinter
import queue
import struct
from collections import deque
from datetime import datetime
from typing import Any, Callable, Optional
import io
import msgpack
import random
import psutil  # ÚJ IMPORT
import os      # ÚJ IMPORT
import shutil
import zipfile
from pathlib import PurePosixPath
from utils.clipboard_sync import (
    clear_clipboard,
    clipboard_items_equal,
    normalize_clipboard_item,
    read_clipboard_content,
    write_clipboard_content,
)
from pynput import keyboard, mouse
from zeroconf import ServiceInfo
from PySide6.QtCore import QObject, Signal, QSettings, QStandardPaths
from config import (
    SERVICE_TYPE,
    SERVICE_NAME_PREFIX,
    APP_NAME,
    ORG_NAME,
    BRAND_NAME,
    VK_CTRL,
    VK_CTRL_R,
    VK_NUMPAD0,
    VK_NUMPAD1,
    VK_NUMPAD2,
    VK_DOWN,
    VK_F12,
    VK_LSHIFT,
    VK_RSHIFT,
    VK_INSERT,
    VK_END,
)
from services.hardware_manager import HardwareManager
from services.input_manager import InputManager
from services.network_manager import NetworkManager
from utils.stability_monitor import StabilityMonitor

# Delay between iterations in the streaming loop to lower CPU usage
STREAM_LOOP_DELAY = 0.05
# Maximum number of events queued for sending before old ones are dropped
SEND_QUEUE_MAXSIZE = 200
CLIPBOARD_STORAGE_DIRNAME = "SharedClipboard"
CLIPBOARD_CLEANUP_INTERVAL_SECONDS = 24 * 60 * 60
class KVMService(QObject):
    __slots__ = (
        'settings', '_running', 'kvm_active', 'client_sockets', 'client_infos',
        'client_roles', 'active_client', 'zeroconf',
        'streaming_thread', 'heartbeat_thread', 'switch_monitor', 'local_ip', 'server_ip',
        'connection_thread', 'device_name', 'clipboard_thread',
        'last_clipboard_item', 'shared_clipboard_item', 'clipboard_lock',
        'clipboard_expiry_seconds', 'server_socket', 'input_provider_socket',
        '_ignore_next_clipboard_change', 'last_server_ip', 'message_queue',
        'message_processor_thread', '_host_mouse_controller', '_orig_mouse_pos',
        '_provider_pressed_keys',
        'discovered_peers', 'connection_manager_thread', 'resolver_thread',
        'resolver_queue', 'service_info', 'peers_lock', 'clients_lock',
        'pending_activation_target', 'provider_stop_event', 'provider_target',
        'current_target', 'current_monitor_input',
        'clipboard_storage_dir',
        '_clipboard_cleanup_marker',
        '_clipboard_last_cleanup',
        '_clipboard_last_persisted_digest',
        'stability_monitor', '_monitor_prefix', '_monitor_thread_keys',
        '_monitor_directory_keys', '_monitor_task_keys', '_monitor_memory_callback',
        'hardware_manager', 'network_manager', 'settings_store',
        'input_manager', '_capture_send_queue', '_capture_sender_thread',
        '_capture_unsent_events', '_capture_unsent_total',
        '_capture_current_vks', '_capture_numpad_vks'
    )

    finished = Signal()
    status_update = Signal(str)

    def __init__(self, settings, stability_monitor: Optional[StabilityMonitor] = None):
        super().__init__()
        self.settings = settings
        self._running = True
        self.kvm_active = False
        # Active client connections (multiple receivers can connect)
        self.client_sockets = []
        # Mapping from socket to human readable client name
        self.client_infos = {}
        # Mapping from socket to declared remote role
        self.client_roles = {}
        # Currently selected client to forward events to
        self.active_client = None
        self.streaming_thread = None
        self.heartbeat_thread = None
        self.switch_monitor = True
        self.local_ip = self._detect_primary_ipv4()
        self.server_ip = None
        self.connection_thread = None
        self.connection_manager_thread = None
        self.resolver_thread = None
        self.service_info = None
        self.settings_store = QSettings(ORG_NAME, APP_NAME)
        self.last_server_ip = self.settings_store.value('network/last_server_ip', None)
        self.device_name = settings.get('device_name', socket.gethostname())

        self.hardware_manager = HardwareManager()
        self.hardware_manager.set_function_key_handler(self.send_provider_function_key)
        self.hardware_manager.switch_requested.connect(self._handle_switch_request)

        self.network_manager = NetworkManager(self, self.settings, self.device_name, self.local_ip)
        self.network_manager.data_received.connect(self._on_network_data)
        self.network_manager.client_connected.connect(self._on_client_connected)
        self.network_manager.client_disconnected.connect(self._on_client_disconnected)

        self.client_sockets = self.network_manager.client_sockets
        self.client_infos = self.network_manager.client_infos
        self.client_roles = self.network_manager.client_roles

        self.zeroconf = self.network_manager.zeroconf
        self.resolver_queue = self.network_manager.resolver_queue
        self.discovered_peers = self.network_manager.discovered_peers
        self.peers_lock = self.network_manager.peers_lock
        self.clients_lock = self.network_manager.clients_lock
        self.clipboard_thread = None
        self.last_clipboard_item = None
        self.shared_clipboard_item = None
        self.clipboard_lock = threading.Lock()
        self.clipboard_expiry_seconds = 12 * 60 * 60
        self.server_socket = None
        self.input_provider_socket = None
        self._ignore_next_clipboard_change = threading.Event()
        self.message_queue = queue.Queue()
        self.message_processor_thread = None
        self._host_mouse_controller = None
        self._orig_mouse_pos = None
        self._provider_pressed_keys = set()
        # Remember if a KVM session was active when the connection dropped
        self.pending_activation_target = None
        # Track ongoing reconnect attempts to avoid duplicates
        self.reconnect_threads = {}
        self.reconnect_lock = threading.Lock()
        self.provider_stop_event = threading.Event()
        self.provider_target = None
        self.current_target = 'desktop'
        self.current_monitor_input = None
        self.clipboard_storage_dir: Optional[str] = None
        self._clipboard_cleanup_marker: Optional[str] = None
        self._clipboard_last_cleanup: float = 0.0
        self._clipboard_last_persisted_digest: Optional[tuple[str, str]] = None

        self.stability_monitor: Optional[StabilityMonitor] = stability_monitor
        self._monitor_prefix = f"kvm-{id(self):x}"
        self._monitor_thread_keys: list[str] = []
        self._monitor_directory_keys: list[str] = []
        self._monitor_task_keys: list[str] = []
        self._monitor_memory_callback: Optional[Callable[[], None]] = None

        self.input_manager = InputManager(self)
        self.input_manager.input_captured.connect(self._handle_captured_input)
        self._capture_send_queue: Optional[queue.Queue] = None
        self._capture_sender_thread: Optional[threading.Thread] = None
        self._capture_unsent_events = deque(maxlen=50)
        self._capture_unsent_total = 0
        self._capture_current_vks: set[int] = set()
        self._capture_numpad_vks: set[int] = set()

        if self.stability_monitor:
            self._register_core_monitoring()

        if self.settings.get('role') == 'ado':
            self._initialize_clipboard_storage()

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
    # Stability monitor integration
    # ------------------------------------------------------------------
    def _register_core_monitoring(self) -> None:
        if not self.stability_monitor:
            return

        monitor = self.stability_monitor

        def register(name: str, supplier: Callable[[], Optional[threading.Thread]], *, grace: float = 30.0) -> None:
            key = f"{self._monitor_prefix}/{name}"
            monitor.register_thread(key, supplier, grace_period=grace)
            self._monitor_thread_keys.append(key)

        register('message_processor', lambda: self.message_processor_thread)
        register('clipboard', lambda: self.clipboard_thread)
        register('streaming', lambda: self.streaming_thread, grace=15.0)
        register('connection_manager', lambda: self.connection_manager_thread)
        register('resolver', lambda: self.resolver_thread)
        register('connection', lambda: self.connection_thread)
        register('heartbeat', lambda: self.heartbeat_thread)

    def _register_clipboard_monitoring(self) -> None:
        if not self.stability_monitor or not self.clipboard_storage_dir:
            return

        monitor = self.stability_monitor
        directory = os.path.abspath(self.clipboard_storage_dir)
        if directory not in self._monitor_directory_keys:
            monitor.add_directory_quota(directory, max_mb=512, min_free_mb=256)
            self._monitor_directory_keys.append(directory)

        task_name = f"{self._monitor_prefix}/clipboard_cleanup"
        if task_name not in self._monitor_task_keys:
            monitor.add_periodic_task(
                task_name,
                max(3600.0, CLIPBOARD_CLEANUP_INTERVAL_SECONDS / 2),
                lambda: self._ensure_clipboard_storage_cleanup(force=True),
            )
            self._monitor_task_keys.append(task_name)

        if self._monitor_memory_callback is None:
            self._monitor_memory_callback = lambda: self._memory_cleanup()
            monitor.register_memory_cleanup(self._monitor_memory_callback)

    def _unregister_monitoring(self) -> None:
        if not self.stability_monitor:
            return

        for key in self._monitor_thread_keys:
            self.stability_monitor.unregister_thread(key)
        self._monitor_thread_keys.clear()

        for directory in self._monitor_directory_keys:
            self.stability_monitor.remove_directory_quota(directory)
        self._monitor_directory_keys.clear()

        for task in self._monitor_task_keys:
            self.stability_monitor.remove_periodic_task(task)
        self._monitor_task_keys.clear()

        if self._monitor_memory_callback is not None:
            self.stability_monitor.unregister_memory_cleanup(self._monitor_memory_callback)
            self._monitor_memory_callback = None

    def _memory_cleanup(self) -> None:
        """Attempt to release cached resources when the process is under pressure."""
        try:
            trimmed = 0
            while self.message_queue.qsize() > SEND_QUEUE_MAXSIZE:
                self.message_queue.get_nowait()
                trimmed += 1
            if trimmed:
                logging.warning("Trimmed %d pending messages during memory cleanup", trimmed)
        except Exception:
            logging.exception("Failed to trim message queue during memory cleanup")
        finally:
            try:
                self._ensure_clipboard_storage_cleanup(force=True)
            except Exception:
                logging.exception("Clipboard cleanup failed during memory pressure mitigation")

    def toggle_monitor_power(self) -> None:
        """Delegate monitor power toggle to the hardware manager."""
        self.hardware_manager.toggle_monitor_power()

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
        self._register_clipboard_monitoring()

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
                # Fallback to simple comparison if abspath fails for any reason
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

        # fmt == 'files'
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
            provider = self.input_provider_socket
            exclude: set[Any] = set()
            if provider:
                if not self._send_to_provider(payload):
                    logging.warning("Failed to notify input provider about clipboard clear.")
                exclude.add(provider)
            if self.client_sockets:
                self._broadcast_message(payload, exclude=exclude)

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
            provider = self.input_provider_socket
            exclude: set[Any] = set()
            if sock:
                exclude.add(sock)
            if provider:
                if provider is not sock:
                    if not self._send_to_provider(payload):
                        logging.warning("Failed to forward clipboard update to input provider.")
                    exclude.add(provider)
                else:
                    exclude.add(provider)
            if self.client_sockets:
                self._broadcast_message(payload, exclude=exclude)
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
    # Network helpers
    # ------------------------------------------------------------------
    def _send_message(self, sock, data) -> bool:
        """Send a msgpack message through the network manager."""
        return self.network_manager.send_message(sock, data)

    def _broadcast_message(self, data, exclude=None) -> None:
        """Broadcast a message to all connected clients."""
        self.network_manager.broadcast_message(data, exclude=exclude)

    def _send_to_provider(self, payload: dict) -> bool:
        """Send a command to the connected input provider if available."""
        sock = self.input_provider_socket
        if not sock:
            logging.warning("No input provider socket available for payload %s", payload)
            return False
        return self._send_message(sock, payload)

    def _apply_event_locally(self, data: dict) -> None:
        """(Deprecated) wrapper maintained for backward compatibility."""
        self.input_manager.simulate_event(data)

    def _handle_provider_event(self, data: dict) -> None:
        """Route events coming from the input provider based on the active target."""
        target = self.current_target
        if target == 'laptop':
            if self.active_client is None:
                logging.debug("No active laptop client to forward provider event %s", data)
                return
            if not self._send_message(self.active_client, data):
                logging.warning("Failed to forward provider event to laptop; deactivating KVM")
                self.deactivate_kvm(reason="forward_failed", switch_monitor=False)
        elif target == 'elitedesk':
            self.input_manager.simulate_event(data)
        else:
            logging.debug(
                "Dropping provider event %s because current target is %s",
                data,
                target,
            )

    def send_provider_function_key(self, key: keyboard.Key, *, source: str = "") -> bool:
        """Request the desktop input provider to tap the given function key."""
        if self.settings.get('role') != 'ado':
            logging.debug("Ignoring provider key tap request in role %s", self.settings.get('role'))
            return False
        vk = None
        if hasattr(key, 'value') and hasattr(key.value, 'vk'):
            vk = key.value.vk
        if vk is None:
            vk = getattr(key, 'vk', None)
        if vk is None:
            logging.warning("Cannot determine virtual key code for %s", key)
            return False
        payload = {
            'command': 'host_key_tap',
            'key_type': 'vk',
            'key': int(vk),
            'source': source,
        }
        if not self._send_to_provider(payload):
            logging.warning("Failed to forward provider key tap for %s (%s)", key, source)
            return False
        logging.info("Forwarded provider key tap %s (%s)", key, source)
        return True

    def _simulate_provider_key_tap(self, key_type: str, key_value, source: str | None = None) -> None:
        """Simulate a key tap locally using the existing event application helper."""
        if key_type == 'vk':
            try:
                key_value = int(key_value)
            except (TypeError, ValueError):
                logging.warning("Invalid virtual key value %s for provider tap", key_value)
                return
        logging.info(
            "Executing provider key tap type=%s value=%s requested by %s",
            key_type,
            key_value,
            source or 'unknown',
        )
        press_event = {'type': 'key', 'key_type': key_type, 'key': key_value, 'pressed': True}
        release_event = {'type': 'key', 'key_type': key_type, 'key': key_value, 'pressed': False}
        try:
            self.input_manager.simulate_event(press_event)
            time.sleep(0.05)
            self.input_manager.simulate_event(release_event)
        except Exception as exc:
            logging.error("Failed to perform provider key tap: %s", exc, exc_info=True)

    def _switch_monitor_for_target(self, target: str, *, allow_switch: bool) -> None:
        """Switch the monitor input according to the current control target."""
        if not allow_switch:
            return
        desired = None
        if target == 'elitedesk':
            desired = self.settings['monitor_codes']['client']
        elif target == 'desktop':
            desired = self.settings['monitor_codes']['host']
        if desired is None or desired == self.current_monitor_input:
            return
        try:
            with list(get_monitors())[0] as monitor:
                monitor.set_input_source(desired)
            self.current_monitor_input = desired
            logging.info("Monitor input switched to %s for target %s", desired, target)
        except Exception as exc:
            logging.error("Failed to switch monitor input for %s: %s", target, exc)
            self.status_update.emit(f"Monitor hiba: {exc}")

    def _detect_primary_ipv4(self) -> str:
        """Determine the primary IPv4 address for outgoing connections."""
        ip = None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
        except Exception:
            ip = None
        if not ip or ip.startswith("127."):
            try:
                host = socket.gethostname()
                for res in socket.getaddrinfo(host, None):
                    if res[0] == socket.AF_INET:
                        candidate = res[4][0]
                        if not candidate.startswith("127."):
                            ip = candidate
                            break
            except Exception:
                pass
        return ip or "127.0.0.1"

    def _ip_watchdog(self):
        """Periodically check for IP changes and re-register Zeroconf service."""
        while self._running:
            time.sleep(5)
            try:
                new_ip = self._detect_primary_ipv4()
                if not new_ip or new_ip == self.local_ip:
                    continue
                logging.info("Local IP changed from %s to %s", self.local_ip, new_ip)
                if self.service_info:
                    try:
                        self.zeroconf.unregister_service(self.service_info)
                    except Exception as e:
                        logging.debug("Failed to unregister Zeroconf service: %s", e)
                self.local_ip = new_ip
                try:
                    addr = socket.inet_aton(self.local_ip)
                    self.service_info = ServiceInfo(
                        SERVICE_TYPE,
                        f"{self.device_name}.{SERVICE_TYPE}",
                        addresses=[addr],
                        port=self.settings['port'],
                    )
                    self.zeroconf.register_service(self.service_info)
                except Exception as e:
                    logging.error("Failed to register Zeroconf service: %s", e)
            except Exception as e:
                logging.debug("IP watchdog error: %s", e)

    def _handle_disconnect(self, sock, reason: str = "unknown") -> None:
        """Cleanup for a disconnected socket with peer-awareness."""
        addr = None
        try:
            addr = sock.getpeername()
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass

        with self.clients_lock:
            peer_name = self.client_infos.get(sock)
            was_active = sock == self.active_client
            if sock in self.client_sockets:
                self.client_sockets.remove(sock)
            if sock in self.client_infos:
                del self.client_infos[sock]
            self.client_roles.pop(sock, None)
            peer_still_connected = (
                peer_name is not None and peer_name in self.client_infos.values()
            )
            if peer_still_connected and was_active:
                for s, name in self.client_infos.items():
                    if name == peer_name:
                        self.active_client = s
                        break

        if peer_still_connected:
            logging.debug(
                "Closed redundant connection to %s (%s)", peer_name, reason
            )
            return

        if self.settings.get('role') == 'ado' and sock == self.input_provider_socket:
            if self.kvm_active:
                self.deactivate_kvm(
                    switch_monitor=self.current_target == 'elitedesk',
                    reason="input provider disconnect",
                )
            self.input_provider_socket = None
            self.pending_activation_target = None
        if self.settings.get('role') == 'input_provider' and sock == self.server_socket:
            self.server_socket = None
            self._stop_input_provider_stream()
        if self.settings.get('role') == 'vevo' and sock == self.server_socket:
            self.server_socket = None

        if was_active and self.kvm_active:
            logging.info("Active client disconnected, deactivating KVM")
            self.pending_activation_target = peer_name
            self.deactivate_kvm(reason=reason)
        elif was_active:
            self.active_client = None
            self.pending_activation_target = None
        logging.debug("Peer cleanup completed; connection manager will attempt reconnection")
        if addr and self._running:
            self._schedule_reconnect(addr[0], self.settings['port'])

    def _schedule_reconnect(self, ip: str, port: int) -> None:
        """Spawn a background thread that keeps trying to reconnect."""

        def _attempt():
            while self._running:
                with self.clients_lock:
                    if any(
                        s.getpeername()[0] == ip
                        for s in self.client_sockets
                        if s.fileno() != -1
                    ):
                        break
                self.connect_to_peer(ip, port)
                time.sleep(5)
            with self.reconnect_lock:
                self.reconnect_threads.pop((ip, port), None)

        with self.reconnect_lock:
            if (ip, port) in self.reconnect_threads:
                return
            t = threading.Thread(target=_attempt, daemon=True, name=f"Reconnect-{ip}")
            self.reconnect_threads[(ip, port)] = t
            t.start()

    # ------------------------------------------------------------------
    # Clipboard synchronization
    # ------------------------------------------------------------------
    def _clipboard_loop_server(self) -> None:
        """Continuously monitor the host clipboard and broadcast changes."""
        logging.info("Clipboard server loop started.")
        while self._running:
            if self._ignore_next_clipboard_change.is_set():
                self._ignore_next_clipboard_change.clear()
                time.sleep(0.5)
                continue

            item = read_clipboard_content()
            if item and not clipboard_items_equal(item, self.last_clipboard_item):
                self._remember_last_clipboard(item)
                stored = self._store_shared_clipboard(item)
                payload = self._build_clipboard_payload(stored)
                provider = self.input_provider_socket
                exclude: set[Any] = set()
                if provider:
                    if not self._send_to_provider(payload):
                        logging.warning("Failed to forward clipboard update to input provider.")
                    exclude.add(provider)
                if self.client_sockets:
                    self._broadcast_message(payload, exclude=exclude)
            self._check_clipboard_expiration()
            time.sleep(0.3)
        logging.info("Clipboard server loop stopped.")

    def _clipboard_loop_client(self) -> None:
        """Monitor local clipboard changes and forward them to the server."""
        logging.info("Clipboard client loop started.")
        while self._running:
            if self._ignore_next_clipboard_change.is_set():
                self._ignore_next_clipboard_change.clear()
                time.sleep(0.5)
                continue

            item = read_clipboard_content()
            if item and not clipboard_items_equal(item, self.last_clipboard_item):
                self._remember_last_clipboard(item)
                sock = self.server_socket
                if sock:
                    payload = self._build_clipboard_payload(item)
                    if not self._send_message(sock, payload):
                        logging.warning("Failed to send clipboard update to server.")
            time.sleep(0.3)
        logging.info("Clipboard client loop stopped.")

    def _process_messages(self):
        """Unified message handler for all peers."""
        logging.debug("Message processor thread started")
        role = self.settings.get('role')
        while self._running:
            try:
                sock, data = self.message_queue.get()
            except Exception:
                break
            if sock is None and data is None:
                break
            try:
                cmd = data.get('command')
                if role == 'ado':
                    if cmd == 'switch_elitedesk':
                        self.toggle_client_control('elitedesk', switch_monitor=True)
                        continue
                    if cmd == 'switch_laptop':
                        self.toggle_client_control('laptop', switch_monitor=False)
                        continue
                    msg_type = data.get('type')
                    if msg_type == 'clipboard_data':
                        self._handle_clipboard_data_message(sock, data)
                        continue
                    if msg_type == 'clipboard_clear':
                        self._handle_clipboard_clear_message(sock)
                        continue
                    if msg_type in {'move_relative', 'click', 'scroll', 'key'} and sock == self.input_provider_socket:
                        self._handle_provider_event(data)
                        continue
                    logging.debug(
                        "Unhandled message type '%s' in controller context from %s",
                        data.get('type') or data.get('command'),
                        self.client_infos.get(sock, sock),
                    )
                    continue

                if role == 'input_provider':
                    if cmd == 'start_stream':
                        target = data.get('target', 'elitedesk')
                        self._start_input_provider_stream(target)
                        continue
                    if cmd == 'stop_stream':
                        self._stop_input_provider_stream()
                        continue
                    if cmd == 'host_key_tap':
                        key_type = data.get('key_type', 'vk')
                        key_value = data.get('key')
                        source = data.get('source')
                        self._simulate_provider_key_tap(key_type, key_value, source)
                        continue
                    msg_type = data.get('type')
                    if msg_type == 'clipboard_data':
                        self._handle_clipboard_data_message(sock, data)
                        continue
                    if msg_type == 'clipboard_clear':
                        self._handle_clipboard_clear_message(sock)
                        continue
                    logging.debug(
                        "Unhandled message type '%s' in input provider context",
                        data.get('type') or data.get('command'),
                    )
                    continue

                msg_type = data.get('type')
                if msg_type in {'move_relative', 'click', 'scroll', 'key'}:
                    self._apply_event_locally(data)
                elif msg_type == 'clipboard_data':
                    self._handle_clipboard_data_message(sock, data)
                elif msg_type == 'clipboard_clear':
                    self._handle_clipboard_clear_message(sock)
                else:
                    logging.debug(
                        "Unhandled message type '%s' in peer message processor",
                        data.get('type') or data.get('command'),
                    )
            except Exception as e:
                logging.error("Failed to process message: %s", e, exc_info=True)

    def _start_input_provider_stream(self, target: str) -> None:
        """Start streaming local input toward the controller when requested."""
        if self.settings.get('role') != 'input_provider':
            return
        if not self.server_socket:
            logging.error("Cannot start input streaming without server connection")
            self.status_update.emit("Hiba: Nincs kapcsolat a vezérlővel")
            return
        if self.streaming_thread and self.streaming_thread.is_alive():
            self.provider_target = target
            self.status_update.emit(f"Állapot: Továbbítás aktív ({target})")
            return
        self.provider_target = target
        self.provider_stop_event.clear()
        self._provider_pressed_keys.clear()
        self.kvm_active = True
        self.status_update.emit(f"Állapot: Továbbítás aktív ({target})")
        self.streaming_thread = threading.Thread(
            target=self._provider_stream_loop,
            daemon=True,
            name="InputProviderStream",
        )
        self.streaming_thread.start()
        logging.info("Input provider streaming started toward %s", target)

    def _stop_input_provider_stream(self) -> None:
        """Stop forwarding events to the controller and restore local control."""
        if self.settings.get('role') != 'input_provider':
            return
        self.provider_stop_event.set()
        if self.streaming_thread and self.streaming_thread.is_alive():
            self.streaming_thread.join(timeout=1.5)
        self.streaming_thread = None
        self.provider_target = None
        self.kvm_active = False
        self.status_update.emit("Állapot: Helyi vezérlés aktív")
        logging.info("Input provider streaming stopped")

    def _provider_stream_loop(self) -> None:
        """Capture local mouse and keyboard events and forward them to the server."""
        controller_sock = self.server_socket
        if not controller_sock:
            logging.error("Provider stream loop started without a server socket")
            self.provider_stop_event.set()
            self.kvm_active = False
            return

        host_mouse = mouse.Controller()
        self._host_mouse_controller = host_mouse
        self._orig_mouse_pos = host_mouse.position
        try:
            root = tkinter.Tk()
            root.withdraw()
            center_x = root.winfo_screenwidth() // 2
            center_y = root.winfo_screenheight() // 2
            root.destroy()
        except Exception:
            center_x, center_y = 800, 600

        host_mouse.position = (center_x, center_y)
        last_pos = {'x': center_x, 'y': center_y}
        is_warping = False
        movement_lock = threading.Lock()
        pending_move = {'dx': 0, 'dy': 0}

        def send_event(payload: dict) -> bool:
            if not self._running:
                return False
            sock = self.server_socket
            if not sock:
                logging.error("Lost server socket while sending provider event")
                return False
            if not self._send_message(sock, payload):
                logging.error("Failed to send provider event %s", payload)
                return False
            return True

        def aggregator():
            while self._running and not self.provider_stop_event.is_set():
                time.sleep(0.01)
                with movement_lock:
                    dx = pending_move['dx']
                    dy = pending_move['dy']
                    pending_move['dx'] = 0
                    pending_move['dy'] = 0
                if dx or dy:
                    if not send_event({'type': 'move_relative', 'dx': dx, 'dy': dy}):
                        self.provider_stop_event.set()
                        break

        agg_thread = threading.Thread(target=aggregator, daemon=True, name="InputMoveAgg")
        agg_thread.start()

        def on_move(x, y):
            nonlocal is_warping
            if self.provider_stop_event.is_set():
                return False
            if is_warping:
                is_warping = False
                return
            dx = x - last_pos['x']
            dy = y - last_pos['y']
            if dx or dy:
                with movement_lock:
                    pending_move['dx'] += dx
                    pending_move['dy'] += dy
            is_warping = True
            try:
                host_mouse.position = (center_x, center_y)
            except Exception:
                pass
            last_pos['x'] = center_x
            last_pos['y'] = center_y

        def on_click(x, y, button, pressed):
            if self.provider_stop_event.is_set():
                return False
            send_event({'type': 'click', 'button': getattr(button, 'name', 'left'), 'pressed': pressed})

        def on_scroll(x, y, dx, dy):
            if self.provider_stop_event.is_set():
                return False
            send_event({'type': 'scroll', 'dx': dx, 'dy': dy})

        def on_key(key, pressed):
            if self.provider_stop_event.is_set():
                return False
            try:
                if hasattr(key, 'char') and key.char is not None:
                    key_type = 'char'
                    key_val = key.char
                elif hasattr(key, 'name') and key.name is not None:
                    key_type = 'special'
                    key_val = key.name
                elif hasattr(key, 'vk') and key.vk is not None:
                    key_type = 'vk'
                    key_val = key.vk
                else:
                    return True
                key_id = (key_type, key_val)
                if pressed:
                    self._provider_pressed_keys.add(key_id)
                else:
                    self._provider_pressed_keys.discard(key_id)
                send_event({'type': 'key', 'key_type': key_type, 'key': key_val, 'pressed': pressed})
            except Exception as exc:
                logging.error("Error while handling provider key event: %s", exc, exc_info=True)
            return True

        mouse_listener = mouse.Listener(on_move=on_move, on_click=on_click, on_scroll=on_scroll, suppress=True)
        keyboard_listener = keyboard.Listener(
            on_press=lambda k: on_key(k, True),
            on_release=lambda k: on_key(k, False),
            suppress=True,
        )
        mouse_listener.start()
        keyboard_listener.start()

        while self._running and not self.provider_stop_event.is_set():
            time.sleep(0.05)

        mouse_listener.stop()
        keyboard_listener.stop()
        agg_thread.join(timeout=1.0)

        if self._provider_pressed_keys:
            sock = self.server_socket
            if sock:
                for key_type, key_val in list(self._provider_pressed_keys):
                    try:
                        self._send_message(sock, {
                            'type': 'key',
                            'key_type': key_type,
                            'key': key_val,
                            'pressed': False,
                        })
                    except Exception:
                        break
            self._provider_pressed_keys.clear()

        if self._host_mouse_controller and self._orig_mouse_pos:
            try:
                self._host_mouse_controller.position = self._orig_mouse_pos
            except Exception:
                pass
        self._host_mouse_controller = None
        self._orig_mouse_pos = None
        self.provider_stop_event.set()
        logging.info("Input provider stream loop exited")

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
        if self.settings.get('role') == 'ado':
            target = name.lower()
            desired_switch_monitor = switch_monitor
            logging.info(
                "Controller toggle requested for target=%s current=%s active=%s",
                target,
                self.current_target,
                self.kvm_active,
            )
            if target not in {'laptop', 'elitedesk'}:
                logging.warning("Unknown controller target: %s", target)
                return
            if self.kvm_active and self.current_target == target:
                logging.info(
                    "Toggle request ignored because target %s is already active",
                    target,
                )
                self.pending_activation_target = None
                return
            if self.kvm_active:
                prior_was_elitedesk = self.current_target == 'elitedesk'
                switching_between_main_targets = (
                    self.current_target in {'laptop', 'elitedesk'}
                    and target in {'laptop', 'elitedesk'}
                    and self.current_target != target
                )
                deactivate_switch_monitor = False if switching_between_main_targets else prior_was_elitedesk
                self.deactivate_kvm(
                    switch_monitor=deactivate_switch_monitor,
                    release_keys=release_keys,
                    reason="controller switch",
                )
                self.pending_activation_target = None
            if target == 'laptop':
                if not self.set_active_client_by_name('laptop'):
                    self.status_update.emit("Hiba: a laptop nem érhető el")
                    self.pending_activation_target = None
                    return
            else:
                self.active_client = None
            self.activate_kvm(switch_monitor=desired_switch_monitor, target=target)
            return

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
        self._unregister_monitoring()
        self.pending_activation_target = None
        if self.settings.get('role') == 'input_provider':
            self._stop_input_provider_stream()
        elif self.kvm_active:
            self.deactivate_kvm(switch_monitor=False, reason="stop() called")  # Leállításkor ne váltson monitort
        else:
            self.input_manager.stop_capturing()
        if self.service_info:
            try:
                self.zeroconf.unregister_service(self.service_info)
            except Exception:
                pass
        try:
            self.zeroconf.close()
        except Exception:
            pass
        try:
            self.hardware_manager.stop()
        except Exception:
            logging.exception("Failed to stop hardware manager cleanly")
        with self.clients_lock:
            for sock in list(self.client_sockets):
                try:
                    sock.close()
                except Exception:
                    pass
            self.client_sockets.clear()
            self.client_infos.clear()
            self.client_roles.clear()
            self.active_client = None
        self.server_socket = None if self.settings.get('role') != 'ado' else self.server_socket
        if self.settings.get('role') == 'ado':
            self.input_provider_socket = None
            self.current_target = 'desktop'
            self.kvm_active = False
        if self.connection_thread and self.connection_thread.is_alive():
            self.connection_thread.join(timeout=1)
        if self.clipboard_thread and self.clipboard_thread.is_alive():
            self.clipboard_thread.join(timeout=1)
        if self.connection_manager_thread and self.connection_manager_thread.is_alive():
            self.connection_manager_thread.join(timeout=1)
        if self.resolver_thread and self.resolver_thread.is_alive():
            self.resolver_thread.join(timeout=1)
        if self.message_processor_thread and self.message_processor_thread.is_alive():
            try:
                self.message_queue.put_nowait((None, None))
            except Exception:
                pass
            self.message_processor_thread.join(timeout=1)
        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            self.heartbeat_thread.join(timeout=1)
        self.heartbeat_thread = None
        # Extra safety to avoid stuck modifier keys on exit
        self.release_hotkey_keys()

    def _heartbeat_monitor(self):
        """Logs detailed diagnostics every 30 seconds."""
        process = psutil.Process(os.getpid())
        logging.info("Heartbeat monitor thread started.")
        while self._running:
            try:
                mem_usage = process.memory_info().rss / (1024 * 1024)
                cpu_usage = process.cpu_percent(interval=1.0)
                active_threads = threading.active_count()
                stream_thread_alive = (
                    self.streaming_thread.is_alive() if self.streaming_thread else "N/A"
                )
                msg_proc_alive = (
                    self.message_processor_thread.is_alive() if self.message_processor_thread else "N/A"
                )
                with self.clients_lock:
                    connected_clients_count = len(self.client_sockets)
                    client_names = list(self.client_infos.values())
                active_client_name = self.client_infos.get(self.active_client, "None")
                log_message = (
                    f"HEARTBEAT - "
                    f"Mem: {mem_usage:.2f} MB, CPU: {cpu_usage:.1f}%, Threads: {active_threads} | "
                    f"KVM Active: {self.kvm_active}, Target: {active_client_name} | "
                    f"Clients: {connected_clients_count} {client_names} | "
                    f"StreamThread: {stream_thread_alive}, MsgProc: {msg_proc_alive}"
                )
                logging.debug(log_message)
                for _ in range(29):
                    if not self._running:
                        break
                    time.sleep(1)
            except Exception as e:
                logging.error(f"Heartbeat monitor failed: {e}", exc_info=True)
                time.sleep(30)
        logging.info("Heartbeat monitor thread stopped.")

    def run(self):
        """Unified entry point starting peer threads and services."""
        logging.info("Worker starting in peer-to-peer mode")
        try:
            register_ok = False
            try:
                addr = socket.inet_aton(self.local_ip)
                self.service_info = ServiceInfo(
                    SERVICE_TYPE,
                    f"{self.device_name}.{SERVICE_TYPE}",
                    addresses=[addr],
                    port=self.settings['port'],
                )
                self.zeroconf.register_service(self.service_info)
                register_ok = True
            except Exception as e:
                logging.error("Failed to register Zeroconf service: %s", e)

            if register_ok:
                threading.Thread(
                    target=self._ip_watchdog,
                    daemon=True,
                    name="IPWatchdog",
                ).start()

            self.message_processor_thread = threading.Thread(
                target=self._process_messages,
                daemon=True,
                name="MsgProcessor",
            )
            self.message_processor_thread.start()

            threading.Thread(
                target=self.accept_connections, daemon=True, name="AcceptThread"
            ).start()
            self.resolver_thread = threading.Thread(
                target=self._resolver_thread,
                daemon=True,
                name="Resolver",
            )
            self.resolver_thread.start()
            threading.Thread(
                target=self.discover_peers, daemon=True, name="DiscoverThread"
            ).start()
            self.connection_manager_thread = threading.Thread(
                target=self._connection_manager,
                daemon=True,
                name="ConnMgr",
            )
            self.connection_manager_thread.start()

            if self.settings.get('role') == 'ado':
                self.clipboard_thread = threading.Thread(
                    target=self._clipboard_loop_server,
                    daemon=True,
                    name="ClipboardSrv",
                )
                self.clipboard_thread.start()
                self.start_main_hotkey_listener()
            else:
                self.clipboard_thread = threading.Thread(
                    target=self._clipboard_loop_client,
                    daemon=True,
                    name="ClipboardCli",
                )
                self.clipboard_thread.start()

            self.heartbeat_thread = threading.Thread(
                target=self._heartbeat_monitor, daemon=True, name="Heartbeat"
            )
            self.heartbeat_thread.start()

            while self._running:
                time.sleep(0.5)
        except Exception as e:
            logging.critical("Worker encountered fatal error: %s", e, exc_info=True)
            self.status_update.emit(
                "Állapot: Hiba - a KVM szolgáltatás leállt"
            )
        finally:
            self._unregister_monitoring()
            self.finished.emit()


    def start_main_hotkey_listener(self):
        """Segédmetódus a globális gyorsbillentyű-figyelő indítására."""
        self.hardware_manager.start()

    def _handle_switch_request(self, target: str, source: str) -> None:
        if target == 'desktop':
            self.deactivate_kvm(switch_monitor=True, reason=source)
            return
        if target in {'laptop', 'elitedesk'}:
            switch_monitor = target != 'laptop'
            self.toggle_client_control(target, switch_monitor=switch_monitor, release_keys=False)

    def _on_network_data(self, sock, data: dict) -> None:
        self.message_queue.put((sock, data))

    def _on_client_connected(self, sock, client_name: str, client_role) -> None:
        if client_role is not None:
            self.client_roles[sock] = client_role
        if self.active_client is None and client_role != 'input_provider':
            self.active_client = sock

        if self.settings.get('role') == 'ado' and client_role == 'input_provider':
            self.input_provider_socket = sock
            logging.info("Input provider connected: %s", client_name)
        if self.settings.get('role') == 'input_provider' and client_role == 'ado':
            self.server_socket = sock
            logging.info("Controller connection established: %s", client_name)
        if self.settings.get('role') == 'vevo' and client_role == 'ado':
            self.server_socket = sock
            logging.info("Laptop connected to controller: %s", client_name)

        if (
            self.pending_activation_target
            and self.pending_activation_target == client_name
            and not self.kvm_active
        ):
            logging.info("Reconnected to %s, resuming KVM", client_name)
            self.active_client = sock
            self.pending_activation_target = None
            self.activate_kvm(switch_monitor=self.switch_monitor)

    def _on_client_disconnected(self, sock, client_name: str) -> None:
        if self.settings.get('role') == 'ado' and sock == self.input_provider_socket:
            logging.info("Input provider disconnected: %s", client_name)
        elif sock == self.server_socket:
            logging.info("Controller disconnected: %s", client_name)
        
    def _process_server_messages(self):
        """Process raw messages received from clients on the server."""
        logging.debug("Server message processor thread started")
        buffers = {}
        try:
            while self._running:
                try:
                    sock, chunk = self.message_queue.get()
                except Exception:
                    break
                if sock is None and chunk is None:
                    break

                if not isinstance(chunk, (bytes, bytearray)):
                    continue

                buffer = buffers.setdefault(sock, bytearray())
                buffer.extend(chunk)
                while len(buffer) >= 4:
                    try:
                        msg_len = struct.unpack('!I', buffer[:4])[0]
                    except struct.error:
                        logging.error("Invalid length header from %s", self.client_infos.get(sock, sock))
                        buffers.pop(sock, None)
                        break
                    if len(buffer) < 4 + msg_len:
                        break
                    payload = bytes(buffer[4:4 + msg_len])
                    del buffer[:4 + msg_len]
                    try:
                        data = msgpack.unpackb(payload, raw=False)
                    except Exception as e:
                        logging.error(
                            "Failed to unpack message from %s: %s",
                            self.client_infos.get(sock, sock),
                            e,
                            exc_info=True,
                        )
                        continue
                    logging.debug(
                        "Server handling message type '%s' from %s",
                        data.get('type') or data.get('command'),
                        self.client_infos.get(sock, sock),
                    )

                    cmd = data.get('command')
                    if cmd == 'switch_elitedesk':
                        self.toggle_client_control('elitedesk', switch_monitor=True)
                        continue
                    if cmd == 'switch_laptop':
                        self.toggle_client_control('laptop', switch_monitor=False)
                        continue

                    msg_type = data.get('type')
                    if msg_type == 'clipboard_data':
                        self._handle_clipboard_data_message(sock, data)
                    elif msg_type == 'clipboard_clear':
                        self._handle_clipboard_clear_message(sock)
                    else:
                        logging.debug(
                            "Unhandled server message type '%s' from %s",
                            data.get('type') or data.get('command'),
                            self.client_infos.get(sock, sock),
                        )
        finally:
            buffers.clear()

    def _process_client_messages(self):
        """Process already unpacked messages received from the server."""
        logging.debug("Client message processor thread started")
        while self._running:
            try:
                sock, data = self.message_queue.get()
            except Exception:
                break
            if sock is None and data is None:
                break
            try:
                logging.debug(
                    "Client handling message type '%s'",
                    data.get('type'),
                )
                msg_type = data.get('type')
                if msg_type in {'move_relative', 'click', 'scroll', 'key'}:
                    self.input_manager.simulate_event(data)
                elif msg_type == 'clipboard_data':
                    self._handle_clipboard_data_message(sock, data)
                elif msg_type == 'clipboard_clear':
                    self._handle_clipboard_clear_message(sock)
                else:
                    logging.debug(
                        "Unhandled client message type '%s'",
                        data.get('type') or data.get('command'),
                    )
            except Exception as e:
                logging.error("Failed to process client message: %s", e, exc_info=True)


    def accept_connections(self):
        """Delegate incoming connection handling to the network manager."""
        self.network_manager.accept_connections()

    def monitor_client(self, sock, addr):
        """Delegate client monitoring to the network manager."""
        self.network_manager.monitor_client(sock, addr)

    def toggle_kvm_active(self, switch_monitor=True):
        """Toggle KVM state with optional monitor switching."""
        logging.info(
            "toggle_kvm_active called. current_state=%s switch_monitor=%s active_client=%s",
            self.kvm_active,
            switch_monitor,
            self.client_infos.get(self.active_client),
        )
        if self.settings.get('role') == 'ado':
            target = self.current_target if self.current_target != 'desktop' else 'elitedesk'
            if not self.kvm_active:
                self.activate_kvm(switch_monitor=switch_monitor, target=target)
            else:
                self.deactivate_kvm(switch_monitor=switch_monitor, reason="toggle_kvm_active")
            self.release_hotkey_keys()
            return
        if self.active_client is None:
            logging.warning("toggle_kvm_active invoked with no active_client")
        if not self.kvm_active:
            self.activate_kvm(switch_monitor=switch_monitor)
        else:
            self.deactivate_kvm(switch_monitor=switch_monitor, reason="toggle_kvm_active")
        self.release_hotkey_keys()

    def activate_kvm(self, switch_monitor=True, target: Optional[str] = None):
        if self.settings.get('role') == 'ado':
            if not self.input_provider_socket:
                self.status_update.emit("Hiba: Nincs input szolgáltató")
                logging.error("Activation requested without connected input provider")
                return
            if target is None:
                target = 'laptop' if self.active_client else 'elitedesk'
            self.switch_monitor = switch_monitor
            self.current_target = target
            self.pending_activation_target = None
            self.kvm_active = True
            if target == 'elitedesk':
                self.status_update.emit("Állapot: EliteDesk irányítása aktív")
                self._switch_monitor_for_target('elitedesk', allow_switch=switch_monitor)
            else:
                self.status_update.emit("Állapot: Laptop vezérlése aktív")
                self._switch_monitor_for_target('desktop', allow_switch=False)
            if not self._send_to_provider({'command': 'start_stream', 'target': target}):
                logging.error("Failed to start input streaming for target %s", target)
                if target == 'elitedesk':
                    self._switch_monitor_for_target('desktop', allow_switch=True)
                self.current_target = 'desktop'
                self.kvm_active = False
                self.status_update.emit("Hiba: nem érhető el az input szolgáltató")
                return
            logging.info("Controller activated for %s", target)
            return

        logging.info(
            "activate_kvm called. switch_monitor=%s active_client=%s",
            switch_monitor,
            self.client_infos.get(self.active_client, "unknown"),
        )
        self.pending_activation_target = None
        if self.active_client is None and self.client_sockets:
            self.active_client = self.client_sockets[0]
            logging.info(
                "No active client selected. Defaulting to %s",
                self.client_infos.get(self.active_client, "ismeretlen"),
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
            self._run_capturing_session()
            if self.kvm_active and self._running:
                logging.warning("Egér szinkronizáció megszakadt, újraindítás...")
                time.sleep(1)

    # worker.py -> JAVÍTOTT deactivate_kvm metódus

    def deactivate_kvm(
        self,
        switch_monitor=None,
        *,
        release_keys: bool = True,
        reason: Optional[str] = None,
    ):
        if self.settings.get('role') == 'ado':
            if not self.kvm_active and self.current_target == 'desktop':
                logging.info("Controller deactivate requested but already idle")
                if release_keys:
                    self.release_hotkey_keys()
                return
            prev_target = self.current_target
            self.input_manager.stop_capturing()
            self.kvm_active = False
            self.current_target = 'desktop'
            if self.input_provider_socket:
                self._send_to_provider({'command': 'stop_stream'})
            host_code = self.settings['monitor_codes']['host']
            need_switch = self.current_monitor_input != host_code
            do_switch = switch_monitor
            if do_switch is None:
                do_switch = prev_target == 'elitedesk' or need_switch
            self._switch_monitor_for_target(
                'desktop',
                allow_switch=bool(do_switch and need_switch),
            )
            self.status_update.emit("Állapot: Asztali gép irányít")
            if release_keys:
                self.release_hotkey_keys()
            logging.info("Controller deactivated (reason=%s)", reason)
            return

        if not self.kvm_active:
            logging.info(
                "deactivate_kvm called, but KVM was already inactive. Reason: %s. No action taken.",
                reason or "unknown",
            )
            if release_keys:
                self.release_hotkey_keys()
            return

        if reason:
            logging.info(
                "deactivate_kvm called. reason=%s switch_monitor=%s kvm_active=%s active_client=%s",
                reason, switch_monitor, self.kvm_active, self.client_infos.get(self.active_client),
            )
        else:
            logging.info(
                "deactivate_kvm called. switch_monitor=%s kvm_active=%s active_client=%s",
                switch_monitor, self.kvm_active, self.client_infos.get(self.active_client),
            )

        self.input_manager.stop_capturing()
        self.kvm_active = False
        self.status_update.emit("Állapot: Inaktív...")
        logging.info("KVM deaktiválva.")

        switch = switch_monitor if switch_monitor is not None else getattr(self, 'switch_monitor', True)
        if switch:
            time.sleep(0.2)
            try:
                with list(get_monitors())[0] as monitor:
                    monitor.set_input_source(self.settings['monitor_codes']['host'])
                    logging.info("Monitor sikeresen visszaváltva a hosztra.")
            except Exception as e:
                self.status_update.emit(f"Monitor hiba: {e}")
                logging.error(f"Monitor hiba: {e}", exc_info=True)

        if release_keys:
            self.release_hotkey_keys()

        if hasattr(self, '_host_mouse_controller') and self._host_mouse_controller and hasattr(self, '_orig_mouse_pos'):
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

    def switch_monitor_input(self, input_code):
        """Delegate monitor input switching to the hardware manager."""
        self.hardware_manager.switch_monitor_input(input_code)
    
    def _run_capturing_session(self) -> None:
        logging.info("Input capture session starting")
        self._capture_current_vks.clear()
        self._capture_numpad_vks.clear()
        self._capture_unsent_events.clear()
        self._capture_unsent_total = 0
        self._capture_send_queue = queue.Queue(maxsize=SEND_QUEUE_MAXSIZE)
        self._capture_sender_thread = threading.Thread(
            target=self._capture_sender_loop,
            daemon=True,
            name="InputSender",
        )
        self._capture_sender_thread.start()
        try:
            self.input_manager.start_capturing()
        except Exception as exc:
            logging.error("Input capture failed: %s", exc, exc_info=True)
        finally:
            if self._capture_send_queue is not None:
                try:
                    self._capture_send_queue.put_nowait(None)
                except Exception:
                    pass
            if self._capture_sender_thread and self._capture_sender_thread.is_alive():
                self._capture_sender_thread.join()
            self._capture_send_queue = None
            self._capture_sender_thread = None
            if self._capture_unsent_total:
                logging.warning(
                    "Unsent or failed events (total=%d, showing_last=%d): %s",
                    self._capture_unsent_total,
                    len(self._capture_unsent_events),
                    list(self._capture_unsent_events),
                )
            logging.info("Input capture session finished")

    def _capture_sender_loop(self) -> None:
        while self.kvm_active and self._running:
            if not self._capture_send_queue:
                break
            try:
                event = self._capture_send_queue.get(timeout=0.05)
            except queue.Empty:
                continue
            if event is None:
                logging.debug("Input sender loop exiting")
                break
            self._dispatch_input_event(event)

    def _handle_captured_input(self, event: dict) -> None:
        if not self.kvm_active or not self._running:
            return
        if event.get('type') == 'key' and self._handle_hotkeys(event):
            return
        self._queue_captured_event(event)

    def _queue_captured_event(self, event: dict) -> None:
        queue_obj = self._capture_send_queue
        if not queue_obj:
            return
        if not self.kvm_active:
            logging.warning(
                "Dropping captured event while inactive: %s (active_client=%s, connected=%d)",
                event,
                self.client_infos.get(self.active_client),
                len(self.client_sockets),
            )
            self._record_unsent_input(event)
            return
        try:
            if queue_obj.full():
                try:
                    queue_obj.get_nowait()
                except queue.Empty:
                    pass
                logging.debug("Input send queue full, dropping oldest event")
            queue_obj.put_nowait(event)
            if event.get('type') == 'move_relative':
                logging.debug(
                    "Relative mouse move queued: dx=%s dy=%s",
                    event.get('dx'),
                    event.get('dy'),
                )
            else:
                logging.debug("Queued event: %s", event)
        except Exception as exc:
            logging.error("Failed to queue input event %s: %s", event, exc, exc_info=True)
            self._record_unsent_input(event)
            self.deactivate_kvm(reason="queue error")

    def _dispatch_input_event(self, event: dict) -> None:
        if not self.kvm_active:
            self._record_unsent_input(event)
            return
        if self.active_client is None and self.client_sockets:
            self.active_client = self.client_sockets[0]
        targets = [self.active_client] if self.active_client else []
        to_remove = []
        active_lost = False
        for sock in list(targets):
            if sock not in self.client_sockets:
                continue
            if not self._send_message(sock, event):
                self._record_unsent_input(event)
                to_remove.append(sock)
        for sock in to_remove:
            if sock == self.active_client:
                active_lost = True
            self._handle_disconnect(sock, "sender error")
            if self.client_sockets and self.active_client is None:
                self.active_client = self.client_sockets[0]
        if active_lost:
            if self.active_client:
                self.status_update.emit(
                    f"Kapcsolat megszakadt. Átváltás: {self.client_infos.get(self.active_client, 'ismeretlen')}"
                )
            else:
                self.status_update.emit(
                    "Kapcsolat megszakadt. Várakozás új kliensre..."
                )
        if to_remove and not self.client_sockets:
            self.deactivate_kvm(reason="all clients disconnected")

    def _record_unsent_input(self, event: Any) -> None:
        self._capture_unsent_total += 1
        summary: Any = event
        try:
            if isinstance(event, dict):
                summary = {}
                for key, value in event.items():
                    if isinstance(value, (bytes, bytearray)):
                        summary[key] = f"<{len(value)} bytes>"
                    elif isinstance(value, str) and len(value) > 200:
                        summary[key] = f"<string len={len(value)}>"
                    else:
                        summary[key] = value
            elif isinstance(event, (bytes, bytearray)):
                summary = f"<{len(event)} bytes>"
        except Exception:
            summary = repr(event)
        self._capture_unsent_events.append(summary)

    def _handle_hotkeys(self, event: dict) -> bool:
        pressed = bool(event.get('pressed'))
        key_type = event.get('key_type')
        key_val = event.get('key')
        vk_code = event.get('vk')
        if vk_code is not None:
            if pressed:
                self._capture_current_vks.add(int(vk_code))
                if event.get('numpad'):
                    self._capture_numpad_vks.add(int(vk_code))
            else:
                self._capture_current_vks.discard(int(vk_code))
                self._capture_numpad_vks.discard(int(vk_code))

        if key_type == 'special' and pressed:
            if key_val == 'f13':
                logging.info("F13 detected locally during streaming; deactivating controller")
                self.deactivate_kvm(switch_monitor=True, reason='streaming pico F13')
                return True
            if key_val == 'f14':
                logging.info("F14 detected locally during streaming; switching to laptop")
                self.toggle_client_control('laptop', switch_monitor=False)
                return True
            if key_val == 'f15':
                logging.info("F15 detected locally during streaming; switching to elitedesk")
                self.toggle_client_control('elitedesk', switch_monitor=True)
                return True
            if key_val in {'f18', 'f19', 'f20', 'f22'}:
                logging.info("Audio hotkey %s handled locally during streaming", key_val)
                return True

        is_shift = VK_LSHIFT in self._capture_current_vks or VK_RSHIFT in self._capture_current_vks
        is_num0 = (
            VK_NUMPAD0 in self._capture_current_vks
            or (
                VK_INSERT in self._capture_current_vks
                and VK_INSERT in self._capture_numpad_vks
            )
        )
        if is_shift and is_num0:
            logging.info("Shift+Numpad0 detected locally; returning control to host")
            for vk_code in [VK_LSHIFT, VK_RSHIFT, VK_NUMPAD0, VK_INSERT]:
                if vk_code in self._capture_current_vks:
                    release_event = {
                        'type': 'key',
                        'key_type': 'vk',
                        'key': vk_code,
                        'pressed': False,
                    }
                    self._dispatch_input_event(release_event)
            self._capture_current_vks.clear()
            self._capture_numpad_vks.clear()
            self.deactivate_kvm(switch_monitor=True, reason='streaming hotkey')
            return True
        return False

    def run_client(self):
        """Deprecated: client logic replaced by peer discovery."""
        pass

    def connect_to_server(self):
        """Deprecated: replaced by peer discovery."""
        return
        """

        # Egyszeri, 5 másodperces kezdeti várakozás a hálózat felépülésére.
        # Ez a metódus elején, a fő cikluson KÍVÜL van, így csak egyszer fut le.
        logging.info("Kezdeti várakozás (5 mp) a hálózat felépülésére...")
        self.status_update.emit("Várakozás a hálózatra...")
        time.sleep(5)

        while self._running:
            ip = self.server_ip or self.last_server_ip
            if not ip:
                self.status_update.emit("Adó keresése a hálózaton...")
                time.sleep(1) # Várunk, amíg a Zeroconf talál egy IP-t
                continue

            hb_thread = None
            s = None # Definiáljuk a socketet a try blokk előtt, hogy a finally is lássa

            try:
                # Tiszta, egyértelmű státusz üzenet a csatlakozás előtt
                self.status_update.emit(f"Csatlakozás: {ip}...")
                
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.settimeout(5.0)
                logging.info(f"Connecting to {ip}:{self.settings['port']}")
                s.connect((ip, self.settings['port']))
                s.settimeout(None)

                # Send initial handshake with our device name so the server can
                # store a friendly identifier instead of just the remote
                # address. If this fails we continue anyway and fall back to the
                # numeric address on the server side.
                try:
                    self._send_message(s, {"device_name": self.device_name})
                except Exception:
                    logging.warning("Failed to send device_name handshake", exc_info=True)
                
                self.server_socket = s
                settings_store = QSettings(ORG_NAME, APP_NAME)
                settings_store.setValue('network/last_server_ip', ip)
                self.last_server_ip = ip
                logging.info("Sikeres csatlakozás!")

                # Sikeres csatlakozás után visszaállítjuk a várakozási időt
                retry_delay = 3

                # Tiszta, egyértelmű státusz üzenet a siker után
                self.status_update.emit("Csatlakozva. Irányítás átvételre kész.")
                
                # Hotkey listener a kliens oldalon
                hotkey_cmd_l = {keyboard.Key.shift, keyboard.KeyCode.from_vk(VK_F12)}
                hotkey_cmd_r = {keyboard.Key.shift_r, keyboard.KeyCode.from_vk(VK_F12)}
                client_pressed_special_keys = set()
                client_pressed_vk_codes = set()
                def hk_press(key):
                    try: client_pressed_vk_codes.add(key.vk)
                    except AttributeError: client_pressed_special_keys.add(key)
                    combined_pressed = client_pressed_special_keys.union({keyboard.KeyCode.from_vk(vk) for vk in client_pressed_vk_codes})
                    if hotkey_cmd_l.issubset(combined_pressed) or hotkey_cmd_r.issubset(combined_pressed):
                        logging.info("Client hotkey (Shift+F12) detected, requesting switch_elitedesk")
                        try:
                            packed = msgpack.packb({'command': 'switch_elitedesk'}, use_bin_type=True)
                            s.sendall(struct.pack('!I', len(packed)) + packed)
                        except Exception: pass
                def hk_release(key):
                    try: client_pressed_vk_codes.discard(key.vk)
                    except AttributeError: client_pressed_special_keys.discard(key)
                hk_listener = keyboard.Listener(on_press=hk_press, on_release=hk_release)
                hk_listener.start()

                # A belső while ciklus, ami az üzeneteket fogadja
                def recv_all(sock, n):
                    data = b''
                    while len(data) < n:
                        chunk = sock.recv(n - len(data))
                        if not chunk: return None
                        data += chunk
                    return data

                while self._running and self.server_ip == ip:
                    raw_len = recv_all(s, 4)
                    if not raw_len: break
                    msg_len = struct.unpack('!I', raw_len)[0]
                    payload = recv_all(s, msg_len)
                    if payload is None: break
                    data = msgpack.unpackb(payload, raw=False)
                    self.message_queue.put((s, data))
            
            except (ConnectionRefusedError, socket.timeout, OSError) as e:
                if self._running:
                    logging.warning(f"Csatlakozás sikertelen: {e.__class__.__name__}. A szerver valószínűleg nem elérhető.")
            
            except Exception as e:
                if self._running:
                    logging.error(f"Váratlan hiba a csatlakozáskor: {e}", exc_info=True)

            finally:
                logging.info("Szerverkapcsolat lezárult vagy sikertelen volt.")
                if hb_thread: hb_thread.join(timeout=0.1)
                
                # A többi cleanup kód
                self.input_manager.release_simulated_keys()
                if hk_listener: hk_listener.stop()
                self.release_hotkey_keys()
                # Biztonságos hívás, csak akkor fut le, ha 's' létezik és létrejött a kapcsolat
                self.server_socket = None
                
                if self._running:
                    # Exponenciális visszalépés
                    self.status_update.emit(f"Újrapróbálkozás {retry_delay:.0f} mp múlva...")
                    logging.info(f"Újracsatlakozási kísérlet {retry_delay:.1f} másodperc múlva...")
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 1.5, max_retry_delay)
        """

    def discover_peers(self):
        """Delegate peer discovery to the network manager."""
        self.network_manager.discover_peers()

    def _resolver_thread(self):
        """Resolve service names queued by discover_peers."""
        self.network_manager.resolver_loop()

    def _connection_manager(self):
        """Continuously probe peers and attempt connections."""
        self.network_manager.connection_manager()

    def connect_to_peer(self, ip, port):
        """Active outbound connection to another peer."""
        self.network_manager.connect_to_peer(ip, port)

