# worker.py - VÉGLEGES JAVÍTOTT VERZIÓ
# Javítva: Streaming listener `AttributeError`, "sticky key" hiba, visszaváltási logika, egér-akadás.

import socket
import time
import threading
import logging
import tkinter
import queue
import struct
from datetime import datetime
from typing import Any, Optional
import io
import msgpack
import random
import psutil  # ÚJ IMPORT
import os      # ÚJ IMPORT
import math
import shutil
import zipfile

if os.name == 'nt':
    import ctypes
    from ctypes import wintypes

    _USER32 = ctypes.windll.user32
    _SM_XVIRTUALSCREEN = 76
    _SM_YVIRTUALSCREEN = 77
    _SM_CXVIRTUALSCREEN = 78
    _SM_CYVIRTUALSCREEN = 79
else:
    _USER32 = None
from clipboard_sync import (
    clear_clipboard,
    clipboard_items_equal,
    normalize_clipboard_item,
    read_clipboard_content,
    write_clipboard_content,
)
from pynput import mouse, keyboard
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser, IPVersion
from monitorcontrol import get_monitors
from monitorcontrol.monitorcontrol import PowerMode
from PySide6.QtCore import QObject, Signal, QSettings, QStandardPaths
import ipaddress
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
from button_input_manager import ButtonInputManager

# Delay between iterations in the streaming loop to lower CPU usage
STREAM_LOOP_DELAY = 0.05
# Maximum number of events queued for sending before old ones are dropped
SEND_QUEUE_MAXSIZE = 200
CLIPBOARD_STORAGE_DIRNAME = "SharedClipboard"
CLIPBOARD_CLEANUP_INTERVAL_SECONDS = 24 * 60 * 60
class KVMWorker(QObject):
    __slots__ = (
        'settings', '_running', 'kvm_active', 'client_sockets', 'client_infos',
        'client_roles', 'active_client', 'pynput_listeners', 'zeroconf',
        'streaming_thread', 'switch_monitor', 'local_ip', 'server_ip',
        'connection_thread', 'device_name', 'clipboard_thread',
        'last_clipboard_item', 'shared_clipboard_item', 'clipboard_lock',
        'clipboard_expiry_seconds', 'server_socket', 'input_provider_socket',
        '_ignore_next_clipboard_change', 'last_server_ip', 'message_queue',
        'message_processor_thread', '_host_mouse_controller', '_orig_mouse_pos',
        'mouse_controller', '_win_mouse_fraction', 'keyboard_controller',
        '_pressed_keys', '_provider_pressed_keys', 'pico_thread', 'pico_handler',
        'discovered_peers', 'connection_manager_thread', 'resolver_thread',
        'resolver_queue', 'service_info', 'peers_lock', 'clients_lock',
        'pending_activation_target', 'provider_stop_event', 'provider_target',
        'current_target', 'current_monitor_input', 'monitor_power_on',
        'button_manager',
        'clipboard_storage_dir',
        '_clipboard_cleanup_marker',
        '_clipboard_last_cleanup'
    )

    finished = Signal()
    status_update = Signal(str)

    def __init__(self, settings):
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
        self.pynput_listeners = []
        self.zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
        self.streaming_thread = None
        self.switch_monitor = True
        self.local_ip = self._detect_primary_ipv4()
        self.server_ip = None
        self.connection_thread = None
        self.connection_manager_thread = None
        self.resolver_thread = None
        self.resolver_queue = queue.Queue()
        self.service_info = None
        settings_store = QSettings(ORG_NAME, APP_NAME)
        self.last_server_ip = settings_store.value('network/last_server_ip', None)
        self.device_name = settings.get('device_name', socket.gethostname())
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
        self.mouse_controller = mouse.Controller()
        self._win_mouse_fraction = [0.0, 0.0]
        self.keyboard_controller = keyboard.Controller()
        self._pressed_keys = set()
        self._provider_pressed_keys = set()
        self.pico_thread = None
        self.pico_handler = None
        self.discovered_peers = {}
        # Lock protecting access to discovered_peers from multiple threads
        self.peers_lock = threading.Lock()
        # Lock protecting client_sockets and client_infos
        self.clients_lock = threading.Lock()
        # Remember if a KVM session was active when the connection dropped
        self.pending_activation_target = None
        # Track ongoing reconnect attempts to avoid duplicates
        self.reconnect_threads = {}
        self.reconnect_lock = threading.Lock()
        self.provider_stop_event = threading.Event()
        self.provider_target = None
        self.current_target = 'desktop'
        self.current_monitor_input = None
        self.monitor_power_on = True
        self.button_manager: Optional[ButtonInputManager] = None
        self.clipboard_storage_dir: Optional[str] = None
        self._clipboard_cleanup_marker: Optional[str] = None
        self._clipboard_last_cleanup: float = 0.0

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

    def toggle_monitor_power(self) -> None:
        """Toggle the primary monitor power state between on and soft off."""
        try:
            monitors = list(get_monitors())
            if not monitors:
                logging.warning("No monitors detected for power toggle (F21).")
                return

            with monitors[0] as monitor:
                try:
                    current_mode = monitor.get_power_mode()
                    monitor_is_on = current_mode == PowerMode.on
                    self.monitor_power_on = monitor_is_on
                except Exception as exc:
                    logging.warning(
                        "Failed to query monitor power state, assuming current value (%s): %s",
                        self.monitor_power_on,
                        exc,
                    )
                    monitor_is_on = self.monitor_power_on

                try:
                    if monitor_is_on:
                        monitor.set_power_mode(PowerMode.off_soft)
                        self.monitor_power_on = False
                        logging.info("Monitor power toggled OFF via F21 hotkey.")
                    else:
                        monitor.set_power_mode(PowerMode.on)
                        self.monitor_power_on = True
                        logging.info("Monitor power toggled ON via F21 hotkey.")
                except Exception as exc:
                    logging.error("Failed to toggle monitor power state: %s", exc, exc_info=True)
        except Exception as exc:
            logging.error("Unexpected error while toggling monitor power: %s", exc, exc_info=True)

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

        base_dir = os.path.join(documents_dir, ORG_NAME, APP_NAME, CLIPBOARD_STORAGE_DIRNAME)
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
            return

        # fmt == 'files'
        unique_name = self._build_unique_storage_name(base_name)
        target_dir = os.path.join(directory, unique_name)
        try:
            os.makedirs(target_dir, exist_ok=False)
        except FileExistsError:
            logging.debug(
                "Clipboard storage target %s already exists; generating a new name.",
                target_dir,
            )
            unique_name = self._build_unique_storage_name(f"{base_name}_extra")
            target_dir = os.path.join(directory, unique_name)
            try:
                os.makedirs(target_dir, exist_ok=False)
            except FileExistsError:
                logging.error(
                    "Unable to reserve clipboard storage directory %s; aborting persistence.",
                    target_dir,
                )
                return
        except Exception as exc:
            logging.error(
                "Failed to create clipboard storage directory %s: %s",
                target_dir,
                exc,
                exc_info=True,
            )
            return

        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                archive.extractall(target_dir)
        except zipfile.BadZipFile as exc:
            logging.error(
                "Clipboard file payload is not a valid archive: %s",
                exc,
            )
            shutil.rmtree(target_dir, ignore_errors=True)
            return
        except Exception as exc:
            logging.error(
                "Failed to unpack clipboard files into %s: %s",
                target_dir,
                exc,
                exc_info=True,
            )
            shutil.rmtree(target_dir, ignore_errors=True)
            return

        file_count = item.get('file_count')
        if not file_count and item.get('entries'):
            file_count = len(item['entries'])
        try:
            file_count_int = int(file_count) if file_count is not None else None
        except (TypeError, ValueError):
            file_count_int = None

        logging.info(
            "Clipboard files saved under %s (%s item%s, %d bytes payload).",
            target_dir,
            file_count_int if file_count_int is not None else 'unknown',
            '' if file_count_int == 1 else 's',
            len(payload),
        )

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
        """Send a msgpack message through the given socket."""
        try:
            packed = msgpack.packb(data, use_bin_type=True)
            sock.sendall(struct.pack('!I', len(packed)) + packed)
            logging.debug(
                "Sent message type '%s' (%d bytes)",
                data.get('type'),
                len(packed),
            )
            return True
        except Exception as e:
            logging.error(
                "Failed to send message type '%s': %s",
                data.get('type'),
                e,
                exc_info=True,
            )
            return False

    def _broadcast_message(self, data, exclude=None) -> None:
        """Broadcast a message to all connected clients."""
        if exclude is None:
            excluded = set()
        elif isinstance(exclude, (set, list, tuple)):
            excluded = set(exclude)
        else:
            excluded = {exclude}
        packed = msgpack.packb(data, use_bin_type=True)
        for s in list(self.client_sockets):
            if s in excluded:
                continue
            try:
                s.sendall(struct.pack('!I', len(packed)) + packed)
                logging.debug(
                    "Broadcast message type '%s' to %s (%d bytes)",
                    data.get('type'),
                    self.client_infos.get(s, 'unknown'),
                    len(packed),
                )
            except Exception as e:
                logging.error("Failed to broadcast message: %s", e)

    def _send_to_provider(self, payload: dict) -> bool:
        """Send a command to the connected input provider if available."""
        sock = self.input_provider_socket
        if not sock:
            logging.warning("No input provider socket available for payload %s", payload)
            return False
        return self._send_message(sock, payload)

    def _move_mouse_relative(self, dx, dy) -> None:
        """Move the cursor relative to its current position."""
        try:
            dx_val = float(dx) if dx is not None else 0.0
        except (TypeError, ValueError):
            dx_val = 0.0
        try:
            dy_val = float(dy) if dy is not None else 0.0
        except (TypeError, ValueError):
            dy_val = 0.0

        if dx_val == 0.0 and dy_val == 0.0:
            return

        if _USER32 is not None:
            try:
                point = wintypes.POINT()
                if not _USER32.GetCursorPos(ctypes.byref(point)):
                    raise ctypes.WinError(ctypes.get_last_error())

                total_dx = dx_val + self._win_mouse_fraction[0]
                total_dy = dy_val + self._win_mouse_fraction[1]
                frac_x, int_x = math.modf(total_dx)
                frac_y, int_y = math.modf(total_dy)

                move_x = int(int_x)
                move_y = int(int_y)

                self._win_mouse_fraction[0] = frac_x
                self._win_mouse_fraction[1] = frac_y

                target_x = point.x + move_x
                target_y = point.y + move_y

                width = _USER32.GetSystemMetrics(_SM_CXVIRTUALSCREEN)
                height = _USER32.GetSystemMetrics(_SM_CYVIRTUALSCREEN)
                if width and height:
                    left = _USER32.GetSystemMetrics(_SM_XVIRTUALSCREEN)
                    top = _USER32.GetSystemMetrics(_SM_YVIRTUALSCREEN)
                    max_x = left + width - 1
                    max_y = top + height - 1
                    if target_x < left:
                        target_x = left
                        self._win_mouse_fraction[0] = 0.0
                    elif target_x > max_x:
                        target_x = max_x
                        self._win_mouse_fraction[0] = 0.0
                    if target_y < top:
                        target_y = top
                        self._win_mouse_fraction[1] = 0.0
                    elif target_y > max_y:
                        target_y = max_y
                        self._win_mouse_fraction[1] = 0.0

                if move_x != 0 or move_y != 0 or target_x != point.x or target_y != point.y:
                    _USER32.SetCursorPos(int(target_x), int(target_y))
                return
            except Exception as exc:
                logging.debug("Native cursor move failed (%s), falling back to pynput", exc)
                self._win_mouse_fraction[0] = 0.0
                self._win_mouse_fraction[1] = 0.0

        self.mouse_controller.move(dx_val, dy_val)

    def _apply_event_locally(self, data: dict) -> None:
        """Apply a remote input event to the local controllers."""
        button_map = {
            'left': mouse.Button.left,
            'right': mouse.Button.right,
            'middle': mouse.Button.middle,
        }
        extra_button = getattr(mouse.Button, 'x1', None)
        if extra_button is not None:
            button_map['x1'] = extra_button
        msg_type = data.get('type')
        if msg_type == 'move_relative':
            self._move_mouse_relative(data.get('dx', 0), data.get('dy', 0))
        elif msg_type == 'click':
            btn = button_map.get(data.get('button'))
            if btn:
                (self.mouse_controller.press if data.get('pressed') else self.mouse_controller.release)(btn)
        elif msg_type == 'scroll':
            self.mouse_controller.scroll(data.get('dx', 0), data.get('dy', 0))
        elif msg_type == 'key':
            k_info = data.get('key')
            key_type = data.get('key_type')
            if key_type == 'char':
                k_press = k_info
            elif key_type == 'special':
                k_press = getattr(keyboard.Key, k_info, None)
            elif key_type == 'vk':
                try:
                    k_press = keyboard.KeyCode.from_vk(int(k_info))
                except Exception:
                    k_press = None
            else:
                k_press = None
            if k_press:
                if data.get('pressed'):
                    self.keyboard_controller.press(k_press)
                    self._pressed_keys.add(k_press)
                else:
                    self.keyboard_controller.release(k_press)
                    self._pressed_keys.discard(k_press)
        else:
            logging.debug("Unhandled local event type: %s", msg_type)

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
            self._apply_event_locally(data)
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
            self._apply_event_locally(press_event)
            time.sleep(0.05)
            self._apply_event_locally(release_event)
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
        self.pending_activation_target = None
        if self.settings.get('role') == 'input_provider':
            self._stop_input_provider_stream()
        elif self.kvm_active:
            self.deactivate_kvm(switch_monitor=False, reason="stop() called")  # Leállításkor ne váltson monitort
        if self.service_info:
            try:
                self.zeroconf.unregister_service(self.service_info)
            except Exception:
                pass
        try:
            self.zeroconf.close()
        except Exception:
            pass
        for listener in self.pynput_listeners:
            try:
                listener.stop()
            except:
                pass
        if self.button_manager:
            try:
                self.button_manager.stop()
            except Exception:
                logging.exception("Failed to stop button manager cleanly")
            self.button_manager = None
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
        if self.pico_thread and self.pico_thread.is_alive():
            self.pico_thread.join(timeout=1)
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

            heartbeat_thread = threading.Thread(
                target=self._heartbeat_monitor, daemon=True, name="Heartbeat"
            )
            heartbeat_thread.start()

            while self._running:
                time.sleep(0.5)
        except Exception as e:
            logging.critical("Worker encountered fatal error: %s", e, exc_info=True)
            self.status_update.emit(
                "Állapot: Hiba - a KVM szolgáltatás leállt"
            )
        finally:
            self.finished.emit()


    def start_main_hotkey_listener(self):
        """Segédmetódus a globális gyorsbillentyű-figyelő indítására."""
        if self.button_manager:
            return
        self.button_manager = ButtonInputManager(self)
        self.button_manager.start()
        
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
        button_map = {
            'left': mouse.Button.left,
            'right': mouse.Button.right,
            'middle': mouse.Button.middle,
        }
        extra_button = getattr(mouse.Button, 'x1', None)
        if extra_button is not None:
            button_map['x1'] = extra_button
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
                if msg_type == 'move_relative':
                    self._move_mouse_relative(data.get('dx', 0), data.get('dy', 0))
                elif msg_type == 'click':
                    btn = button_map.get(data.get('button'))
                    if btn:
                        (self.mouse_controller.press if data.get('pressed') else self.mouse_controller.release)(btn)
                elif msg_type == 'scroll':
                    self.mouse_controller.scroll(data.get('dx', 0), data.get('dy', 0))
                elif msg_type == 'key':
                    k_info = data.get('key')
                    if data.get('key_type') == 'char':
                        k_press = k_info
                    elif data.get('key_type') == 'special':
                        k_press = getattr(keyboard.Key, k_info, None)
                    elif data.get('key_type') == 'vk':
                        k_press = keyboard.KeyCode.from_vk(int(k_info))
                    else:
                        k_press = None
                    if k_press:
                        if data.get('pressed'):
                            self.keyboard_controller.press(k_press)
                            self._pressed_keys.add(k_press)
                        else:
                            self.keyboard_controller.release(k_press)
                            self._pressed_keys.discard(k_press)
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
        """Accept connections from peers; keep only if our IP wins the tie."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        while self._running:
            try:
                server_socket.bind(('', self.settings['port']))
                break
            except OSError as e:
                logging.error("Port bind failed: %s. Retrying...", e)
                time.sleep(5)

        server_socket.listen(5)
        logging.info(f"TCP server listening on {self.settings['port']}")

        while self._running:
            try:
                client_sock, addr = server_socket.accept()
            except OSError:
                break

            peer_ip = addr[0]
            try:
                local_addr = ipaddress.ip_address(self.local_ip)
                remote_addr = ipaddress.ip_address(peer_ip)
                if local_addr > remote_addr:
                    client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    threading.Thread(
                        target=self.monitor_client,
                        args=(client_sock, addr),
                        daemon=True,
                    ).start()
                else:
                    client_sock.close()
            except Exception:
                try:
                    client_sock.close()
                except Exception:
                    pass

        try:
            server_socket.close()
        except Exception:
            pass

    def monitor_client(self, sock, addr):
        """Monitor a single connection. Handles lifecycle and incoming data."""
        sock.settimeout(30.0)

        def recv_all(s, n):
            data = b''
            while len(data) < n:
                chunk = s.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
            return data

        client_name = str(addr)

        # Exchange device names with the peer. Each side sends first then reads.
        try:
            self._send_message(
                sock,
                {
                    'type': 'intro',
                    'device_name': self.device_name,
                    'role': self.settings.get('role'),
                },
            )
            raw_len = recv_all(sock, 4)
            if raw_len:
                msg_len = struct.unpack('!I', raw_len)[0]
                payload = recv_all(sock, msg_len)
                if payload:
                    hello = msgpack.unpackb(payload, raw=False)
                    client_name = hello.get('device_name', client_name)
                    client_role = hello.get('role')
                    if (
                        self.settings.get('role') == 'vevo'
                        and client_role == 'ado'
                    ):
                        try:
                            peer_ip = sock.getpeername()[0]
                        except Exception:
                            peer_ip = addr[0] if isinstance(addr, tuple) else None
                        if (
                            peer_ip
                            and peer_ip != self.last_server_ip
                            and peer_ip != self.local_ip
                        ):
                            self.last_server_ip = peer_ip
                            settings_store = QSettings(ORG_NAME, APP_NAME)
                            settings_store.setValue('network/last_server_ip', peer_ip)
                            logging.info(
                                "Laptop client stored last server IP: %s", peer_ip
                            )
                else:
                    client_role = None
            else:
                client_role = None
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            return

        with self.clients_lock:
            self.client_sockets.append(sock)
            self.client_infos[sock] = client_name
            if 'client_role' in locals():
                self.client_roles[sock] = client_role
            if self.active_client is None and client_role != 'input_provider':
                self.active_client = sock

        if self.settings.get('role') == 'ado' and client_role == 'input_provider':
            self.input_provider_socket = sock
            logging.info("Input provider connected: %s", client_name)
        if self.settings.get('role') == 'input_provider' and client_role == 'ado':
            self.server_socket = sock
            logging.info("Controller connection established: %s", client_name)
        if (
            self.pending_activation_target
            and self.pending_activation_target == client_name
            and not self.kvm_active
        ):
            logging.info("Reconnected to %s, resuming KVM", client_name)
            self.active_client = sock
            self.pending_activation_target = None
            self.activate_kvm(switch_monitor=self.switch_monitor)
        logging.info(f"Client connected: {client_name} ({addr})")
        logging.debug(
            "monitor_client start for %s",
            client_name,
        )
        # send current clipboard to newly connected client
        if self.settings.get('role') == 'ado':
            self._check_clipboard_expiration()
            payload = self._get_shared_clipboard_payload()
            if payload:
                try:
                    self._send_message(sock, payload)
                except Exception as exc:
                    logging.debug(
                        "Failed to send initial clipboard to %s: %s",
                        client_name,
                        exc,
                    )
        try:
            buffer = bytearray()
            logging.debug("monitor_client main loop starting for %s", client_name)
            while self._running:
                logging.debug("monitor_client waiting for data from %s", client_name)
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buffer.extend(chunk)
                    logging.debug("Received %d bytes from %s", len(chunk), client_name)
                    while len(buffer) >= 4:
                        msg_len = struct.unpack('!I', buffer[:4])[0]
                        if len(buffer) < 4 + msg_len:
                            break
                        payload = bytes(buffer[4:4 + msg_len])
                        del buffer[:4 + msg_len]
                        try:
                            data = msgpack.unpackb(payload, raw=False)
                        except Exception as e:
                            logging.error("Failed to unpack message from %s: %s", client_name, e, exc_info=True)
                            continue
                        logging.debug(
                            "monitor_client processing message type '%s'", data.get('type') or data.get('command')
                        )
                        self.message_queue.put((sock, data))
                except socket.timeout:
                    logging.debug(
                        "Socket timeout waiting for data from %s (timeout=%s)",
                        client_name,
                        sock.gettimeout(),
                    )
                    continue
                except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, socket.error):
                    break
                except Exception as e:
                    logging.error(
                        f"monitor_client recv error from {client_name}: {e}",
                        exc_info=True,
                    )
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError) as e:
            logging.warning(f"Hálózati hiba a kliensnél ({client_name}): {e}")
        except Exception as e:
            logging.error(f"Váratlan hiba a monitor_client-ben ({client_name}): {e}", exc_info=True)
       # worker.py -> monitor_client metóduson belüli 'finally' blokk JAVÍTVA

        # worker.py -> monitor_client metóduson belüli 'finally' blokk - VÉGLEGES JAVÍTÁS

        finally:
            logging.warning(f"Kliens lecsatlakozott: {client_name} ({addr}).")
            self._handle_disconnect(sock, "monitor_client")
            logging.debug("monitor_client exit for %s", client_name)

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
            self.start_kvm_streaming()
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
        """Switch the primary monitor to the given input source."""
        try:
            with list(get_monitors())[0] as monitor:
                monitor.set_input_source(input_code)
                logging.info("Monitor input switched to %s", input_code)
        except Exception as exc:
            logging.error("Failed to switch monitor input: %s", exc)
    
    def start_kvm_streaming(self):
        logging.info("start_kvm_streaming: initiating control transfer")
        if getattr(self, 'switch_monitor', True):
            try:
                with list(get_monitors())[0] as monitor:
                    monitor.set_input_source(self.settings['monitor_codes']['client'])
            except Exception as e:
                logging.error(f"Monitor hiba: {e}", exc_info=True)
                self.status_update.emit(f"Monitor hiba: {e}")
                self.deactivate_kvm(reason="monitor switch failed")
                return
        
        host_mouse_controller = mouse.Controller()
        self._host_mouse_controller = host_mouse_controller
        self._orig_mouse_pos = host_mouse_controller.position
        try:
            root = tkinter.Tk()
            root.withdraw()
            center_x, center_y = root.winfo_screenwidth()//2, root.winfo_screenheight()//2
            root.destroy()
        except:
            center_x, center_y = 800, 600
        
        host_mouse_controller.position = (center_x, center_y)
        last_pos = {'x': center_x, 'y': center_y}
        is_warping = False

        accumulated_movement = {'dx': 0, 'dy': 0}
        movement_lock = threading.Lock()

        send_queue = queue.Queue(maxsize=SEND_QUEUE_MAXSIZE)
        unsent_events = []

        def sender():
            last_tick = time.time()
            while self.kvm_active and self._running:
                events = []
                try:
                    payload = send_queue.get(timeout=0.01)
                    got_q = True
                except queue.Empty:
                    payload = None
                    got_q = False

                if got_q and payload is None:
                    logging.debug("Sender thread exiting")
                    break
                if got_q and payload is not None:
                    if isinstance(payload, tuple):
                        events.append(payload)
                    else:
                        events.append((payload, None))

                now = time.time()
                if now - last_tick >= 0.015:
                    with movement_lock:
                        dx = accumulated_movement['dx']
                        dy = accumulated_movement['dy']
                        accumulated_movement['dx'] = 0
                        accumulated_movement['dy'] = 0
                    if dx != 0 or dy != 0:
                        move_evt = {'type': 'move_relative', 'dx': dx, 'dy': dy}
                        events.append((msgpack.packb(move_evt, use_bin_type=True), move_evt))
                    last_tick = now

                if not events:
                    continue

                to_remove = []
                active_lost = False
                if self.active_client is None and self.client_sockets:
                    self.active_client = self.client_sockets[0]
                targets = [self.active_client] if self.active_client else []
                for sock in list(targets):
                    if sock not in self.client_sockets:
                        continue
                    for packed, event in events:
                        try:
                            prev_to = sock.gettimeout()
                            sock.settimeout(0.1)
                            sock.sendall(struct.pack('!I', len(packed)) + packed)
                            sock.settimeout(prev_to)
                            if event and event.get('type') == 'move_relative':
                                logging.debug(
                                    "Mouse move sent to %s: dx=%s dy=%s",
                                    self.client_infos.get(sock, sock.getpeername()),
                                    event.get('dx'),
                                    event.get('dy'),
                                )
                            else:
                                logging.debug(
                                    "Sent %d bytes to %s",
                                    len(packed),
                                    self.client_infos.get(sock, sock.getpeername()),
                                )
                        except (socket.timeout, BlockingIOError):
                            logging.warning(
                                "Client not reading, disconnecting %s",
                                self.client_infos.get(sock, sock.getpeername()),
                            )
                            to_remove.append(sock)
                            break
                        except Exception as e:
                            try:
                                event_dbg = msgpack.unpackb(packed, raw=False)
                            except Exception:
                                event_dbg = '<unpack failed>'
                            logging.error(
                                f"Failed sending event {event_dbg} to {self.client_infos.get(sock, sock.getpeername())}: {e}",
                                exc_info=True,
                            )
                            if event_dbg != '<unpack failed>':
                                unsent_events.append(event_dbg)
                            to_remove.append(sock)
                            break
                for s in to_remove:
                    if s == self.active_client:
                        active_lost = True
                    self._handle_disconnect(s, "sender error")
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
                    break

        sender_thread = threading.Thread(target=sender, daemon=True)
        sender_thread.start()

        def send(data):
            """Queue an event for sending and log the details."""
            if not self.kvm_active:
                logging.warning(
                    "Send called while KVM inactive. Event=%s active_client=%s connected_clients=%d",
                    data,
                    self.client_infos.get(self.active_client),
                    len(self.client_sockets),
                )
                unsent_events.append(data)
                return False
            try:
                packed = msgpack.packb(data, use_bin_type=True)
                if send_queue.full():
                    try:
                        send_queue.get_nowait()
                    except queue.Empty:
                        pass
                    logging.debug("Send queue full, dropping oldest event")
                send_queue.put_nowait((packed, data))
                if data.get('type') == 'move_relative':
                    logging.debug(
                        f"Egér pozíció elküldve: dx={data['dx']} dy={data['dy']}"
                    )
                else:
                    logging.debug(f"Queued event: {data}")
                return True
            except Exception as e:
                logging.error(f"Failed to queue event {data}: {e}", exc_info=True)
                unsent_events.append(data)
                self.deactivate_kvm(reason="queue error")
                return False

        def on_move(x, y):
            nonlocal is_warping
            if is_warping:
                is_warping = False
                return
            dx = x - last_pos['x']
            dy = y - last_pos['y']
            if dx != 0 or dy != 0:
                with movement_lock:
                    accumulated_movement['dx'] += dx
                    accumulated_movement['dy'] += dy
            is_warping = True
            host_mouse_controller.position = (center_x, center_y)
            last_pos['x'], last_pos['y'] = center_x, center_y

        def on_click(x,y,b,p):
            send({'type':'click','button':b.name,'pressed':p})

        def on_scroll(x,y,dx,dy):
            send({'type':'scroll','dx':dx,'dy':dy})
        
        pressed_keys = set()
        current_vks = set()
        numpad_vks = set()

        def get_vk(key):
            if hasattr(key, "vk") and key.vk is not None:
                return key.vk
            if hasattr(key, "value") and hasattr(key.value, "vk"):
                return key.value.vk
            return None

        # worker.py -> start_kvm_streaming metóduson belüli on_key JAVÍTVA

        def on_key(k, p):
            """Forward keyboard events and handle Pico/host hotkeys DURING streaming."""
            try:
                # --- ÚJ, FONTOS RÉSZ: VEZÉRLÉS FIGYELÉSE STREAMING ALATT ---
                # A billentyű lenyomásakor (p=True) ellenőrizzük a vezérlőgombokat.
                if p:
                    if k == keyboard.Key.f13:
                        logging.info("!!! Visszaváltás a hosztra (Pico F13) észlelve a streaming alatt !!!")
                        self.deactivate_kvm(switch_monitor=True, reason='streaming pico F13')
                        return # Ne küldjük tovább az F13-at a kliensnek
                    if k == keyboard.Key.f14:
                        logging.info("!!! Váltás laptopra (Pico F14) észlelve a streaming alatt !!!")
                        self.toggle_client_control('laptop', switch_monitor=False)
                        return # Ne küldjük tovább
                    if k == keyboard.Key.f15:
                        logging.info("!!! Váltás EliteDeskre (Pico F15) észlelve a streaming alatt !!!")
                        self.toggle_client_control('elitedesk', switch_monitor=True)
                        return
                    if k in (keyboard.Key.f18, keyboard.Key.f19, keyboard.Key.f20, keyboard.Key.f22):
                        logging.info("Audio/mute hotkey %s captured locally during streaming", k)
                        return

                # Itt jön a már meglévő logika a Shift+Numpad0 figyelésére is.
                # Ezt is kiegészítjük, hogy a Pico gombokkal konzisztens legyen.
                vk = get_vk(k)
                if vk is not None:
                    if p:
                        current_vks.add(vk)
                        if getattr(k, '_flags', 0) == 0:
                            numpad_vks.add(vk)
                    else:
                        current_vks.discard(vk)
                        numpad_vks.discard(vk)

                is_shift = VK_LSHIFT in current_vks or VK_RSHIFT in current_vks
                is_num0 = VK_NUMPAD0 in current_vks or (VK_INSERT in current_vks and VK_INSERT in numpad_vks)
                
                # Visszaváltás Shift+Num0-val
                if is_shift and is_num0:
                    logging.info("!!! Visszaváltás a hosztra (Shift+Numpad0) észlelve a streaming alatt !!!")
                    # Elengedjük a billentyűket a kliensen, mielőtt megszakítjuk a kapcsolatot
                    for vk_code in [VK_LSHIFT, VK_RSHIFT, VK_NUMPAD0, VK_INSERT]:
                        if vk_code in current_vks:
                            send({"type": "key", "key_type": "vk", "key": vk_code, "pressed": False})
                    current_vks.clear()
                    self.deactivate_kvm(switch_monitor=True, reason='streaming hotkey')
                    return
                
                # --- EDDIG TART AZ ÚJ ÉS MÓDOSÍTOTT LOGIKA ---

                # Az eredeti billentyű-továbbító logika marad
                if hasattr(k, "char") and k.char is not None:
                    key_type = "char"
                    key_val = k.char
                elif hasattr(k, "name"):
                    key_type = "special"
                    key_val = k.name
                elif hasattr(k, "vk"):
                    key_type = "vk"
                    key_val = k.vk
                else:
                    logging.warning(f"Ismeretlen billentyű: {k}")
                    return False

                key_id = (key_type, key_val)
                if p:
                    pressed_keys.add(key_id)
                else:
                    pressed_keys.discard(key_id)

                if not send({"type": "key", "key_type": key_type, "key": key_val, "pressed": p}):
                    return False
            except Exception as e:
                logging.error(f"Hiba az on_key függvényben: {e}", exc_info=True)
                return False

        m_listener = mouse.Listener(on_move=on_move, on_click=on_click, on_scroll=on_scroll, suppress=True)
        k_listener = keyboard.Listener(on_press=lambda k:on_key(k,True), on_release=lambda k:on_key(k,False), suppress=True)
        
        m_listener.start()
        k_listener.start()
        
        while self.kvm_active and self._running:
            time.sleep(STREAM_LOOP_DELAY)

        for ktype, kval in list(pressed_keys):
            send({"type": "key", "key_type": ktype, "key": kval, "pressed": False})
        pressed_keys.clear()

        m_listener.stop()
        k_listener.stop()
        send_queue.put(None)
        sender_thread.join()
        while not send_queue.empty():
            leftover = send_queue.get()
            if leftover and isinstance(leftover, tuple):
                _, evt = leftover
            else:
                evt = None
            if evt:
                unsent_events.append(evt)

        if unsent_events:
            logging.warning("Unsent or failed events: %s", unsent_events)

        logging.info("Streaming listenerek leálltak.")

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
                for k in list(self._pressed_keys):
                    try: self.keyboard_controller.release(k)
                    except: pass
                self._pressed_keys.clear()
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
        """Background zeroconf browser populating discovered_peers."""

        class Listener:
            def __init__(self, worker):
                self.worker = worker

            def add_service(self, zc, type_, name):
                self.worker.resolver_queue.put(name)

            def update_service(self, zc, type_, name):
                self.worker.resolver_queue.put(name)

            def remove_service(self, zc, type_, name):
                with self.worker.peers_lock:
                    self.worker.discovered_peers.pop(name, None)

        ServiceBrowser(self.zeroconf, SERVICE_TYPE, Listener(self))
        while self._running:
            time.sleep(0.1)

    def _resolver_thread(self):
        """Resolve service names queued by discover_peers."""
        while self._running:
            try:
                name = self.resolver_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                info = self.zeroconf.get_service_info(SERVICE_TYPE, name, 3000)
                if not info:
                    continue
                ip = None
                for addr in info.addresses:
                    if isinstance(addr, bytes) and len(addr) == 4:
                        ip = socket.inet_ntoa(addr)
                        break
                if not ip:
                    continue
                port = info.port
                if ip == self.local_ip and port == self.settings['port']:
                    continue
                with self.peers_lock:
                    self.discovered_peers[name] = {'ip': ip, 'port': port}
            except Exception as e:
                logging.debug("Resolver failed for %s: %s", name, e)

    def _connection_manager(self):
        """Continuously probe peers and attempt connections."""
        while self._running:
            with self.peers_lock:
                peers = list(self.discovered_peers.values())

            if self.settings.get('role') == 'vevo' and self.last_server_ip:
                if self.last_server_ip != self.local_ip and not any(
                    peer.get('ip') == self.last_server_ip for peer in peers
                ):
                    peers.append({'ip': self.last_server_ip, 'port': self.settings['port']})

            for peer in peers:
                ip = peer['ip']
                port = peer['port']
                with self.clients_lock:
                    already = any(
                        s.getpeername()[0] == ip
                        for s in self.client_sockets
                        if s.fileno() != -1
                    )
                if already:
                    continue
                self.connect_to_peer(ip, port)
            time.sleep(2)

    def connect_to_peer(self, ip, port):
        """Active outbound connection to another peer."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.connect((ip, port))
        except Exception as e:
            logging.error("Failed to connect to peer %s:%s: %s", ip, port, e)
            try:
                sock.close()
            except Exception:
                pass
            return

        threading.Thread(
            target=self.monitor_client,
            args=(sock, (ip, port)),
            daemon=True,
        ).start()

