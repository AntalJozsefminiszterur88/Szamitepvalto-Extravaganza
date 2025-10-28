# orchestrator.py - VÉGLEGES JAVÍTOTT VERZIÓ
# Javítva: Streaming listener `AttributeError`, "sticky key" hiba, visszaváltási logika, egér-akadás.

import socket
import time
import threading
import logging
import tkinter
import queue
import struct
from collections import deque
from typing import Any, Callable, Iterable, Optional
import msgpack
import random
import psutil  # ÚJ IMPORT
import os      # ÚJ IMPORT

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
from pynput import mouse, keyboard
from zeroconf import ServiceInfo, Zeroconf, IPVersion
from kvm_core.monitor import MonitorController
from kvm_core.network.peer_manager import PeerManager
from kvm_core.input.provider import InputProvider
from kvm_core.input.receiver import InputReceiver
from kvm_core.state import KVMState
from PySide6.QtCore import QObject, Signal, QSettings
from config import (
    SERVICE_TYPE,
    SERVICE_NAME_PREFIX,
    APP_NAME,
    ORG_NAME,
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
    VK_DIVIDE,
    VK_SUBTRACT,
    VK_MULTIPLY,
    VK_ADD,
)
from hardware.button_input_manager import ButtonInputManager
from utils.stability_monitor import StabilityMonitor
from kvm_core.clipboard import ClipboardManager, CLIPBOARD_CLEANUP_INTERVAL_SECONDS

# Delay between iterations in the streaming loop to lower CPU usage
STREAM_LOOP_DELAY = 0.05
# Maximum number of events queued for sending before old ones are dropped
SEND_QUEUE_MAXSIZE = 200
FORCE_NUMPAD_VK = {VK_DIVIDE, VK_SUBTRACT, VK_MULTIPLY, VK_ADD}
MOUSE_SYNC_INACTIVITY_TIMEOUT = 1.0
class KVMOrchestrator(QObject):
    __slots__ = (
        'settings', '_running', 'state', 'pynput_listeners', 'zeroconf',
        'streaming_thread', 'heartbeat_thread', 'switch_monitor', 'local_ip', 'server_ip',
        'connection_thread', 'device_name', 'clipboard_manager',
        'server_socket', 'input_provider_socket',
        'last_server_ip', 'message_queue',
        'message_processor_thread', '_host_mouse_controller', '_orig_mouse_pos',
        'pico_thread', 'pico_handler', 'peer_manager',
        'service_info', 'clients_lock',
        'pending_activation_target', 'provider_target',
        'monitor_controller',
        'button_manager',
        'stability_monitor', '_monitor_prefix', '_monitor_thread_keys',
        '_monitor_directory_keys', '_monitor_task_keys', '_monitor_memory_callback',
        'input_provider', 'input_receiver'
    )

    finished = Signal()
    status_update = Signal(str)

    def __init__(self, settings, stability_monitor: Optional[StabilityMonitor] = None):
        super().__init__()
        self.settings = settings
        self._running = True
        self.state = KVMState()
        self.pynput_listeners = []
        self.zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
        self.streaming_thread = None
        self.heartbeat_thread = None
        self.switch_monitor = True
        self.local_ip = self._detect_primary_ipv4()
        self.server_ip = None
        self.connection_thread = None
        self.service_info = None
        settings_store = QSettings(ORG_NAME, APP_NAME)
        self.last_server_ip = settings_store.value('network/last_server_ip', None)
        self.device_name = settings.get('device_name', socket.gethostname())
        self.clipboard_manager = None
        self.server_socket = None
        self.input_provider_socket = None
        self.message_queue = queue.Queue()
        self.message_processor_thread = None
        self._host_mouse_controller = None
        self._orig_mouse_pos = None
        self.pico_thread = None
        self.pico_handler = None
        # Lock protecting operations that need to coordinate with other resources
        self.clients_lock = threading.Lock()
        # Remember if a KVM session was active when the connection dropped
        self.pending_activation_target = None
        # Track ongoing reconnect attempts to avoid duplicates
        self.reconnect_threads = {}
        self.reconnect_lock = threading.Lock()
        self.provider_target = None
        self.state.set_target('desktop')
        monitor_codes = self.settings.get('monitor_codes', {}) or {}
        host_code = monitor_codes.get('host')
        client_code = monitor_codes.get('client')
        self.monitor_controller = MonitorController(
            host_input=host_code,
            client_input=client_code,
        )
        self.button_manager: Optional[ButtonInputManager] = None

        self.stability_monitor: Optional[StabilityMonitor] = stability_monitor
        self._monitor_prefix = f"kvm-{id(self):x}"
        self._monitor_thread_keys: list[str] = []
        self._monitor_directory_keys: list[str] = []
        self._monitor_task_keys: list[str] = []
        self._monitor_memory_callback: Optional[Callable[[], None]] = None

        self.input_receiver = InputReceiver()
        self.input_provider = InputProvider(
            self._send_provider_event,
            is_running=lambda: self._running,
            force_numpad_vk=FORCE_NUMPAD_VK,
        )

        def _peer_message_handler(peer_connection, data):
            sock = getattr(peer_connection, 'socket', None)
            self.message_queue.put((sock, data))

        self.peer_manager = PeerManager(
            self,
            self.state,
            self.zeroconf,
            port=self.settings['port'],
            device_name=self.device_name,
            message_callback=_peer_message_handler,
        )

        def _broadcast_clipboard(payload: dict, exclude: Optional[Iterable[Any]] = None) -> None:
            exclude_set = set(exclude or [])
            self.peer_manager.broadcast(
                payload,
                exclude_peer=exclude_set if exclude_set else None,
            )

        self.clipboard_manager = ClipboardManager(
            self.settings,
            _broadcast_clipboard,
            send_to_peer_callback=self.peer_manager.send_to_peer,
            get_server_socket=lambda: self.server_socket,
            send_to_provider_callback=self._send_to_provider,
            get_input_provider_socket=lambda: self.input_provider_socket,
            get_client_sockets=lambda: self.state.get_client_sockets(),
        )

        if self.stability_monitor:
            self._register_core_monitoring()
            if self.settings.get('role') == 'ado':
                self._register_clipboard_monitoring()

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
        register(
            'clipboard',
            lambda: self.clipboard_manager.thread if self.clipboard_manager else None,
        )
        register('streaming', lambda: self.streaming_thread, grace=15.0)
        register('connection_manager', lambda: self.peer_manager.connection_manager_thread)
        register('resolver', lambda: self.peer_manager.resolver_thread)
        register('connection', lambda: self.connection_thread)
        register('heartbeat', lambda: self.heartbeat_thread)
        register('pico', lambda: self.pico_thread)

    def _register_clipboard_monitoring(self) -> None:
        if not self.stability_monitor or not self.clipboard_manager:
            return

        storage_dir = self.clipboard_manager.storage_dir
        if not storage_dir:
            return

        monitor = self.stability_monitor
        directory = os.path.abspath(storage_dir)
        if directory not in self._monitor_directory_keys:
            monitor.add_directory_quota(directory, max_mb=512, min_free_mb=256)
            self._monitor_directory_keys.append(directory)

        task_name = f"{self._monitor_prefix}/clipboard_cleanup"
        if task_name not in self._monitor_task_keys:
            monitor.add_periodic_task(
                task_name,
                max(3600.0, CLIPBOARD_CLEANUP_INTERVAL_SECONDS / 2),
                lambda: self.clipboard_manager.ensure_storage_cleanup(force=True),
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
                if self.clipboard_manager:
                    self.clipboard_manager.ensure_storage_cleanup(force=True)
            except Exception:
                logging.exception("Clipboard cleanup failed during memory pressure mitigation")

    def toggle_monitor_power(self) -> None:
        """Toggle the primary monitor power state between on and soft off."""
        self.monitor_controller.toggle_power()

    # ------------------------------------------------------------------
    # Network helpers
    # ------------------------------------------------------------------
    def _send_to_provider(self, payload: dict) -> bool:
        """Send a command to the connected input provider if available."""
        sock = self.input_provider_socket
        if not sock:
            logging.warning("No input provider socket available for payload %s", payload)
            return False
        return self.peer_manager.send_to_peer(sock, payload)

    def _send_provider_event(self, payload: dict) -> bool:
        if not self._running:
            return False
        sock = self.server_socket
        if not sock:
            logging.error("Lost server socket while sending provider event")
            return False
        if not self.peer_manager.send_to_peer(sock, payload):
            logging.error("Failed to send provider event %s", payload)
            return False
        return True

    def _handle_provider_event(self, data: dict) -> None:
        """Route events coming from the input provider based on the active target."""
        target = self.state.get_target()
        if target == 'laptop':
            active_client = self.state.get_active_client()
            if active_client is None:
                logging.debug("No active laptop client to forward provider event %s", data)
                return
            if not self.peer_manager.send_to_peer(active_client, data):
                logging.warning("Failed to forward provider event to laptop; deactivating KVM")
                self.deactivate_kvm(reason="forward_failed", switch_monitor=False)
        elif target == 'elitedesk':
            self.input_receiver.apply_event(data)
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
            self.input_receiver.apply_event(press_event)
            time.sleep(0.05)
            self.input_receiver.apply_event(release_event)
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
        current_input = self.monitor_controller.current_input
        if desired is None or desired == current_input:
            return
        success, error = self.monitor_controller.switch_to_input(desired, label=target)
        if not success:
            self.status_update.emit(
                f"Monitor hiba: {error}" if error else "Monitor hiba: bemenet váltása sikertelen"
            )

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

    def _schedule_reconnect(self, ip: str, port: int) -> None:
        """Spawn a background thread that keeps trying to reconnect."""

        def _attempt():
            while self._running:
                with self.clients_lock:
                    if any(
                        s.getpeername()[0] == ip
                        for s in self.state.get_client_sockets()
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
                    if self.clipboard_manager and self.clipboard_manager.handle_network_message(sock, data):
                        continue
                    msg_type = data.get('type')
                    if msg_type in {'move_relative', 'click', 'scroll', 'key'} and sock == self.input_provider_socket:
                        self._handle_provider_event(data)
                        continue
                    logging.debug(
                        "Unhandled message type '%s' in controller context from %s",
                        data.get('type') or data.get('command'),
                        self.state.get_client_info(sock) or sock,
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
                    if self.clipboard_manager and self.clipboard_manager.handle_network_message(sock, data):
                        continue
                    msg_type = data.get('type')
                    logging.debug(
                        "Unhandled message type '%s' in input provider context",
                        data.get('type') or data.get('command'),
                    )
                    continue

                msg_type = data.get('type')
                if self.clipboard_manager and self.clipboard_manager.handle_network_message(sock, data):
                    continue
                if msg_type in {'move_relative', 'click', 'scroll', 'key'}:
                    self.input_receiver.apply_event(data)
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
        if self.input_provider.is_running():
            self.provider_target = target
            self.status_update.emit(f"Állapot: Továbbítás aktív ({target})")
            return
        self.provider_target = target
        self.state.set_active(True)
        self.status_update.emit(f"Állapot: Továbbítás aktív ({target})")
        self.input_provider.start()
        self.streaming_thread = self.input_provider.thread
        logging.info("Input provider streaming started toward %s", target)

    def _stop_input_provider_stream(self) -> None:
        """Stop forwarding events to the controller and restore local control."""
        if self.settings.get('role') != 'input_provider':
            return
        self.input_provider.stop()
        self.streaming_thread = None
        self.provider_target = None
        self.state.set_active(False)
        self.status_update.emit("Állapot: Helyi vezérlés aktív")
        logging.info("Input provider streaming stopped")

    def set_active_client_by_name(self, name):
        """Select a connected client by name as the active target."""
        logging.debug(f"set_active_client_by_name called with name={name}")
        for sock, cname in self.state.iter_clients():
            if cname.lower().startswith(name.lower()):
                self.state.set_active_client(sock)
                logging.info(f"Active client set to {cname}")
                return True
        logging.warning(f"No client matching '{name}' found")
        return False

    def toggle_client_control(self, name: str, *, switch_monitor: bool = True, release_keys: bool = True) -> None:
        """Activate or deactivate control for a specific client."""
        if self.settings.get('role') == 'ado':
            target = name.lower()
            desired_switch_monitor = switch_monitor
            current_target = self.state.get_target()
            is_active = self.state.is_active()
            logging.info(
                "Controller toggle requested for target=%s current=%s active=%s",
                target,
                current_target,
                is_active,
            )
            if target not in {'laptop', 'elitedesk'}:
                logging.warning("Unknown controller target: %s", target)
                return
            if is_active and current_target == target:
                logging.info(
                    "Toggle request ignored because target %s is already active",
                    target,
                )
                self.pending_activation_target = None
                return
            if is_active:
                prior_was_elitedesk = current_target == 'elitedesk'
                switching_between_main_targets = (
                    current_target in {'laptop', 'elitedesk'}
                    and target in {'laptop', 'elitedesk'}
                    and current_target != target
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
                self.state.set_active_client(None)
            self.activate_kvm(switch_monitor=desired_switch_monitor, target=target)
            return

        active_client = self.state.get_active_client()
        current = (self.state.get_client_info(active_client) or "").lower() if active_client else ""
        target = name.lower()
        logging.info(
            "toggle_client_control start: target=%s current=%s kvm_active=%s switch_monitor=%s",
            target,
            current,
            self.state.is_active(),
            switch_monitor,
        )
        if self.state.is_active() and current.startswith(target):
            logging.debug("Deactivating KVM because active client matches target")
            self.deactivate_kvm(release_keys=release_keys, reason="toggle_client_control same client")
            return
        if self.state.is_active():
            logging.debug("Deactivating current KVM session before switching client")
            self.deactivate_kvm(release_keys=release_keys, reason="toggle_client_control switch")
        if self.set_active_client_by_name(name):
            logging.debug("Activating KVM for client %s", name)
            self.activate_kvm(switch_monitor=switch_monitor)
        logging.info("toggle_client_control end")

    def stop(self):
        logging.info("stop() metódus meghívva.")
        self._running = False
        if self.clipboard_manager:
            self.clipboard_manager.stop()
        self._unregister_monitoring()
        self.pending_activation_target = None
        self.peer_manager.stop()
        if self.settings.get('role') == 'input_provider':
            self._stop_input_provider_stream()
        elif self.state.is_active():
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
            for sock in list(self.state.get_client_sockets()):
                try:
                    sock.close()
                except Exception:
                    pass
            self.state.clear_clients()
        self.server_socket = None if self.settings.get('role') != 'ado' else self.server_socket
        if self.settings.get('role') == 'ado':
            self.input_provider_socket = None
            self.state.set_target('desktop')
            self.state.set_active(False)
        if self.connection_thread and self.connection_thread.is_alive():
            self.connection_thread.join(timeout=1)
        if self.pico_thread and self.pico_thread.is_alive():
            self.pico_thread.join(timeout=1)
        if self.peer_manager.connection_manager_thread and self.peer_manager.connection_manager_thread.is_alive():
            self.peer_manager.connection_manager_thread.join(timeout=1)
        if self.peer_manager.accept_thread and self.peer_manager.accept_thread.is_alive():
            self.peer_manager.accept_thread.join(timeout=1)
        if self.peer_manager.resolver_thread and self.peer_manager.resolver_thread.is_alive():
            self.peer_manager.resolver_thread.join(timeout=1)
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
                    client_infos = self.state.get_client_infos()
                connected_clients_count = len(client_infos)
                client_names = list(client_infos.values())
                active_client = self.state.get_active_client()
                active_client_name = client_infos.get(active_client, "None")
                log_message = (
                    f"HEARTBEAT - "
                    f"Mem: {mem_usage:.2f} MB, CPU: {cpu_usage:.1f}%, Threads: {active_threads} | "
                    f"KVM Active: {self.state.is_active()}, Target: {active_client_name} | "
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

            self.peer_manager.start()

            if self.clipboard_manager:
                self.clipboard_manager.start()
                if self.settings.get('role') == 'ado':
                    self.start_main_hotkey_listener()

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
                        logging.error("Invalid length header from %s", self.state.get_client_info(sock) or sock)
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
                            self.state.get_client_info(sock) or sock,
                            e,
                            exc_info=True,
                        )
                        continue
                    logging.debug(
                        "Server handling message type '%s' from %s",
                        data.get('type') or data.get('command'),
                        self.state.get_client_info(sock) or sock,
                    )

                    cmd = data.get('command')
                    if cmd == 'switch_elitedesk':
                        self.toggle_client_control('elitedesk', switch_monitor=True)
                        continue
                    if cmd == 'switch_laptop':
                        self.toggle_client_control('laptop', switch_monitor=False)
                        continue

                    if self.clipboard_manager and self.clipboard_manager.handle_network_message(sock, data):
                        continue
                    logging.debug(
                        "Unhandled server message type '%s' from %s",
                        data.get('type') or data.get('command'),
                        self.state.get_client_info(sock) or sock,
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
                if self.clipboard_manager and self.clipboard_manager.handle_network_message(sock, data):
                    continue
                msg_type = data.get('type')
                if msg_type in {'move_relative', 'click', 'scroll', 'key'}:
                    self.input_receiver.apply_event(data)
                else:
                    logging.debug(
                        "Unhandled client message type '%s'",
                        data.get('type') or data.get('command'),
                    )
            except Exception as e:
                logging.error("Failed to process client message: %s", e, exc_info=True)


    def toggle_kvm_active(self, switch_monitor=True):
        """Toggle KVM state with optional monitor switching."""
        active_client = self.state.get_active_client()
        active_client_name = (
            self.state.get_client_info(active_client) if active_client else None
        )
        logging.info(
            "toggle_kvm_active called. current_state=%s switch_monitor=%s active_client=%s",
            self.state.is_active(),
            switch_monitor,
            active_client_name,
        )
        if self.settings.get('role') == 'ado':
            current_target = self.state.get_target()
            target = current_target if current_target != 'desktop' else 'elitedesk'
            if not self.state.is_active():
                self.activate_kvm(switch_monitor=switch_monitor, target=target)
            else:
                self.deactivate_kvm(switch_monitor=switch_monitor, reason="toggle_kvm_active")
            self.release_hotkey_keys()
            return
        if active_client is None:
            logging.warning("toggle_kvm_active invoked with no active_client")
        if not self.state.is_active():
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
            active_client = self.state.get_active_client()
            if target is None:
                target = 'laptop' if active_client else 'elitedesk'
            self.switch_monitor = switch_monitor
            self.state.set_target(target)
            self.pending_activation_target = None
            self.state.set_active(True)
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
                self.state.set_target('desktop')
                self.state.set_active(False)
                self.status_update.emit("Hiba: nem érhető el az input szolgáltató")
                return
            logging.info("Controller activated for %s", target)
            return

        logging.info(
            "activate_kvm called. switch_monitor=%s active_client=%s",
            switch_monitor,
            self.state.get_client_info(self.state.get_active_client()) or "unknown",
        )
        self.pending_activation_target = None
        active_client = self.state.get_active_client()
        if active_client is None:
            sockets = self.state.get_client_sockets()
            if sockets:
                active_client = sockets[0]
                self.state.set_active_client(active_client)
                logging.info(
                    "No active client selected. Defaulting to %s",
                    self.state.get_client_info(active_client) or "ismeretlen",
                )
        if not self.state.has_clients():
            self.status_update.emit("Hiba: Nincs csatlakozott kliens a váltáshoz!")
            logging.warning("Váltási kísérlet kliens kapcsolat nélkül.")
            return

        self.switch_monitor = switch_monitor
        self.state.set_active(True)

        self.status_update.emit("Állapot: Aktív...")
        logging.info("KVM aktiválva.")
        self.streaming_thread = threading.Thread(target=self._streaming_loop, daemon=True, name="StreamingThread")
        self.streaming_thread.start()
        logging.debug("Streaming thread started")

    def _streaming_loop(self):
        """Keep streaming active and restart if it stops unexpectedly."""
        while self.state.is_active() and self._running:
            self.start_kvm_streaming()
            if self.state.is_active() and self._running:
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
            current_target = self.state.get_target()
            if not self.state.is_active() and current_target == 'desktop':
                logging.info("Controller deactivate requested but already idle")
                if release_keys:
                    self.release_hotkey_keys()
                return
            prev_target = current_target
            self.state.set_active(False)
            self.state.set_target('desktop')
            if self.input_provider_socket:
                self._send_to_provider({'command': 'stop_stream'})
            host_code = self.settings['monitor_codes']['host']
            need_switch = self.monitor_controller.current_input != host_code
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

        if not self.state.is_active():
            logging.info(
                "deactivate_kvm called, but KVM was already inactive. Reason: %s. No action taken.",
                reason or "unknown",
            )
            if release_keys:
                self.release_hotkey_keys()
            return

        active_client = self.state.get_active_client()
        active_client_name = self.state.get_client_info(active_client) if active_client else None
        if reason:
            logging.info(
                "deactivate_kvm called. reason=%s switch_monitor=%s kvm_active=%s active_client=%s",
                reason,
                switch_monitor,
                self.state.is_active(),
                active_client_name,
            )
        else:
            logging.info(
                "deactivate_kvm called. switch_monitor=%s kvm_active=%s active_client=%s",
                switch_monitor,
                self.state.is_active(),
                active_client_name,
            )

        self.state.set_active(False)
        self.status_update.emit("Állapot: Inaktív...")
        logging.info("KVM deaktiválva.")

        switch = switch_monitor if switch_monitor is not None else getattr(self, 'switch_monitor', True)
        if switch:
            time.sleep(0.2)
            success, error = self.monitor_controller.switch_to_host()
            if not success:
                if error:
                    self.status_update.emit(f"Monitor hiba: {error}")
                    logging.error("Monitor hiba a hosztra váltáskor: %s", error)
                else:
                    logging.error("Monitor hiba a hosztra váltáskor")

        if release_keys:
            self.release_hotkey_keys()

        if hasattr(self, '_host_mouse_controller') and self._host_mouse_controller and hasattr(self, '_orig_mouse_pos'):
            try:
                self._host_mouse_controller.position = self._orig_mouse_pos
            except Exception as e:
                logging.error(f"Failed to restore mouse position: {e}", exc_info=True)

        self._host_mouse_controller = None
        self._orig_mouse_pos = None

        client_sockets = self.state.get_client_sockets()
        active_client = self.state.get_active_client()
        if active_client not in client_sockets:
            if active_client is not None:
                logging.warning("Active client disconnected during deactivation")
            else:
                logging.debug("No active client set after deactivation")

            if client_sockets:
                new_active = client_sockets[0]
                self.state.set_active_client(new_active)
                logging.info(
                    "Reselected active client: %s",
                    self.state.get_client_info(new_active),
                )
            else:
                self.state.set_active_client(None)

    def switch_monitor_input(self, input_code):
        """Switch the primary monitor to the given input source."""
        success, error = self.monitor_controller.switch_to_input(input_code)
        if not success and error:
            self.status_update.emit(f"Monitor hiba: {error}")
    
    def start_kvm_streaming(self):
        logging.info("start_kvm_streaming: initiating control transfer")
        state = self.state
        if getattr(self, 'switch_monitor', True):
            success, error = self.monitor_controller.switch_to_client()
            if not success:
                message = error or "bemenet váltása sikertelen"
                self.status_update.emit(f"Monitor hiba: {message}")
                logging.error("Monitor hiba a kliensre váltáskor: %s", message)
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

        sync_state_lock = threading.Lock()
        sync_state = {
            'last_activity': time.monotonic(),
            'paused': False,
            'resume_requested': False,
        }

        send_queue = queue.Queue(maxsize=SEND_QUEUE_MAXSIZE)
        unsent_events = deque(maxlen=50)
        unsent_events_total = 0

        def record_unsent(event: Any) -> None:
            nonlocal unsent_events_total
            unsent_events_total += 1
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
            unsent_events.append(summary)

        def sender():
            last_tick = time.monotonic()
            while state.is_active() and self._running:
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

                dx = dy = 0
                now = time.monotonic()
                if now - last_tick >= 0.015:
                    with movement_lock:
                        dx = accumulated_movement['dx']
                        dy = accumulated_movement['dy']
                        accumulated_movement['dx'] = 0
                        accumulated_movement['dy'] = 0
                    last_tick = now

                sync_message = None
                with sync_state_lock:
                    paused = sync_state['paused']
                    last_activity = sync_state['last_activity']
                    if sync_state['resume_requested']:
                        sync_state['resume_requested'] = False
                        sync_state['paused'] = False
                        paused = False
                        sync_message = {'type': 'sync_resume'}
                    elif not paused and (now - last_activity) >= MOUSE_SYNC_INACTIVITY_TIMEOUT:
                        sync_state['paused'] = True
                        paused = True
                        sync_message = {'type': 'sync_pause'}

                if sync_message is not None:
                    logging.debug("Mouse synchronization state changed: %s", sync_message['type'])
                    events.append((msgpack.packb(sync_message, use_bin_type=True), sync_message))

                if (dx != 0 or dy != 0) and not paused:
                    move_evt = {'type': 'move_relative', 'dx': dx, 'dy': dy}
                    events.append((msgpack.packb(move_evt, use_bin_type=True), move_evt))
                elif (dx != 0 or dy != 0) and paused:
                    logging.debug("Mouse movement suppressed due to inactivity pause: dx=%s dy=%s", dx, dy)

                if not events:
                    continue

                to_remove = []
                active_lost = False
                active_client = state.get_active_client()
                client_sockets = state.get_client_sockets()
                if active_client is None and client_sockets:
                    active_client = client_sockets[0]
                    state.set_active_client(active_client)
                targets = [active_client] if active_client else []
                for sock in list(targets):
                    if sock not in client_sockets:
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
                                    state.get_client_info(sock) or sock.getpeername(),
                                    event.get('dx'),
                                    event.get('dy'),
                                )
                            else:
                                logging.debug(
                                    "Sent %d bytes to %s",
                                    len(packed),
                                    state.get_client_info(sock) or sock.getpeername(),
                                )
                        except (socket.timeout, BlockingIOError):
                            logging.warning(
                                "Client not reading, disconnecting %s",
                                state.get_client_info(sock) or sock.getpeername(),
                            )
                            to_remove.append(sock)
                            break
                        except Exception as e:
                            try:
                                event_dbg = msgpack.unpackb(packed, raw=False)
                            except Exception:
                                event_dbg = '<unpack failed>'
                            logging.error(
                                f"Failed sending event {event_dbg} to {state.get_client_info(sock) or sock.getpeername()}: {e}",
                                exc_info=True,
                            )
                            if event_dbg != '<unpack failed>':
                                record_unsent(event_dbg)
                            to_remove.append(sock)
                            break
                for s in to_remove:
                    current_active = state.get_active_client()
                    if s == current_active:
                        active_lost = True
                    self.peer_manager.disconnect_peer(s, "sender error")
                    if state.get_active_client() is None:
                        remaining = state.get_client_sockets()
                        if remaining:
                            state.set_active_client(remaining[0])
                if active_lost:
                    current_active = state.get_active_client()
                    if current_active:
                        self.status_update.emit(
                            f"Kapcsolat megszakadt. Átváltás: {state.get_client_info(current_active) or 'ismeretlen'}"
                        )
                    else:
                        self.status_update.emit(
                            "Kapcsolat megszakadt. Várakozás új kliensre..."
                        )
                if to_remove and not state.has_clients():
                    self.deactivate_kvm(reason="all clients disconnected")
                    break

        sender_thread = threading.Thread(target=sender, daemon=True)
        sender_thread.start()

        def send(data):
            """Queue an event for sending and log the details."""
            if not state.is_active():
                logging.warning(
                    "Send called while KVM inactive. Event=%s active_client=%s connected_clients=%d",
                    data,
                    state.get_client_info(state.get_active_client()),
                    len(state.get_client_sockets()),
                )
                record_unsent(data)
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
                record_unsent(data)
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
                with sync_state_lock:
                    sync_state['last_activity'] = time.monotonic()
                    if sync_state['paused']:
                        sync_state['resume_requested'] = True
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
                forced_vk = None
                if hasattr(k, "vk") and k.vk in FORCE_NUMPAD_VK:
                    forced_vk = k.vk
                elif hasattr(k, "value") and hasattr(k.value, "vk") and k.value.vk in FORCE_NUMPAD_VK:
                    forced_vk = k.value.vk

                if forced_vk is not None:
                    key_type = "vk"
                    key_val = forced_vk
                elif hasattr(k, "char") and k.char is not None:
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
        
        while state.is_active() and self._running:
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
                record_unsent(evt)

        if unsent_events_total:
            logging.warning(
                "Unsent or failed events (total=%d, showing_last=%d): %s",
                unsent_events_total,
                len(unsent_events),
                list(unsent_events),
            )

        logging.info("Streaming listenerek leálltak.")

    def run_client(self):
        """Deprecated: client logic replaced by peer discovery."""
        pass

