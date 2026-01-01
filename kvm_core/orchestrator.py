# orchestrator.py - VÉGLEGES JAVÍTOTT VERZIÓ
# Javítva: Streaming listener `AttributeError`, "sticky key" hiba, visszaváltási logika, egér-akadás.

import socket
import time
import threading
import logging
from logging.handlers import RotatingFileHandler
import queue
import struct
from typing import Callable, Iterable, Optional
import msgpack
import os      # ÚJ IMPORT
from pathlib import Path

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
from pynput import keyboard
from kvm_core.monitor import MonitorController
from kvm_core.diagnostics import DiagnosticsManager
from kvm_core.network.peer_manager import PeerManager
from kvm_core.input.host_capture import HostInputCapture
from kvm_core.input.provider import InputProvider
from kvm_core.input.receiver import InputReceiver
from kvm_core.state import KVMState
from PySide6.QtCore import QObject, Signal, QSettings
from config.constants import (
    APP_NAME,
    ORG_NAME,
    ENABLE_SHARED_CLIPBOARD,
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
from kvm_core.message_handler import MessageHandler
from config.log_aggregator import LogAggregator
from utils.logging_setup import create_controller_file_handler, resolve_log_paths
from utils.path_helpers import resolve_documents_directory
from utils.remote_logging import RemoteLogHandler, get_remote_log_handler

FORCE_NUMPAD_VK = {VK_DIVIDE, VK_SUBTRACT, VK_MULTIPLY, VK_ADD}


class KVMOrchestrator(QObject):

    finished = Signal()
    status_update = Signal(str)

    def __init__(
        self,
        settings,
        stability_monitor: Optional[StabilityMonitor] = None,
        *,
        remote_log_handler: Optional[RemoteLogHandler] = None,
    ):
        super().__init__()
        self.settings = settings
        self._running = True
        self.state = KVMState()
        self.pynput_listeners = []
        self.streaming_thread = None
        self.switch_monitor = True
        self.local_ip = self._detect_primary_ipv4()
        self.server_ip = None
        self.connection_thread = None
        settings_store = QSettings(ORG_NAME, APP_NAME)
        self.last_server_ip = settings_store.value('network/last_server_ip', None)
        self.device_name = settings.get('device_name', socket.gethostname())
        self.clipboard_manager = None
        self.server_socket = None
        self.input_provider_socket = None
        self.message_queue = queue.Queue()
        self.message_processor_thread = None
        self.pico_thread = None
        self.pico_handler = None
        monitor_codes = self.settings.get('monitor_codes', {}) or {}
        host_code = monitor_codes.get('host')
        client_code = monitor_codes.get('client')
        self.monitor_controller = MonitorController(
            host_input=host_code,
            client_input=client_code,
        )
        self.button_manager: Optional[ButtonInputManager] = None

        self.stability_monitor: Optional[StabilityMonitor] = stability_monitor
        self._instrumented_methods: set[str] = set()
        if self.stability_monitor:
            self._instrument_monitored_methods()
        self._monitor_prefix = f"kvm-{id(self):x}"
        self._monitor_thread_keys: list[str] = []
        self._monitor_directory_keys: list[str] = []
        self._monitor_task_keys: list[str] = []
        self._monitor_memory_callback: Optional[Callable[[], None]] = None

        self.log_aggregator: Optional[LogAggregator] = None
        role = self.settings.get('role')
        self.remote_log_handler: Optional[RemoteLogHandler] = None
        if self.stability_monitor:
            if role == 'ado':
                self.stability_monitor.configure_role(
                    role='ado',
                    request_statistics_callback=self._request_client_statistics,
                    get_client_names_callback=self._get_connected_client_names,
                )
            else:
                self.stability_monitor.configure_role(role=role)

        if role == 'ado':
            self.log_aggregator = LogAggregator()
            self.log_aggregator.start()
        else:
            if remote_log_handler is not None:
                self.remote_log_handler = remote_log_handler
            else:
                self.remote_log_handler = get_remote_log_handler()
            if self.remote_log_handler:
                self.remote_log_handler.set_source(self.device_name)

        self.input_receiver = InputReceiver()
        self.input_provider = InputProvider(
            self._send_provider_event,
            is_running=lambda: self._running,
            force_numpad_vk=FORCE_NUMPAD_VK,
        )

        self.host_capture = HostInputCapture(
            self._send_host_event,
            state=self.state,
            monitor_controller=self.monitor_controller,
            status_update=self.status_update,
            deactivate_callback=self.deactivate_kvm,
            toggle_client_control=self.toggle_client_control,
            send_provider_function_key=lambda key, source: self.send_provider_function_key(
                key,
                source=source,
            ),
            is_running=lambda: self._running,
            get_switch_monitor=lambda: getattr(self, 'switch_monitor', True),
            force_numpad_vk=FORCE_NUMPAD_VK,
        )

        def _peer_message_handler(peer_connection, data):
            sock = getattr(peer_connection, 'socket', None)
            self.message_queue.put((sock, data))

        self.peer_manager = PeerManager(
            self,
            self.state,
            port=self.settings['port'],
            device_name=self.device_name,
            message_callback=_peer_message_handler,
        )

        if ENABLE_SHARED_CLIPBOARD:
            self.clipboard_manager = ClipboardManager(
                role=role,
                get_server_ip=self._get_clipboard_server_ip,
            )
        else:
            logging.info("Shared clipboard sync is temporarily disabled.")

        self.message_handler = MessageHandler(
            get_role=lambda: self.settings.get('role'),
            toggle_client_control=self.toggle_client_control,
            get_clipboard_manager=lambda: self.clipboard_manager,
            handle_provider_event=self._handle_provider_event,
            input_receiver=self.input_receiver,
            start_input_provider_stream=self._start_input_provider_stream,
            stop_input_provider_stream=self._stop_input_provider_stream,
            simulate_provider_key_tap=self._simulate_provider_key_tap,
            get_input_provider_socket=lambda: self.input_provider_socket,
            state=self.state,
            send_to_server=self._send_to_server,
            get_device_name=lambda: self.device_name,
            log_aggregator=self.log_aggregator,
            stability_monitor=self.stability_monitor,
        )

        self.diagnostics_manager = DiagnosticsManager(
            orchestrator=self,
            state=self.state,
        )

        self._heartbeat_thread: Optional[threading.Thread] = None
        self._heartbeat_stop = threading.Event()
        self._session_start_time = time.monotonic()
        self._crash_report_uploaded = False

        self._network_services_active = False

        if self.stability_monitor:
            self._register_core_monitoring()
            if self.settings.get('role') == 'ado':
                self._register_clipboard_monitoring()

    def _configure_logging(self) -> None:
        """Remove existing log handlers and attach the correct one for the
        current role.
        """
        role = self.settings.get("role")
        root_logger = logging.getLogger()

        # Remove any previously added file or remote handlers.
        for handler in list(root_logger.handlers):
            if isinstance(handler, (RotatingFileHandler, RemoteLogHandler)):
                root_logger.removeHandler(handler)

        documents_dir = resolve_documents_directory()
        _, log_file_path = resolve_log_paths(documents_dir)
        prefix = f"[{self.device_name}] - "
        file_handler = create_controller_file_handler(
            log_file_path, default_remote_source=prefix
        )
        root_logger.addHandler(file_handler)
        logging.info("File logging configured for role: %s", role)

        if role != "ado" and self.remote_log_handler:
            root_logger.addHandler(self.remote_log_handler)
            logging.info("Remote logging handler attached for client role.")

    def _get_clipboard_server_ip(self) -> Optional[str]:
        if self.server_socket:
            try:
                peer = self.server_socket.getpeername()
            except OSError:
                peer = None
            if isinstance(peer, tuple) and peer:
                return peer[0]
        if self.last_server_ip:
            return self.last_server_ip
        settings_store = QSettings(ORG_NAME, APP_NAME)
        stored_ip = settings_store.value("network/last_server_ip", None)
        if stored_ip:
            self.last_server_ip = stored_ip
        return stored_ip

    def release_hotkey_keys(self):
        """Release potential stuck hotkey keys without generating input."""
        kc = keyboard.Controller()
        keys = [
            keyboard.Key.shift_l,
            keyboard.Key.shift_r,
            keyboard.Key.alt_l,
            keyboard.Key.alt_r,
            keyboard.Key.ctrl_l,
            keyboard.Key.ctrl_r,
            keyboard.Key.tab,
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
    def _instrument_monitored_methods(self) -> None:
        if not self.stability_monitor:
            return

        monitored_methods = [
            "activate_kvm",
            "deactivate_kvm",
            "toggle_client_control",
            "_send_host_event",
            "send_provider_function_key",
            "switch_monitor_input",
        ]

        for name in monitored_methods:
            if name in self._instrumented_methods:
                continue
            original = getattr(self, name, None)
            if original is None:
                continue
            decorator = self.stability_monitor.track_method_call(name)
            wrapped = decorator(original)
            setattr(self, name, wrapped)
            self._instrumented_methods.add(name)

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
        register(
            'streaming',
            lambda: self.streaming_thread or (self.host_capture.thread if self.host_capture else None),
            grace=15.0,
        )
        register('connection_manager', lambda: self.peer_manager.connection_manager_thread)
        register('resolver', lambda: self.peer_manager.resolver_thread)
        register('connection', lambda: self.connection_thread)
        register('heartbeat', lambda: self.diagnostics_manager.heartbeat_thread)
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

    def _heartbeat_loop(self) -> None:
        """Periodic session tasks, including deferred crash upload."""
        logging.debug("KVM heartbeat loop started.")
        while self._running and not self._heartbeat_stop.is_set():
            if self._heartbeat_stop.wait(30):
                break
            try:
                runtime = time.monotonic() - self._session_start_time
                if (
                    self.state.is_active()
                    and runtime >= 60
                    and not self._crash_report_uploaded
                ):
                    self._upload_pending_crashes()
                    self._crash_report_uploaded = True
            except Exception:
                logging.exception("Heartbeat loop failed", exc_info=True)
        logging.debug("KVM heartbeat loop stopped.")

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

    def force_send_f22_to_desktop(self) -> bool:
        """Send a direct F22 trigger to the input provider, bypassing routing."""
        sock = self.peer_manager.get_socket_by_role("input_provider")
        if not sock:
            logging.warning("Input provider is not connected; cannot force F22 trigger")
            return False
        payload = {"command": "force_f22_trigger"}
        if not self.peer_manager.send_to_peer(sock, payload):
            logging.warning("Failed to send force F22 trigger to input provider")
            return False
        return True

    def _send_to_server(self, payload: dict) -> bool:
        if self.settings.get('role') == 'ado':
            return False
        sock = self.server_socket
        if not sock:
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
        target = self.state.get_current_target()
        if target == 'laptop':
            if self.state.get_active_client() is None:
                logging.debug("No active laptop client to forward provider event %s", data)
                return
            if not self.peer_manager.send_to_peer(self.state.get_active_client(), data):
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

    def _resume_network_services(self) -> None:
        if self._network_services_active:
            return
        self.peer_manager.start()
        if self.clipboard_manager:
            self.clipboard_manager.start()
            if self.settings.get('role') == 'ado':
                self.start_main_hotkey_listener()
        self._network_services_active = True

    def _pause_network_services(self) -> None:
        if not self._network_services_active and not self.peer_manager.is_running:
            self._network_services_active = False
            self.state.set_active(False)
            return
        self.peer_manager.stop()
        if self.clipboard_manager:
            self.clipboard_manager.stop()
        self._network_services_active = False
        self.state.set_active(False)

    def _process_messages(self):
        """Unified message handler for all peers."""
        logging.debug("Message processor thread started")
        while self._running:
            try:
                sock, data = self.message_queue.get()
            except Exception:
                break
            if sock is None and data is None:
                break
            self.message_handler.handle(sock, data)

    def _start_input_provider_stream(self, target: str) -> None:
        """Start streaming local input toward the controller when requested."""
        if self.settings.get('role') != 'input_provider':
            return
        if not self.server_socket:
            logging.error("Cannot start input streaming without server connection")
            self.status_update.emit("Hiba: Nincs kapcsolat a vezérlővel")
            return
        if self.input_provider.is_running():
            self.state.set_provider_target(target)
            self.status_update.emit(f"Állapot: Továbbítás aktív ({target})")
            return
        self.state.set_provider_target(target)
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
        self.state.set_provider_target(None)
        self.state.set_active(False)
        self.status_update.emit("Állapot: Helyi vezérlés aktív")
        logging.info("Input provider streaming stopped")

    def set_active_client_by_name(self, name):
        """Select a connected client by name as the active target."""
        logging.debug(f"set_active_client_by_name called with name={name}")
        for sock, cname in self.state.get_client_infos().items():
            if cname.lower().startswith(name.lower()):
                self.state.set_active_client(sock)
                logging.info(f"Active client set to {cname}")
                return True
        logging.warning(f"No client matching '{name}' found")
        return False

    def _request_client_statistics(self, period: str) -> None:
        if self.settings.get('role') != 'ado':
            return
        if self.stability_monitor:
            try:
                client_names = list(self._get_connected_client_names())
            except Exception:
                logging.exception("Failed to enumerate clients before requesting statistics")
                client_names = []
            self.stability_monitor.expect_stats_from(client_names)
        payload = {"command": "get_statistics", "period": period}
        self.peer_manager.broadcast(payload)

    def _get_connected_client_names(self) -> Iterable[str]:
        infos = self.state.get_client_infos()
        return list(infos.values())

    def _on_server_connected(self) -> None:
        if self.remote_log_handler:
            # Ensure the handler metadata reflects the active device name.
            self.remote_log_handler.set_source(self.device_name)
            # Use a stable sender method that is not bound to a specific connection.
            self.remote_log_handler.set_send_callback(self._send_to_server)
            logging.info("Remote logging callback is now active.")

    def _on_server_disconnected(self) -> None:
        if self.remote_log_handler:
            self.remote_log_handler.set_send_callback(None)

    def _upload_pending_crashes(self) -> None:
        """Upload locally persisted crash dumps to the controller server."""

        crash_path = Path(resolve_documents_directory()) / APP_NAME / "crash_dump.pending"
        if not crash_path.exists() or not crash_path.is_file():
            return

        try:
            content = crash_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            logging.exception("Failed to read crash dump from %s", crash_path)
            return

        payload = {
            "command": "upload_crash_report",
            "source": self.device_name,
            "content": content,
        }

        if not self._send_to_server(payload):
            logging.warning("Unable to upload crash report; will retry on next connection")
            return

        try:
            try:
                crash_path.unlink(missing_ok=True)
            except TypeError:
                # Python < 3.8 compatibility: remove without missing_ok
                try:
                    crash_path.unlink()
                except FileNotFoundError:
                    pass
        except (PermissionError, OSError) as exc:
            logging.warning("Cannot delete active crash dump: %s", exc)
        except Exception:
            logging.exception("Failed to remove crash dump after upload: %s", crash_path)

    def toggle_client_control(self, name: str, *, switch_monitor: bool = True, release_keys: bool = True) -> None:
        """Activate or deactivate control for a specific client."""
        if self.settings.get('role') == 'ado':
            target = name.lower()
            desired_switch_monitor = switch_monitor
            logging.info(
                "Controller toggle requested for target=%s current=%s active=%s",
                target,
                self.state.get_current_target(),
                self.state.is_active(),
            )
            if target not in {'laptop', 'elitedesk'}:
                logging.warning("Unknown controller target: %s", target)
                return
            if self.state.is_active() and self.state.get_current_target() == target:
                logging.info(
                    "Toggle request ignored because target %s is already active",
                    target,
                )
                self.state.set_pending_activation_target(None)
                return
            if self.state.is_active():
                prior_was_elitedesk = self.state.get_current_target() == 'elitedesk'
                switching_between_main_targets = (
                    self.state.get_current_target() in {'laptop', 'elitedesk'}
                    and target in {'laptop', 'elitedesk'}
                    and self.state.get_current_target() != target
                )
                deactivate_switch_monitor = False if switching_between_main_targets else prior_was_elitedesk
                self.deactivate_kvm(
                    switch_monitor=deactivate_switch_monitor,
                    release_keys=release_keys,
                    reason="controller switch",
                )
                self.state.set_pending_activation_target(None)
            if target == 'laptop':
                if not self.set_active_client_by_name('laptop'):
                    self.status_update.emit("Hiba: a laptop nem érhető el")
                    self.state.set_pending_activation_target(None)
                    return
            else:
                self.state.set_active_client(None)
            self.activate_kvm(switch_monitor=desired_switch_monitor, target=target)
            return

        current = self.state.get_client_name(self.state.get_active_client(), "").lower()
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
        logging.info("Orchestrator shutdown initiated.")
        self._running = False

        self._heartbeat_stop.set()
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            self._heartbeat_thread.join(timeout=1.0)
        self._heartbeat_thread = None

        logging.info("Stopping host capture...")
        self.host_capture.stop()
        self.streaming_thread = self.host_capture.thread
        logging.info("Host capture stopped.")

        logging.info("Stopping network services...")
        self._pause_network_services()
        logging.info("Network services stopped.")

        logging.info("Unregistering monitoring...")
        self._unregister_monitoring()
        logging.info("Monitoring unregistered.")

        self.state.set_pending_activation_target(None)

        if self.settings.get('role') == 'input_provider':
            logging.info("Stopping input provider stream...")
            self._stop_input_provider_stream()
            logging.info("Input provider stream stopped.")
        elif self.state.is_active():
            logging.info("Deactivating active KVM session...")
            self.deactivate_kvm(switch_monitor=False, reason="stop() called")  # Leállításkor ne váltson monitort
            logging.info("KVM session deactivated.")

        logging.info("Stopping DiagnosticsManager...")
        self.diagnostics_manager.stop()
        logging.info("DiagnosticsManager stopped.")

        logging.info("Stopping pynput listeners...")
        for listener in self.pynput_listeners:
            try:
                listener.stop()
            except Exception:
                logging.exception("Failed to stop pynput listener cleanly")
        logging.info("Pynput listeners stopped.")

        if self.button_manager:
            logging.info("Stopping ButtonInputManager...")
            try:
                self.button_manager.stop()
                logging.info("ButtonInputManager stopped.")
            except Exception:
                logging.exception("Failed to stop button manager cleanly")
            self.button_manager = None

        if self.log_aggregator:
            logging.info("Stopping LogAggregator...")
            self.log_aggregator.stop()
            self.log_aggregator = None
            logging.info("LogAggregator stopped.")

        if self.remote_log_handler:
            logging.info("Resetting remote log handler callback...")
            self.remote_log_handler.set_send_callback(None)

        logging.info("Closing client sockets...")
        for sock in self.state.get_client_sockets():
            try:
                sock.close()
            except Exception:
                logging.exception("Failed to close client socket cleanly")
        logging.info("Client sockets closed.")

        self.state.clear_clients()
        self.server_socket = None if self.settings.get('role') != 'ado' else self.server_socket
        if self.settings.get('role') == 'ado':
            logging.info("Resetting ADO role state...")
            self.input_provider_socket = None
            self.state.set_current_target('desktop')
            self.state.set_active(False)

        if self.connection_thread and self.connection_thread.is_alive():
            logging.info("Joining connection thread...")
            self.connection_thread.join(timeout=1)
            logging.info("Connection thread joined.")
        if self.pico_thread and self.pico_thread.is_alive():
            logging.info("Joining Pico thread...")
            self.pico_thread.join(timeout=1)
            logging.info("Pico thread joined.")
        if self.peer_manager.connection_manager_thread and self.peer_manager.connection_manager_thread.is_alive():
            logging.info("Joining peer connection manager thread...")
            self.peer_manager.connection_manager_thread.join(timeout=1)
            logging.info("Peer connection manager thread joined.")
        if self.peer_manager.accept_thread and self.peer_manager.accept_thread.is_alive():
            logging.info("Joining peer accept thread...")
            self.peer_manager.accept_thread.join(timeout=1)
            logging.info("Peer accept thread joined.")
        if self.peer_manager.resolver_thread and self.peer_manager.resolver_thread.is_alive():
            logging.info("Joining peer resolver thread...")
            self.peer_manager.resolver_thread.join(timeout=1)
            logging.info("Peer resolver thread joined.")
        if self.message_processor_thread and self.message_processor_thread.is_alive():
            logging.info("Stopping message processor thread...")
            try:
                self.message_queue.put_nowait((None, None))
            except Exception:
                logging.exception("Failed to signal message processor thread for shutdown")
            self.message_processor_thread.join(timeout=1)
            logging.info("Message processor thread joined.")

        # Extra safety to avoid stuck modifier keys on exit
        logging.info("Releasing hotkey keys...")
        self.release_hotkey_keys()
        logging.info("Hotkey keys released.")

        logging.info("Orchestrator shutdown complete.")

    def start(self) -> None:
        """Prepare the orchestrator and configure role-specific features."""
        self._session_start_time = time.monotonic()
        self._crash_report_uploaded = False
        self._heartbeat_stop.clear()
        self._configure_logging()

    def run(self) -> None:
        """Unified entry point starting peer threads and services."""
        if self.settings.get('role') == 'ado':
            logging.info("Starting ButtonInputManager for EliteDesk...")
            self.start_main_hotkey_listener()

        self.start()
        logging.info("Worker starting in hub-and-spoke mode")
        try:
            self.message_processor_thread = threading.Thread(
                target=self._process_messages,
                daemon=True,
                name="MsgProcessor",
            )
            self.message_processor_thread.start()

            self.diagnostics_manager.start()

            if self._heartbeat_thread is None or not self._heartbeat_thread.is_alive():
                self._heartbeat_thread = threading.Thread(
                    target=self._heartbeat_loop,
                    daemon=True,
                    name="KVMSessionHeartbeat",
                )
                self._heartbeat_thread.start()

            self._resume_network_services()

            while self._running:
                time.sleep(0.5)
        except Exception as e:
            logging.critical("Worker encountered fatal error: %s", e, exc_info=True)
            self.status_update.emit(
                "Állapot: Hiba - a KVM szolgáltatás leállt"
            )
        finally:
            self._pause_network_services()
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
                        logging.error("Invalid length header from %s", self.state.get_client_name(sock, sock))
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
                            self.state.get_client_name(sock, sock),
                            e,
                            exc_info=True,
                        )
                        continue
                    logging.debug(
                        "Server handling message type '%s' from %s",
                        data.get('type') or data.get('command'),
                        self.state.get_client_name(sock, sock),
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
                        self.state.get_client_name(sock, sock),
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
        logging.info(
            "toggle_kvm_active called. current_state=%s switch_monitor=%s active_client=%s",
            self.state.is_active(),
            switch_monitor,
            self.state.get_client_name(self.state.get_active_client()),
        )
        if self.settings.get('role') == 'ado':
            target = self.state.get_current_target() if self.state.get_current_target() != 'desktop' else 'elitedesk'
            if not self.state.is_active():
                self.activate_kvm(switch_monitor=switch_monitor, target=target)
            else:
                self.deactivate_kvm(switch_monitor=switch_monitor, reason="toggle_kvm_active")
            self.release_hotkey_keys()
            return
        if self.state.get_active_client() is None:
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
            if target is None:
                target = 'laptop' if self.state.get_active_client() else 'elitedesk'
            self.switch_monitor = switch_monitor
            self.state.set_current_target(target)
            self.state.set_pending_activation_target(None)
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
                self.state.set_current_target('desktop')
                self.state.set_active(False)
                self.status_update.emit("Hiba: nem érhető el az input szolgáltató")
                return
            logging.info("Controller activated for %s", target)
            return

        logging.info(
            "activate_kvm called. switch_monitor=%s active_client=%s",
            switch_monitor,
            self.state.get_client_name(self.state.get_active_client(), "unknown"),
        )
        self.state.set_pending_activation_target(None)
        if self.state.get_active_client() is None and self.state.get_client_sockets():
            self.state.set_active_client(self.state.get_client_sockets()[0])
            logging.info(
                "No active client selected. Defaulting to %s",
                self.state.get_client_name(self.state.get_active_client(), "ismeretlen"),
            )
        if not self.state.get_client_sockets():
            self.status_update.emit("Hiba: Nincs csatlakozott kliens a váltáshoz!")
            logging.warning("Váltási kísérlet kliens kapcsolat nélkül.")
            return

        self.switch_monitor = switch_monitor
        self.state.set_active(True)

        self.status_update.emit("Állapot: Aktív...")
        logging.info("KVM aktiválva.")
        self.host_capture.start()
        self.streaming_thread = self.host_capture.thread
        logging.debug("Streaming capture started")

    # worker.py -> JAVÍTOTT deactivate_kvm metódus

    def deactivate_kvm(
        self,
        switch_monitor=None,
        *,
        release_keys: bool = True,
        reason: Optional[str] = None,
    ):
        if self.settings.get('role') == 'ado':
            if not self.state.is_active() and self.state.get_current_target() == 'desktop':
                logging.info("Controller deactivate requested but already idle")
                if release_keys:
                    self.release_hotkey_keys()
                return
            prev_target = self.state.get_current_target()
            self.state.set_active(False)
            self.state.set_current_target('desktop')
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

        if reason:
            logging.info(
                "deactivate_kvm called. reason=%s switch_monitor=%s kvm_active=%s active_client=%s",
                reason, switch_monitor, self.state.is_active(), self.state.get_client_name(self.state.get_active_client()),
            )
        else:
            logging.info(
                "deactivate_kvm called. switch_monitor=%s kvm_active=%s active_client=%s",
                switch_monitor, self.state.is_active(), self.state.get_client_name(self.state.get_active_client()),
            )

        self.state.set_active(False)
        self.status_update.emit("Állapot: Inaktív...")
        logging.info("KVM deaktiválva.")

        self.host_capture.stop()
        self.streaming_thread = self.host_capture.thread

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

        if self.state.get_active_client() not in self.state.get_client_sockets():
            if self.state.get_active_client() is not None:
                logging.warning("Active client disconnected during deactivation")
            else:
                logging.debug("No active client set after deactivation")

            if self.state.get_client_sockets():
                self.state.set_active_client(self.state.get_client_sockets()[0])
                logging.info("Reselected active client: %s", self.state.get_client_name(self.state.get_active_client()))
            else:
                self.state.set_active_client(None)

    def switch_monitor_input(self, input_code):
        """Switch the primary monitor to the given input source."""
        success, error = self.monitor_controller.switch_to_input(input_code)
        if not success and error:
            self.status_update.emit(f"Monitor hiba: {error}")

    def _send_host_event(self, packed: bytes, event: Optional[dict]) -> bool:
        """Forward a single packed host event to the active client."""
        if not self.state.is_active():
            return False

        if self.state.get_active_client() is None and self.state.get_client_sockets():
            self.state.set_active_client(self.state.get_client_sockets()[0])

        targets = [self.state.get_active_client()] if self.state.get_active_client() else []
        if not targets:
            logging.debug("No active client available for event %s", event)
            return True

        to_remove = []
        active_lost = False

        for sock in list(targets):
            if sock not in self.state.get_client_sockets():
                continue
            try:
                prev_to = sock.gettimeout()
                sock.settimeout(0.1)
                sock.sendall(struct.pack('!I', len(packed)) + packed)
                sock.settimeout(prev_to)
                if event and event.get('type') == 'move_relative':
                    logging.debug(
                        "Mouse move sent to %s: dx=%s dy=%s",
                        self.state.get_client_name(sock, sock.getpeername()),
                        event.get('dx'),
                        event.get('dy'),
                    )
                else:
                    logging.debug(
                        "Sent %d bytes to %s",
                        len(packed),
                        self.state.get_client_name(sock, sock.getpeername()),
                    )
            except (socket.timeout, BlockingIOError):
                logging.warning(
                    "Client not reading, disconnecting %s",
                    self.state.get_client_name(sock, sock.getpeername()),
                )
                to_remove.append(sock)
                break
            except Exception as exc:
                try:
                    event_dbg = msgpack.unpackb(packed, raw=False)
                except Exception:
                    event_dbg = '<unpack failed>'
                logging.error(
                    "Failed sending event %s to %s: %s",
                    event_dbg,
                    self.state.get_client_name(sock, sock.getpeername()),
                    exc,
                    exc_info=True,
                )
                to_remove.append(sock)
                break

        for sock in to_remove:
            if sock == self.state.get_active_client():
                active_lost = True
            self.peer_manager.disconnect_peer(sock, "sender error")
            if self.state.get_client_sockets() and self.state.get_active_client() is None:
                self.state.set_active_client(self.state.get_client_sockets()[0])

        if active_lost:
            if self.state.get_active_client():
                self.status_update.emit(
                    "Kapcsolat megszakadt. Átváltás: "
                    f"{self.state.get_client_name(self.state.get_active_client(), 'ismeretlen')}"
                )
            else:
                self.status_update.emit("Kapcsolat megszakadt. Várakozás új kliensre...")

        if to_remove and not self.state.get_client_sockets():
            self.deactivate_kvm(reason="all clients disconnected")
            return False

        return True
    
    def run_client(self):
        """Deprecated: client logic replaced by peer discovery."""
        pass
