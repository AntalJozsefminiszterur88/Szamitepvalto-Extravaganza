# worker.py - VÉGLEGES JAVÍTOTT VERZIÓ
# Javítva: Streaming listener `AttributeError`, "sticky key" hiba, visszaváltási logika, egér-akadás.

import socket
import time
import threading
import logging
import queue
import struct
from typing import Optional
import msgpack
import psutil  # ÚJ IMPORT
import os      # ÚJ IMPORT
from clipboard_sync import safe_copy, safe_paste
from pynput import mouse, keyboard
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser, IPVersion
from monitorcontrol import get_monitors
from PySide6.QtCore import QObject, Signal, QSettings
from file_transfer import FileTransferHandler
import ipaddress
from config import (
    SERVICE_TYPE,
    SERVICE_NAME_PREFIX,
    APP_NAME,
    ORG_NAME,
    BRAND_NAME,
    TEMP_DIR_PARTS,
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

# Delay between iterations in the streaming loop to lower CPU usage
STREAM_LOOP_DELAY = 0.05
# Maximum number of events queued for sending before old ones are dropped
SEND_QUEUE_MAXSIZE = 200
# File transfer chunk size
FILE_CHUNK_SIZE = 65536
# Socket timeout (seconds) during file transfers
# Timeout while waiting for file transfer data
# Increased from 30 to 90 seconds to handle slower networks
TRANSFER_TIMEOUT = 90
# Minimum delay between progress updates
PROGRESS_UPDATE_INTERVAL = 0.5


class KVMWorker(QObject):
    __slots__ = (
        'settings', '_running', 'kvm_active', 'client_sockets', 'client_infos',
        'active_client', 'pynput_listeners', 'zeroconf',
        'switch_monitor', 'local_ip', 'server_ip', 'connection_thread',
        'device_name', 'clipboard_thread', 'last_clipboard', 'server_socket',
        '_ignore_next_clipboard_change',
        'last_server_ip', 'file_handler', 'message_queue', 'message_processor_thread',
        '_host_mouse_controller', '_orig_mouse_pos', 'mouse_controller',
        'keyboard_controller', '_pressed_keys', 'pico_thread', 'pico_handler',
        'discovered_peers', 'connection_manager_thread', 'resolver_thread',
        'resolver_queue', 'service_info', 'peers_lock', 'clients_lock',
        'pending_activation_target'
    )

    finished = Signal()
    status_update = Signal(str)
    update_progress_display = Signal(int, str)  # percentage, label text
    file_transfer_error = Signal(str)
    incoming_upload_started = Signal(str, float)

    def __init__(self, settings):
        super().__init__()
        self.settings = settings
        self._running = True
        self.kvm_active = False
        # Active client connections (multiple receivers can connect)
        self.client_sockets = []
        # Mapping from socket to human readable client name
        self.client_infos = {}
        # Currently selected client to forward events to
        self.active_client = None
        self.pynput_listeners = []
        self.zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
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
        self.last_clipboard = ""
        self.server_socket = None
        self._ignore_next_clipboard_change = threading.Event()
        self.file_handler = FileTransferHandler(self)
        self.message_queue = queue.Queue()
        self.message_processor_thread = None
        self._host_mouse_controller = None
        self._orig_mouse_pos = None
        self.mouse_controller = mouse.Controller()
        self.keyboard_controller = keyboard.Controller()
        self._pressed_keys = set()
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
    # Clipboard utilities
    # ------------------------------------------------------------------
    def _set_clipboard(self, text: str) -> None:
        """Safely set the system clipboard and flag it to prevent feedback."""
        if not text or text == self.last_clipboard:
            return
        try:
            self._ignore_next_clipboard_change.set()
            safe_copy(text)
            self.last_clipboard = text
            logging.debug("Clipboard set by application.")
        except Exception as e:
            logging.error(f"Failed to set clipboard: {e}", exc_info=True)
            self._ignore_next_clipboard_change.clear()

    def _get_clipboard(self) -> Optional[str]:
        """Safely read the system clipboard. Returns None if no text is available."""
        try:
            text = safe_paste()
        except Exception as e:
            logging.error("Failed to read clipboard: %s", e)
            return None
        return text if text else None

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
        packed = msgpack.packb(data, use_bin_type=True)
        for s in list(self.client_sockets):
            if s is exclude:
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
        self.file_handler.on_client_disconnected(sock)
        if sock == self.server_socket:
            self.server_socket = None
            logging.info(
                "A központi vezérlővel való kapcsolat megszakadt, a server_socket törölve."
            )

        with self.clients_lock:
            peer_name = self.client_infos.get(sock)
            was_active = sock == self.active_client
            if sock in self.client_sockets:
                self.client_sockets.remove(sock)
            if sock in self.client_infos:
                del self.client_infos[sock]
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
        """Monitors clipboard ONLY when KVM is active (HOST)."""
        logging.info("Clipboard server loop started.")
        while self._running and self.kvm_active:
            if self._ignore_next_clipboard_change.is_set():
                self._ignore_next_clipboard_change.clear()
                time.sleep(0.5)
                continue

            text = self._get_clipboard()
            if text is not None and text != self.last_clipboard:
                self.last_clipboard = text
                if self.active_client:
                    self._send_message(self.active_client, {'type': 'clipboard_text', 'text': text})
            time.sleep(0.5)
        logging.info("Clipboard server loop stopped.")

    def _clipboard_loop_client(self) -> None:
        """Monitors clipboard and syncs with server (CLIENT)."""
        logging.info("Clipboard client loop started.")
        while self._running:
            if not self.kvm_active:
                if self._ignore_next_clipboard_change.is_set():
                    self._ignore_next_clipboard_change.clear()
                    time.sleep(0.5)
                    continue

                text = self._get_clipboard()
                if text is not None and text != self.last_clipboard:
                    self.last_clipboard = text
                    if self.server_socket:
                        try:
                            self._send_message(self.server_socket, {'type': 'clipboard_text', 'text': text})
                        except Exception:
                            logging.warning("Failed to send clipboard update to server.")
            time.sleep(0.5)
        logging.info("Clipboard client loop stopped.")

    def _process_messages(self):
        """Unified message handler for all peers."""
        logging.debug("Message processor thread started")
        button_map = {
            'left': mouse.Button.left,
            'right': mouse.Button.right,
            'middle': mouse.Button.middle,
        }
        while self._running:
            try:
                sock, data = self.message_queue.get()
            except Exception:
                break
            if sock is None and data is None:
                break
            try:
                cmd = data.get('command')
                if cmd == 'switch_elitedesk':
                    self.set_control_target('elitedesk')
                    continue
                if cmd == 'switch_laptop':
                    self.set_control_target('laptop')
                    continue
                msg_type = data.get('type')
                sender = self.client_infos.get(sock)
                if (
                    self.settings.get('role') == 'ado'
                    and sender == 'desktop'
                    and msg_type in {'move_relative', 'click', 'scroll', 'key'}
                ):
                    if self.active_client:
                        self._send_message(self.active_client, data)
                        continue
                if msg_type == 'move_relative':
                    self.mouse_controller.move(data.get('dx', 0), data.get('dy', 0))
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
                elif msg_type == 'clipboard_text':
                    text = data.get('text', '')
                    if text and text != self.last_clipboard:
                        self._set_clipboard(text)
                        if self.settings.get('role') == 'ado':
                            self._broadcast_message(data, exclude=sock)
                else:
                    self.file_handler.handle_network_message(data, sock)
            except Exception as e:
                logging.error("Failed to process message: %s", e, exc_info=True)

    # ------------------------------------------------------------------
    # File transfer delegation
    # ------------------------------------------------------------------
    def share_files(self, paths, operation='copy') -> None:
        self.file_handler.share_files(paths, operation)

    def request_paste(self, dest_dir) -> None:
        self.file_handler.request_paste(dest_dir)

    def cancel_file_transfer(self):
        self.file_handler.cancel_file_transfer()

    # ------------------------------------------------------------------
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

    def set_control_target(self, target_name: str) -> None:
        """Set the current control target and switch the monitor accordingly."""
        target = target_name.lower()
        logging.info("Setting control target to: %s", target)
        # Always mark session as active
        self.kvm_active = True

        if target == 'elitedesk':
            # Switch back to the host machine
            self.active_client = None
        elif target in ('desktop', 'laptop'):
            if not self.set_active_client_by_name(target):
                logging.warning("Control target '%s' not found", target_name)
                return
        else:
            logging.warning("Control target '%s' not found", target_name)
            return

        if self.switch_monitor:
            self._switch_monitor_to_target(target)

    def stop(self):
        logging.info("stop() metódus meghívva.")
        self._running = False
        self.pending_activation_target = None
        if self.kvm_active:
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
        with self.clients_lock:
            for sock in list(self.client_sockets):
                try:
                    sock.close()
                except Exception:
                    pass
            self.client_sockets.clear()
            self.client_infos.clear()
            self.active_client = None
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
        self.file_handler.cleanup()
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
                    f"MsgProc: {msg_proc_alive}"
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
        role = self.settings.get('role')
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

            if role == 'ado':
                self.start_main_hotkey_listener()
            elif role == 'input_provider':
                self.run_input_provider()
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

    def run_input_provider(self):
        self.clipboard_thread = threading.Thread(
            target=self._clipboard_loop_client,
            daemon=True,
            name="ClipboardCli",
        )
        self.clipboard_thread.start()
        threading.Thread(
            target=self._start_permanent_input_streaming,
            daemon=True,
            name="InputProviderStream",
        ).start()

    def _start_permanent_input_streaming(self):
        last_pos = self.mouse_controller.position
        def safe_send(data):
            if self.server_socket:
                try:
                    self._send_message(self.server_socket, data)
                except Exception as e:
                    logging.error(f"Failed to send input event: {e}", exc_info=True)
        def on_move(x, y):
            nonlocal last_pos
            dx = x - last_pos[0]
            dy = y - last_pos[1]
            last_pos = (x, y)
            if dx or dy:
                safe_send({'type': 'move_relative', 'dx': dx, 'dy': dy})
        def on_click(x, y, button, pressed):
            safe_send({'type': 'click', 'button': button.name, 'pressed': pressed})
        def on_scroll(x, y, dx, dy):
            safe_send({'type': 'scroll', 'dx': dx, 'dy': dy})
        def on_key(key, pressed):
            try:
                if isinstance(key, keyboard.Key):
                    key_type = 'special'
                    key_val = key.name
                elif isinstance(key, keyboard.KeyCode) and key.vk:
                    key_type = 'vk'
                    key_val = key.vk
                elif hasattr(key, 'char') and key.char is not None:
                    key_type = 'char'
                    key_val = key.char
                else:
                    return
                safe_send({'type': 'key', 'key_type': key_type, 'key': key_val, 'pressed': pressed})
            except Exception as e:
                logging.error(f"Error in on_key: {e}", exc_info=True)
        m_listener = mouse.Listener(on_move=on_move, on_click=on_click, on_scroll=on_scroll, suppress=True)
        k_listener = keyboard.Listener(on_press=lambda k: on_key(k, True), on_release=lambda k: on_key(k, False), suppress=True)
        m_listener.start()
        k_listener.start()
        try:
            while self._running:
                time.sleep(STREAM_LOOP_DELAY)
        finally:
            m_listener.stop()
            k_listener.stop()

    def start_main_hotkey_listener(self):
        """Segédmetódus a globális gyorsbillentyű-figyelő indítására."""
        if self.pynput_listeners:
            return

        current_pressed_vk = set()
        numpad_pressed_vk = set()
        
        VK_F13, VK_F14, VK_F15, VK_F16 = 124, 125, 126, 127

        def handle_action(action_name):
            logging.info(f"!!! Hotkey action triggered: {action_name} !!!")
            if "desktop" in action_name:
                self.set_control_target('desktop')
            elif "laptop" in action_name:
                self.set_control_target('laptop')
            elif "elitedesk" in action_name:
                self.set_control_target('elitedesk')

        def on_press(key):
            if key == keyboard.Key.f13:
                logging.info("!!! Pico gomb 1 (F13) észlelve !!!")
                self.set_control_target('desktop')
                return
            if key == keyboard.Key.f14:
                logging.info("!!! Pico gomb 2 (F14) észlelve !!!")
                self.set_control_target('laptop')
                return
            if key == keyboard.Key.f15:
                logging.info("!!! Pico gomb 3 (F15) észlelve !!!")
                self.set_control_target('elitedesk')
                return
            if key == keyboard.Key.f16:
                logging.info("!!! Pico gomb 4 (F16) észlelve !!!")
                self.switch_monitor_input(17)
                return

            vk = getattr(key, 'vk', None)
            if vk is None: return

            current_pressed_vk.add(vk)
            if getattr(key, '_flags', 0) == 0:
                numpad_pressed_vk.add(vk)
            
            is_shift_pressed = VK_LSHIFT in current_pressed_vk or VK_RSHIFT in current_pressed_vk
            if is_shift_pressed:
                if VK_NUMPAD0 in current_pressed_vk or (VK_INSERT in current_pressed_vk and VK_INSERT in numpad_pressed_vk): handle_action("desktop")
                elif VK_NUMPAD1 in current_pressed_vk or (VK_END in current_pressed_vk and VK_END in numpad_pressed_vk): handle_action("laptop")
                elif VK_NUMPAD2 in current_pressed_vk or (VK_DOWN in current_pressed_vk and VK_DOWN in numpad_pressed_vk): handle_action("elitedesk")

        def on_release(key):
            vk = getattr(key, 'vk', None)
            if vk is not None:
                current_pressed_vk.discard(vk)
                numpad_pressed_vk.discard(vk)

        hotkey_listener = keyboard.Listener(on_press=on_press, on_release=on_release)
        self.pynput_listeners.append(hotkey_listener)
        hotkey_listener.start()
        logging.info("Pynput figyelő elindítva (kiterjesztve F13-F16 billentyűkkel).")
        
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
                        self.set_control_target('elitedesk')
                        continue
                    if cmd == 'switch_laptop':
                        self.set_control_target('laptop')
                        continue

                    if data.get('type') == 'clipboard_text':
                        text = data.get('text', '')
                        if text and text != self.last_clipboard:
                            self._set_clipboard(text)
                            self._broadcast_message(data, exclude=sock)
                    else:
                        self.file_handler.handle_network_message(data, sock)
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
                    self.mouse_controller.move(data.get('dx', 0), data.get('dy', 0))
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
                elif msg_type == 'clipboard_text':
                    text = data.get('text', '')
                    if text and text != self.last_clipboard:
                        self._set_clipboard(text)
                else:
                    self.file_handler.handle_network_message(data, sock)
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
            self._send_message(sock, {'type': 'intro', 'device_name': self.device_name})
            raw_len = recv_all(sock, 4)
            if raw_len:
                msg_len = struct.unpack('!I', raw_len)[0]
                payload = recv_all(sock, msg_len)
                if payload:
                    hello = msgpack.unpackb(payload, raw=False)
                    client_name = hello.get('device_name', client_name)
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            return

        with self.clients_lock:
            self.client_sockets.append(sock)
            self.client_infos[sock] = client_name
            if self.active_client is None:
                self.active_client = sock
        if self.settings.get('role') == 'input_provider' and client_name == 'elitedesk':
            self.server_socket = sock
            logging.info(
                f"Input provider sikeresen hozzárendelve a központi vezérlőhöz ({client_name})."
            )
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
        if self.last_clipboard:
            try:
                self._send_message(sock, {'type': 'clipboard_text', 'text': self.last_clipboard})
            except Exception:
                pass
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
                    if sock in self.file_handler.current_uploads:
                        self.file_handler.handle_transfer_timeout(sock)
                        break
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
        if self.active_client is None:
            logging.warning("toggle_kvm_active invoked with no active_client")
        if not self.kvm_active:
            self.activate_kvm(switch_monitor=switch_monitor)
        else:
            self.deactivate_kvm(switch_monitor=switch_monitor, reason="toggle_kvm_active")
        self.release_hotkey_keys()

    def activate_kvm(self, switch_monitor=True):
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

        if self.settings.get('role') == 'ado':
            if self.clipboard_thread is None or not self.clipboard_thread.is_alive():
                self.clipboard_thread = threading.Thread(
                    target=self._clipboard_loop_server,
                    daemon=True,
                    name="ClipboardSrv"
                )
                self.clipboard_thread.start()

        self.status_update.emit("Állapot: Aktív...")
        logging.info("KVM aktiválva.")

    # worker.py -> JAVÍTOTT deactivate_kvm metódus

    def deactivate_kvm(
        self,
        switch_monitor=None,
        *,
        release_keys: bool = True,
        reason: Optional[str] = None,
    ):
        # --- EZT A BLOKKOT ILLESZD BE A FÜGGVÉNY ELEJÉRE ---
        # Védelmi feltétel: ha a KVM már eleve inaktív, ne csináljunk semmit.
        # Ez megakadályozza a hibákat és a felesleges műveleteket.
        if not self.kvm_active:
            logging.info(
                "deactivate_kvm called, but KVM was already inactive. Reason: %s. No action taken.",
                reason or "unknown",
            )
            # Biztonsági okokból a billentyű-elengedést itt is lefuttathatjuk.
            if release_keys:
                self.release_hotkey_keys()
            return
        # --- EDDIG TART AZ ÚJ RÉSZ ---

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
        
        self.kvm_active = False # Most már biztosak lehetünk benne, hogy 'True'-ról váltunk 'False'-ra.
        if self.settings.get('role') == 'ado' and self.clipboard_thread:
            self.clipboard_thread.join(timeout=1)
            self.clipboard_thread = None
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

    def _switch_monitor_to_target(self, target_name: str) -> None:
        """Switch monitor input based on the specified control target."""
        try:
            if target_name == 'elitedesk':
                code = self.settings['monitor_codes']['host']
            elif target_name == 'desktop':
                code = self.settings['monitor_codes']['client']
            else:
                logging.debug("No monitor switch required for target: %s", target_name)
                return
            with list(get_monitors())[0] as monitor:
                monitor.set_input_source(code)
                logging.info("Monitor switched to target %s", target_name)
        except Exception as exc:
            logging.error("Failed to switch monitor for %s: %s", target_name, exc, exc_info=True)
            self.status_update.emit(f"Monitor hiba: {exc}")
    
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
                self.file_handler._cancel_transfer.clear()
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
                if s: self.file_handler.on_client_disconnected(s)

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
            for peer in peers:
                ip = peer['ip']
                port = peer['port']
                with self.clients_lock:
                    already = any(
                        s.getpeername()[0] == ip
                        for s in self.client_sockets
                        if s.fileno() != -1
                    )
                if not already:
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

