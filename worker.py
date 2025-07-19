# worker.py - VÉGLEGES JAVÍTOTT VERZIÓ
# Javítva: Streaming listener `AttributeError`, "sticky key" hiba, visszaváltási logika, egér-akadás.

import socket
import time
import threading
import logging
import tkinter
import queue
import struct
from typing import Optional
import msgpack
import pyperclip
from pynput import mouse, keyboard
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser
from monitorcontrol import get_monitors
from PySide6.QtCore import QObject, Signal, QSettings
from file_transfer import FileTransferHandler
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
        'active_client', 'pynput_listeners', 'zeroconf', 'streaming_thread',
        'switch_monitor', 'local_ip', 'server_ip', 'connection_thread',
        'device_name', 'clipboard_thread', 'last_clipboard', 'server_socket',
        'last_server_ip', 'file_handler', 'message_queue', 'message_processor_thread',
        '_host_mouse_controller', '_orig_mouse_pos', 'mouse_controller',
        'keyboard_controller', '_pressed_keys'
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
        self.zeroconf = Zeroconf()
        self.streaming_thread = None
        self.switch_monitor = True
        self.local_ip = socket.gethostbyname(socket.gethostname())
        self.server_ip = None
        self.connection_thread = None
        settings_store = QSettings(ORG_NAME, APP_NAME)
        self.last_server_ip = settings_store.value('network/last_server_ip', None)
        self.device_name = settings.get('device_name', socket.gethostname())
        self.clipboard_thread = None
        self.last_clipboard = ""
        self.server_socket = None
        self.file_handler = FileTransferHandler(self)
        self.message_queue = queue.Queue()
        self.message_processor_thread = None
        self._host_mouse_controller = None
        self._orig_mouse_pos = None
        self.mouse_controller = mouse.Controller()
        self.keyboard_controller = keyboard.Controller()
        self._pressed_keys = set()

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
        """Safely set the system clipboard."""
        try:
            pyperclip.copy(text)
            self.last_clipboard = text
        except Exception as e:
            logging.error("Failed to set clipboard: %s", e)

    def _get_clipboard(self) -> str:
        """Safely read the system clipboard."""
        try:
            return pyperclip.paste()
        except Exception as e:
            logging.error("Failed to read clipboard: %s", e)
            return self.last_clipboard

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

    # ------------------------------------------------------------------
    # Clipboard synchronization
    # ------------------------------------------------------------------
    def _clipboard_loop_server(self) -> None:
        while self._running:
            text = self._get_clipboard()
            if text != self.last_clipboard:
                self.last_clipboard = text
                self._broadcast_message({'type': 'clipboard_text', 'text': text})
            time.sleep(0.5)

    def _clipboard_loop_client(self, sock) -> None:
        while self._running and self.server_socket is sock:
            text = self._get_clipboard()
            if text != self.last_clipboard:
                self.last_clipboard = text
                self._send_message(sock, {'type': 'clipboard_text', 'text': text})
            time.sleep(0.5)

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

    def toggle_client_control(self, name: str, *, switch_monitor: bool = True, release_keys: bool = True) -> None:
        """Activate or deactivate control for a specific client."""
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
        if self.kvm_active:
            self.deactivate_kvm(switch_monitor=False, reason="stop() called")  # Leállításkor ne váltson monitort
        try:
            self.zeroconf.close()
        except:
            pass
        for listener in self.pynput_listeners:
            try:
                listener.stop()
            except:
                pass
        for sock in list(getattr(self, 'client_sockets', [])):
            try:
                sock.close()
            except Exception:
                pass
        self.client_infos.clear()
        self.active_client = None
        if self.connection_thread and self.connection_thread.is_alive():
            self.connection_thread.join(timeout=1)
        if self.clipboard_thread and self.clipboard_thread.is_alive():
            self.clipboard_thread.join(timeout=1)
        if self.message_processor_thread and self.message_processor_thread.is_alive():
            try:
                self.message_queue.put_nowait((None, None))
            except Exception:
                pass
            self.message_processor_thread.join(timeout=1)
        self.file_handler.cleanup()
        # Extra safety to avoid stuck modifier keys on exit
        self.release_hotkey_keys()

    def run(self):
        logging.info(f"Worker elindítva {self.settings['role']} módban.")
        if self.settings['role'] == 'ado':
            self.run_server()
        else:
            self.run_client()
        self.finished.emit()

    def run_server(self):
        accept_thread = threading.Thread(target=self.accept_connections, daemon=True, name="AcceptThread")
        accept_thread.start()

        self.clipboard_thread = threading.Thread(
            target=self._clipboard_loop_server, daemon=True, name="ClipboardSrv"
        )
        self.clipboard_thread.start()

        
        info = ServiceInfo(
            SERVICE_TYPE,
            f"{SERVICE_NAME_PREFIX}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(socket.gethostbyname(socket.gethostname()))],
            port=self.settings['port']
        )
        self.zeroconf.register_service(info)
        self.status_update.emit(
            "Adó szolgáltatás regisztrálva. Gyorsbillentyűk: "
            "Asztal - Shift + Numpad 0, Laptop - Shift + Numpad 1, "
            "ElitDesk - Shift + Numpad 2"
        )
        logging.info("Zeroconf szolgáltatás regisztrálva.")



        # A gombnyomásokat figyelő halmazok
        current_pressed_vk = set()
        current_pressed_special = set()

        # A hotkey kombinációk definíciója egy szótárban
        hotkey_combinations = {
            # Pico Hotkeys (speciális billentyűk)
            frozenset({keyboard.Key.ctrl_l, keyboard.Key.alt_l, keyboard.Key.f1}): "pico_desktop",
            frozenset({keyboard.Key.ctrl_r, keyboard.Key.alt_gr, keyboard.Key.f1}): "pico_desktop",
            frozenset({keyboard.Key.ctrl_l, keyboard.Key.alt_l, keyboard.Key.f2}): "pico_laptop",
            frozenset({keyboard.Key.ctrl_r, keyboard.Key.alt_gr, keyboard.Key.f2}): "pico_laptop",
            frozenset({keyboard.Key.ctrl_l, keyboard.Key.alt_l, keyboard.Key.f3}): "pico_elitedesk",
            frozenset({keyboard.Key.ctrl_r, keyboard.Key.alt_gr, keyboard.Key.f3}): "pico_elitedesk",

            # Eredeti Hotkeys (NumLock OFF, speciális billentyűk)
            frozenset({keyboard.Key.shift, keyboard.Key.insert}): "desktop_numoff",
            frozenset({keyboard.Key.shift_r, keyboard.Key.insert}): "desktop_numoff",
            frozenset({keyboard.Key.shift, keyboard.Key.end}): "laptop_numoff",
            frozenset({keyboard.Key.shift_r, keyboard.Key.end}): "laptop_numoff",
            frozenset({keyboard.Key.shift, keyboard.Key.down}): "elitedesk_numoff",
            frozenset({keyboard.Key.shift_r, keyboard.Key.down}): "elitedesk_numoff",
        }

        def on_press(key):
            try:
                current_pressed_vk.add(key.vk)
            except AttributeError:
                current_pressed_special.add(key)

            # Ellenőrizzük a speciális billentyűk kombinációit
            pressed_special_set = frozenset(current_pressed_special)
            if pressed_special_set in hotkey_combinations:
                action = hotkey_combinations[pressed_special_set]
                handle_action(action)
                return

            # Ellenőrizzük a VK kódos kombinációkat (NumLock ON)
            if (VK_LSHIFT in current_pressed_vk or VK_RSHIFT in current_pressed_vk):
                if VK_NUMPAD0 in current_pressed_vk:
                    handle_action("desktop_numon")
                elif VK_NUMPAD1 in current_pressed_vk:
                    handle_action("laptop_numon")
                elif VK_NUMPAD2 in current_pressed_vk:
                    handle_action("elitedesk_numon")

        def on_release(key):
            try:
                current_pressed_vk.discard(key.vk)
            except AttributeError:
                current_pressed_special.discard(key)

        def handle_action(action_name):
            logging.info(f"!!! Hotkey action triggered: {action_name} !!!")
            if "desktop" in action_name:
                self.deactivate_kvm(switch_monitor=True, reason=action_name)
            elif "laptop" in action_name:
                self.toggle_client_control('laptop', switch_monitor=False, release_keys=False)
            elif "elitedesk" in action_name:
                self.toggle_client_control('elitedesk', switch_monitor=True, release_keys=False)

        hotkey_listener = keyboard.Listener(on_press=on_press, on_release=on_release)
        self.pynput_listeners.append(hotkey_listener)
        hotkey_listener.start()
        logging.info("Pynput figyelő elindítva.")

        while self._running:
            time.sleep(0.5)

        logging.info("Adó szolgáltatás leállt.")

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

                    if data.get('type') == 'clipboard_text':
                        text = data.get('text', '')
                        if text != self.last_clipboard:
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
                    if text != self.last_clipboard:
                        self._set_clipboard(text)
                else:
                    self.file_handler.handle_network_message(data, sock)
            except Exception as e:
                logging.error("Failed to process client message: %s", e, exc_info=True)


    def accept_connections(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                server_socket.bind(('', self.settings['port']))
                server_socket.listen(5)
                logging.info(f"TCP szerver elindítva a {self.settings['port']} porton.")

                while self._running:
                    client_sock, addr = server_socket.accept()
                    client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    self.client_sockets.append(client_sock)
                    if self.active_client is None:
                        self.active_client = client_sock
                    logging.info(f"Kliens csatlakozva: {addr}.")
                    self.status_update.emit(f"Kliens csatlakozva: {addr}. Várakozás gyorsbillentyűre.")

                    threading.Thread(target=self.monitor_client, args=(client_sock, addr), daemon=True).start()
        except Exception as e:
            if self._running:
                logging.error(f"Hiba a kliens fogadásakor: {e}", exc_info=True)

    def monitor_client(self, sock, addr):
        """Monitor a single client connection, handle commands and remove it on disconnect."""
        sock.settimeout(30.0)
        def recv_all(s, n):
            data = b''
            while len(data) < n:
                chunk = s.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
            return data

        # Expect an initial handshake with the client name
        client_name = str(addr)
        try:
            raw_len = recv_all(sock, 4)
            if raw_len:
                msg_len = struct.unpack('!I', raw_len)[0]
                payload = recv_all(sock, msg_len)
                if payload:
                    hello = msgpack.unpackb(payload, raw=False)
                    client_name = hello.get('device_name', client_name)
        except Exception:
            pass
        self.client_infos[sock] = client_name
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
                        cmd = data.get('command')
                        if cmd == 'switch_elitedesk':
                            self.toggle_client_control('elitedesk', switch_monitor=True)
                            continue
                        if cmd == 'switch_laptop':
                            self.toggle_client_control('laptop', switch_monitor=False)
                            continue
                        if data.get('type') == 'clipboard_text':
                            text = data.get('text', '')
                            if text != self.last_clipboard:
                                self._set_clipboard(text)
                                self._broadcast_message(data, exclude=sock)
                        else:
                            self.file_handler.handle_network_message(data, sock)
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
        finally:
            logging.warning(f"Kliens lecsatlakozott: {addr}.")
            try:
                sock.close()
            except Exception:
                pass
            self.file_handler.on_client_disconnected(sock)
            if sock in self.client_sockets:
                self.client_sockets.remove(sock)
            if sock in self.client_infos:
                del self.client_infos[sock]
            if sock == self.active_client:
                if self.client_sockets:
                    self.active_client = self.client_sockets[0]
                    self.status_update.emit(
                        f"Aktív kliens megszakadt. Átváltás: {self.client_infos.get(self.active_client, 'ismeretlen')}"
                    )
                else:
                    self.active_client = None
            if self.kvm_active and not self.client_sockets:
                self.deactivate_kvm(reason="all clients disconnected")
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

    def deactivate_kvm(
        self,
        switch_monitor=None,
        *,
        release_keys: bool = True,
        reason: Optional[str] = None,
    ):
        if reason:
            logging.info(
                "deactivate_kvm called. reason=%s switch_monitor=%s kvm_active=%s active_client=%s",
                reason,
                switch_monitor,
                self.kvm_active,
                self.client_infos.get(self.active_client),
            )
        else:
            logging.info(
                "deactivate_kvm called. switch_monitor=%s kvm_active=%s active_client=%s",
                switch_monitor,
                self.kvm_active,
                self.client_infos.get(self.active_client),
            )
        self.kvm_active = False
        self.status_update.emit("Állapot: Inaktív...")
        logging.info("KVM deaktiválva.")

        # A monitor visszaváltást a toggle metódus végzi, miután a streaming szál leállt
        switch = switch_monitor if switch_monitor is not None else getattr(self, 'switch_monitor', True)
        if switch:
            # Itt egy kis időt adunk a streaming szálnak a leállásra, mielőtt váltunk
            time.sleep(0.2)
            try:
                with list(get_monitors())[0] as monitor:
                    monitor.set_input_source(self.settings['monitor_codes']['host'])
                    logging.info("Monitor sikeresen visszaváltva a hosztra.")
            except Exception as e:
                self.status_update.emit(f"Monitor hiba: {e}")
                logging.error(f"Monitor hiba: {e}", exc_info=True)
        # Ensure hotkey keys are released when deactivating if requested
        if release_keys:
            self.release_hotkey_keys()

        if hasattr(self, '_host_mouse_controller') and hasattr(self, '_orig_mouse_pos'):
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

        send_queue = queue.Queue(maxsize=SEND_QUEUE_MAXSIZE)
        unsent_events = []

        def sender():
            while self.kvm_active and self._running:
                try:
                    payload = send_queue.get(timeout=0.1)
                except queue.Empty:
                    continue
                if payload is None:
                    logging.debug("Sender thread exiting")
                    break
                if isinstance(payload, tuple):
                    packed, event = payload
                else:
                    packed, event = payload, None
                to_remove = []
                active_lost = False
                if self.active_client is None and self.client_sockets:
                    self.active_client = self.client_sockets[0]
                targets = [self.active_client] if self.active_client else []
                for sock in list(targets):
                    if sock not in self.client_sockets:
                        continue
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
                    except Exception as e:
                        try:
                            event = msgpack.unpackb(packed, raw=False)
                        except Exception:
                            event = '<unpack failed>'
                        logging.error(
                            f"Failed sending event {event} to {self.client_infos.get(sock, sock.getpeername())}: {e}",
                            exc_info=True,
                        )
                        if event != '<unpack failed>':
                            unsent_events.append(event)
                        to_remove.append(sock)
                for s in to_remove:
                    try:
                        s.close()
                    except Exception:
                        pass
                    if s in self.client_sockets:
                        self.client_sockets.remove(s)
                    if s in self.client_infos:
                        del self.client_infos[s]
                    if s == self.active_client:
                        self.active_client = None
                        active_lost = True
                        if self.client_sockets:
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
                send({'type': 'move_relative', 'dx': dx, 'dy': dy})
            is_warping = True
            host_mouse_controller.position = (center_x, center_y)
            last_pos['x'], last_pos['y'] = center_x, center_y

        def on_click(x,y,b,p):
            send({'type':'click','button':b.name,'pressed':p})

        def on_scroll(x,y,dx,dy):
            send({'type':'scroll','dx':dx,'dy':dy})
        
        pressed_keys = set()
        current_vks = set()

        def get_vk(key):
            if hasattr(key, "vk") and key.vk is not None:
                return key.vk
            if hasattr(key, "value") and hasattr(key.value, "vk"):
                return key.value.vk
            return None

        def on_key(k, p):
            """Forward keyboard events to the client and handle the hotkey."""
            try:
                vk = get_vk(k)
                if vk is not None:
                    if p:
                        current_vks.add(vk)
                    else:
                        current_vks.discard(vk)

                if (
                    (VK_LSHIFT in current_vks or VK_RSHIFT in current_vks)
                    and (VK_NUMPAD0 in current_vks or VK_INSERT in current_vks)
                ):
                    logging.info("!!! Visszaváltás a hosztra (Shift+Numpad0) észlelve a streaming alatt !!!")
                    # Send key releases to the client before disabling streaming
                    for vk_code in [VK_LSHIFT, VK_RSHIFT, VK_NUMPAD0, VK_INSERT]:
                        if vk_code in current_vks:
                            send({"type": "key", "key_type": "vk", "key": vk_code, "pressed": False})
                            pressed_keys.discard(("vk", vk_code))
                    current_vks.clear()
                    self.deactivate_kvm(switch_monitor=True, reason='streaming hotkey')
                    return
                if (
                    (VK_LSHIFT in current_vks or VK_RSHIFT in current_vks)
                    and VK_NUMPAD1 in current_vks
                ):
                    active_name = self.client_infos.get(self.active_client, "").lower()
                    logging.debug(
                        f"Hotkey detected for laptop with current_vks={current_vks} while active={active_name}"
                    )
                    if active_name != "elitedesk":
                        for vk_code in [VK_LSHIFT, VK_RSHIFT, VK_NUMPAD1]:
                            if vk_code in current_vks:
                                send({"type": "key", "key_type": "vk", "key": vk_code, "pressed": False})
                                pressed_keys.discard(("vk", vk_code))
                        current_vks.clear()
                        self.toggle_client_control('laptop', switch_monitor=False, release_keys=False)
                        return
                if (
                    (VK_LSHIFT in current_vks or VK_RSHIFT in current_vks)
                    and VK_NUMPAD2 in current_vks
                ):
                    active_name = self.client_infos.get(self.active_client, "").lower()
                    logging.debug(
                        f"Hotkey detected for elitedesk with current_vks={current_vks} while active={active_name}"
                    )
                    if active_name != "laptop":
                        for vk_code in [VK_LSHIFT, VK_RSHIFT, VK_NUMPAD2]:
                            if vk_code in current_vks:
                                send({"type": "key", "key_type": "vk", "key": vk_code, "pressed": False})
                                pressed_keys.discard(("vk", vk_code))
                        current_vks.clear()
                        self.toggle_client_control('elitedesk', switch_monitor=True, release_keys=False)
                        return

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
        class ServiceListener:
            def __init__(self, worker):
                self.worker = worker

            def add_service(self, zc, type, name):
                info = zc.get_service_info(type, name)
                if info:
                    ip = socket.inet_ntoa(info.addresses[0])
                    if ip == self.worker.local_ip:
                        return  # ignore our own service
                    self.worker.server_ip = ip
                    self.worker.last_server_ip = ip  # remember last found host
                    logging.info(f"Adó szolgáltatás megtalálva a {ip} címen.")
                    self.worker.status_update.emit(f"Adó megtalálva: {ip}. Csatlakozás...")
                # Connection thread runs continuously, just update the server IP
            def update_service(self, zc, type, name):
                pass
            def remove_service(self, zc, type, name):
                self.worker.server_ip = None
                self.worker.status_update.emit("Az Adó szolgáltatás eltűnt, újra keresem...")
                logging.warning("Adó szolgáltatás eltűnt.")

        settings_store = QSettings(ORG_NAME, APP_NAME)

        # Start connection thread immediately using stored last IP if available
        if self.last_server_ip and not self.server_ip:
            self.server_ip = self.last_server_ip
        if not self.connection_thread:
            self.connection_thread = threading.Thread(
                target=self.connect_to_server,
                daemon=True,
                name="ConnectThread",
            )
            self.connection_thread.start()

        if not self.message_processor_thread:
            self.message_processor_thread = threading.Thread(
                target=self._process_client_messages,
                daemon=True,
                name="MsgProcessor",
            )
            self.message_processor_thread.start()

        browser = ServiceBrowser(self.zeroconf, SERVICE_TYPE, ServiceListener(self))
        self.status_update.emit("Vevő mód: Keresem az Adó szolgáltatást...")
        while self._running:
            time.sleep(0.5)

    def connect_to_server(self):
        """
        Intelligens újracsatlakozási logikával ellátott metódus a szerverhez való csatlakozáshoz.
        Kezeli a hálózat lassú felépülését induláskor (pl. Wi-Fi).
        """
        self._pressed_keys = set()
        hk_listener = None

        # Intelligens újrapróbálkozási logika változói
        retry_delay = 3
        max_retry_delay = 30

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
                
                self.server_socket = s
                settings_store = QSettings(ORG_NAME, APP_NAME)
                settings_store.setValue('network/last_server_ip', ip)
                self.last_server_ip = ip
                self.file_handler._cancel_transfer.clear()
                logging.info("Sikeres csatlakozás!")

                # Sikeres csatlakozás után visszaállítjuk a várakozási időt
                retry_delay = 3

                self.clipboard_thread = threading.Thread(
                    target=self._clipboard_loop_client, args=(s,), daemon=True, name="ClipboardCli"
                )
                self.clipboard_thread.start()

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
                if self.clipboard_thread: self.clipboard_thread.join(timeout=0.1)
                
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

