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
        'active_client', 'pynput_listeners', 'zeroconf', 'streaming_thread',
        'switch_monitor', 'local_ip', 'server_ip', 'connection_thread',
        'device_name', 'clipboard_thread', 'last_clipboard', 'server_socket',
        'last_server_ip', 'file_handler', 'message_queue', 'message_processor_thread',
        '_host_mouse_controller', '_orig_mouse_pos', 'mouse_controller',
        'keyboard_controller', '_pressed_keys', 'pico_thread', 'pico_handler'
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
        self.pico_thread = None
        self.pico_handler = None

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
        if self.pico_thread and self.pico_thread.is_alive():
            self.pico_thread.join(timeout=1)
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
        """
        A program fő, szimmetrikus működésű ciklusa.
        Minden példány egyszerre hirdet (mint egy szerver) és keres (mint egy kliens).
        """
        logging.info(f"Worker elindítva szimmetrikus módban: {self.device_name}.")
        
        # Ez a szál fogja feldolgozni a bejövő üzeneteket (pl. egérmozgás)
        self.message_processor_thread = threading.Thread(
            target=self._process_messages, daemon=True, name="MsgProcessor"
        )
        self.message_processor_thread.start()

        # 1. SZÁL: Folyamatosan fogadja a bejövő kapcsolatokat (Szerver szerepkör)
        accept_thread = threading.Thread(target=self.accept_connections, daemon=True, name="AcceptThread")
        accept_thread.start()
        
        # 2. SZÁL: Folyamatosan keres más KVM példányokat (Kliens szerepkör)
        discovery_thread = threading.Thread(target=self.discover_peers, daemon=True, name="DiscoveryThread")
        discovery_thread.start()
        
        # A Zeroconf szolgáltatást most már mindenki hirdeti
        info = ServiceInfo(
            SERVICE_TYPE,
            f"{self.device_name}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(self.local_ip)],
            port=self.settings['port']
        )
        self.zeroconf.register_service(info)
        logging.info(f"'{self.device_name}' szolgáltatás regisztrálva a hálózaton.")

        # A hoszt (asztali gép) elindítja a fő vezérlő logikákat
        if self.settings['role'] == 'ado':
            self.start_main_hotkey_listener()
            self.clipboard_thread = threading.Thread(
                target=self._clipboard_loop_server, daemon=True, name="ClipboardSrv"
            )
            self.clipboard_thread.start()

        # A fő szál egyszerűen életben tartja a folyamatot
        while self._running:
            time.sleep(1)

        self.zeroconf.unregister_service(info)
        logging.info(f"Worker leállt: {self.device_name}.")

    def _handle_disconnect(self, sock, reason="unknown"):
        """Központi függvény a lecsatlakozások kezelésére."""
        client_name = self.client_infos.get(sock, "ismeretlen")
        logging.warning(f"Kapcsolat megszakadt: {client_name}. Ok: {reason}")
        
        try: sock.close()
        except Exception: pass

        was_active_client = (sock == self.active_client)
        if sock in self.client_sockets: self.client_sockets.remove(sock)
        if sock in self.client_infos: del self.client_infos[sock]
        
        if self.settings['role'] == 'ado':
            self.status_update.emit(f"Kliens lecsatlakozott: {client_name}")
            if was_active_client and self.kvm_active:
                logging.info(f"Aktív kliens '{client_name}' lecsatlakozott. Irányítás visszaadása a hosztnak.")
                self.deactivate_kvm(reason="active client disconnected")
            elif was_active_client:
                self.active_client = None

    def discover_peers(self):
        """Folyamatosan keresi a hálózaton lévő többi KVM példányt."""
        class ServiceListener:
            def __init__(self, worker): self.worker = worker
            
            def add_service(self, zc, type, name):
                info = zc.get_service_info(type, name)
                if not info: return
                
                ip = socket.inet_ntoa(info.addresses[0])
                port = info.port
                
                if ip == self.worker.local_ip and port == self.worker.settings['port']: return

                already_connected = any(
                    s.getpeername() == (ip, port) for s in self.worker.client_sockets if s.fileno() != -1
                )

                if not already_connected:
                    logging.info(f"Új KVM példányt találtunk: {name} ({ip}:{port}). Csatlakozási kísérlet...")
                    threading.Thread(target=self.worker.connect_to_peer, args=(ip, port), daemon=True).start()

            def update_service(self, zc, type, name): self.add_service(zc, type, name)
            def remove_service(self, zc, type, name): logging.info(f"KVM szolgáltatás eltűnt: {name}")

        browser = ServiceBrowser(self.zeroconf, SERVICE_TYPE, ServiceListener(self))
        while self._running: time.sleep(5)

    def connect_to_peer(self, ip, port):
        """Csatlakozik egy másik KVM példányhoz."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(5.0)
            s.connect((ip, port))
            s.settimeout(None)

            self._send_message(s, {"type": "handshake", "device_name": self.device_name})
            raw_len = s.recv(4)
            if not raw_len: raise ConnectionAbortedError("Handshake failed")
            msg_len = struct.unpack('!I', raw_len)[0]
            payload = s.recv(msg_len)
            data = msgpack.unpackb(payload, raw=False)
            peer_name = data.get('device_name', ip)

            logging.info(f"Sikeres kimenő kapcsolat: {peer_name} ({ip}:{port})")
            
            self.client_sockets.append(s)
            self.client_infos[s] = peer_name
            if self.settings['role'] == 'ado': self.status_update.emit(f"Kapcsolat létrejött: {peer_name}")
            
            self.monitor_client(s, (ip, port))
        except Exception as e:
            logging.error(f"Nem sikerült csatlakozni a peer-hez ({ip}:{port}): {e}")
            if 's' in locals() and s: s.close()

    def accept_connections(self):
        """Folyamatosan próbálja megnyitni a portot és fogadni a kapcsolatokat."""
        while self._running:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    server_socket.bind(('', self.settings['port']))
                    server_socket.listen(5)
                    logging.info(f"TCP listener elindítva a {self.settings['port']} porton.")
                    
                    while self._running:
                        client_sock, addr = server_socket.accept()
                        client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        
                        raw_len = client_sock.recv(4)
                        if not raw_len: raise ConnectionAbortedError("Handshake failed")
                        msg_len = struct.unpack('!I', raw_len)[0]
                        payload = client_sock.recv(msg_len)
                        data = msgpack.unpackb(payload, raw=False)
                        client_name = data.get('device_name', addr[0])

                        logging.info(f"Bejövő kapcsolat fogadva: {client_name} ({addr[0]}:{addr[1]})")
                        self._send_message(client_sock, {"type": "handshake", "device_name": self.device_name})

                        self.client_sockets.append(client_sock)
                        self.client_infos[client_sock] = client_name
                        if self.settings['role'] == 'ado': self.status_update.emit(f"Kapcsolat létrejött: {client_name}")

                        threading.Thread(target=self.monitor_client, args=(client_sock, addr), daemon=True).start()
            except OSError as e:
                if self._running:
                    logging.error(f"Hiba a listener indításakor: {e}. Újrapróbálkozás 5 mp múlva...")
                    time.sleep(5)
            except Exception as e:
                if self._running:
                    logging.error(f"Váratlan hiba az accept_connections-ben: {e}", exc_info=True)
                    time.sleep(5)

    def _process_messages(self):
        """Feldolgozza a különböző peerektől érkező üzeneteket."""
        button_map = {'left': mouse.Button.left, 'right': mouse.Button.right, 'middle': mouse.Button.middle}
        while self._running:
            sock, data = self.message_queue.get()
            if sock is None: break
            
            msg_type = data.get('type')
            
            if self.settings['role'] == 'ado':
                if data.get('command') == 'switch_elitedesk':
                    self.toggle_client_control('elitedesk', switch_monitor=True)
                    continue

            if msg_type == 'move_relative': self.mouse_controller.move(data.get('dx', 0), data.get('dy', 0))
            elif msg_type == 'click':
                btn = button_map.get(data.get('button'))
                if btn: (self.mouse_controller.press if data.get('pressed') else self.mouse_controller.release)(btn)
            elif msg_type == 'scroll': self.mouse_controller.scroll(data.get('dx', 0), data.get('dy', 0))
            elif msg_type == 'key':
                k_info = data.get('key')
                if data.get('key_type') == 'char': k_press = k_info
                elif data.get('key_type') == 'special': k_press = getattr(keyboard.Key, k_info, None)
                elif data.get('key_type') == 'vk': k_press = keyboard.KeyCode.from_vk(int(k_info))
                else: k_press = None
                if k_press:
                    (self.keyboard_controller.press if data.get('pressed') else self.keyboard_controller.release)(k_press)
            elif msg_type == 'clipboard_text':
                text = data.get('text', '')
                if self.settings['role'] == 'ado':
                    if text != self.last_clipboard:
                        self._set_clipboard(text)
                        self._broadcast_message(data, exclude=sock)
                else:
                    if text != self._get_clipboard():
                        self._set_clipboard(text)
            else:
                self.file_handler.handle_network_message(data, sock)
    
    def monitor_client(self, sock, addr):
        """Figyeli az egyedi kapcsolatokat."""
        try:
            while self._running:
                raw_len = sock.recv(4)
                if not raw_len: break
                msg_len = struct.unpack('!I', raw_len)[0]
                payload = sock.recv(msg_len)
                if not payload: break
                data = msgpack.unpackb(payload, raw=False)
                if data.get('type') != 'handshake':
                    self.message_queue.put((sock, data))
        
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            self._handle_disconnect(sock, "kapcsolat megszakadt")
        except Exception as e:
            self._handle_disconnect(sock, f"váratlan hiba: {e}")

    # A KVM vezérlő és streaming metódusok (ezek többnyire változatlanok)
    def start_main_hotkey_listener(self):
        if self.pynput_listeners: return
        current_pressed_vk, numpad_pressed_vk = set(), set()
        VK_F13, VK_F14, VK_F15 = 124, 125, 126
        def handle_action(action_name):
            if "desktop" in action_name: self.deactivate_kvm(switch_monitor=True, reason=action_name)
            elif "laptop" in action_name: self.toggle_client_control('laptop', switch_monitor=False, release_keys=False)
            elif "elitedesk" in action_name: self.toggle_client_control('elitedesk', switch_monitor=True, release_keys=False)
        def on_press(key):
            if key == keyboard.Key.f13: self.deactivate_kvm(switch_monitor=True, reason="pico F13")
            elif key == keyboard.Key.f14: self.toggle_client_control('laptop', switch_monitor=False)
            elif key == keyboard.Key.f15: self.toggle_client_control('elitedesk', switch_monitor=True)
            vk = getattr(key, 'vk', None)
            if vk is None: return
            current_pressed_vk.add(vk)
            if getattr(key, '_flags', 0) == 0: numpad_pressed_vk.add(vk)
            is_shift = VK_LSHIFT in current_pressed_vk or VK_RSHIFT in current_pressed_vk
            if is_shift:
                if VK_NUMPAD0 in current_pressed_vk or (VK_INSERT in current_pressed_vk and VK_INSERT in numpad_pressed_vk): handle_action("desktop")
                elif VK_NUMPAD1 in current_pressed_vk or (VK_END in current_pressed_vk and VK_END in numpad_pressed_vk): handle_action("laptop")
                elif VK_NUMPAD2 in current_pressed_vk or (VK_DOWN in current_pressed_vk and VK_DOWN in numpad_pressed_vk): handle_action("elitedesk")
        def on_release(key):
            vk = getattr(key, 'vk', None)
            if vk: current_pressed_vk.discard(vk); numpad_pressed_vk.discard(vk)
        hotkey_listener = keyboard.Listener(on_press=on_press, on_release=on_release)
        self.pynput_listeners.append(hotkey_listener)
        hotkey_listener.start()
        logging.info("Fő gyorsbillentyű-figyelő elindítva.")

    def deactivate_kvm(self, switch_monitor=None, *, release_keys: bool = True, reason: Optional[str] = None):
        if not self.kvm_active:
            logging.info("deactivate_kvm hívva, de a KVM már inaktív. Ok: %s", reason or "ismeretlen")
            if release_keys: self.release_hotkey_keys()
            return
        logging.info("KVM deaktiválása. Ok: %s", reason or "ismeretlen")
        self.kvm_active = False
        self.status_update.emit("Állapot: Inaktív...")
        switch = switch_monitor if switch_monitor is not None else getattr(self, 'switch_monitor', True)
        if switch:
            time.sleep(0.2)
            try:
                with list(get_monitors())[0] as monitor:
                    monitor.set_input_source(self.settings['monitor_codes']['host'])
            except Exception as e:
                self.status_update.emit(f"Monitor hiba: {e}")
        if release_keys: self.release_hotkey_keys()
        if hasattr(self, '_host_mouse_controller') and self._host_mouse_controller:
            try: self._host_mouse_controller.position = self._orig_mouse_pos
            except: pass
        self._host_mouse_controller = None
        self._orig_mouse_pos = None

    def activate_kvm(self, switch_monitor=True):
        if not self.client_sockets:
            self.status_update.emit("Hiba: Nincs csatlakozott kliens a váltáshoz!")
            return
        if self.active_client is None: self.active_client = self.client_sockets[0]
        self.switch_monitor = switch_monitor
        self.kvm_active = True
        self.status_update.emit("Állapot: Aktív...")
        self.streaming_thread = threading.Thread(target=self._streaming_loop, daemon=True, name="StreamingThread")
        self.streaming_thread.start()

    def _streaming_loop(self):
        while self.kvm_active and self._running:
            self.start_kvm_streaming()
            if self.kvm_active and self._running: time.sleep(1)

    def start_kvm_streaming(self):
        # EZ A METÓDUS ÉS A BENNE LÉVŐ SENDER, ON_MOVE, ON_CLICK, ON_SCROLL, ON_KEY FÜGGVÉNYEK
        # PONTOSAN UGYANAZOK MARADNAK, MINT A KORÁBBI, JÓL MŰKÖDŐ VERZIÓBAN VOLTAK.
        # A RÖVIDSÉG KEDVÉÉRT ITT NEM ISMÉTELJÜK MEG, DE A TE FÁJLODBAN BENNE KELL HAGYNOD!
        # ... (a teljes start_kvm_streaming kódja ide jön)
    
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

