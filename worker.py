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
)

# Delay between iterations in the streaming loop to lower CPU usage
STREAM_LOOP_DELAY = 0.05
# Maximum number of events queued for sending before old ones are dropped
SEND_QUEUE_MAXSIZE = 200
# File transfer chunk size
FILE_CHUNK_SIZE = 65536
# Socket timeout (seconds) during file transfers
TRANSFER_TIMEOUT = 30
# Minimum delay between progress updates
PROGRESS_UPDATE_INTERVAL = 0.5


class KVMWorker(QObject):
    __slots__ = (
        'settings', '_running', 'kvm_active', 'client_sockets', 'client_infos',
        'active_client', 'pynput_listeners', 'zeroconf', 'streaming_thread',
        'switch_monitor', 'local_ip', 'server_ip', 'connection_thread',
        'device_name', 'clipboard_thread', 'last_clipboard', 'server_socket',
        'last_server_ip', 'file_handler'
    )

    finished = Signal()
    status_update = Signal(str)
    update_progress_display = Signal(int, str)  # percentage, label text
    file_transfer_error = Signal(str)
    incoming_upload_started = Signal(str, int)

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
        self._host_mouse_controller = None
        self._orig_mouse_pos = None

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
            return True
        except Exception as e:
            logging.error("Failed to send message: %s", e, exc_info=True)
            return False

    def _broadcast_message(self, data, exclude=None) -> None:
        """Broadcast a message to all connected clients."""
        packed = msgpack.packb(data, use_bin_type=True)
        for s in list(self.client_sockets):
            if s is exclude:
                continue
            try:
                s.sendall(struct.pack('!I', len(packed)) + packed)
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

        # Definitions for NumLock OFF state based on diagnostic results
        hotkey_desktop_l_numoff = {keyboard.Key.shift, keyboard.Key.insert}
        hotkey_desktop_r_numoff = {keyboard.Key.shift_r, keyboard.Key.insert}
        hotkey_laptop_l_numoff = {keyboard.Key.shift, keyboard.Key.end}
        hotkey_laptop_r_numoff = {keyboard.Key.shift_r, keyboard.Key.end}
        hotkey_elitdesk_l_numoff = {keyboard.Key.shift, VK_NUMPAD2}
        hotkey_elitdesk_r_numoff = {keyboard.Key.shift_r, VK_NUMPAD2}

        # Definitions for NumLock ON state (fallback using VK codes)
        hotkey_desktop_l_numon = {VK_LSHIFT, VK_NUMPAD0}
        hotkey_desktop_r_numon = {VK_RSHIFT, VK_NUMPAD0}
        hotkey_laptop_l_numon = {VK_LSHIFT, VK_NUMPAD1}
        hotkey_laptop_r_numon = {VK_RSHIFT, VK_NUMPAD1}
        hotkey_elitdesk_l_numon = {VK_LSHIFT, VK_NUMPAD2}
        hotkey_elitdesk_r_numon = {VK_RSHIFT, VK_NUMPAD2}

        current_pressed_vk_codes = set()
        current_pressed_special_keys = set()
        pending_client = None

        def on_press(key):
            nonlocal pending_client
            try:
                current_pressed_vk_codes.add(key.vk)
            except AttributeError:
                current_pressed_special_keys.add(key)

            logging.debug(
                f"Key pressed: {key}. VKs: {current_pressed_vk_codes}, Specials: {current_pressed_special_keys}"
            )

            if (
                hotkey_desktop_l_numoff.issubset(current_pressed_special_keys)
                or hotkey_desktop_r_numoff.issubset(current_pressed_special_keys)
            ) or (
                hotkey_desktop_l_numon.issubset(current_pressed_vk_codes)
                or hotkey_desktop_r_numon.issubset(current_pressed_vk_codes)
            ):
                logging.info("!!! Asztal gyorsbillentyű észlelve! Visszaváltás... !!!")
                pending_client = 'desktop'
            elif (
                hotkey_laptop_l_numoff.issubset(current_pressed_special_keys)
                or hotkey_laptop_r_numoff.issubset(current_pressed_special_keys)
            ) or (
                hotkey_laptop_l_numon.issubset(current_pressed_vk_codes)
                or hotkey_laptop_r_numon.issubset(current_pressed_vk_codes)
            ):
                logging.info("!!! Laptop gyorsbillentyű észlelve! Váltás... !!!")
                pending_client = 'laptop'
            elif (
                hotkey_elitdesk_l_numoff.issubset(
                    current_pressed_special_keys.union(current_pressed_vk_codes)
                )
                or hotkey_elitdesk_r_numoff.issubset(
                    current_pressed_special_keys.union(current_pressed_vk_codes)
                )
            ) or (
                hotkey_elitdesk_l_numon.issubset(current_pressed_vk_codes)
                or hotkey_elitdesk_r_numon.issubset(current_pressed_vk_codes)
            ):
                logging.info("!!! ElitDesk gyorsbillentyű észlelve! Váltás... !!!")
                pending_client = 'elitedesk'

        def on_release(key):
            nonlocal pending_client
            try:
                current_pressed_vk_codes.discard(key.vk)
            except AttributeError:
                current_pressed_special_keys.discard(key)

            logging.debug(
                f"Key released: {key}. VKs: {current_pressed_vk_codes}, Specials: {current_pressed_special_keys}"
            )

            if pending_client and not current_pressed_vk_codes and not current_pressed_special_keys:
                logging.info(f"Hotkey action executed: {pending_client}")
                if pending_client == 'desktop':
                    self.deactivate_kvm(switch_monitor=True, reason="desktop hotkey")
                else:
                    self.toggle_client_control(
                        pending_client,
                        switch_monitor=(pending_client == 'elitedesk'),
                        release_keys=False,
                    )
                pending_client = None
        
        hotkey_listener = keyboard.Listener(on_press=on_press, on_release=on_release)
        self.pynput_listeners.append(hotkey_listener)
        hotkey_listener.start()
        logging.info("Gyorsbillentyű figyelő elindítva.")

        while self._running:
            time.sleep(0.5)
        
        logging.info("Adó szolgáltatás leállt.")

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
        buffer = b''

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
            last_log = time.time()
            while self._running:
                if time.time() - last_log >= 10:
                    logging.debug(
                        "monitor_client main loop.",
                    )
                    last_log = time.time()
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buffer += chunk
                    while len(buffer) >= 4:
                        msg_len = struct.unpack('!I', buffer[:4])[0]
                        if len(buffer) < 4 + msg_len:
                            break
                        payload = buffer[4:4 + msg_len]
                        buffer = buffer[4 + msg_len:]
                        try:
                            data = msgpack.unpackb(payload, raw=False)
                        except Exception:
                            logging.warning("Hibas parancs a klienstol")
                            continue

                        cmd = data.get('command')
                        if cmd == 'switch_elitedesk':
                            self.toggle_client_control('elitedesk', switch_monitor=True)
                        elif cmd == 'switch_laptop':
                            self.toggle_client_control('laptop', switch_monitor=False)
                        else:
                            if data.get('type') == 'clipboard_text':
                                text = data.get('text', '')
                                if text != self.last_clipboard:
                                    self._set_clipboard(text)
                                    self._broadcast_message(data, exclude=sock)
                            else:
                                self.file_handler.handle_network_message(data, sock)
                except socket.timeout:
                    continue
                except (socket.error, BrokenPipeError):
                    break
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
                targets = [self.active_client] if self.active_client else list(self.client_sockets)
                for sock in list(targets):
                    if sock not in self.client_sockets:
                        continue
                    try:
                        sock.settimeout(0.1)
                        sock.sendall(struct.pack('!I', len(packed)) + packed)
                        sock.settimeout(1.0)
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
                if active_lost:
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
        current_special_keys = set()

        def get_vk(key):
            if hasattr(key, "vk") and key.vk is not None:
                return key.vk
            if hasattr(key, "value") and hasattr(key.value, "vk"):
                return key.value.vk
            return None

        hotkey_desktop_l_numoff = {keyboard.Key.shift, keyboard.Key.insert}
        hotkey_desktop_r_numoff = {keyboard.Key.shift_r, keyboard.Key.insert}
        hotkey_laptop_l_numoff = {keyboard.Key.shift, keyboard.Key.end}
        hotkey_laptop_r_numoff = {keyboard.Key.shift_r, keyboard.Key.end}
        hotkey_elitdesk_l_numoff = {keyboard.Key.shift, VK_NUMPAD2}
        hotkey_elitdesk_r_numoff = {keyboard.Key.shift_r, VK_NUMPAD2}

        hotkey_desktop_l_numon = {VK_LSHIFT, VK_NUMPAD0}
        hotkey_desktop_r_numon = {VK_RSHIFT, VK_NUMPAD0}
        hotkey_laptop_l_numon = {VK_LSHIFT, VK_NUMPAD1}
        hotkey_laptop_r_numon = {VK_RSHIFT, VK_NUMPAD1}
        hotkey_elitdesk_l_numon = {VK_LSHIFT, VK_NUMPAD2}
        hotkey_elitdesk_r_numon = {VK_RSHIFT, VK_NUMPAD2}


        def on_key(k, p):
            """Forward keyboard events to the client and kezelje a gyorsbillentyűt."""
            try:
                vk = get_vk(k)
                if vk is not None:
                    if p:
                        current_vks.add(vk)
                    else:
                        current_vks.discard(vk)
                if isinstance(k, keyboard.Key):
                    if p:
                        current_special_keys.add(k)
                    else:
                        current_special_keys.discard(k)

                if (
                    hotkey_desktop_l_numoff.issubset(current_special_keys)
                    or hotkey_desktop_r_numoff.issubset(current_special_keys)
                    or (
                        (VK_LSHIFT in current_vks or VK_RSHIFT in current_vks)
                        and VK_NUMPAD0 in current_vks
                    )
                ):
                    logging.info("!!! Visszaváltás a hosztra (Shift+Numpad0) észlelve a streaming alatt !!!")
                    # Send key releases to the client before disabling streaming
                    for vk_code in [VK_LSHIFT, VK_RSHIFT, VK_NUMPAD0]:
                        if vk_code in current_vks:
                            send({"type": "key", "key_type": "vk", "key": vk_code, "pressed": False})
                            pressed_keys.discard(("vk", vk_code))
                    current_vks.clear()
                    self.deactivate_kvm(switch_monitor=True, reason='streaming hotkey')
                    return
                if (
                    hotkey_laptop_l_numoff.issubset(current_special_keys)
                    or hotkey_laptop_r_numoff.issubset(current_special_keys)
                    or (
                        (VK_LSHIFT in current_vks or VK_RSHIFT in current_vks)
                        and VK_NUMPAD1 in current_vks
                    )
                ):
                    logging.debug(f"Hotkey detected for laptop with current_vks={current_vks}")
                    for vk_code in [VK_LSHIFT, VK_RSHIFT, VK_NUMPAD1]:
                        if vk_code in current_vks:
                            send({"type": "key", "key_type": "vk", "key": vk_code, "pressed": False})
                            pressed_keys.discard(("vk", vk_code))
                    current_vks.clear()
                    self.toggle_client_control('laptop', switch_monitor=False, release_keys=False)
                    return
                if (
                    hotkey_elitdesk_l_numoff.issubset(current_special_keys.union(current_vks))
                    or hotkey_elitdesk_r_numoff.issubset(current_special_keys.union(current_vks))
                    or (
                        (VK_LSHIFT in current_vks or VK_RSHIFT in current_vks)
                        and VK_NUMPAD2 in current_vks
                    )
                ):
                    logging.debug(f"Hotkey detected for elitedesk with current_vks={current_vks}")
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

        browser = ServiceBrowser(self.zeroconf, SERVICE_TYPE, ServiceListener(self))
        self.status_update.emit("Vevő mód: Keresem az Adó szolgáltatást...")
        while self._running:
            time.sleep(0.5)

    def connect_to_server(self):
        mouse_controller = mouse.Controller()
        keyboard_controller = keyboard.Controller()
        pressed_keys = set()
        button_map = {
            'left': mouse.Button.left,
            'right': mouse.Button.right,
            'middle': mouse.Button.middle,
        }
        hk_listener = None

        while self._running:
            ip = self.server_ip or self.last_server_ip
            if not ip:
                time.sleep(0.5)
                continue

            hb_thread = None  # Ensure heartbeat thread variable is always defined

            logging.debug(
                "connect_to_server attempting to connect to %s cancel=%s",
                ip,
                self.file_handler._cancel_transfer.is_set(),
            )

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
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
                    logging.debug("Connected to server")

                    try:
                        hello = msgpack.packb({'device_name': self.device_name}, use_bin_type=True)
                        s.sendall(struct.pack('!I', len(hello)) + hello)
                        logging.debug("Handshake sent to server")
                    except Exception as e:
                        logging.error(f"Failed to send handshake: {e}")

                    self.clipboard_thread = threading.Thread(
                        target=self._clipboard_loop_client, args=(s,), daemon=True, name="ClipboardCli"
                    )
                    self.clipboard_thread.start()

                    logging.info("TCP kapcsolat sikeres.")
                    self.status_update.emit("Csatlakozva. Irányítás átvéve.")

                    def send_command(cmd):
                        try:
                            packed = msgpack.packb({'command': cmd}, use_bin_type=True)
                            s.sendall(struct.pack('!I', len(packed)) + packed)
                            logging.info(f"Command sent to server: {cmd}")
                        except Exception:
                            logging.error("Nem sikerult parancsot kuldeni", exc_info=True)

                    hotkey_cmd_l = {keyboard.Key.shift, keyboard.KeyCode.from_vk(VK_F12)}
                    hotkey_cmd_r = {keyboard.Key.shift_r, keyboard.KeyCode.from_vk(VK_F12)}

                    client_pressed_special_keys = set()
                    client_pressed_vk_codes = set()

                    def hk_press(key):
                        try:
                            client_pressed_vk_codes.add(key.vk)
                        except AttributeError:
                            client_pressed_special_keys.add(key)

                        combined_pressed = client_pressed_special_keys.union(
                            {keyboard.KeyCode.from_vk(vk) for vk in client_pressed_vk_codes}
                        )

                        if hotkey_cmd_l.issubset(combined_pressed) or hotkey_cmd_r.issubset(combined_pressed):
                            logging.info("Client hotkey (Shift+F12) detected, requesting switch_elitedesk")
                            send_command('switch_elitedesk')

                    def hk_release(key):
                        try:
                            client_pressed_vk_codes.discard(key.vk)
                        except AttributeError:
                            client_pressed_special_keys.discard(key)

                    hk_listener = keyboard.Listener(on_press=hk_press, on_release=hk_release)
                    hk_listener.start()

                    last_event_time = time.time()
                    last_warning = 0
                    hb_thread = None

                    def heartbeat():
                        nonlocal last_warning
                        while self._running and self.server_ip == ip:
                            if time.time() - last_event_time > 2:
                                if time.time() - last_warning > 2:
                                    logging.warning("No input events received for over 2 seconds")
                                    last_warning = time.time()
                            time.sleep(1)

                    hb_thread = threading.Thread(target=heartbeat, daemon=True, name="HeartbeatThread")
                    hb_thread.start()

                    def recv_all(sock, n):
                        data = b''
                        while len(data) < n:
                            chunk = sock.recv(n - len(data))
                            if not chunk:
                                return None
                            data += chunk
                        return data

                    while self._running and self.server_ip == ip:
                        logging.debug(
                            "connect_to_server recv loop. cancel=%s",
                            self.file_handler._cancel_transfer.is_set(),
                        )
                        raw_len = recv_all(s, 4)
                        if not raw_len:
                            break
                        msg_len = struct.unpack('!I', raw_len)[0]
                        payload = recv_all(s, msg_len)
                        if payload is None:
                            break
                        try:
                            data = msgpack.unpackb(payload, raw=False)
                            last_event_time = time.time()
                            event_type = data.get('type')
                            if event_type == 'move_relative':
                                mouse_controller.move(data['dx'], data['dy'])
                            elif event_type == 'click':
                                b = button_map.get(data['button'])
                                if b:
                                    (mouse_controller.press if data['pressed'] else mouse_controller.release)(b)
                            elif event_type == 'scroll':
                                mouse_controller.scroll(data['dx'], data['dy'])
                            elif event_type == 'key':
                                k_info = data['key']
                                if data['key_type'] == 'char':
                                    k_press = k_info
                                elif data['key_type'] == 'special':
                                    k_press = getattr(keyboard.Key, k_info, None)
                                elif data['key_type'] == 'vk':
                                    k_press = keyboard.KeyCode.from_vk(int(k_info))
                                else:
                                    k_press = None
                                if k_press:
                                    if data['pressed']:
                                        keyboard_controller.press(k_press)
                                        pressed_keys.add(k_press)
                                    else:
                                        keyboard_controller.release(k_press)
                                        pressed_keys.discard(k_press)
                            elif event_type == 'clipboard_text':
                                text = data.get('text', '')
                                if text != self.last_clipboard:
                                    self._set_clipboard(text)
                            else:
                                self.file_handler.handle_network_message(data, s)
                        except Exception as e:
                            logging.error(
                                f"Hiba a szervertől kapott üzenet feldolgozásakor: {e}",
                                exc_info=True,
                            )

            except Exception as e:
                if self._running:
                    logging.error(f"Csatlakozás sikertelen: {e}", exc_info=True)
                    self.status_update.emit(
                        f"Kapcsolat sikertelen: {e}. Újrapróbálkozás 5 mp múlva..."
                    )

            finally:
                logging.info("Connection to server closed")
                if hb_thread is not None:
                    try:
                        hb_thread.join(timeout=0.1)
                    except Exception:
                        pass
                if self.clipboard_thread is not None:
                    try:
                        self.clipboard_thread.join(timeout=0.1)
                    except Exception:
                        pass
                for k in list(pressed_keys):
                    try:
                        keyboard_controller.release(k)
                    except Exception:
                        pass
                if hk_listener is not None:
                    try:
                        hk_listener.stop()
                    except Exception:
                        pass
                self.release_hotkey_keys()
                self.file_handler.on_client_disconnected(s)
                self.server_socket = None
                if self._running:
                    logging.info("Újracsatlakozási kísérlet 2 másodperc múlva...")
                    time.sleep(2)
                logging.debug("connect_to_server loop ended")
