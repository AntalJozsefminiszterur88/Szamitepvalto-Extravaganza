"""
Definitive, Monolithic KVM worker.
This file contains ALL background logic (networking, input handling, file transfer)
to eliminate errors from fragmented code and mixins.
Architecture: Two Permanent Listeners for maximum stability.
"""

import socket
import time
import threading
import struct
import logging
from typing import Optional
import tkinter
import os
import shutil
import zipfile
import tempfile

import msgpack
import pyperclip
from pynput import mouse, keyboard
from zeroconf import Zeroconf, ServiceBrowser, ServiceInfo
from monitorcontrol import get_monitors
from PySide6.QtCore import QObject, Signal, QSettings

from config import (
    SERVICE_TYPE,
    SERVICE_NAME_PREFIX,
    APP_NAME,
    ORG_NAME,
    VK_NUMPAD0,
    VK_NUMPAD1,
    VK_NUMPAD2,
    VK_LSHIFT,
    VK_RSHIFT,
    TEMP_DIR_PARTS,
    VK_F12,
)


FILE_CHUNK_SIZE = 65536
TRANSFER_TIMEOUT = 30
PROGRESS_UPDATE_INTERVAL = 0.5


def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return socket.gethostbyname(socket.gethostname())


class KVMWorker(QObject):
    """Self contained worker handling networking and input forwarding."""

    __slots__ = (
        'settings', '_running', 'kvm_active', 'client_sockets', 'client_infos',
        'active_client', 'zeroconf', 'local_ip', 'server_ip', 'connection_thread',
        'device_name', 'clipboard_thread', 'last_clipboard', 'server_socket',
        'network_file_clipboard', '_cancel_transfer', 'last_server_ip',
        'clipboard_lock', '_input_listeners'
    )

    finished = Signal()
    status_update = Signal(str)
    update_progress_display = Signal(int, str)
    file_transfer_error = Signal(str)
    incoming_upload_started = Signal(str, int)
    request_deactivation = Signal(str)

    def __init__(self, settings):
        super().__init__()
        self.settings = settings
        self._running = True
        self.kvm_active = False
        self._input_listeners = []

        self.zeroconf = Zeroconf()
        self.local_ip = get_local_ip()
        self.client_sockets, self.client_infos, self.active_client = [], {}, None
        self.server_ip, self.connection_thread, self.server_socket = None, None, None

        self.device_name = settings.get('device_name', socket.gethostname())
        settings_store = QSettings(ORG_NAME, APP_NAME)
        self.last_server_ip = settings_store.value('network/last_server_ip', None)

        self.clipboard_thread, self.last_clipboard, self.clipboard_lock = None, "", threading.Lock()

        self.network_file_clipboard = None
        self._cancel_transfer = threading.Event()

    # ------------------------------------------------------------------
    # --- LIFECYCLE MANAGEMENT ---
    # ------------------------------------------------------------------
    def run(self):
        logging.info(f"Worker starting in '{self.settings['role']}' mode.")
        if self.settings['role'] == 'ado':
            input_thread = threading.Thread(target=self._input_handler, daemon=True, name="InputHandler")
            input_thread.start()
            self.run_server()
        else:
            self.run_client()
        logging.info("Worker run loop finished.")

    def stop(self):
        logging.info("--- WORKER STOPPING ---")
        self._running = False
        if self.kvm_active:
            self.deactivate_kvm(switch_monitor=False, reason="stop() called")
        for listener in self._input_listeners:
            try:
                listener.stop()
            except Exception:
                pass
        try:
            self.zeroconf.close()
        except Exception:
            pass
        for sock in list(self.client_sockets):
            self._remove_client(sock, "stopping")
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        self.finished.emit()

    # ------------------------------------------------------------------
    # --- KVM STATE MANAGEMENT ---
    # ------------------------------------------------------------------
    def release_all_keys(self):
        kc = keyboard.Controller()
        keys = [
            keyboard.Key.shift,
            keyboard.Key.ctrl,
            keyboard.Key.alt,
            keyboard.KeyCode.from_vk(VK_NUMPAD0),
            keyboard.KeyCode.from_vk(VK_NUMPAD1),
            keyboard.KeyCode.from_vk(VK_NUMPAD2),
        ]
        for key in keys:
            try:
                kc.release(key)
            except Exception:
                pass

    def activate_kvm(self, switch_monitor=True):
        if not self.active_client:
            self.status_update.emit("Hiba: Nincs kliens a váltáshoz!")
            return
        if self.kvm_active:
            return

        client_name = self.client_infos.get(self.active_client, "ismeretlen")
        logging.info(f"--- Activating KVM. Target: {client_name} ---")

        if switch_monitor:
            try:
                with list(get_monitors())[0] as monitor:
                    monitor.set_input_source(self.settings['monitor_codes']['client'])
            except Exception as e:
                self.status_update.emit(f"Monitor hiba: {e}")

        self.kvm_active = True
        self.status_update.emit(f"Állapot: Aktív - {client_name}")

    def deactivate_kvm(self, switch_monitor=True, *, reason: Optional[str] = None):
        if not self.kvm_active:
            return

        logging.info(f"--- Deactivating KVM. Reason: {reason or 'unknown'} ---")

        if switch_monitor:
            try:
                with list(get_monitors())[0] as monitor:
                    monitor.set_input_source(self.settings['monitor_codes']['host'])
            except Exception as e:
                self.status_update.emit(f"Monitor hiba: {e}")

        self.kvm_active = False
        self.release_all_keys()
        self.active_client = None
        self.status_update.emit("Állapot: Inaktív. Várakozás...")

    def set_active_client_by_name(self, name):
        for sock, cname in self.client_infos.items():
            if cname.lower().startswith(name.lower()):
                self.active_client = sock
                return True
        return False

    def toggle_client_control(self, name: str, *, switch_monitor: bool = True):
        current_client_name = self.client_infos.get(self.active_client, "").lower()
        target_name = name.lower()
        is_desktop_target = target_name == 'desktop'

        if self.kvm_active:
            if current_client_name.startswith(target_name) or is_desktop_target:
                self.deactivate_kvm(reason=f"toggle for {name}", switch_monitor=True)
            else:
                self.deactivate_kvm(reason=f"switching to {name}", switch_monitor=False)
                if self.set_active_client_by_name(name):
                    self.activate_kvm(switch_monitor=switch_monitor)
        else:
            if not is_desktop_target and self.set_active_client_by_name(name):
                self.activate_kvm(switch_monitor=switch_monitor)

    # ------------------------------------------------------------------
    # --- INPUT HANDLING (SINGLE-THREAD, DUAL-LISTENER) ---
    # ------------------------------------------------------------------
    def _input_handler(self):
        logging.info("--- PERMANENT INPUT HANDLER STARTED ---")

        hotkey_map = {
            'desktop': ({VK_LSHIFT, VK_NUMPAD0}, {keyboard.Key.shift, keyboard.Key.insert}),
            'laptop': ({VK_LSHIFT, VK_NUMPAD1}, {keyboard.Key.shift, keyboard.Key.end}),
            'elitedesk': ({VK_LSHIFT, VK_NUMPAD2}, {keyboard.Key.shift, VK_NUMPAD2}),
        }

        # --- Suppressing Listener (for active KVM) ---
        pressed_keys_forwarded = set()
        try:
            root = tkinter.Tk(); root.withdraw()
            center_x, center_y = (root.winfo_screenwidth() // 2, root.winfo_screenheight() // 2)
            root.destroy()
        except Exception:
            center_x, center_y = 800, 600
        is_warping = False
        mouse_controller = mouse.Controller()

        def send(data):
            if not self.active_client:
                return
            try:
                packed = msgpack.packb(data, use_bin_type=True)
                message = struct.pack('!I', len(packed)) + packed
                self.active_client.sendall(message)
            except (OSError, ConnectionResetError):
                self._remove_client(self.active_client, "send failed")

        def on_move_suppress(x, y):
            nonlocal is_warping
            if not self.kvm_active:
                return
            if is_warping:
                is_warping = False
                return
            dx, dy = x - mouse_controller.position[0], y - mouse_controller.position[1]
            if dx != 0 or dy != 0:
                send({'type': 'move_relative', 'dx': dx, 'dy': dy})
            is_warping = True
            mouse_controller.position = (center_x, center_y)

        def on_click_suppress(x, y, button, pressed):
            if not self.kvm_active:
                return
            send({'type': 'click', 'button': button.name, 'pressed': pressed})

        def on_scroll_suppress(x, y, dx, dy):
            if not self.kvm_active:
                return
            send({'type': 'scroll', 'dx': dx, 'dy': dy})

        def on_key_event(key, is_pressed):
            if self.kvm_active:
                if hasattr(key, "char") and key.char:
                    key_type, key_val = "char", key.char
                elif hasattr(key, "name"):
                    key_type, key_val = "special", key.name
                elif hasattr(key, "vk"):
                    key_type, key_val = "vk", key.vk
                else:
                    return
                key_id = (key_type, key_val)
                if is_pressed:
                    if key_id not in pressed_keys_forwarded:
                        pressed_keys_forwarded.add(key_id)
                        send({"type": "key", "key_type": key_type, "key": key_val, "pressed": True})
                else:
                    if key_id in pressed_keys_forwarded:
                        pressed_keys_forwarded.discard(key_id)
                        send({"type": "key", "key_type": key_type, "key": key_val, "pressed": False})

        # --- Non-Suppressing Listener (for idle KVM) ---
        idle_vks, idle_special, pending_client = set(), set(), None

        def on_press_idle(key):
            nonlocal pending_client
            if self.kvm_active:
                return
            try:
                idle_vks.add(key.vk)
            except AttributeError:
                idle_special.add(key)
            for target, (vk_set, key_set) in hotkey_map.items():
                if vk_set.issubset(idle_vks) or key_set.issubset(idle_special):
                    pending_client = target
                    break

        def on_release_idle(key):
            nonlocal pending_client
            if self.kvm_active:
                return
            try:
                idle_vks.discard(key.vk)
            except AttributeError:
                idle_special.discard(key)
            if pending_client and not idle_vks and not idle_special:
                self.toggle_client_control(pending_client)
                pending_client = None

        suppressing_mouse = mouse.Listener(
            on_move=on_move_suppress,
            on_click=on_click_suppress,
            on_scroll=on_scroll_suppress,
            suppress=True,
        )
        suppressing_keyboard = keyboard.Listener(
            on_press=lambda k: on_key_event(k, True),
            on_release=lambda k: on_key_event(k, False),
            suppress=True,
        )
        idle_keyboard = keyboard.Listener(
            on_press=on_press_idle,
            on_release=on_release_idle,
            suppress=False,
        )

        self._input_listeners.extend([suppressing_mouse, suppressing_keyboard, idle_keyboard])
        suppressing_mouse.start(); suppressing_keyboard.start(); idle_keyboard.start()
        suppressing_mouse.join(); suppressing_keyboard.join(); idle_keyboard.join()

    # ------------------------------------------------------------------
    # --- NETWORKING & HELPERS ---
    # ------------------------------------------------------------------

    def _remove_client(self, sock, reason: str = ""):
        if sock is None:
            return
        client_name = self.client_infos.get(sock, "<unknown>")
        logging.warning("Kliens eltávolítva: %s. Ok: %s", client_name, reason)
        try:
            sock.close()
        except Exception:
            pass
        if sock in self.client_sockets:
            self.client_sockets.remove(sock)
        if sock in self.client_infos:
            del self.client_infos[sock]
        if sock == self.active_client:
            self.request_deactivation.emit(f"aktív kliens ({client_name}) lecsatlakozott")

    def _send_message(self, sock, data):
        try:
            packed = msgpack.packb(data, use_bin_type=True)
            sock.sendall(struct.pack('!I', len(packed)) + packed)
            return True
        except Exception:
            return False

    def _broadcast_message(self, data, exclude=None):
        to_remove = []
        packed = msgpack.packb(data, use_bin_type=True)
        message = struct.pack('!I', len(packed)) + packed
        for s in list(self.client_sockets):
            if s is exclude:
                continue
            try:
                s.sendall(message)
            except Exception:
                to_remove.append(s)
        for s in to_remove:
            self._remove_client(s, "broadcast failed")

    # ---------------------- Server side ----------------------

    def run_server(self):
        accept_thread = threading.Thread(target=self.accept_connections, daemon=True, name="AcceptThread")
        accept_thread.start()

        self.clipboard_thread = threading.Thread(target=self._clipboard_loop_server, daemon=True, name="ClipboardSrv")
        self.clipboard_thread.start()

        info = ServiceInfo(
            SERVICE_TYPE,
            f"{SERVICE_NAME_PREFIX}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(self.local_ip)],
            port=self.settings['port'],
        )
        self.zeroconf.register_service(info)

        while self._running:
            time.sleep(1)

    def accept_connections(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                server_socket.bind(('', self.settings['port']))
                server_socket.listen(5)
                while self._running:
                    client_sock, addr = server_socket.accept()
                    client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    self.client_sockets.append(client_sock)
                    threading.Thread(target=self.monitor_client, args=(client_sock, addr), daemon=True).start()
        except Exception as e:
            if self._running:
                logging.error(f"Szerver hiba: {e}")

    def monitor_client(self, sock, addr):
        buffer = b''

        def recv_all(s, n):
            data = b''
            while len(data) < n:
                chunk = s.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
            return data

        client_name = str(addr)
        try:
            raw_len = recv_all(sock, 4)
            if raw_len:
                msg_len = struct.unpack('!I', raw_len)[0]
                payload = recv_all(sock, msg_len)
                if payload:
                    hello = msgpack.unpackb(payload, raw=False)
                    client_name = hello.get('device_name', client_name)
            self.client_infos[sock] = client_name

            with self.clipboard_lock:
                last_clip = self.last_clipboard
            if last_clip:
                self._send_message(sock, {'type': 'clipboard_text', 'text': last_clip})

        except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
            self._remove_client(sock, "handshake failed")
            return
        except Exception as e:
            logging.error("Hiba a kliens handshake során: %s", e)
            self._remove_client(sock, "handshake error")
            return

        upload_info = None
        try:
            while self._running and sock in self.client_sockets:
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

                    data = msgpack.unpackb(payload, raw=False)
                    cmd = data.get('command')
                    if cmd == 'switch_elitedesk':
                        self.toggle_client_control('elitedesk')
                    elif cmd == 'switch_laptop':
                        self.toggle_client_control('laptop')
                    elif data.get('type') == 'clipboard_text':
                        text = data.get('text', '')
                        broadcast = False
                        with self.clipboard_lock:
                            if text != self.last_clipboard:
                                self.last_clipboard = text
                                broadcast = True
                        if broadcast:
                            self._set_clipboard(text)
                            self._broadcast_message(data, exclude=sock)
                    elif data.get('type') == 'paste_request':
                        dest = data.get('destination')
                        if self.network_file_clipboard and self.network_file_clipboard.get('archive'):
                            self._cancel_transfer.clear()
                            self._send_archive(sock, self.network_file_clipboard['archive'], dest)
                    elif data.get('type') == 'file_metadata':
                        temp_dir_for_download = self._get_temp_dir()
                        incoming_path = os.path.join(temp_dir_for_download, data['name'])
                        self._clear_network_file_clipboard()
                        try:
                            incoming_file = open(incoming_path, 'wb')
                        except Exception as e:
                            self.file_transfer_error.emit(str(e))
                            break
                        self.incoming_upload_started.emit(data.get('name'), data.get('size', 0))
                        self._cancel_transfer.clear()
                        sock.settimeout(TRANSFER_TIMEOUT)
                        upload_info = {
                            'file': incoming_file,
                            'path': incoming_path,
                            'temp_dir': temp_dir_for_download,
                            'size': data.get('size', 0),
                            'name': data.get('name'),
                            'received': 0,
                            'start_time': time.time(),
                            'paths': data.get('paths', []),
                            'operation': data.get('operation', 'copy'),
                            'source_id': data.get('source_id', client_name),
                        }
                    elif data.get('type') == 'file_chunk':
                        if upload_info:
                            try:
                                upload_info['file'].write(data['data'])
                                upload_info['received'] += len(data['data'])
                            except Exception as e:
                                self.file_transfer_error.emit(str(e))
                                self._cancel_transfer.set()
                                break
                    elif data.get('type') == 'file_end':
                        if upload_info:
                            upload_info['file'].close()
                            self.network_file_clipboard = {
                                'paths': upload_info['paths'],
                                'operation': upload_info['operation'],
                                'archive': upload_info['path'],
                                'source_id': upload_info.get('source_id', client_name),
                            }
                            self._broadcast_message({
                                'type': 'network_clipboard_set',
                                'source_id': upload_info.get('source_id', client_name),
                                'operation': upload_info['operation'],
                            }, exclude=sock)
                            upload_info = None
                            sock.settimeout(None)
                    elif data.get('type') == 'paste_success':
                        src = data.get('source_id')
                        if (
                            self.network_file_clipboard
                            and self.network_file_clipboard.get('operation') == 'cut'
                            and self.network_file_clipboard.get('source_id') == src
                        ):
                            self._clear_network_file_clipboard()
        finally:
            if upload_info and upload_info.get('temp_dir'):
                shutil.rmtree(upload_info['temp_dir'], ignore_errors=True)
            self._remove_client(sock, "monitor finished")

    # ---------------------- Client side ----------------------

    def run_client(self):
        class ServiceListener:
            def __init__(self, worker):
                self.worker = worker

            def add_service(self, zc, type, name):
                info = zc.get_service_info(type, name)
                if info and socket.inet_ntoa(info.addresses[0]) != self.worker.local_ip:
                    ip = socket.inet_ntoa(info.addresses[0])
                    if not self.worker.server_socket:
                        self.worker.last_server_ip = ip
                        QSettings(ORG_NAME, APP_NAME).setValue('network/last_server_ip', ip)
                        threading.Thread(target=self.worker.connect_to_server, args=(ip, self.worker.settings['port']), daemon=True).start()

            def update_service(self, zc, type, name):
                pass

            def remove_service(self, zc, type, name):
                if self.worker.server_ip == name.split('.')[0]:
                    self.worker.server_ip = None

        ServiceBrowser(self.zeroconf, SERVICE_TYPE, ServiceListener(self))
        self.connection_thread = threading.Thread(target=self._reconnect_loop, daemon=True, name="ReconnectLoop")
        self.connection_thread.start()
        while self._running:
            time.sleep(1)

    def _reconnect_loop(self):
        while self._running:
            if not self.server_socket and self.last_server_ip:
                self.connect_to_server(self.last_server_ip, self.settings['port'])
            time.sleep(3)

    def connect_to_server(self, ip: str, port: int) -> None:
        mouse_controller = mouse.Controller()
        keyboard_controller = keyboard.Controller()
        pressed_keys = set()
        button_map = {'left': mouse.Button.left, 'right': mouse.Button.right, 'middle': mouse.Button.middle}
        hk_listener = None
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(3.0)
            s.connect((ip, port))
            s.settimeout(None)
            self.server_socket = s
            self.server_ip = ip
            QSettings(ORG_NAME, APP_NAME).setValue('network/last_server_ip', ip)
            self.last_server_ip = ip

            hello = msgpack.packb({'device_name': self.device_name}, use_bin_type=True)
            s.sendall(struct.pack('!I', len(hello)) + hello)

            time.sleep(0.2)

            self.clipboard_thread = threading.Thread(target=self._clipboard_loop_client, args=(s,), daemon=True, name="ClipboardCli")
            self.clipboard_thread.start()

            def send_command(cmd):
                try:
                    packed = msgpack.packb({'command': cmd}, use_bin_type=True)
                    s.sendall(struct.pack('!I', len(packed)) + packed)
                except Exception:
                    pass

            hotkey_cmd_l = {keyboard.Key.shift, keyboard.KeyCode.from_vk(VK_F12)}
            hotkey_cmd_r = {keyboard.Key.shift_r, keyboard.KeyCode.from_vk(VK_F12)}
            client_pressed_keys = set()

            def hk_press(key):
                client_pressed_keys.add(key)
                if hotkey_cmd_l.issubset(client_pressed_keys) or hotkey_cmd_r.issubset(client_pressed_keys):
                    send_command('switch_elitedesk')

            def hk_release(key):
                client_pressed_keys.discard(key)

            hk_listener = keyboard.Listener(on_press=hk_press, on_release=hk_release)
            hk_listener.start()

            def recv_all(sock, n):
                data = b''
                while len(data) < n:
                    chunk = sock.recv(n - len(data))
                    if not chunk:
                        return None
                    data += chunk
                return data

            while self._running and self.server_socket is s:
                raw_len = recv_all(s, 4)
                if not raw_len:
                    break
                msg_len = struct.unpack('!I', raw_len)[0]
                payload = recv_all(s, msg_len)
                if payload is None:
                    break

                data = msgpack.unpackb(payload, raw=False)
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
                    k_info, k_type, pressed = data['key'], data['key_type'], data['pressed']
                    if k_type == 'char':
                        k_press = k_info
                    elif k_type == 'special':
                        k_press = getattr(keyboard.Key, k_info, None)
                    elif k_type == 'vk':
                        k_press = keyboard.KeyCode.from_vk(int(k_info))
                    else:
                        k_press = None
                    if k_press:
                        if pressed:
                            keyboard_controller.press(k_press)
                            pressed_keys.add(k_press)
                        else:
                            keyboard_controller.release(k_press)
                            pressed_keys.discard(k_press)
                elif event_type == 'clipboard_text':
                    text = data.get('text', '')
                    with self.clipboard_lock:
                        if text != self.last_clipboard:
                            self._set_clipboard(text)
        except (socket.timeout, ConnectionRefusedError, OSError):
            if self._running:
                self.status_update.emit(f"Kapcsolat sikertelen: {ip}")
        except Exception as e:
            if self._running:
                logging.error(f"Váratlan kliens hiba: {e}", exc_info=True)
                self.status_update.emit(f"Kliens hiba: {e}")
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
            if hk_listener:
                hk_listener.stop()
            for k in list(pressed_keys):
                try:
                    keyboard_controller.release(k)
                except Exception:
                    pass
            if self.server_socket is s:
                self.server_socket = None

    # ---------------------- Clipboard handling ----------------------

    def _set_clipboard(self, text: str):
        with self.clipboard_lock:
            try:
                pyperclip.copy(text)
            except Exception:
                pass

    def _get_clipboard(self) -> str:
        with self.clipboard_lock:
            try:
                return pyperclip.paste()
            except Exception:
                return ""

    def _clipboard_loop_server(self):
        while self._running:
            time.sleep(1.0)
            try:
                current_text = self._get_clipboard()
                if current_text and current_text != self.last_clipboard:
                    self.last_clipboard = current_text
                    self._broadcast_message({'type': 'clipboard_text', 'text': current_text})
            except Exception:
                pass

    def _clipboard_loop_client(self, sock):
        while self._running and self.server_socket is sock:
            time.sleep(1.0)
            try:
                current_text = self._get_clipboard()
                if current_text and current_text != self.last_clipboard:
                    self.last_clipboard = current_text
                    self._send_message(sock, {'type': 'clipboard_text', 'text': current_text})
            except Exception:
                break

    # ---------------------- File transfer helpers ----------------------

    def _get_temp_dir(self) -> str:
        base_path = self.settings.get('temp_path') or tempfile.gettempdir()
        app_temp_path = os.path.join(base_path, *TEMP_DIR_PARTS)
        os.makedirs(app_temp_path, exist_ok=True)
        return tempfile.mkdtemp(dir=app_temp_path)

    def _create_archive(self, paths, cancel_event: Optional[threading.Event] = None):
        temp_dir = self._get_temp_dir()
        archive = os.path.join(temp_dir, 'share.zip')
        try:
            total_files = 0
            for p in paths:
                if os.path.isdir(p):
                    for _, _, files in os.walk(p):
                        total_files += len(files)
                else:
                    total_files += 1

            archived_files = 0
            with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
                for p in paths:
                    if cancel_event and cancel_event.is_set():
                        raise RuntimeError('archive canceled')
                    if os.path.isdir(p):
                        base = os.path.basename(p.rstrip(os.sep))
                        for root, _, files in os.walk(p):
                            for f in files:
                                full = os.path.join(root, f)
                                rel = os.path.join(base, os.path.relpath(full, p))
                                zf.write(full, rel)
                                archived_files += 1
                                percentage = int(archived_files / total_files * 100) if total_files else 0
                                self.update_progress_display.emit(percentage, f"Tömörítés: {os.path.basename(full)}")
                    else:
                        zf.write(p, os.path.basename(p))
                        archived_files += 1
                        percentage = int(archived_files / total_files * 100) if total_files else 0
                        self.update_progress_display.emit(percentage, f"Tömörítés: {os.path.basename(p)}")
            self.update_progress_display.emit(100, f"Tömörítés kész. ({os.path.basename(archive)})")
        except Exception as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            self.file_transfer_error.emit(str(e))
            return None
        return archive

    def _safe_extract_archive(self, archive_path, dest_dir):
        temp_extract = tempfile.mkdtemp(dir=dest_dir)
        try:
            with zipfile.ZipFile(archive_path, 'r') as zf:
                zf.extractall(temp_extract)
            if self._cancel_transfer.is_set():
                raise RuntimeError('transfer canceled')
            for name in os.listdir(temp_extract):
                source_path = os.path.join(temp_extract, name)
                target_path_base = os.path.join(dest_dir, name)
                final_target_path = target_path_base
                counter = 2
                base, ext = os.path.splitext(name)
                while os.path.exists(final_target_path):
                    if ext:
                        new_name = f"{base} ({counter}){ext}"
                    else:
                        new_name = f"{name} ({counter})"
                    final_target_path = os.path.join(dest_dir, new_name)
                    counter += 1
                shutil.move(source_path, final_target_path)
        finally:
            shutil.rmtree(temp_extract, ignore_errors=True)

    def _send_archive(self, sock, archive_path, dest_dir):
        self._cancel_transfer.clear()
        prev_to = sock.gettimeout()
        sock.settimeout(TRANSFER_TIMEOUT)
        try:
            size = os.path.getsize(archive_path)
            name = os.path.basename(archive_path)
            meta = {
                'type': 'file_metadata',
                'name': name,
                'size': size,
                'dest': dest_dir,
                'source_id': self.network_file_clipboard.get('source_id') if self.network_file_clipboard else self.device_name,
            }
            if not self._send_message(sock, meta):
                return
            sent = 0
            with open(archive_path, 'rb') as f:
                while not self._cancel_transfer.is_set():
                    chunk = f.read(FILE_CHUNK_SIZE)
                    if not chunk:
                        break
                    if not self._send_message(sock, {'type': 'file_chunk', 'data': chunk}):
                        raise IOError('send failed')
                    sent += len(chunk)
                    current_percentage = int((sent / size) * 100) if size > 0 else 0
                    self.update_progress_display.emit(current_percentage, f"{name}: {sent/1024/1024:.1f}MB")
            if self._cancel_transfer.is_set():
                self._send_message(sock, {'type': 'transfer_canceled'})
                return
            self.update_progress_display.emit(100, f"{name}: Kész! ({size/1024/1024:.1f}MB)")
            self._send_message(sock, {'type': 'file_end'})
        except Exception as e:
            self.file_transfer_error.emit(str(e))
        finally:
            sock.settimeout(prev_to)
            self._cancel_transfer.clear()

    def _clear_network_file_clipboard(self):
        if self.network_file_clipboard and self.network_file_clipboard.get('archive'):
            try:
                os.remove(self.network_file_clipboard['archive'])
            except FileNotFoundError:
                pass
            except Exception as e:
                logging.error("Failed to remove temporary archive %s: %s", self.network_file_clipboard['archive'], e)
        self.network_file_clipboard = None

    def cancel_file_transfer(self):
        self._cancel_transfer.set()

    def share_files(self, paths, operation='copy') -> None:
        threading.Thread(target=self._share_files_thread, args=(paths, operation), daemon=True).start()

    def _share_files_thread(self, paths, operation):
        self._cancel_transfer.clear()
        cancel_evt = threading.Event()
        result = {}

        def run_archiving():
            result['archive'] = self._create_archive(paths, cancel_event=cancel_evt)

        arch_thread = threading.Thread(target=run_archiving, daemon=True)
        arch_thread.start()
        arch_thread.join(self.settings.get('archive_timeout_seconds', 900))
        if arch_thread.is_alive():
            cancel_evt.set()
            arch_thread.join(5)
            self.file_transfer_error.emit("Archiválás időtúllépés")
            if result.get('archive'):
                shutil.rmtree(os.path.dirname(result['archive']), ignore_errors=True)
            return
        archive = result.get('archive')
        temp_archive_dir = None
        try:
            if not archive:
                self._clear_network_file_clipboard()
                return
            temp_archive_dir = os.path.dirname(archive)
            if self.settings['role'] == 'ado':
                self._clear_network_file_clipboard()
                self.network_file_clipboard = {
                    'paths': paths,
                    'operation': operation,
                    'archive': archive,
                    'source_id': self.device_name,
                }
                self._broadcast_message({
                    'type': 'network_clipboard_set',
                    'source_id': self.device_name,
                    'operation': operation,
                })
            else:
                sock = self.server_socket
                if not sock:
                    self.file_transfer_error.emit("Nincs kapcsolat a szerverrel a küldéshez.")
                    return
                self._send_archive(sock, archive, dest_dir="")
        finally:
            if temp_archive_dir and self.settings['role'] != 'ado':
                shutil.rmtree(temp_archive_dir, ignore_errors=True)
            self._cancel_transfer.clear()

    def request_paste(self, dest_dir) -> None:
        self._cancel_transfer.clear()
        if self.settings['role'] == 'ado':
            if not self.network_file_clipboard or not self.network_file_clipboard.get('archive'):
                return
            try:
                archive_name = os.path.basename(self.network_file_clipboard['archive']) if self.network_file_clipboard else "archívum"
                self.update_progress_display.emit(0, f"Kibontás: {archive_name}")
                self._safe_extract_archive(self.network_file_clipboard['archive'], dest_dir)
                self.update_progress_display.emit(100, f"{archive_name}: Feldolgozás kész!")
            except Exception as e:
                self.file_transfer_error.emit(f"Kibontási hiba: {e}")
                return
            if self.network_file_clipboard.get('operation') == 'cut':
                src_id = self.network_file_clipboard.get('source_id')
                if src_id == self.device_name:
                    for pth in self.network_file_clipboard.get('paths', []):
                        try:
                            if os.path.isdir(pth):
                                shutil.rmtree(pth)
                            else:
                                os.remove(pth)
                        except Exception:
                            pass
                    self._clear_network_file_clipboard()
                else:
                    for s, name in self.client_infos.items():
                        if name == src_id:
                            self._send_message(s, {'type': 'delete_source', 'paths': self.network_file_clipboard.get('paths', [])})
                            break
                    self._clear_network_file_clipboard()
        else:
            sock = self.server_socket
            if sock:
                self._send_message(sock, {'type': 'paste_request', 'destination': dest_dir})
        self._cancel_transfer.clear()

