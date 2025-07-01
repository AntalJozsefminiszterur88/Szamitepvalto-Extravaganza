# connection_utils.py - FINAL STABILIZED VERSION
# Fixes client-side race condition on connect and centralizes client-side hotkey listener.

import socket
import time
import threading
import logging
import struct
import os
import shutil
from typing import Optional

import msgpack
from pynput import mouse, keyboard
from zeroconf import ServiceInfo, ServiceBrowser
from PySide6.QtCore import QSettings

from config import (
    SERVICE_TYPE,
    SERVICE_NAME_PREFIX,
    APP_NAME,
    ORG_NAME,
    VK_F12,
    VK_LSHIFT,
    VK_RSHIFT,
)
from file_transfer import (
    FILE_CHUNK_SIZE,
    TRANSFER_TIMEOUT,
    PROGRESS_UPDATE_INTERVAL,
)


class ConnectionMixin:
    """Mixin class providing server/client connection logic."""
    __slots__ = ()

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
            addresses=[socket.inet_aton(self.local_ip)],
            port=self.settings['port']
        )
        self.zeroconf.register_service(info)
        self.status_update.emit(
            "Adó szolgáltatás regisztrálva. Gyorsbillentyűk aktívak."
        )
        logging.info("Zeroconf szolgáltatás regisztrálva.")


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

                    logging.info(f"Kliens csatlakozva: {addr}.")
                    self.status_update.emit(f"Kliens csatlakozva: {addr}. Várakozás gyorsbillentyűre.")

                    threading.Thread(target=self.monitor_client, args=(client_sock, addr), daemon=True, name=f"ClientMon-{addr[0]}").start()
        except Exception as e:
            if self._running and not str(e).startswith('[WinError 10038]'):
                logging.error(f"Hiba a kliens fogadásakor: {e}", exc_info=True)

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
            logging.info(f"Kliens azonosítva: {client_name} ({addr})")

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

                        data = msgpack.unpackb(payload, raw=False)
                        cmd = data.get('command')
                        if cmd == 'switch_elitedesk':
                            self.toggle_client_control('elitedesk', switch_monitor=True)
                        elif cmd == 'switch_laptop':
                            self.toggle_client_control('laptop', switch_monitor=False)
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
                        # ... other file transfer types ...
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
                                'file': incoming_file, 'path': incoming_path, 'temp_dir': temp_dir_for_download,
                                'size': data.get('size', 0), 'name': data.get('name'), 'received': 0, 'start_time': time.time(),
                                'paths': data.get('paths', []), 'operation': data.get('operation', 'copy'),
                                'source_id': data.get('source_id', client_name),
                            }
                        elif data.get('type') == 'file_chunk':
                            if upload_info:
                                try:
                                    upload_info['file'].write(data['data'])
                                    upload_info['received'] += len(data['data'])
                                    # Progress update logic
                                except Exception as e:
                                    self.file_transfer_error.emit(str(e))
                                    self._cancel_transfer.set()
                                    break
                        elif data.get('type') == 'file_end':
                            if upload_info:
                                upload_info['file'].close()
                                self.network_file_clipboard = {
                                    'paths': upload_info['paths'], 'operation': upload_info['operation'],
                                    'archive': upload_info['path'], 'source_id': upload_info.get('source_id', client_name),
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
                            if self.network_file_clipboard and self.network_file_clipboard.get('operation') == 'cut' and self.network_file_clipboard.get('source_id') == src:
                                # Cut logic
                                self._clear_network_file_clipboard()

                except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
                    break
                except Exception:
                    continue

        finally:
            if upload_info and upload_info.get('temp_dir'):
                shutil.rmtree(upload_info['temp_dir'], ignore_errors=True)
            self._remove_client(sock, "monitor_client finished")

    def run_client(self):
        class ServiceListener:
            def __init__(self, worker): self.worker = worker
            def add_service(self, zc, type, name):
                info = zc.get_service_info(type, name)
                if info and socket.inet_ntoa(info.addresses[0]) != self.worker.local_ip:
                    ip = socket.inet_ntoa(info.addresses[0])
                    if not self.worker.server_socket:
                        self.worker.last_server_ip = ip
                        QSettings(ORG_NAME, APP_NAME).setValue('network/last_server_ip', ip)
                        self.worker.status_update.emit(f"Adó megtalálva: {ip}. Csatlakozás...")
                        threading.Thread(target=self.worker.connect_to_server, args=(ip, self.worker.settings['port']), daemon=True).start()
            def update_service(self, zc, type, name): pass
            def remove_service(self, zc, type, name):
                 if self.worker.server_ip == name.split('.')[0]:
                     self.worker.server_ip = None
                     self.worker.status_update.emit("Adó szolgáltatás eltűnt. Keresés...")

        ServiceBrowser(self.zeroconf, SERVICE_TYPE, ServiceListener(self))
        self.status_update.emit("Vevő mód: Keresem az Adó szolgáltatást...")
        self.connection_thread = threading.Thread(target=self._reconnect_loop, daemon=True, name="ReconnectLoop")
        self.connection_thread.start()
        while self._running:
            time.sleep(0.5)

    def _reconnect_loop(self):
        while self._running:
            if not self.server_socket and self.last_server_ip:
                self.connect_to_server(self.last_server_ip, self.settings['port'])
            time.sleep(3)

    def connect_to_server(self, ip: str, port: int) -> None:
        mouse_controller = mouse.Controller()
        keyboard_controller = keyboard.Controller()
        pressed_keys = set()
        button_map = { 'left': mouse.Button.left, 'right': mouse.Button.right, 'middle': mouse.Button.middle }
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

            # STABILITY FIX: Short delay before starting threads and loops
            time.sleep(0.2)

            self.clipboard_thread = threading.Thread(target=self._clipboard_loop_client, args=(s,), daemon=True, name="ClipboardCli")
            self.clipboard_thread.start()
            self.status_update.emit("Csatlakozva. Irányítás átvéve.")

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

            # Client-side hotkey listener for remote switching
            hk_listener = keyboard.Listener(on_press=hk_press, on_release=hk_release)
            hk_listener.start()

            def recv_all(sock, n):
                data = b''
                while len(data) < n:
                    chunk = sock.recv(n - len(data))
                    if not chunk: return None
                    data += chunk
                return data

            while self._running and self.server_socket is s:
                raw_len = recv_all(s, 4)
                if not raw_len: break
                msg_len = struct.unpack('!I', raw_len)[0]
                payload = recv_all(s, msg_len)
                if payload is None: break

                data = msgpack.unpackb(payload, raw=False)
                event_type = data.get('type')
                if event_type == 'move_relative':
                    mouse_controller.move(data['dx'], data['dy'])
                elif event_type == 'click':
                    b = button_map.get(data['button'])
                    if b: (mouse_controller.press if data['pressed'] else mouse_controller.release)(b)
                elif event_type == 'scroll':
                    mouse_controller.scroll(data['dx'], data['dy'])
                elif event_type == 'key':
                    k_info, k_type, pressed = data['key'], data['key_type'], data['pressed']
                    if k_type == 'char': k_press = k_info
                    elif k_type == 'special': k_press = getattr(keyboard.Key, k_info, None)
                    elif k_type == 'vk': k_press = keyboard.KeyCode.from_vk(int(k_info))
                    else: k_press = None
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
                # ... other file transfer events ...

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            if self._running:
                self.status_update.emit(f"Kapcsolat sikertelen: {ip}")
        except Exception as e:
            if self._running:
                logging.error(f"Váratlan kliens hiba: {e}", exc_info=True)
                self.status_update.emit(f"Kliens hiba: {e}")
        finally:
            if s:
                try: s.close()
                except: pass
            if hk_listener:
                hk_listener.stop()
            for k in list(pressed_keys):
                try: keyboard_controller.release(k)
                except: pass
            self.release_hotkey_keys()
            if self.server_socket is s:
                self.server_socket = None
