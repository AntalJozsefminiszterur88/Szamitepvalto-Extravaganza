# connection_utils.py
"""Networking related functions extracted from worker.py."""

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
    VK_NUMPAD0,
    VK_NUMPAD1,
    VK_NUMPAD2,
    VK_F12,
    VK_LSHIFT,
    VK_RSHIFT,
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
            "monitor_client start for %s cancel=%s",
            client_name,
            self._cancel_transfer.is_set(),
        )
        # send current clipboard to newly connected client
        if self.last_clipboard:
            try:
                self._send_message(sock, {'type': 'clipboard_text', 'text': self.last_clipboard})
            except Exception:
                pass
        upload_info = None

        try:
            last_log = time.time()
            while self._running:
                if time.time() - last_log >= 10:
                    logging.debug(
                        "monitor_client main loop. cancel=%s received=%d",
                        self._cancel_transfer.is_set(),
                        upload_info['received'] if upload_info else 0,
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
                            cmd = data.get('command')
                            if cmd == 'switch_elitedesk':
                                self.toggle_client_control('elitedesk', switch_monitor=True)
                            elif cmd == 'switch_laptop':
                                self.toggle_client_control('laptop', switch_monitor=False)
                            elif data.get('type') == 'clipboard_text':
                                text = data.get('text', '')
                                if text != self.last_clipboard:
                                    self._set_clipboard(text)
                                    self._broadcast_message(data, exclude=sock)
                            elif data.get('type') == 'paste_request':
                                dest = data.get('destination')
                                if self.network_file_clipboard and self.network_file_clipboard.get('archive'):
                                    self._cancel_transfer.clear()
                                    logging.debug("Cancel flag cleared for paste_request")
                                    self._send_archive(sock, self.network_file_clipboard['archive'], dest)
                            elif data.get('type') == 'file_metadata':
                                logging.info("[WORKER_DEBUG] Received 'upload_file_start' from client: %s (size: %s)", data.get('name'), data.get('size'))
                                temp_dir_for_download = self._get_temp_dir()
                                incoming_path = os.path.join(temp_dir_for_download, data['name'])
                                self._clear_network_file_clipboard()
                                try:
                                    incoming_file = open(incoming_path, 'wb')
                                except Exception as e:
                                    logging.error('Failed to open incoming file: %s', e, exc_info=True)
                                    self.file_transfer_error.emit(str(e))
                                    self._clear_network_file_clipboard()
                                    break
                                self.incoming_upload_started.emit(
                                    data.get('name'),
                                    data.get('size', 0)
                                )
                                logging.info("[WORKER_DEBUG] Emitting incoming_upload_started for: %s, size: %s", data.get('name'), data.get('size', 0))
                                self._cancel_transfer.clear()
                                logging.debug("Receiving upload, cancel flag cleared")
                                sock.settimeout(TRANSFER_TIMEOUT)
                                upload_info = {
                                    'file': incoming_file,
                                    'path': incoming_path,
                                    'temp_dir': temp_dir_for_download,
                                    'paths': data.get('paths', []),
                                    'operation': data.get('operation', 'copy'),
                                    'size': data.get('size', 0),
                                    'name': data.get('name'),
                                    'source_id': data.get('source_id', client_name),
                                    'received': 0,
                                    'start_time': time.time(),
                                }
                                last_percentage = -1
                                last_emit_time = time.time()
                                self.update_progress_display.emit(0, f"{upload_info['name']}: 0MB / {upload_info['size']/1024/1024:.1f}MB")
                            elif data.get('type') == 'file_chunk':
                                if upload_info:
                                    try:
                                        upload_info['file'].write(data['data'])
                                        upload_info['received'] += len(data['data'])
                                        if time.time() - last_emit_time >= PROGRESS_UPDATE_INTERVAL:
                                            current_percentage = int((upload_info['received'] / upload_info['size']) * 100) if upload_info['size'] > 0 else 0

                                            # --- Speed and ETR Calculation ---
                                            elapsed_time = time.time() - upload_info['start_time']
                                            speed_mbps = (upload_info['received'] / (1024*1024)) / elapsed_time if elapsed_time > 0 else 0
                                            remaining_bytes = upload_info['size'] - upload_info['received']
                                            etr_seconds = int(remaining_bytes / (speed_mbps * 1024 * 1024)) if speed_mbps > 0 else 0
                                            etr_str = time.strftime('%M:%S', time.gmtime(etr_seconds)) if etr_seconds < 3600 else time.strftime('%H:%M:%S', time.gmtime(etr_seconds))

                                            label = f"{upload_info['name']}: {upload_info['received']/1024/1024:.1f}MB / {upload_info['size']/1024/1024:.1f}MB\n"
                                            label += f"Sebesség: {speed_mbps:.1f} MB/s | Hátralévő idő: {etr_str}"

                                            self.update_progress_display.emit(current_percentage, label)
                                            last_percentage = current_percentage
                                            last_emit_time = time.time()
                                        if self._cancel_transfer.is_set():
                                            break
                                    except Exception as e:
                                        logging.error('Error writing chunk: %s', e, exc_info=True)
                                        self.file_transfer_error.emit(str(e))
                                        self._clear_network_file_clipboard()
                                        self._cancel_transfer.set()
                                        break
                            elif data.get('type') == 'file_end':
                                if upload_info:
                                    logging.info(
                                        "[WORKER_DEBUG] Received 'upload_file_end' for: %s",
                                        upload_info['name'],
                                    )
                                    upload_info['file'].close()
                                    final_label = f"{upload_info['name']}: Kész! ({upload_info['size']/1024/1024:.1f}MB)"
                                    self.update_progress_display.emit(100, final_label)
                                    self._clear_network_file_clipboard()
                                    self.network_file_clipboard = {
                                        'paths': upload_info['paths'],
                                        'operation': upload_info['operation'],
                                        'archive': upload_info['path'],
                                        'source_id': upload_info.get('source_id', client_name),
                                    }
                                    logging.debug(
                                        "Network file clipboard set: %s", self.network_file_clipboard
                                    )
                                    self._broadcast_message({
                                        'type': 'network_clipboard_set',
                                        'source_id': upload_info.get('source_id', client_name),
                                        'operation': upload_info['operation'],
                                    }, exclude=sock)
                                    upload_info = None
                                    sock.settimeout(1.0)
                                    self._cancel_transfer.clear()
                                    logging.debug("Upload finished, cancel flag cleared")
                            elif data.get('type') == 'paste_success':
                                src = data.get('source_id')
                                if (
                                    self.network_file_clipboard
                                    and self.network_file_clipboard.get('operation') == 'cut'
                                    and self.network_file_clipboard.get('source_id') == src
                                ):
                                    if src == self.device_name:
                                        for pth in self.network_file_clipboard.get('paths', []):
                                            try:
                                                if os.path.isdir(pth):
                                                    shutil.rmtree(pth)
                                                else:
                                                    os.remove(pth)
                                            except Exception as e:
                                                logging.error("Failed to delete %s: %s", pth, e)
                                        self._clear_network_file_clipboard()
                                    else:
                                        for s2, n2 in self.client_infos.items():
                                            if n2 == src:
                                                self._send_message(s2, {
                                                    'type': 'delete_source',
                                                    'paths': self.network_file_clipboard.get('paths', []),
                                                })
                                                break
                                        self._clear_network_file_clipboard()
                            if self._cancel_transfer.is_set():
                                if upload_info:
                                    try:
                                        upload_info['file'].close()
                                        os.remove(upload_info['path'])
                                    except Exception:
                                        pass
                                    upload_info = None
                                self._clear_network_file_clipboard()
                                sock.settimeout(1.0)
                                self._cancel_transfer.clear()
                                logging.debug("Upload canceled or finished, cancel flag cleared")
                        except Exception:
                            logging.warning("Hibas parancs a klienstol")
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
            if upload_info and upload_info.get('temp_dir'):
                logging.warning("Cleaning up incomplete download directory: %s", upload_info['temp_dir'])
                try:
                    upload_info['file'].close()
                except Exception:
                    pass
                shutil.rmtree(upload_info['temp_dir'], ignore_errors=True)
            upload_info = None
            self._cancel_transfer.clear()
            self._clear_network_file_clipboard()
            if sock in self.client_sockets:
                self.client_sockets.remove(sock)
            if sock in self.client_infos:
                del self.client_infos[sock]
            if sock == self.active_client:
                self.active_client = None
            if self.kvm_active and not self.client_sockets:
                self.deactivate_kvm(reason="all clients disconnected")
            logging.debug("monitor_client exit for %s", client_name)
    def run_client(self):
        """Run the client mode with persistent discovery and reconnect logic."""

        class ServiceListener:
            def __init__(self, worker):
                self.worker = worker

            def add_service(self, zc, type, name):
                info = zc.get_service_info(type, name)
                if info:
                    ip = socket.inet_ntoa(info.addresses[0])
                    if ip == self.worker.local_ip:
                        return  # ignore our own service
                    self.worker.last_server_ip = ip
                    settings_store = QSettings(ORG_NAME, APP_NAME)
                    settings_store.setValue('network/last_server_ip', ip)
                    logging.info(f"Adó szolgáltatás megtalálva a {ip} címen.")
                    self.worker.status_update.emit(f"Adó megtalálva: {ip}. Csatlakozás...")

            def update_service(self, zc, type, name):
                pass

            def remove_service(self, zc, type, name):
                logging.warning("Adó szolgáltatás eltűnt.")

        # Start Zeroconf discovery
        ServiceBrowser(self.zeroconf, SERVICE_TYPE, ServiceListener(self))
        self.status_update.emit("Vevő mód: Keresem az Adó szolgáltatást...")

        # Start background reconnect loop
        if not self.connection_thread:
            self.connection_thread = threading.Thread(
                target=self._reconnect_loop,
                daemon=True,
                name="ReconnectThread",
            )
            self.connection_thread.start()

        # Keep the method alive
        while self._running:
            time.sleep(0.5)

    def _reconnect_loop(self):
        """Background task that keeps the server connection alive."""
        while self._running:
            if not self.server_socket and self.last_server_ip:
                self.connect_to_server(self.last_server_ip, self.settings['port'])
            time.sleep(2)

    def connect_to_server(self, ip: str, port: int) -> None:
        """Attempt a single connection to the specified server."""
        mouse_controller = mouse.Controller()
        keyboard_controller = keyboard.Controller()
        pressed_keys = set()
        button_map = {
            'left': mouse.Button.left,
            'right': mouse.Button.right,
            'middle': mouse.Button.middle,
        }
        hk_listener = None
        hb_thread = None

        logging.debug(
            "connect_to_server attempting to connect to %s cancel=%s",
            ip,
            self._cancel_transfer.is_set(),
        )

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(5.0)
            logging.info(f"Connecting to {ip}:{port}")
            s.connect((ip, port))
            s.settimeout(None)
            self.server_socket = s
            self.server_ip = ip
            settings_store = QSettings(ORG_NAME, APP_NAME)
            settings_store.setValue('network/last_server_ip', ip)
            self.last_server_ip = ip
            incoming_info = None
            self._cancel_transfer.clear()
            logging.debug("Connected to server, cancel flag cleared")
            logging.debug("Cancel flag state at connect: %s", self._cancel_transfer.is_set())

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

            def heartbeat():
                nonlocal last_warning
                while self._running and self.server_socket is s:
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

            while self._running and self.server_socket is s:
                logging.debug(
                    "connect_to_server recv loop. cancel=%s received=%d",
                    self._cancel_transfer.is_set(),
                    incoming_info['received'] if incoming_info else 0,
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
                    elif event_type == 'file_metadata':
                        temp_dir_for_download = self._get_temp_dir()
                        incoming_tmp = os.path.join(temp_dir_for_download, data['name'])
                        self._cancel_transfer.clear()
                        logging.debug("Receiving file, cancel flag cleared")
                        try:
                            incoming_file = open(incoming_tmp, 'wb')
                        except Exception as e:
                            logging.error('Failed to open receive file: %s', e, exc_info=True)
                            self.file_transfer_error.emit(str(e))
                            break
                        s.settimeout(TRANSFER_TIMEOUT)
                        incoming_info = {
                            'path': incoming_tmp,
                            'dest': data['dest'],
                            'size': data['size'],
                            'name': data['name'],
                            'file': incoming_file,
                            'received': 0,
                            'source_id': data.get('source_id', self.device_name),
                            'temp_dir': temp_dir_for_download,
                            'start_time': time.time(),
                        }
                        last_percentage = -1
                        last_emit_time = time.time()
                        self.update_progress_display.emit(0, f"{incoming_info['name']}: 0MB / {incoming_info['size']/1024/1024:.1f}MB")
                    elif event_type == 'file_chunk':
                        if incoming_info:
                            try:
                                incoming_info['file'].write(data['data'])
                                incoming_info['received'] += len(data['data'])
                                current_percentage = int((incoming_info['received'] / incoming_info['size']) * 100) if incoming_info['size'] > 0 else 0
                                if current_percentage > last_percentage or time.time() - last_emit_time > PROGRESS_UPDATE_INTERVAL:
                                    elapsed_time = time.time() - incoming_info['start_time']
                                    speed_mbps = (incoming_info['received'] / (1024*1024)) / elapsed_time if elapsed_time > 0 else 0
                                    remaining_bytes = incoming_info['size'] - incoming_info['received']
                                    etr_seconds = int(remaining_bytes / (speed_mbps * 1024 * 1024)) if speed_mbps > 0 else 0
                                    etr_str = time.strftime('%M:%S', time.gmtime(etr_seconds)) if etr_seconds < 3600 else time.strftime('%H:%M:%S', time.gmtime(etr_seconds))

                                    label = f"{incoming_info['name']}: {incoming_info['received']/1024/1024:.1f}MB / {incoming_info['size']/1024/1024:.1f}MB\n"
                                    label += f"Sebesség: {speed_mbps:.1f} MB/s | Hátralévő idő: {etr_str}"
                                    self.update_progress_display.emit(current_percentage, label)
                                    last_percentage = current_percentage
                                    last_emit_time = time.time()
                                if self._cancel_transfer.is_set():
                                    break
                            except Exception as e:
                                logging.error('Receive error: %s', e, exc_info=True)
                                self.file_transfer_error.emit(str(e))
                                self._cancel_transfer.set()
                                break
                    elif event_type == 'file_end':
                        if incoming_info:
                            incoming_info['file'].close()
                            try:
                                self._safe_extract_archive(incoming_info['path'], incoming_info['dest'])
                            finally:
                                shutil.rmtree(incoming_info['temp_dir'], ignore_errors=True)
                            self._send_message(s, {'type': 'paste_success', 'source_id': incoming_info.get('source_id')})
                            s.settimeout(None)
                            final_label = f"{incoming_info['name']}: Kész! ({incoming_info['size']/1024/1024:.1f}MB)"
                            self.update_progress_display.emit(100, final_label)
                            incoming_info = None
                            self._cancel_transfer.clear()
                            logging.debug("Download finished, cancel flag cleared")
                    elif event_type == 'delete_source':
                        for pth in data.get('paths', []):
                            try:
                                if os.path.isdir(pth):
                                    shutil.rmtree(pth)
                                else:
                                    os.remove(pth)
                            except Exception as e:
                                logging.error('Failed to delete %s: %s', pth, e)
                except Exception:
                    logging.warning("Hibás adatcsomag")

                if self._cancel_transfer.is_set():
                    if incoming_info:
                        try:
                            incoming_info['file'].close()
                        except Exception:
                            pass
                        if incoming_info.get('temp_dir'):
                            shutil.rmtree(incoming_info['temp_dir'], ignore_errors=True)
                        incoming_info = None
                    s.settimeout(None)
                    self._cancel_transfer.clear()
                    logging.debug("Download canceled or finished, cancel flag cleared")

        except Exception as e:
            if self._running:
                logging.error(f"Csatlakozás sikertelen: {e}", exc_info=True)
                self.status_update.emit(f"Kapcsolat sikertelen: {e}")

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
            if incoming_info and incoming_info.get('temp_dir'):
                logging.warning(
                    "Cleaning up incomplete download directory: %s",
                    incoming_info['temp_dir'],
                )
                try:
                    incoming_info['file'].close()
                except Exception:
                    pass
                shutil.rmtree(incoming_info['temp_dir'], ignore_errors=True)
            incoming_info = None
            self._cancel_transfer.clear()
            self.server_socket = None
            logging.debug("connect_to_server loop ended")

