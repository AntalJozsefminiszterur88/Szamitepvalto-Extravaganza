import logging
import os
import queue
import socket
import struct
import threading
import time
import tempfile
import zipfile
import shutil

import msgpack
import pyperclip
from pynput import keyboard
from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser
from monitorcontrol import get_monitors
from PySide6.QtCore import QObject, Signal, QSettings

from .networking import accept_connections, KVMServiceListener
from ..input.input_streamer import InputStreamer
from ..input.input_receiver import InputReceiver
from ..input.hotkey_manager import HotkeyManager
from .file_sender import FileSender
from ..config import (
    SERVICE_TYPE,
    SERVICE_NAME_PREFIX,
    APP_NAME,
    ORG_NAME,
    TEMP_DIR_PARTS,
)


def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return socket.gethostbyname(socket.gethostname())


class KVMWorker(QObject):
    finished = Signal()
    status_update = Signal(str)
    update_progress_display = Signal(int, str)
    file_transfer_error = Signal(str)

    # ------------------------------------------------------------------
    def __init__(self, settings):
        super().__init__()
        self.settings = settings
        self._running = True
        self.kvm_active = False
        self.client_sockets = []
        self.client_infos = {}
        self.active_client = None
        self.server_socket = None
        self.zeroconf = Zeroconf()
        self.local_ip = get_local_ip()
        self.device_name = settings.get('device_name', socket.gethostname())
        self.last_server_ip = QSettings(ORG_NAME, APP_NAME).value('network/last_server_ip', None)
        self.hotkey_manager = HotkeyManager(self)
        self.input_streamer = InputStreamer(self)
        self.input_receiver = InputReceiver()
        self.file_sender = FileSender(self)
        self.clipboard_thread = None
        self.last_clipboard = ""
        self.network_file_clipboard = None
        self._cancel_transfer = threading.Event()
        self.switch_monitor = True
        self._reconnect_thread = None
        self.state_lock = threading.Lock()

    # ------------------------------------------------------------------
    def stop(self):
        self._running = False
        self.hotkey_manager.stop()
        self.input_streamer.stop()
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None

    # ------------------------------------------------------------------
    def run(self):
        logging.info("Worker started in %s mode", self.settings['role'])
        if self.settings['role'] == 'ado':
            self.run_server()
        else:
            self.run_client()
        self.finished.emit()

    # ------------------------------------------------------------------
    def run_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.server_socket.bind(('', self.settings['port']))
        self.server_socket.listen(5)

        info = ServiceInfo(
            SERVICE_TYPE,
            f"{SERVICE_NAME_PREFIX}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(self.local_ip)],
            port=self.settings['port'],
        )
        self.zeroconf.register_service(info)
        self.status_update.emit("Adó üzemmód: várakozás kliensekre")

        self.hotkey_manager.start()
        accept_thread = threading.Thread(
            target=accept_connections, args=(self, self.server_socket), daemon=True
        )
        accept_thread.start()

        while self._running:
            time.sleep(0.5)

        self.zeroconf.unregister_all_services()
        accept_thread.join(timeout=0.2)
        self.hotkey_manager.stop()
        try:
            self.server_socket.close()
        except Exception:
            pass
        self.server_socket = None

    # ------------------------------------------------------------------
    def run_client(self):
        listener = KVMServiceListener(self)
        ServiceBrowser(self.zeroconf, SERVICE_TYPE, listener)

        # Always keep a reconnect loop running so the client will
        # automatically try to re-establish the connection whenever it is
        # lost. The loop attempts to connect using the last known IP and
        # also relies on Zeroconf events when a server becomes available.
        self._start_reconnect_loop()

        self.status_update.emit("Vevő mód: Keresem az Adó szolgáltatást...")
        while self._running:
            time.sleep(1)

    # ------------------------------------------------------------------
    def _start_reconnect_loop(self):
        if self._reconnect_thread and self._reconnect_thread.is_alive():
            return
        self._reconnect_thread = threading.Thread(target=self._reconnect_loop, daemon=True)
        self._reconnect_thread.start()

    def _reconnect_loop(self):
        # Keep looping as long as the worker is running. The loop itself only
        # attempts to reconnect when there is no active connection. This way the
        # thread can remain alive and will automatically retry should the
        # connection drop at any time.
        while self._running:
            with self.state_lock:
                need_connect = self.server_socket is None and self.last_server_ip
            if need_connect:
                self.status_update.emit(
                    f"Újrakapcsolódás {self.last_server_ip}..."
                )
                self.connect_to_server(self.last_server_ip, self.settings['port'])
            for _ in range(5):
                if not self._running:
                    break
                with self.state_lock:
                    if self.server_socket:
                        break
                time.sleep(1)

    # ------------------------------------------------------------------
    def connect_to_server(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(5.0)
            s.connect((ip, port))
            s.settimeout(None)
        except Exception as e:
            logging.error("Connection failed: %s", e, exc_info=True)
            self.status_update.emit(f"Kapcsolódás sikertelen: {e}")
            if self._running:
                self._start_reconnect_loop()
            return

        with self.state_lock:
            self.server_socket = s
        QSettings(ORG_NAME, APP_NAME).setValue('network/last_server_ip', ip)
        self.last_server_ip = ip
        self._send_message(s, {'device_name': self.device_name})
        self.status_update.emit("Csatlakozva. Irányítás átvéve.")
        self.clipboard_thread = threading.Thread(target=self._clipboard_loop_client, args=(s,), daemon=True)
        self.clipboard_thread.start()
        self.switch_monitor = True
        # Avoid capturing local input on the client. The streamer is only
        # started when the host explicitly activates a KVM session.

        try:
            self._client_recv_loop(s)
        finally:
            self.input_streamer.stop()
            self.kvm_active = False
            if self.clipboard_thread:
                self.clipboard_thread.join(timeout=0.2)
            try:
                s.close()
            except Exception:
                pass
            with self.state_lock:
                self.server_socket = None
            self.status_update.emit("Kapcsolat megszűnt")
            if self._running:
                self._start_reconnect_loop()

    # ------------------------------------------------------------------
    def _client_recv_loop(self, sock):
        def recvall(s, n):
            data = b''
            while len(data) < n:
                try:
                    chunk = s.recv(n - len(data))
                except OSError:
                    return None
                if not chunk:
                    return None
                data += chunk
            return data

        incoming = None
        last_emit = time.time()
        while self._running and self.server_socket is sock:
            raw_len = recvall(sock, 4)
            if not raw_len:
                break
            msg_len = struct.unpack('!I', raw_len)[0]
            payload = recvall(sock, msg_len)
            if payload is None:
                break
            data = msgpack.unpackb(payload, raw=False)
            t = data.get('type')
            if t in ('move_relative', 'click', 'scroll', 'key'):
                self.input_receiver.process_event(data)
            elif t == 'clipboard_text':
                text = data.get('text', '')
                if text != self.last_clipboard:
                    self._set_clipboard(text)
            elif t == 'file_metadata':
                temp_dir = self._get_temp_dir()
                incoming = {
                    'path': os.path.join(temp_dir, data['name']),
                    'dest': data['dest'],
                    'size': data['size'],
                    'name': data['name'],
                    'file': open(os.path.join(temp_dir, data['name']), 'wb'),
                    'received': 0,
                    'start': time.time(),
                }
                self.update_progress_display.emit(0, f"{incoming['name']}: 0%")
            elif t == 'file_chunk':
                if incoming:
                    incoming['file'].write(data['data'])
                    incoming['received'] += len(data['data'])
                    if incoming['size']:
                        pct = int((incoming['received'] / incoming['size']) * 100)
                        if pct > 100:
                            pct = 100
                        if time.time() - last_emit >= 0.5:
                            self.update_progress_display.emit(pct, f"{incoming['name']}: {pct}%")
                            last_emit = time.time()
            elif t == 'file_end':
                if incoming:
                    incoming['file'].close()
                    try:
                        self._safe_extract_archive(incoming['path'], incoming['dest'])
                    finally:
                        shutil.rmtree(os.path.dirname(incoming['path']), ignore_errors=True)
                    self.update_progress_display.emit(100, f"{incoming['name']}: kész")
                    incoming = None
            elif t == 'transfer_canceled':
                if incoming:
                    incoming['file'].close()
                    shutil.rmtree(os.path.dirname(incoming['path']), ignore_errors=True)
                    incoming = None
            elif 'command' in data:
                cmd = data['command']
                if cmd == 'switch_elitedesk':
                    self.toggle_client_control('elitedesk', switch_monitor=True)
                elif cmd == 'switch_laptop':
                    self.toggle_client_control('laptop', switch_monitor=False)

    # ------------------------------------------------------------------
    def monitor_client(self, sock, addr):
        def recvall(s, n):
            data = b''
            while len(data) < n:
                try:
                    chunk = s.recv(n - len(data))
                except OSError:
                    return None
                if not chunk:
                    return None
                data += chunk
            return data

        client_name = str(addr)
        try:
            raw_len = recvall(sock, 4)
            if raw_len:
                msg_len = struct.unpack('!I', raw_len)[0]
                payload = recvall(sock, msg_len)
                if payload:
                    hello = msgpack.unpackb(payload, raw=False)
                    client_name = hello.get('device_name', client_name)
        except Exception:
            pass
        with self.state_lock:
            self.client_infos[sock] = client_name
        self.status_update.emit(f"Kliens csatlakozva: {client_name}")

        incoming = None
        last_emit = time.time()
        try:
            while self._running:
                raw = recvall(sock, 4)
                if not raw:
                    break
                msg_len = struct.unpack('!I', raw)[0]
                payload = recvall(sock, msg_len)
                if payload is None:
                    break
                data = msgpack.unpackb(payload, raw=False)
                if 'command' in data:
                    cmd = data['command']
                    if cmd == 'switch_elitedesk':
                        self.toggle_client_control('elitedesk', switch_monitor=True)
                    elif cmd == 'switch_laptop':
                        self.toggle_client_control('laptop', switch_monitor=False)
                    continue
                t = data.get('type')
                if t == 'clipboard_text':
                    text = data.get('text', '')
                    if text != self.last_clipboard:
                        self._set_clipboard(text)
                        self._broadcast_message(data, exclude=sock)
                elif t == 'paste_request':
                    dest = data.get('destination')
                    if self.network_file_clipboard and self.network_file_clipboard.get('archive'):
                        self._cancel_transfer.clear()
                        self.file_sender._send_archive(sock, self.network_file_clipboard['archive'], dest)
                elif t == 'file_metadata':
                    temp_dir = self._get_temp_dir()
                    incoming = {
                        'file': open(os.path.join(temp_dir, data['name']), 'wb'),
                        'path': os.path.join(temp_dir, data['name']),
                        'temp_dir': temp_dir,
                        'size': data.get('size', 0),
                        'name': data.get('name'),
                        'received': 0,
                    }
                    self.update_progress_display.emit(0, f"{incoming['name']}: 0%")
                elif t == 'file_chunk':
                    if incoming:
                        incoming['file'].write(data['data'])
                        incoming['received'] += len(data['data'])
                        if incoming['size']:
                            pct = int((incoming['received'] / incoming['size']) * 100)
                            if time.time() - last_emit >= 0.5:
                                self.update_progress_display.emit(pct, f"{incoming['name']}: {pct}%")
                                last_emit = time.time()
                elif t == 'file_end':
                    if incoming:
                        incoming['file'].close()
                        try:
                            self._safe_extract_archive(incoming['path'], data.get('dest', '.'))
                        finally:
                            shutil.rmtree(incoming['temp_dir'], ignore_errors=True)
                        self.update_progress_display.emit(100, f"{incoming['name']}: kész")
                        incoming = None
        finally:
            if incoming:
                incoming['file'].close()
                shutil.rmtree(incoming.get('temp_dir', ''), ignore_errors=True)
            self.handle_client_disconnection(sock)

    # ------------------------------------------------------------------
    def _send_message(self, sock, data):
        try:
            packed = msgpack.packb(data, use_bin_type=True)
            sock.sendall(struct.pack('!I', len(packed)) + packed)
            return True
        except Exception as e:
            logging.error("Failed to send message: %s", e)
            return False

    def _broadcast_message(self, data, exclude=None):
        packed = msgpack.packb(data, use_bin_type=True)
        for s in list(self.client_sockets):
            if s is exclude:
                continue
            try:
                s.sendall(struct.pack('!I', len(packed)) + packed)
            except Exception:
                pass

    # ------------------------------------------------------------------
    def _clipboard_loop_server(self):
        while self._running:
            text = self._get_clipboard()
            if text != self.last_clipboard:
                self.last_clipboard = text
                self._broadcast_message({'type': 'clipboard_text', 'text': text})
            time.sleep(0.5)

    def _clipboard_loop_client(self, sock):
        while self._running and self.server_socket is sock:
            text = self._get_clipboard()
            if text != self.last_clipboard:
                self.last_clipboard = text
                self._send_message(sock, {'type': 'clipboard_text', 'text': text})
            time.sleep(0.5)

    # ------------------------------------------------------------------
    def _get_clipboard(self):
        try:
            return pyperclip.paste()
        except Exception:
            return self.last_clipboard

    def _set_clipboard(self, text):
        try:
            pyperclip.copy(text)
            self.last_clipboard = text
        except Exception:
            pass

    # ------------------------------------------------------------------
    def _get_temp_dir(self):
        base = self.settings.get('temp_path') or tempfile.gettempdir()
        root = os.path.join(base, *TEMP_DIR_PARTS)
        os.makedirs(root, exist_ok=True)
        return tempfile.mkdtemp(dir=root)

    def _safe_extract_archive(self, archive_path, dest_dir):
        temp_extract = tempfile.mkdtemp(dir=dest_dir)
        with zipfile.ZipFile(archive_path, 'r') as zf:
            zf.extractall(temp_extract)
        for name in os.listdir(temp_extract):
            src = os.path.join(temp_extract, name)
            target = os.path.join(dest_dir, name)
            base, ext = os.path.splitext(target)
            i = 2
            while os.path.exists(target):
                target = f"{base} ({i}){ext}"
                i += 1
            shutil.move(src, target)
        shutil.rmtree(temp_extract, ignore_errors=True)

    def _clear_network_file_clipboard(self):
        if self.network_file_clipboard and self.network_file_clipboard.get('archive'):
            try:
                os.remove(self.network_file_clipboard['archive'])
            except Exception:
                pass
        self.network_file_clipboard = None

    # ------------------------------------------------------------------
    def share_files(self, paths, operation='copy'):
        if self.settings['role'] != 'ado':
            sock = self.server_socket
            if not sock:
                self.file_transfer_error.emit('Nincs kapcsolat a szerverrel a küldéshez.')
                return
            self.file_sender.send_files(paths, operation, sock)
            return

        archive = self.file_sender._create_archive(paths)
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

    def request_paste(self, dest_dir):
        if self.settings['role'] == 'ado':
            if not self.network_file_clipboard or not self.network_file_clipboard.get('archive'):
                return
            self.update_progress_display.emit(0, 'Kibontás...')
            self._safe_extract_archive(self.network_file_clipboard['archive'], dest_dir)
            self.update_progress_display.emit(100, 'Kibontás kész')
        else:
            if not self.server_socket:
                self.file_transfer_error.emit('Nincs kapcsolat a szerverrel a fogadáshoz.')
                return
            self._send_message(self.server_socket, {'type': 'paste_request', 'destination': dest_dir})

    def cancel_file_transfer(self):
        self._cancel_transfer.set()

    # ------------------------------------------------------------------
    def toggle_client_control(self, client_name, switch_monitor=True, release_keys=True):
        if self.settings['role'] != 'ado':
            return
        with self.state_lock:
            for sock, name in self.client_infos.items():
                if name == client_name:
                    self.active_client = sock
                    break
            else:
                sock = None
        if sock is None:
            self.status_update.emit(f'Nincs ilyen kliens: {client_name}')
            return
        self.switch_monitor = switch_monitor
        with self.state_lock:
            start_stream = not self.kvm_active
            self.kvm_active = True
        if start_stream:
            self.input_streamer.start()
        self.status_update.emit(f'Irányítás átvéve: {client_name}')

    def deactivate_kvm(self, switch_monitor=True, reason=''):
        with self.state_lock:
            if not self.kvm_active:
                return
            self.kvm_active = False
        self.input_streamer.stop()
        self.input_receiver.release_pressed_keys()
        if switch_monitor:
            try:
                with list(get_monitors())[0] as mon:
                    mon.set_input_source(self.settings['monitor_codes']['host'])
            except Exception as e:
                logging.error("Monitor switch failed: %s", e)
        if reason:
            logging.info("KVM deactivated: %s", reason)
        self.status_update.emit('Irányítás átadva a hosztnak')

    # ------------------------------------------------------------------
    def handle_client_disconnection(self, sock):
        """Clean up after an unexpected client disconnect."""
        try:
            sock.close()
        except Exception:
            pass
        with self.state_lock:
            if sock in self.client_sockets:
                self.client_sockets.remove(sock)
            name = self.client_infos.pop(sock, 'ismeretlen kliens')
            was_active = sock == self.active_client
            if was_active:
                self.active_client = None
        if was_active:
            self.deactivate_kvm(
                switch_monitor=self.switch_monitor, reason='client_disconnect'
            )
        self.status_update.emit(f"Kliens bontva: {name}")
