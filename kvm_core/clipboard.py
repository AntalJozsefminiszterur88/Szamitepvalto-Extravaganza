import io
import functools
import logging
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import zipfile
from typing import Any, Callable, Optional

import pyperclip
from PIL import Image, ImageGrab
import win32clipboard
from PySide6.QtCore import QCoreApplication, QObject, Qt, QThread, QTimer, Slot
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QPushButton,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

from config.constants import BRAND_NAME, CLIPBOARD_PORT, CLIPBOARD_PROTOCOL_ID

CLIPBOARD_CLEANUP_INTERVAL_SECONDS = 24 * 60 * 60

def _resolve_cache_dir() -> str:
    base_dir = (
        os.environ.get("LOCALAPPDATA")
        or os.environ.get("APPDATA")
        or os.path.expanduser("~")
    )
    return os.path.join(base_dir, BRAND_NAME, "Szamitepvalto-Extravaganza", "ClipboardCache")


DEFAULT_CACHE_DIR = _resolve_cache_dir()
RECONNECT_DELAY = 3

MAX_RAM_ZIP_SIZE = 500 * 1024 * 1024

TYPE_HANDSHAKE = 0
TYPE_TEXT = 1
TYPE_IMAGE = 2
TYPE_FILES = 3


def _enable_keepalive(sock: socket.socket) -> None:
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        return

    if hasattr(socket, "SIO_KEEPALIVE_VALS"):
        try:
            sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 10_000, 3_000))
        except OSError:
            pass

    for option_name, value in (
        ("TCP_KEEPIDLE", 10),
        ("TCP_KEEPINTVL", 3),
        ("TCP_KEEPCNT", 3),
        ("TCP_KEEPALIVE", 10),
    ):
        option = getattr(socket, option_name, None)
        if option is None:
            continue
        try:
            sock.setsockopt(socket.IPPROTO_TCP, option, value)
        except OSError:
            pass


class FloatingProgress(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowFlags(
            Qt.Tool
            | Qt.FramelessWindowHint
            | Qt.WindowStaysOnTopHint
            | Qt.WindowDoesNotAcceptFocus
        )
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setFixedSize(300, 80)

        container = QWidget(self)
        container.setStyleSheet("background-color: #333333; border-radius: 6px;")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 10, 12, 10)

        self.label = QLabel("Feldolgozás...")
        self.label.setStyleSheet("color: white; font-size: 10pt;")
        layout.addWidget(self.label)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        layout.addWidget(self.progress)

        container.setGeometry(0, 0, 300, 80)
        self._position_window()

    def _position_window(self) -> None:
        screen = QGuiApplication.primaryScreen()
        if not screen:
            return
        geometry = screen.availableGeometry()
        x = geometry.right() - self.width() - 20
        y = geometry.bottom() - self.height() - 60
        self.move(x, y)

    def update_text(self, text: str) -> None:
        self.label.setText(text)

    def stop_and_close(self) -> None:
        self.close()


class ConfirmDialog(QDialog):
    def __init__(self, file_list: list[str], total_size_mb: float) -> None:
        super().__init__()
        self.setWindowTitle("Megerősítés")
        self.setModal(True)
        self.resize(500, 400)
        self.result = False

        layout = QVBoxLayout(self)
        header = QLabel("ADAT FOGADÁSA")
        header.setStyleSheet("color: #2196F3; font-size: 14pt; font-weight: bold;")
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)

        info_text = f"Méret: {total_size_mb:.2f} MB\nFájlok száma: {len(file_list)} db"
        info_label = QLabel(info_text)
        info_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(info_label)

        list_widget = QListWidget()
        for path in file_list:
            list_widget.addItem(os.path.basename(path))
        layout.addWidget(list_widget)

        button_layout = QHBoxLayout()
        cancel_button = QPushButton("ELVETÉS")
        cancel_button.setStyleSheet("background-color: #f44336; color: white; padding: 6px 12px;")
        cancel_button.clicked.connect(self._on_cancel)
        ok_button = QPushButton("BEILLESZTÉS")
        ok_button.setStyleSheet("background-color: #4CAF50; color: white; padding: 6px 12px;")
        ok_button.clicked.connect(self._on_ok)
        button_layout.addWidget(cancel_button)
        button_layout.addWidget(ok_button)
        layout.addLayout(button_layout)

    def _on_ok(self) -> None:
        self.result = True
        self.accept()

    def _on_cancel(self) -> None:
        self.result = False
        self.reject()


class ClipboardUiHelper(QObject):
    def __init__(self) -> None:
        super().__init__()
        self.progress_win: Optional[FloatingProgress] = None

    @Slot(object)
    def show_progress(self, text: object) -> None:
        message = str(text)
        if self.progress_win:
            self.progress_win.update_text(message)
            return
        self.progress_win = FloatingProgress()
        self.progress_win.update_text(message)
        self.progress_win.show()

    @Slot()
    def hide_progress(self) -> None:
        if not self.progress_win:
            return
        self.progress_win.stop_and_close()
        self.progress_win = None

    @Slot(object, object, object)
    def confirm_files(self, file_list: object, total_size_mb: object, result_container: object) -> None:
        files = list(file_list) if isinstance(file_list, (list, tuple)) else []
        size_mb = float(total_size_mb) if total_size_mb is not None else 0.0
        dialog = ConfirmDialog(files, size_mb)
        dialog.exec()
        if isinstance(result_container, dict):
            result_container["result"] = dialog.result
            event = result_container.get("event")
            if isinstance(event, threading.Event):
                event.set()


class ClipboardManager:
    """Clipboard synchronization via dedicated TCP socket connections."""

    def __init__(self, *, role: str, get_server_ip: Optional[Callable[[], Optional[str]]] = None) -> None:
        self.role = role
        self.is_server = role == "ado"
        self._get_server_ip = get_server_ip or (lambda: None)

        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._monitor_thread: Optional[threading.Thread] = None

        self.server_socket: Optional[socket.socket] = None
        self.client_socket: Optional[socket.socket] = None
        self.clients: list[socket.socket] = []
        self._clients_lock = threading.Lock()

        self.ignore_next_change = False
        self.is_internal_update = False

        self.clipboard_lock = threading.Lock()
        self.last_text_content = ""
        self.last_image_hash: Optional[int] = None
        self.last_file_list_hash: Optional[int] = None

        self._ui_helper: Optional[ClipboardUiHelper] = None
        app_instance = QCoreApplication.instance()
        if app_instance:
            self._ui_helper = ClipboardUiHelper()
            self._ui_helper.moveToThread(app_instance.thread())

        self.cache_dir = DEFAULT_CACHE_DIR
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
        except PermissionError:
            fallback_dir = os.path.join(
                tempfile.gettempdir(),
                "Szamitepvalto-Extravaganza",
                "ClipboardCache",
            )
            os.makedirs(fallback_dir, exist_ok=True)
            logging.warning(
                "Clipboard cache dir %s is not writable, using %s instead.",
                self.cache_dir,
                fallback_dir,
            )
            self.cache_dir = fallback_dir

    @property
    def thread(self) -> Optional[threading.Thread]:
        return self._monitor_thread

    @property
    def storage_dir(self) -> Optional[str]:
        return self.cache_dir

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        logging.info("Starting clipboard sync (%s)", "server" if self.is_server else "client")
        self._running.set()
        self.flush_startup_clipboard()
        self.clean_cache_directory()

        self._monitor_thread = threading.Thread(
            target=self.clipboard_monitor_loop,
            daemon=True,
            name="ClipboardMonitor",
        )
        self._monitor_thread.start()

        if self.is_server:
            target = self.start_server
            name = "ClipboardServer"
        else:
            target = self.start_client_loop
            name = "ClipboardClient"

        self._thread = threading.Thread(target=target, daemon=True, name=name)
        self._thread.start()

    def stop(self) -> None:
        logging.info("Stopping ClipboardManager...")
        self._running.clear()
        self._close_sockets()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1)
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=1)
        self._thread = None
        self._monitor_thread = None
        self._invoke_ui("hide_progress")
        logging.info("ClipboardManager stopped.")

    def handle_network_message(self, peer: Any, data: dict) -> bool:
        return False

    def ensure_storage_cleanup(self, *, force: bool = False) -> None:
        self.clean_cache_directory()

    def _invoke_ui(self, method: str, *args: object) -> None:
        if not self._ui_helper:
            return
        helper = self._ui_helper
        if QThread.currentThread() == helper.thread():
            getattr(helper, method)(*args)
            return
        QTimer.singleShot(
            0,
            helper,
            functools.partial(getattr(helper, method), *args),
        )

    def show_progress(self, text: str) -> None:
        self._invoke_ui("show_progress", text)

    def hide_progress(self) -> None:
        self._invoke_ui("hide_progress")

    def confirm_files(self, file_list: list[str], total_size_mb: float) -> bool:
        if not self._ui_helper:
            return True
        result_container = {"event": threading.Event(), "result": False}
        self._invoke_ui("confirm_files", file_list, total_size_mb, result_container)
        event = result_container["event"]
        event.wait()
        return bool(result_container.get("result"))

    def flush_startup_clipboard(self) -> None:
        logging.info("Clipboard startup snapshot...")
        try:
            self.last_text_content = pyperclip.paste()
            content = ImageGrab.grabclipboard()
            if isinstance(content, list):
                self.last_file_list_hash = hash("".join(content))
            elif isinstance(content, Image.Image):
                buf = io.BytesIO()
                content.save(buf, format="PNG")
                self.last_image_hash = hash(buf.getvalue())
        except Exception:
            pass

    def send_message(self, sock: socket.socket, data_bytes: bytes, msg_type: int) -> None:
        type_header = struct.pack("B", msg_type)
        len_header = struct.pack(">I", len(data_bytes))
        sock.sendall(type_header + len_header + data_bytes)

    def receive_message(self, sock: socket.socket) -> tuple[Optional[int], Optional[bytes]]:
        try:
            try:
                type_data = sock.recv(1)
            except socket.timeout:
                return None, None
            if not type_data:
                return None, b""
            msg_type = struct.unpack("B", type_data)[0]

            try:
                len_data = sock.recv(4)
            except socket.timeout:
                return None, None
            if not len_data:
                return None, b""
            msg_len = struct.unpack(">I", len_data)[0]

            data = b""
            while len(data) < msg_len:
                try:
                    chunk = sock.recv(min(1024 * 1024, msg_len - len(data)))
                except socket.timeout:
                    return None, None
                if not chunk:
                    return None, b""
                data += chunk
            return msg_type, data
        except (ConnectionResetError, BrokenPipeError):
            return None, b""
        except Exception:
            return None, b""

    def process_incoming_data(self, msg_type: int, data: bytes) -> None:
        try:
            self.is_internal_update = True

            if msg_type == TYPE_TEXT:
                text = data.decode("utf-8")
                logging.info("Szöveg érkezett: %s kar.", len(text))
                with self.clipboard_lock:
                    self.last_text_content = text
                    pyperclip.copy(text)

            elif msg_type == TYPE_IMAGE:
                logging.info("Kép érkezett: %s bájt.", len(data))
                self.safe_set_clipboard_image(data)

            elif msg_type == TYPE_FILES:
                self.show_progress("Fogadás és kicsomagolás...")
                logging.info("Zip érkezett (%0.1f KB).", len(data) / 1024)
                file_paths = self.unpack_and_cache_files(data)

                if file_paths:
                    total_size = sum(os.path.getsize(f) for f in file_paths)
                    size_mb = total_size / (1024 * 1024)
                    count = len(file_paths)

                    self.hide_progress()
                    logging.info(
                        "Beillesztés folyamatban (%s fájl, %0.1f MB)...",
                        count,
                        size_mb,
                    )
                    self.set_clipboard_files_via_powershell(file_paths)
        except Exception as exc:
            logging.exception("Clipboard processing error: %s", exc)
            self.hide_progress()
            self.is_internal_update = False

    def clean_cache_directory(self) -> None:
        try:
            for filename in os.listdir(self.cache_dir):
                path = os.path.join(self.cache_dir, filename)
                try:
                    if os.path.isfile(path):
                        os.unlink(path)
                    elif os.path.isdir(path):
                        shutil.rmtree(path)
                except Exception:
                    pass
        except Exception:
            pass

    def pack_files_to_zip(self, file_paths: list[str]) -> Optional[bytes]:
        try:
            self.show_progress("Tömörítés...")
            mem_zip = io.BytesIO()
            with zipfile.ZipFile(mem_zip, "w", zipfile.ZIP_DEFLATED) as zf:
                for file_path in file_paths:
                    if os.path.exists(file_path) and os.path.isfile(file_path):
                        zf.write(file_path, os.path.basename(file_path))
            return mem_zip.getvalue()
        except Exception as exc:
            logging.error("Zip hiba: %s", exc)
            return None
        finally:
            self.hide_progress()

    def unpack_and_cache_files(self, zip_bytes: bytes) -> list[str]:
        self.clean_cache_directory()
        try:
            mem_zip = io.BytesIO(zip_bytes)
            with zipfile.ZipFile(mem_zip, "r") as zf:
                zf.extractall(self.cache_dir)
                extracted = [
                    os.path.abspath(os.path.normpath(os.path.join(self.cache_dir, name)))
                    for name in zf.namelist()
                ]
            return extracted
        except Exception as exc:
            logging.error("Unzip hiba: %s", exc)
            return []

    def start_server(self) -> None:
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _enable_keepalive(self.server_socket)
        self.server_socket.settimeout(1.0)
        try:
            self.server_socket.bind(("0.0.0.0", CLIPBOARD_PORT))
            self.server_socket.listen(5)
            logging.info("Clipboard server active (port: %s)", CLIPBOARD_PORT)

            while self._running.is_set():
                try:
                    client_sock, addr = self.server_socket.accept()
                    try:
                        _enable_keepalive(client_sock)
                        client_sock.settimeout(1.0)
                        msg_type, data = self.receive_message(client_sock)
                        if msg_type == TYPE_HANDSHAKE and data == CLIPBOARD_PROTOCOL_ID:
                            logging.info("Clipboard client connected: %s", addr)
                            with self._clients_lock:
                                self.clients.append(client_sock)
                            threading.Thread(
                                target=self.handle_client,
                                args=(client_sock,),
                                daemon=True,
                            ).start()
                        else:
                            client_sock.close()
                    except Exception:
                        client_sock.close()
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception as exc:
            logging.error("Clipboard server error: %s", exc)

    def handle_client(self, client_sock: socket.socket) -> None:
        try:
            while self._running.is_set():
                msg_type, data = self.receive_message(client_sock)
                if msg_type is None and data is None:
                    continue
                if msg_type is None and data == b"":
                    break
                if data is not None and msg_type is not None:
                    self.process_incoming_data(msg_type, data)
                    self.broadcast_data(data, msg_type, sender_socket=client_sock)
                else:
                    break
        except Exception:
            pass
        finally:
            with self._clients_lock:
                if client_sock in self.clients:
                    self.clients.remove(client_sock)
            try:
                client_sock.close()
            except Exception:
                pass

    def broadcast_data(self, data_bytes: bytes, msg_type: int, sender_socket: Optional[socket.socket] = None) -> None:
        dead_clients: list[socket.socket] = []
        with self._clients_lock:
            clients = list(self.clients)
        for client in clients:
            if client != sender_socket:
                try:
                    self.send_message(client, data_bytes, msg_type)
                except Exception:
                    dead_clients.append(client)
        if dead_clients:
            with self._clients_lock:
                for dead in dead_clients:
                    if dead in self.clients:
                        self.clients.remove(dead)

    def start_client_loop(self) -> None:
        while self._running.is_set():
            try:
                server_ip = self._get_server_ip()
                if not server_ip:
                    time.sleep(RECONNECT_DELAY)
                    continue
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                _enable_keepalive(self.client_socket)
                self.client_socket.settimeout(1.0)
                self.client_socket.connect((server_ip, CLIPBOARD_PORT))
                self.send_message(self.client_socket, CLIPBOARD_PROTOCOL_ID, TYPE_HANDSHAKE)
                logging.info("Clipboard server connected (%s)", server_ip)
                while self._running.is_set():
                    msg_type, data = self.receive_message(self.client_socket)
                    if msg_type is None and data is None:
                        continue
                    if msg_type is None and data == b"":
                        break
                    if data is not None and msg_type is not None:
                        self.process_incoming_data(msg_type, data)
                    else:
                        break
            except Exception:
                pass
            finally:
                self._close_client_socket()
            if self._running.is_set():
                time.sleep(RECONNECT_DELAY)

    def clipboard_monitor_loop(self) -> None:
        while self._running.is_set():
            time.sleep(1.0)

            if self.is_internal_update:
                self.is_internal_update = False
                continue

            if self.ignore_next_change:
                self.ignore_next_change = False
                continue

            if not self.clipboard_lock.acquire(blocking=False):
                continue

            try:
                try:
                    curr_text = pyperclip.paste()
                    if curr_text and curr_text != self.last_text_content:
                        if not os.path.exists(curr_text):
                            self.last_text_content = curr_text
                            logging.info("Szöveg másolás.")
                            self.send_data_out(curr_text.encode("utf-8"), TYPE_TEXT)
                            continue
                except Exception:
                    pass

                try:
                    content = ImageGrab.grabclipboard()
                    if isinstance(content, list) and len(content) > 0:
                        hash_str = "".join(content)
                        if self.last_file_list_hash != hash(hash_str):
                            self.last_file_list_hash = hash(hash_str)

                            total_size = sum(
                                os.path.getsize(f) for f in content if os.path.exists(f)
                            )
                            size_mb = total_size / (1024 * 1024)

                            if total_size > MAX_RAM_ZIP_SIZE:
                                logging.warning(
                                    "⚠️ TÚL NAGY FÁJL (%0.1f MB)! A küldés megszakítva.",
                                    size_mb,
                                )
                            else:
                                logging.info("Fájlok észlelve (%s db).", len(content))
                                zip_data = self.pack_files_to_zip(content)
                                if zip_data:
                                    logging.info(
                                        "Küldés (%0.1f KB)...", len(zip_data) / 1024
                                    )
                                    self.send_data_out(zip_data, TYPE_FILES)
                                    self.hide_progress()

                    elif isinstance(content, Image.Image):
                        buf = io.BytesIO()
                        content.save(buf, format="PNG")
                        img_bytes = buf.getvalue()
                        if self.last_image_hash != hash(img_bytes):
                            self.last_image_hash = hash(img_bytes)
                            logging.info("Kép másolás.")
                            self.send_data_out(img_bytes, TYPE_IMAGE)
                except Exception:
                    self.hide_progress()
            finally:
                if self.clipboard_lock.locked():
                    self.clipboard_lock.release()

    def send_data_out(self, data_bytes: bytes, msg_type: int) -> None:
        try:
            if self.is_server:
                self.broadcast_data(data_bytes, msg_type)
            elif self.client_socket:
                self.send_message(self.client_socket, data_bytes, msg_type)
        except Exception:
            pass

    def set_clipboard_files_via_powershell(self, file_paths: list[str]) -> None:
        with self.clipboard_lock:
            self.is_internal_update = True
            try:
                ps_script = [
                    "Add-Type -AssemblyName System.Windows.Forms",
                    "$files = New-Object System.Collections.Specialized.StringCollection",
                ]
                for path in file_paths:
                    clean_path = os.path.abspath(path)
                    ps_script.append(f'$files.Add("{clean_path}")')
                ps_script.append("[System.Windows.Forms.Clipboard]::SetFileDropList($files)")
                full_command = "; ".join(ps_script)
                subprocess.run(
                    [
                        "powershell",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        full_command,
                    ],
                    check=True,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                logging.info("KÉSZ! (PowerShell, %s fájl)", len(file_paths))
                self.last_file_list_hash = hash("".join(file_paths))

            except Exception as exc:
                logging.error("PowerShell hiba: %s", exc)
                self.is_internal_update = False

    def safe_set_clipboard_image(self, data_bytes: bytes) -> None:
        with self.clipboard_lock:
            self.is_internal_update = True
            try:
                image = Image.open(io.BytesIO(data_bytes))
                output = io.BytesIO()
                image.convert("RGB").save(output, "BMP")
                data = output.getvalue()[14:]
                output.close()
                for _ in range(5):
                    try:
                        win32clipboard.OpenClipboard()
                        win32clipboard.EmptyClipboard()
                        win32clipboard.SetClipboardData(win32clipboard.CF_DIB, data)
                        win32clipboard.CloseClipboard()
                        break
                    except Exception:
                        time.sleep(0.1)
                self.last_image_hash = hash(data_bytes)
            except Exception:
                self.is_internal_update = False

    def _close_client_socket(self) -> None:
        if not self.client_socket:
            return
        try:
            self.client_socket.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.client_socket.close()
        except Exception:
            pass
        self.client_socket = None

    def _close_sockets(self) -> None:
        self._close_client_socket()
        if self.server_socket:
            try:
                self.server_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None
        with self._clients_lock:
            clients = list(self.clients)
            self.clients = []
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                client.close()
            except Exception:
                pass
