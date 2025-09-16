#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LAN Drop (HU) – PySide6 alapú fájlátviteli felület widget formában."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import platform
import socket
import sys
import tempfile
import time
import zipfile
from contextlib import closing
from dataclasses import dataclass
from typing import Callable, List, Optional

from PySide6.QtCore import QObject, QThread, QTimer, Qt, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QCheckBox,
    QProgressBar,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


APP_NAME = "LAN Drop"
VERSION = "1.2.2 (PySide6 - HU)"
DEFAULT_PORT = 5001
CHUNK_SIZE = 1024 * 1024
TIMEOUT = 120
AUTO_CLEAN_INTERVAL_MS = 5 * 60 * 1000


def human_bytes(num: int) -> str:
    step = 1024.0
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num < step:
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.2f} {unit}"
        num /= step
    return f"{num:.2f} PB"


def get_local_ip_guess() -> str:
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def unique_filename(dest_dir: str, filename: str) -> str:
    base, ext = os.path.splitext(filename)
    counter = 1
    candidate = filename
    while os.path.exists(os.path.join(dest_dir, candidate)) or os.path.exists(
        os.path.join(dest_dir, candidate + ".part")
    ):
        candidate = f"{base} ({counter}){ext}"
        counter += 1
    return candidate


def sha256_of_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_remove(path: str) -> None:
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


def app_config_dir() -> str:
    system_name = platform.system().lower()
    if "windows" in system_name:
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
        return os.path.join(base, "LAN Drop")
    if "darwin" in system_name or "mac" in system_name:
        return os.path.join(
            os.path.expanduser("~/Library/Application Support"), "LAN Drop"
        )
    return os.path.join(os.path.expanduser("~/.config"), "lan_drop")


def app_config_path() -> str:
    config_directory = app_config_dir()
    os.makedirs(config_directory, exist_ok=True)
    return os.path.join(config_directory, "config.json")


def app_temp_dir() -> str:
    directory = os.path.join(tempfile.gettempdir(), "lan_drop_tmp")
    os.makedirs(directory, exist_ok=True)
    return directory


def should_exclude(name: str) -> bool:
    basename = os.path.basename(name)
    if basename in {"__pycache__", ".git", ".idea", ".vscode"}:
        return True
    patterns = ["*.part", "*.tmp", "*.temp", "*.log~", "Thumbs.db", ".DS_Store"]
    return any(fnmatch.fnmatch(basename, pattern) for pattern in patterns)


def zip_directory(
    src_dir: str,
    dst_zip: str,
    log_cb: Callable[[str], None],
    progress_cb: Callable[[str, int, int, object], None],
) -> None:
    log_cb(f"[ZIP] Összecsomagolás: {src_dir} → {dst_zip}")
    progress_cb(f"Csomagolás: {os.path.basename(dst_zip)}...", -1, -1, None)
    with zipfile.ZipFile(dst_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for root, dirs, files in os.walk(src_dir):
            dirs[:] = [directory for directory in dirs if not should_exclude(directory)]
            for filename in files:
                if should_exclude(filename):
                    continue
                full_path = os.path.join(root, filename)
                relative_path = os.path.relpath(full_path, start=os.path.dirname(src_dir))
                archive.write(full_path, arcname=relative_path)
    size = os.path.getsize(dst_zip)
    log_cb(f"[ZIP] Kész ({human_bytes(size)})")


def _recv_line(sock: socket.socket) -> Optional[bytes]:
    data = b""
    while True:
        try:
            chunk = sock.recv(1)
            if not chunk:
                return None if not data else data
            if chunk == b"\n":
                return data
            data += chunk
        except socket.timeout:
            raise
        except Exception:
            return None if not data else data


@dataclass
class TransferHeader:
    kind: str
    filename: str
    size: int
    use_checksum: bool
    sha256: str
    shared_key_hash: str

    def to_json_bytes(self) -> bytes:
        return (json.dumps(self.__dict__) + "\n").encode("utf-8")

    @staticmethod
    def from_json_bytes(data: bytes) -> "TransferHeader":
        payload = json.loads(data.decode("utf-8"))
        return TransferHeader(
            kind=payload["kind"],
            filename=payload["filename"],
            size=int(payload["size"]),
            use_checksum=bool(payload.get("use_checksum", False)),
            sha256=payload.get("sha256", ""),
            shared_key_hash=payload.get("shared_key_hash", ""),
        )


class WorkerSignals(QObject):
    log_message = Signal(str)
    progress_updated = Signal(str, int, int, object)
    send_complete = Signal(str, int, float)


class ReceiverHandler(QThread):
    def __init__(
        self,
        conn: socket.socket,
        addr: tuple[str, int],
        dest_dir: str,
        shared_key_hash: str,
        signals: WorkerSignals,
    ) -> None:
        super().__init__()
        self.conn = conn
        self.addr = addr
        self.dest_dir = dest_dir
        self.shared_key_hash = shared_key_hash or ""
        self.signals = signals

    def run(self) -> None:
        part_path = ""
        log = self.signals.log_message.emit
        progress = self.signals.progress_updated.emit
        try:
            self.conn.settimeout(TIMEOUT)
            header_bytes = _recv_line(self.conn)
            if not header_bytes:
                log(f"[{self.addr[0]}] Kapcsolat lezárult fejléc nélkül.")
                return
            header = TransferHeader.from_json_bytes(header_bytes)
            if self.shared_key_hash and header.shared_key_hash != self.shared_key_hash:
                log(f"[{self.addr[0]}] Elutasítva: shared key nem egyezik.")
                self.conn.sendall(b"ERR:KEY\n")
                return
            if header.kind != "file":
                log(f"[{self.addr[0]}] Ismeretlen fajta: {header.kind}")
                self.conn.sendall(b"ERR:KIND\n")
                return
            final_name = unique_filename(self.dest_dir, os.path.basename(header.filename))
            part_path = os.path.join(self.dest_dir, final_name + ".part")
            final_path = os.path.join(self.dest_dir, final_name)
            safe_remove(part_path)
            received = 0
            hasher = hashlib.sha256() if header.use_checksum else None
            self.conn.sendall(b"OK:READY\n")
            start_time = time.time()
            with open(part_path, "wb") as handle:
                remaining = header.size
                while remaining > 0:
                    chunk = self.conn.recv(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    handle.write(chunk)
                    received += len(chunk)
                    remaining -= len(chunk)
                    if hasher:
                        hasher.update(chunk)
                    progress(final_name, received, header.size, None)
            self.conn.sendall(b"OK:RECEIVED\n")
            duration = max(1e-6, time.time() - start_time)
            if received != header.size:
                log(f"[{self.addr[0]}] Hiányos fogadás. Takarítás.")
                safe_remove(part_path)
                self.conn.sendall(b"ERR:LENGTH\n")
                return
            if header.use_checksum and hasher and hasher.hexdigest() != header.sha256:
                log(f"[{self.addr[0]}] Checksum eltérés. Takarítás.")
                safe_remove(part_path)
                self.conn.sendall(b"ERR:CHECKSUM\n")
                return
            os.replace(part_path, final_path)
            log(
                f"[{self.addr[0]}] Mentve: '{final_name}' ({human_bytes(header.size)}) "
                f"{duration:.2f} s alatt ~ {human_bytes(int(header.size / duration))}/s."
            )
            self.conn.sendall(b"OK:DONE\n")
        except Exception as exc:  # pragma: no cover - hálózati kivétel
            log(f"[{self.addr[0]}] Hiba: {exc}")
            if part_path:
                safe_remove(part_path)
            try:
                self.conn.sendall(b"ERR:EXC\n")
            except Exception:
                pass
        finally:
            try:
                self.conn.close()
            except Exception:
                pass


class ReceiverServer(QThread):
    def __init__(
        self,
        host: str,
        port: int,
        dest_dir: str,
        shared_key_hash: str,
        signals: WorkerSignals,
    ) -> None:
        super().__init__()
        self.host = host
        self.port = port
        self.dest_dir = dest_dir
        self.shared_key_hash = shared_key_hash or ""
        self.signals = signals
        self._sock: Optional[socket.socket] = None
        self.handlers: List[ReceiverHandler] = []

    def stop(self) -> None:
        self.requestInterruption()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass

    def run(self) -> None:
        log = self.signals.log_message.emit
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((self.host, self.port))
                sock.listen(5)
                sock.settimeout(1.0)
                self._sock = sock
                log(f"Fogadó figyel {self.host}:{self.port} címen")
                while not self.isInterruptionRequested():
                    try:
                        conn, addr = sock.accept()
                        handler = ReceiverHandler(
                            conn, addr, self.dest_dir, self.shared_key_hash, self.signals
                        )
                        self.handlers.append(handler)
                        handler.start()
                    except socket.timeout:
                        continue
        except Exception as exc:  # pragma: no cover - hálózati kivétel
            log(f"Fogadó hiba: {exc}")


class Sender(QThread):
    def __init__(
        self,
        host: str,
        port: int,
        shared_key: str,
        files: List[str],
        use_checksum: bool,
        signals: WorkerSignals,
    ) -> None:
        super().__init__()
        self.host = host
        self.port = port
        self.shared_key = shared_key or ""
        self.files = files
        self.use_checksum = use_checksum
        self.signals = signals
        self._to_cleanup: List[str] = []

    def run(self) -> None:
        log = self.signals.log_message.emit
        try:
            expanded = self._prepare_paths(self.files)
            for path in expanded:
                try:
                    duration = self._send_one(path)
                    self.signals.send_complete.emit(
                        os.path.basename(path), os.path.getsize(path), duration
                    )
                except Exception as exc:
                    log(f"[KÜLD] Hiba ('{os.path.basename(path)}'): {exc}")
        finally:
            for path in self._to_cleanup:
                safe_remove(path)

    def _prepare_paths(self, items: List[str]) -> List[str]:
        log_cb = self.signals.log_message.emit
        progress_cb = self.signals.progress_updated.emit
        prepared: List[str] = []
        for item in items:
            if os.path.isdir(item):
                base_name = os.path.basename(os.path.normpath(item))
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                zip_path = os.path.join(app_temp_dir(), f"{base_name}_{timestamp}.zip")
                zip_directory(item, zip_path, log_cb, progress_cb)
                prepared.append(zip_path)
                self._to_cleanup.append(zip_path)
            elif os.path.isfile(item):
                prepared.append(item)
            else:
                log_cb(f"[KÜLD] Figyelmeztetés: nem található: {item}")
        return prepared

    def _send_one(self, path: str) -> float:
        log_cb = self.signals.log_message.emit
        progress_cb = self.signals.progress_updated.emit

        size = os.path.getsize(path)
        filename = os.path.basename(path)
        keyhash = (
            hashlib.sha256(self.shared_key.encode("utf-8")).hexdigest()
            if self.shared_key
            else ""
        )
        checksum = ""
        if self.use_checksum:
            log_cb(f"[KÜLD] SHA-256 számítás: '{filename}'...")
            start = time.time()
            checksum = sha256_of_file(path)
            log_cb(f"[KÜLD] SHA-256 kész {time.time() - start:.2f} s alatt.")
        header = TransferHeader("file", filename, size, self.use_checksum, checksum, keyhash)
        log_cb(
            f"[KÜLD] Kapcsolódás {self.host}:{self.port} -> '{filename}' "
            f"({human_bytes(size)})..."
        )
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect((self.host, self.port))
            sock.sendall(header.to_json_bytes())
            response = _recv_line(sock)
            if response != b"OK:READY":
                raise RuntimeError(f"Fogadó nem kész (válasz: {response!r}).")
            sent = 0
            start_time = time.time()
            with open(path, "rb") as handle:
                while True:
                    chunk = handle.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    sock.sendall(chunk)
                    sent += len(chunk)
                    elapsed = max(1e-6, time.time() - start_time)
                    progress_cb(filename, sent, size, sent / elapsed)
            resp_received = _recv_line(sock)
            if resp_received != b"OK:RECEIVED":
                raise RuntimeError(
                    f"Fogadó hibát jelzett fogadáskor: {resp_received!r}"
                )
            duration = max(1e-6, time.time() - start_time)
            final_response = _recv_line(sock)
            if final_response != b"OK:DONE":
                raise RuntimeError(
                    f"Fogadó hibát jelzett a feldolgozásnál: {final_response!r}"
                )
            log_cb(
                f"[KÜLD] Kész '{filename}' {duration:.2f} s alatt ~ "
                f"{human_bytes(int(size / duration))}/s."
            )
            return duration


class FileTransferWidget(QWidget):
    def __init__(
        self,
        parent: Optional[QWidget] = None,
        on_back: Optional[Callable[[], None]] = None,
    ) -> None:
        super().__init__(parent)
        self.on_back = on_back

        self.worker_signals = WorkerSignals()
        self.worker_signals.log_message.connect(self._log)
        self.worker_signals.progress_updated.connect(self._update_progress)
        self.worker_signals.send_complete.connect(self._on_send_done)

        self._receiver_thread: Optional[ReceiverServer] = None
        self.sender_thread: Optional[Sender] = None
        self._auto_clean_timer: Optional[QTimer] = None

        self._debounce_timer = QTimer(self)
        self._debounce_timer.setSingleShot(True)
        self._debounce_timer.timeout.connect(self._save_settings)

        self._build_layout()
        self.setStyleSheet(STYLESHEET)
        self._load_settings()
        self._connect_signals()

        self._auto_clean_all()
        self._auto_clean_timer = QTimer(self)
        self._auto_clean_timer.timeout.connect(self._auto_clean_all)
        self._auto_clean_timer.start(AUTO_CLEAN_INTERVAL_MS)

    def _build_layout(self) -> None:
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(10, 10, 10, 10)
        header_layout.setSpacing(10)
        self.back_button = QPushButton("Vissza")
        self.back_button.clicked.connect(self._handle_back)
        header_layout.addWidget(self.back_button)
        header_layout.addStretch()
        outer_layout.addWidget(header)

        main_widget = QWidget()
        main_layout = QHBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar.setFixedWidth(220)

        title_label = QLabel(APP_NAME)
        title_label.setStyleSheet("font-size: 16pt; font-weight: bold;")
        sidebar_layout.addWidget(title_label)
        subtitle_label = QLabel("Egyszerű LAN fájlátvitel")
        sidebar_layout.addWidget(subtitle_label)
        sidebar_layout.addStretch()

        content = QWidget()
        content_layout = QVBoxLayout(content)

        recv_frame = QGroupBox("Fogadó")
        recv_layout = QGridLayout(recv_frame)
        recv_layout.addWidget(QLabel("Célmappa:"), 0, 0)
        self.entry_receiver_dest = QLineEdit()
        recv_layout.addWidget(self.entry_receiver_dest, 0, 1)
        self.btn_browse = QPushButton("Tallózás…")
        recv_layout.addWidget(self.btn_browse, 0, 2)

        recv_layout.addWidget(QLabel("Port (figyelés):"), 1, 0)
        self.entry_receiver_port = QLineEdit(str(DEFAULT_PORT))
        self.entry_receiver_port.setFixedWidth(80)

        key_label = QLabel("Opcionális közös kulcs:")
        key_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.entry_receiver_key = QLineEdit()
        self.entry_receiver_key.setEchoMode(QLineEdit.EchoMode.Password)

        h_layout1 = QHBoxLayout()
        h_layout1.addWidget(self.entry_receiver_port)
        h_layout1.addStretch()
        h_layout1.addWidget(key_label)
        h_layout1.setContentsMargins(0, 6, 0, 0)
        recv_layout.addLayout(h_layout1, 1, 1)
        recv_layout.addWidget(self.entry_receiver_key, 1, 2)

        self.btn_start = QPushButton("Fogadó indítása")
        self.btn_start.setObjectName("AccentButton")
        self.lbl_status = QLabel("Állapot: leállítva")
        self.lbl_ip = QLabel(f"Helyi IP-címed: {get_local_ip_guess()}")
        self.lbl_ip.setAlignment(Qt.AlignmentFlag.AlignRight)

        h_layout2 = QHBoxLayout()
        h_layout2.addWidget(self.lbl_status)
        h_layout2.addStretch()
        h_layout2.addWidget(self.lbl_ip)
        h_layout2.setContentsMargins(0, 8, 0, 0)

        recv_layout.addWidget(self.btn_start, 2, 0)
        recv_layout.addLayout(h_layout2, 2, 1, 1, 2)

        send_frame = QGroupBox("Küldő")
        send_layout = QGridLayout(send_frame)
        send_layout.addWidget(QLabel("Fogadó IP:"), 0, 0)
        self.sender_ip = QLineEdit(get_local_ip_guess())
        send_layout.addWidget(self.sender_ip, 0, 1)
        send_layout.addWidget(QLabel("Port:"), 0, 2)
        self.sender_port = QLineEdit(str(DEFAULT_PORT))
        send_layout.addWidget(self.sender_port, 0, 3)

        send_layout.addWidget(QLabel("Opcionális közös kulcs:"), 1, 0)
        self.sender_key = QLineEdit()
        self.sender_key.setEchoMode(QLineEdit.EchoMode.Password)
        send_layout.addWidget(self.sender_key, 1, 1)
        self.use_checksum = QCheckBox("Ellenőrzőösszeg (lassabb)")
        send_layout.addWidget(self.use_checksum, 1, 2, 1, 2)

        self.files_list = QListWidget()
        self.files_list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        send_layout.addWidget(self.files_list, 2, 0, 1, 4)

        btn_layout = QHBoxLayout()
        self.btn_add_files = QPushButton("Fájlok…")
        self.btn_add_dirs = QPushButton("Mappák…")
        self.btn_remove = QPushButton("Törlés")
        self.btn_clear = QPushButton("Ürítés")
        self.btn_send = QPushButton("Küldés")
        self.btn_send.setObjectName("AccentButton")
        btn_layout.addWidget(self.btn_add_files)
        btn_layout.addWidget(self.btn_add_dirs)
        btn_layout.addWidget(self.btn_remove)
        btn_layout.addWidget(self.btn_clear)
        btn_layout.addStretch()
        btn_layout.addWidget(self.btn_send)
        send_layout.addLayout(btn_layout, 3, 0, 1, 4)

        prog_frame = QGroupBox("Folyamat")
        prog_layout = QVBoxLayout(prog_frame)
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress_label = QLabel("Nincs aktív átvitel.")
        prog_layout.addWidget(self.progress)
        prog_layout.addWidget(self.progress_label)

        log_frame = QGroupBox("Napló")
        log_layout = QVBoxLayout(log_frame)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)

        footer = QWidget()
        footer.setObjectName("footer")
        footer_layout = QHBoxLayout(footer)
        self.btn_clean_parts = QPushButton(".part fájlok törlése")
        footer_layout.addWidget(self.btn_clean_parts)
        footer_layout.addStretch()
        footer_layout.addWidget(QLabel(f"{APP_NAME} {VERSION}"))

        content_layout.addWidget(recv_frame)
        content_layout.addWidget(send_frame)
        content_layout.addWidget(prog_frame)
        content_layout.addWidget(log_frame)

        main_layout.addWidget(sidebar)
        main_layout.addWidget(content)

        outer_layout.addWidget(main_widget)
        outer_layout.addWidget(footer)

    def _connect_signals(self) -> None:
        self.entry_receiver_dest.textChanged.connect(self._save_settings_debounced)
        self.entry_receiver_port.textChanged.connect(self._save_settings_debounced)
        self.sender_ip.textChanged.connect(self._save_settings_debounced)
        self.sender_port.textChanged.connect(self._save_settings_debounced)
        self.use_checksum.stateChanged.connect(self._save_settings_debounced)

        self.btn_browse.clicked.connect(self._choose_dest)
        self.btn_start.clicked.connect(self._toggle_receiver)
        self.btn_add_files.clicked.connect(self._add_files)
        self.btn_add_dirs.clicked.connect(self._add_dirs)
        self.btn_remove.clicked.connect(self._remove_selected)
        self.btn_clear.clicked.connect(self._clear_files)
        self.btn_send.clicked.connect(self._send_selected)
        self.btn_clean_parts.clicked.connect(lambda: self._clean_temp(silent=False))

    def _load_settings(self) -> None:
        try:
            cfg_path = app_config_path()
            if os.path.exists(cfg_path):
                with open(cfg_path, "r", encoding="utf-8") as handle:
                    cfg = json.load(handle)
                self.entry_receiver_dest.setText(
                    cfg.get("receiver_dest", os.path.expanduser("~/Downloads"))
                )
                self.entry_receiver_port.setText(
                    str(cfg.get("receiver_port", DEFAULT_PORT))
                )
                self.sender_ip.setText(cfg.get("sender_ip", get_local_ip_guess()))
                self.sender_port.setText(str(cfg.get("sender_port", DEFAULT_PORT)))
                self.use_checksum.setChecked(bool(cfg.get("use_checksum", False)))
        except Exception as exc:  # pragma: no cover - IO hiba
            print("Beállítás betöltési hiba:", exc, file=sys.stderr)

    def _save_settings(self) -> None:
        try:
            cfg = {
                "receiver_dest": self.entry_receiver_dest.text().strip(),
                "receiver_port": int(self.entry_receiver_port.text()),
                "sender_ip": self.sender_ip.text().strip(),
                "sender_port": int(self.sender_port.text()),
                "use_checksum": self.use_checksum.isChecked(),
            }
            with open(app_config_path(), "w", encoding="utf-8") as handle:
                json.dump(cfg, handle, indent=2)
        except (ValueError, TypeError):
            pass
        except Exception as exc:  # pragma: no cover - IO hiba
            print("Beállítás mentési hiba:", exc, file=sys.stderr)

    def _save_settings_debounced(self) -> None:
        self._debounce_timer.start(500)

    def _choose_dest(self) -> None:
        directory = QFileDialog.getExistingDirectory(
            self, "Válassz célmappát", self.entry_receiver_dest.text()
        )
        if directory:
            self.entry_receiver_dest.setText(os.path.normpath(directory))
            self._log(f"Célmappa: {directory}")
            self._save_settings()
            self._clean_temp(silent=True)

    def _toggle_receiver(self) -> None:
        if self._receiver_thread and self._receiver_thread.isRunning():
            self._receiver_thread.stop()
            self._receiver_thread.wait()
            self._receiver_thread = None
            self.btn_start.setText("Fogadó indítása")
            self.lbl_status.setText("Állapot: leállítva")
            for widget in (
                self.entry_receiver_dest,
                self.btn_browse,
                self.entry_receiver_port,
                self.entry_receiver_key,
            ):
                widget.setEnabled(True)
            self._log("Fogadó leállítva.")
            return

        dest = self.entry_receiver_dest.text().strip()
        if not dest or not os.path.isdir(dest):
            QMessageBox.critical(self, APP_NAME, "Válassz érvényes célmappát!")
            return
        try:
            port = int(self.entry_receiver_port.text())
        except ValueError:
            QMessageBox.critical(self, APP_NAME, "Érvénytelen port.")
            return

        key = self.entry_receiver_key.text().strip()
        keyhash = hashlib.sha256(key.encode("utf-8")).hexdigest() if key else ""

        self._receiver_thread = ReceiverServer(
            "0.0.0.0", port, dest, keyhash, self.worker_signals
        )
        self._receiver_thread.start()

        self.btn_start.setText("Fogadó leállítása")
        self.lbl_status.setText(f"Állapot: figyelés {get_local_ip_guess()}:{port}")
        for widget in (
            self.entry_receiver_dest,
            self.btn_browse,
            self.entry_receiver_port,
            self.entry_receiver_key,
        ):
            widget.setEnabled(False)
        self._log(f"Fogadó elindult. Mentés ide: {dest}")
        self._save_settings()

    def _add_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Válaszd ki a fájlokat")
        if files:
            self.files_list.addItems(files)

    def _add_dirs(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Válassz egy mappát")
        if directory:
            self.files_list.addItem(os.path.normpath(directory))

    def _remove_selected(self) -> None:
        for item in self.files_list.selectedItems():
            self.files_list.takeItem(self.files_list.row(item))

    def _clear_files(self) -> None:
        self.files_list.clear()

    def _send_selected(self) -> None:
        items = [self.files_list.item(index).text() for index in range(self.files_list.count())]
        if not items:
            QMessageBox.information(self, APP_NAME, "Nincs mit küldeni!")
            return

        host = self.sender_ip.text().strip()
        try:
            port = int(self.sender_port.text())
        except ValueError:
            QMessageBox.critical(self, APP_NAME, "Érvénytelen port.")
            return

        key = self.sender_key.text().strip()
        use_checksum = self.use_checksum.isChecked()

        sender_thread = Sender(host, port, key, items, use_checksum, self.worker_signals)
        sender_thread.start()

        self._log(f"[KÜLD] {len(items)} elem küldése → {host}:{port} ...")
        self._save_settings()
        self.sender_thread = sender_thread

    def _update_progress(self, name: str, done: int, total: int, bps: Optional[float]) -> None:
        if total == -1:
            self.progress.setRange(0, 0)
            self.progress_label.setText(name)
            return

        self.progress.setRange(0, 100)
        percentage = 0 if total == 0 else (done / max(1, total)) * 100
        self.progress.setValue(int(percentage))
        speed = f" — {human_bytes(int(bps))}/s" if bps is not None else ""
        self.progress_label.setText(
            f"{name}: {human_bytes(done)} / {human_bytes(total)} ({percentage:.1f}%)" + speed
        )

    def _on_send_done(self, name: str, size: int, duration: float) -> None:
        self._reset_progress()
        avg = human_bytes(int(size / max(1e-6, duration)))
        QMessageBox.information(
            self,
            "Sikeres küldés!",
            f"Fájl: {name}\nMéret: {human_bytes(size)}\nIdő: {duration:.2f} s ({avg}/s)",
        )

    def _reset_progress(self) -> None:
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress_label.setText("Nincs aktív átvitel.")

    def _log(self, message: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")

    def _auto_clean_all(self) -> None:
        self._clean_temp(silent=True)
        self._clean_temp_zips(silent=True)

    def _clean_temp(self, silent: bool = False) -> None:
        dest = self.entry_receiver_dest.text().strip()
        if not dest or not os.path.isdir(dest):
            if not silent:
                QMessageBox.critical(
                    self, APP_NAME, "Válassz érvényes célmappát a takarításhoz."
                )
            return
        removed = 0
        for name in os.listdir(dest):
            if name.endswith(".part"):
                if safe_remove(os.path.join(dest, name)) is None:
                    removed += 1
        if not silent and removed > 0:
            self._log(f"{removed} db .part fájl törölve.")

    def _clean_temp_zips(self, silent: bool = False) -> None:
        temp_dir = app_temp_dir()
        removed = 0
        now = time.time()
        try:
            for name in os.listdir(temp_dir):
                if name.lower().endswith(".zip"):
                    path = os.path.join(temp_dir, name)
                    try:
                        if (now - os.path.getmtime(path)) > 5 * 60:
                            os.remove(path)
                            removed += 1
                    except Exception:
                        pass
            if not silent and removed > 0:
                self._log(f"{removed} db ideiglenes ZIP törölve.")
        except FileNotFoundError:
            pass

    def shutdown(self) -> None:
        self._save_settings()
        if self._auto_clean_timer:
            self._auto_clean_timer.stop()
        if self._receiver_thread and self._receiver_thread.isRunning():
            self._receiver_thread.stop()
            self._receiver_thread.wait()
        self._auto_clean_all()

    def _handle_back(self) -> None:
        self._save_settings()
        if callable(self.on_back):
            self.on_back()


STYLESHEET = """
QWidget {
    background-color: #2f3136;
    color: #dcddde;
    font-family: "Segoe UI", sans-serif;
    font-size: 10pt;
}
QWidget#sidebar {
    background-color: #36393f;
    border-right: 1px solid #202225;
}
QWidget#footer {
    background-color: #36393f;
    border-top: 1px solid #202225;
}
QGroupBox {
    background-color: #36393f;
    border: 1px solid #202225;
    border-radius: 4px;
    margin-top: 1ex;
    font-weight: bold;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 3px;
    left: 10px;
}
QPushButton {
    background-color: #484b51;
    border: 1px solid #202225;
    padding: 6px 12px;
    border-radius: 3px;
}
QPushButton:hover {
    background-color: #5a5e66;
}
QPushButton:pressed {
    background-color: #4e5159;
}
QPushButton#AccentButton {
    background-color: #7289da;
    color: white;
    font-weight: bold;
    padding: 8px 16px;
}
QPushButton#AccentButton:hover {
    background-color: #677bc4;
}
QPushButton#AccentButton:pressed {
    background-color: #5b6eae;
}
QLineEdit, QTextEdit, QListWidget {
    background-color: #202225;
    border: 1px solid #1a1b1e;
    border-radius: 3px;
    padding: 5px;
}
QProgressBar {
    border: 1px solid #202225;
    border-radius: 3px;
    text-align: center;
    background-color: #202225;
}
QProgressBar::chunk {
    background-color: #7289da;
    border-radius: 3px;
}
QCheckBox::indicator {
    width: 14px;
    height: 14px;
}
"""


if __name__ == "__main__":  # pragma: no cover - manuális futtatás
    from PySide6.QtWidgets import QApplication, QMainWindow

    app = QApplication(sys.argv)
    window = QMainWindow()
    widget = FileTransferWidget()
    window.setCentralWidget(widget)
    window.resize(980, 680)
    window.show()
    app.processEvents()

    def _center_window_on_screen(target: QWidget) -> None:
        screen = target.screen() or QGuiApplication.primaryScreen()
        if not screen:
            return
        frame = target.frameGeometry()
        frame.moveCenter(screen.availableGeometry().center())
        target.move(frame.topLeft())

    _center_window_on_screen(window)
    sys.exit(app.exec())
