# gui.py - FINAL STRUCTURAL FIX
# Adds a handler for the deactivation request signal from the worker.

import sys
import time
import logging
import os
import shutil

# Windows specific module only available on that platform
try:
    import winreg
except ImportError:
    winreg = None
    
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QRadioButton, QLabel, QLineEdit, QCheckBox, QPushButton, QGridLayout,
    QSystemTrayIcon, QMenu, QFileDialog, QProgressDialog, QInputDialog, QMessageBox,
)
from PySide6.QtGui import QIcon, QAction
from PySide6.QtCore import QSize, QSettings, QThread, Qt, QTimer, QStandardPaths

from worker import KVMWorker
from config import APP_NAME, ORG_NAME, DEFAULT_PORT, ICON_PATH, TEMP_DIR_PARTS


def set_autostart(enabled: bool) -> None:
    if sys.platform.startswith("win") and winreg is not None:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        app_name = "KVM_Switch_UMKGL"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE) as reg_key:
                if enabled:
                    app_path = f'"{sys.executable}" --tray' if getattr(sys, "frozen", False) else f'"{sys.executable}" "{os.path.abspath(sys.argv[0])}" --tray'
                    winreg.SetValueEx(reg_key, app_name, 0, winreg.REG_SZ, app_path)
                else:
                    winreg.DeleteValue(reg_key, app_name)
        except FileNotFoundError:
            if not enabled:
                pass
            else:
                logging.warning("Autostart registry key not found.")
        except Exception as e:
            logging.error("Hiba az automatikus indulás beállításakor: %s", e)


class MainWindow(QMainWindow):
    __slots__ = (
        'radio_desktop', 'radio_laptop', 'radio_elitedesk', 'port',
        'host_code', 'client_code', 'autostart_check',
        'start_button', 'status_label', 'kvm_thread', 'kvm_worker',
        'tray_icon', 'share_button', 'cut_share_button', 'paste_button', 'progress_dialog',
        'temp_path_edit', 'browse_temp_path_button'
    )
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KVM Switch Vezérlőpult v8")
        self.setWindowIcon(QIcon(ICON_PATH))
        self.setFixedSize(QSize(450, 520))

        central_widget, main_layout = QWidget(), QVBoxLayout()
        self.setCentralWidget(central_widget)
        central_widget.setLayout(main_layout)
        
        # UI Setup (condensed for prompt brevity, logic is unchanged)
        role_box = QGroupBox("Eszköz kiválasztása")
        role_layout = QHBoxLayout()
        self.radio_desktop = QRadioButton("Asztali gép (irányít)")
        self.radio_laptop = QRadioButton("Laptop")
        self.radio_elitedesk = QRadioButton("ElitDesk")
        role_layout.addWidget(self.radio_desktop); role_layout.addWidget(self.radio_laptop); role_layout.addWidget(self.radio_elitedesk)
        role_box.setLayout(role_layout)
        
        network_box = QGroupBox("Hálózati Beállítások")
        network_layout = QGridLayout()
        network_layout.addWidget(QLabel("Port:"), 0, 0)
        self.port = QLineEdit()
        network_layout.addWidget(self.port, 0, 1)
        network_box.setLayout(network_layout)

        monitor_box = QGroupBox("Monitor Kódok (Adó módban)")
        monitor_layout = QGridLayout()
        monitor_layout.addWidget(QLabel("Hoszt kód:"), 0, 0); self.host_code = QLineEdit(); monitor_layout.addWidget(self.host_code, 0, 1)
        monitor_layout.addWidget(QLabel("Kliens kód:"), 1, 0); self.client_code = QLineEdit(); monitor_layout.addWidget(self.client_code, 1, 1)
        monitor_box.setLayout(monitor_layout)
        
        other_box = QGroupBox("Egyéb Beállítások")
        other_layout = QGridLayout()
        self.autostart_check = QCheckBox("Automatikus indulás a rendszerrel")
        other_layout.addWidget(self.autostart_check, 1, 0, 1, 2)
        other_layout.addWidget(QLabel("Ideiglenes mappa:"), 2, 0)
        temp_path_layout = QHBoxLayout()
        self.temp_path_edit = QLineEdit(); self.temp_path_edit.setReadOnly(True)
        self.browse_temp_path_button = QPushButton("Tallózás...")
        temp_path_layout.addWidget(self.temp_path_edit); temp_path_layout.addWidget(self.browse_temp_path_button)
        other_layout.addLayout(temp_path_layout, 2, 1)
        other_box.setLayout(other_layout)
        
        file_box = QGroupBox("Hálózati Fájl Vágólap")
        file_layout = QHBoxLayout()
        self.share_button = QPushButton("Megosztás"); self.cut_share_button = QPushButton("Kivágás"); self.paste_button = QPushButton("Beillesztés")
        file_layout.addWidget(self.share_button); file_layout.addWidget(self.cut_share_button); file_layout.addWidget(self.paste_button)
        file_box.setLayout(file_layout)
        
        main_layout.addWidget(role_box); main_layout.addWidget(network_box); main_layout.addWidget(monitor_box); main_layout.addWidget(other_box); main_layout.addWidget(file_box)
        
        self.start_button = QPushButton("KVM Szolgáltatás Indítása")
        self.status_label = QLabel("Állapot: Inaktív"); self.status_label.setWordWrap(True)
        main_layout.addWidget(self.start_button); main_layout.addWidget(self.status_label)
        
        # Connections and initialization
        self.browse_temp_path_button.clicked.connect(self.browse_temp_directory)
        self.share_button.clicked.connect(self.share_network_file)
        self.cut_share_button.clicked.connect(lambda: self.share_network_file(cut=True))
        self.paste_button.clicked.connect(self.paste_network_file)
        self.start_button.clicked.connect(self.toggle_kvm_service)
        
        self.kvm_thread = None
        self.kvm_worker = None
        self.progress_dialog = None
        self.init_tray_icon()
        self.load_settings()

    def get_settings(self):
        # ... (no change)
        device = 'desktop' if self.radio_desktop.isChecked() else 'laptop' if self.radio_laptop.isChecked() else 'elitedesk'
        return {'role': 'ado' if device == 'desktop' else 'vevo', 'device_name': device, 'port': int(self.port.text()),
                'monitor_codes': {'host': int(self.host_code.text()), 'client': int(self.client_code.text())},
                'temp_path': self.temp_path_edit.text()}

    def toggle_kvm_service(self):
        if self.kvm_thread and self.kvm_thread.isRunning(): self.stop_kvm_service()
        else: self.start_kvm_service()

    def start_kvm_service(self):
        # STRUCTURAL CHANGE: Connect the new signal
        self.kvm_thread = QThread()
        self.kvm_worker = KVMWorker(self.get_settings())
        self.kvm_worker.moveToThread(self.kvm_thread)
        self.kvm_thread.started.connect(self.kvm_worker.run)
        self.kvm_worker.finished.connect(self.on_service_stopped)
        self.kvm_worker.status_update.connect(self.on_status_update)
        self.kvm_worker.update_progress_display.connect(self.update_progress_display)
        self.kvm_worker.file_transfer_error.connect(self.on_transfer_error)
        self.kvm_worker.incoming_upload_started.connect(self.on_incoming_upload_started)
        self.kvm_worker.request_deactivation.connect(self.handle_deactivation_request)  # NEW CONNECTION
        self.kvm_thread.start()
        self.start_button.setText("KVM Szolgáltatás Leállítása")
        self.set_controls_enabled(False)

    # NEW SLOT to handle deactivation safely
    def handle_deactivation_request(self, reason: str):
        logging.info(f"Deaktiválási kérelem érkezett: {reason}")
        if self.kvm_worker:
            self.kvm_worker.deactivate_kvm(reason=reason)

    def stop_kvm_service(self):
        if self.kvm_worker: self.kvm_worker.stop()

    def on_service_stopped(self):
        if self.kvm_thread:
            self.kvm_thread.quit()
            self.kvm_thread.wait()
        self.kvm_thread = None
        self.kvm_worker = None
        self.start_button.setText("KVM Szolgáltatás Indítása")
        self.on_status_update("Állapot: Inaktív")
        self.set_controls_enabled(True)

    def save_settings(self):
        # ... (no change, but added call to set_autostart)
        settings = QSettings(ORG_NAME, APP_NAME)
        device = 'desktop' if self.radio_desktop.isChecked() else 'laptop' if self.radio_laptop.isChecked() else 'elitedesk'
        settings.setValue("device/name", device)
        settings.setValue("network/port", self.port.text())
        settings.setValue("monitor/host_code", self.host_code.text())
        settings.setValue("monitor/client_code", self.client_code.text())
        autostart_enabled = self.autostart_check.isChecked()
        settings.setValue("other/autostart", autostart_enabled)
        settings.setValue("other/temp_path", self.temp_path_edit.text())
        set_autostart(autostart_enabled)

    def load_settings(self):
        # ... (no change)
        settings = QSettings(ORG_NAME, APP_NAME)
        device = settings.value("device/name", "desktop")
        if device == 'desktop': self.radio_desktop.setChecked(True)
        elif device == 'laptop': self.radio_laptop.setChecked(True)
        else: self.radio_elitedesk.setChecked(True)
        self.port.setText(settings.value("network/port", str(DEFAULT_PORT)))
        self.host_code.setText(settings.value("monitor/host_code", "17"))
        self.client_code.setText(settings.value("monitor/client_code", "18"))
        self.autostart_check.setChecked(settings.value("other/autostart", False, type=bool))
        default_temp = os.path.join(QStandardPaths.writableLocation(QStandardPaths.TempLocation), *TEMP_DIR_PARTS)
        self.temp_path_edit.setText(settings.value("other/temp_path", default_temp))
        
        # Connect signals after loading to prevent saving on startup
        self.radio_desktop.toggled.connect(self.save_settings)
        self.radio_laptop.toggled.connect(self.save_settings)
        self.radio_elitedesk.toggled.connect(self.save_settings)
        self.port.textChanged.connect(self.save_settings)
        self.host_code.textChanged.connect(self.save_settings)
        self.client_code.textChanged.connect(self.save_settings)
        self.autostart_check.toggled.connect(self.save_settings)

    def set_controls_enabled(self, enabled):
        # ... (no change)
        self.radio_desktop.setEnabled(enabled)
        self.radio_laptop.setEnabled(enabled)
        self.radio_elitedesk.setEnabled(enabled)
        self.port.setEnabled(enabled)
        self.host_code.setEnabled(enabled)
        self.client_code.setEnabled(enabled)
        self.autostart_check.setEnabled(enabled)
        
    def on_status_update(self, message): self.status_label.setText(message)
    
    def init_tray_icon(self):
        # ... (no change)
        self.tray_icon = QSystemTrayIcon(QIcon(ICON_PATH), self)
        tray_menu = QMenu()
        show_action = QAction("Vezérlőpult", self, triggered=self.show)
        quit_action = QAction("Kilépés", self, triggered=self.quit_application)
        tray_menu.addAction(show_action); tray_menu.addAction(quit_action)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        self.tray_icon.activated.connect(lambda r: self.show() if r == QSystemTrayIcon.ActivationReason.Trigger else None)

    def closeEvent(self, event): event.ignore(); self.hide()
    
    def quit_application(self): self.stop_kvm_service(); QTimer.singleShot(200, QApplication.instance().quit)
        
    def browse_temp_directory(self):
        # ... (no change)
        drive, ok = QInputDialog.getItem(self, "Meghajtó kiválasztása", "Válassz:", [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")], 0, False)
        if ok and drive:
            target_dir = os.path.join(drive, *TEMP_DIR_PARTS)
            try:
                os.makedirs(target_dir, exist_ok=True)
                self.temp_path_edit.setText(target_dir)
                self.save_settings()
            except OSError as e: QMessageBox.warning(self, "Hiba", f"Nem sikerült a mappát létrehozni: {e}")

    # File transfer methods are unchanged
    def share_network_file(self, cut: bool = False):
        if not self.kvm_worker: return
        paths, _ = QFileDialog.getOpenFileNames(self, "Fájlok kiválasztása")
        if not paths:
            folder = QFileDialog.getExistingDirectory(self, "Mappa kiválasztása")
            if folder: paths = [folder]
            else: return
        self.show_progress_dialog("Fájl küldése")
        self.kvm_worker.share_files(paths, 'cut' if cut else 'copy')

    def paste_network_file(self):
        if not self.kvm_worker: return
        dest = QFileDialog.getExistingDirectory(self, "Cél mappa kiválasztása")
        if dest:
            self.show_progress_dialog("Fájl fogadása")
            self.kvm_worker.request_paste(dest)

    def show_progress_dialog(self, title: str):
        if self.progress_dialog: self.progress_dialog.close()
        self.progress_dialog = QProgressDialog("", "Mégse", 0, 100, self)
        self.progress_dialog.setWindowTitle(title)
        self.progress_dialog.canceled.connect(self.cancel_transfer)
        self.progress_dialog.setMinimumDuration(0)
        self.progress_dialog.show()

    def on_incoming_upload_started(self, filename: str, total_size: int): self.show_progress_dialog("Fájl fogadása")
    def cancel_transfer(self):
        if self.kvm_worker: self.kvm_worker.cancel_file_transfer()
        if self.progress_dialog: self.progress_dialog.close()
    def on_transfer_error(self, msg: str):
        self.on_status_update(f"Hiba: {msg}")
        if self.progress_dialog: self.progress_dialog.close()

    def update_progress_display(self, percentage: int, label: str):
        if not self.progress_dialog or not self.progress_dialog.isVisible(): return
        self.progress_dialog.setValue(percentage)
        self.progress_dialog.setLabelText(label)
        if percentage >= 100:
            QTimer.singleShot(4000, self.progress_dialog.close)
