# gui.py - VÉGLEGES
# Hozzáadva a tényleges autostart logika.

import sys
import time
import logging
import os

# Windows specific module only available on that platform
import winreg  # type: ignore
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGroupBox,
    QRadioButton,
    QLabel,
    QLineEdit,
    QCheckBox,
    QPushButton,
    QGridLayout,
    QSystemTrayIcon,
    QMenu,
    QFileDialog,
    QProgressDialog,
    QInputDialog,
    QMessageBox,
)
from PySide6.QtGui import QIcon, QAction
from PySide6.QtCore import QSize, QSettings, QThread, Qt, QTimer, QStandardPaths


from worker import KVMWorker
from config import APP_NAME, ORG_NAME, DEFAULT_PORT, ICON_PATH, TEMP_DIR_PARTS

MB = 1024 * 1024


def set_autostart(enabled: bool) -> None:
    """Enable or disable autostart depending on the current platform."""
    if sys.platform.startswith("win") and winreg is not None:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        app_name = "KVM_Switch"
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
            if enabled:
                if getattr(sys, "frozen", False):
                    app_path = f'"{sys.executable}" --tray'
                else:
                    script = os.path.join(os.path.dirname(__file__), "main.py")
                    app_path = f'"{sys.executable}" "{script}" --tray'
                winreg.SetValueEx(reg_key, app_name, 0, winreg.REG_SZ, app_path)
                logging.info("Automatikus indulás bekapcsolva. Útvonal: %s", app_path)
            else:
                winreg.DeleteValue(reg_key, app_name)
                logging.info("Automatikus indulás kikapcsolva.")
            winreg.CloseKey(reg_key)
        except FileNotFoundError:
            logging.warning("Automatikus indulás kikapcsolva (kulcs nem létezett).")
        except Exception as e:  # pragma: no cover - platform specific
            logging.error("Hiba az automatikus indulás beállításakor: %s", e)
    else:
        logging.info("Autostart beállítás kihagyva: nem támogatott platform.")


class MainWindow(QMainWindow):
    __slots__ = (
        'radio_desktop', 'radio_laptop', 'radio_elitedesk', 'port',
        'host_code', 'client_code', 'hotkey_label', 'autostart_check',
        'start_button', 'status_label', 'kvm_thread', 'kvm_worker',
        'tray_icon', 'share_button', 'cut_share_button', 'paste_button', 'progress_dialog',
        'temp_path_edit', 'browse_temp_path_button'
    )

    # A MainWindow többi része változatlan...
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KVM Switch Vezérlőpult v7")
        self.setWindowIcon(QIcon(ICON_PATH))
        # Prevent resizing during runtime
        # Provide a bit more vertical room so texts are not cramped
        # Slightly increased height so long texts fit within the window
        # Provide a bit more space vertically for future additions
        self.setFixedSize(QSize(450, 560))

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        role_box = QGroupBox("Eszköz kiválasztása")
        role_layout = QHBoxLayout()
        role_layout.setSpacing(15)
        role_layout.setContentsMargins(10, 10, 10, 10)
        self.radio_desktop = QRadioButton("Asztali gép (irányít)")
        self.radio_laptop = QRadioButton("Laptop")
        self.radio_elitedesk = QRadioButton("ElitDesk")
        role_layout.addWidget(self.radio_desktop)
        role_layout.addWidget(self.radio_laptop)
        role_layout.addWidget(self.radio_elitedesk)
        role_box.setLayout(role_layout)
        main_layout.addWidget(role_box)

        network_box = QGroupBox("Hálózati Beállítások")
        network_layout = QGridLayout()
        network_layout.addWidget(QLabel("Port:"), 0, 0)
        self.port = QLineEdit()
        network_layout.addWidget(self.port, 0, 1)
        network_box.setLayout(network_layout)
        main_layout.addWidget(network_box)

        monitor_box = QGroupBox("Monitor Kódok (Adó módban)")
        monitor_layout = QGridLayout()
        monitor_layout.addWidget(QLabel("Hoszt kód:"), 0, 0)
        self.host_code = QLineEdit()
        monitor_layout.addWidget(self.host_code, 0, 1)
        monitor_layout.addWidget(QLabel("Kliens kód:"), 1, 0)
        self.client_code = QLineEdit()
        monitor_layout.addWidget(self.client_code, 1, 1)
        monitor_box.setLayout(monitor_layout)
        main_layout.addWidget(monitor_box)

        other_box = QGroupBox("Egyéb Beállítások")
        other_layout = QGridLayout()
        other_layout.addWidget(QLabel("Gyorsbillentyű:"), 0, 0)
        self.hotkey_label = QLabel(
            "Asztal: Shift + Numpad 0 | Laptop: Shift + Numpad 1 | ElitDesk: Shift + Numpad 2"
        )
        other_layout.addWidget(self.hotkey_label, 0, 1)
        self.autostart_check = QCheckBox(
            "Automatikus indulás a rendszerrel"
        )
        other_layout.addWidget(self.autostart_check, 1, 0, 1, 2)

        other_layout.addWidget(QLabel("Ideiglenes mappa:"), 2, 0)
        temp_path_layout = QHBoxLayout()
        self.temp_path_edit = QLineEdit()
        self.temp_path_edit.setReadOnly(True)
        temp_path_layout.addWidget(self.temp_path_edit)

        self.browse_temp_path_button = QPushButton("Tallózás...")
        self.browse_temp_path_button.clicked.connect(self.browse_temp_directory)
        temp_path_layout.addWidget(self.browse_temp_path_button)

        other_layout.addLayout(temp_path_layout, 2, 1)
        other_box.setLayout(other_layout)
        main_layout.addWidget(other_box)

        file_box = QGroupBox("Hálózati Fájl Vágólap")
        file_layout = QHBoxLayout()
        self.share_button = QPushButton("Megosztás")
        self.share_button.clicked.connect(self.share_network_file)
        self.cut_share_button = QPushButton("Kivágás")
        self.cut_share_button.clicked.connect(lambda: self.share_network_file(cut=True))
        self.paste_button = QPushButton("Beillesztés")
        self.paste_button.clicked.connect(self.paste_network_file)
        file_layout.addWidget(self.share_button)
        file_layout.addWidget(self.cut_share_button)
        file_layout.addWidget(self.paste_button)
        file_box.setLayout(file_layout)
        main_layout.addWidget(file_box)

        self.start_button = QPushButton("KVM Szolgáltatás Indítása")
        self.start_button.clicked.connect(self.toggle_kvm_service)
        main_layout.addWidget(self.start_button)

        self.status_label = QLabel("Állapot: Inaktív")
        self.status_label.setWordWrap(True)
        self.status_label.setAlignment(Qt.AlignTop)
        self.status_label.setFixedHeight(90)
        main_layout.addWidget(self.status_label)

        self.kvm_thread = None
        self.kvm_worker = None
        self.progress_dialog = None
        self.init_tray_icon()
        self.load_settings()

    def get_settings(self):
        if self.radio_desktop.isChecked():
            mode = 'ado'
            device = 'desktop'
        elif self.radio_laptop.isChecked():
            mode = 'vevo'
            device = 'laptop'
        else:
            mode = 'vevo'
            device = 'elitedesk'
        return {
            'role': mode,
            'device_name': device,
            'port': int(self.port.text()),
            'monitor_codes': {
                'host': int(self.host_code.text()),
                'client': int(self.client_code.text()),
            },
            'temp_path': self.temp_path_edit.text(),
        }

    def toggle_kvm_service(self):
        if self.kvm_thread and self.kvm_thread.isRunning():
            self.stop_kvm_service()
        else:
            self.start_kvm_service()

    def start_kvm_service(self):
        self.kvm_thread = QThread()
        self.kvm_worker = KVMWorker(self.get_settings())
        self.kvm_worker.moveToThread(self.kvm_thread)
        self.kvm_thread.started.connect(self.kvm_worker.run)
        self.kvm_worker.finished.connect(self.on_service_stopped)
        self.kvm_worker.status_update.connect(self.on_status_update)
        self.kvm_worker.update_progress_display.connect(self.update_progress_display)
        self.kvm_worker.file_transfer_error.connect(self.on_transfer_error)
        self.kvm_thread.start()
        self.start_button.setText("KVM Szolgáltatás Leállítása")
        self.set_controls_enabled(False)

    def stop_kvm_service(self):
        if self.kvm_worker:
            self.kvm_worker.stop()

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
        settings = QSettings(ORG_NAME, APP_NAME)
        if self.radio_desktop.isChecked():
            device = 'desktop'
        elif self.radio_laptop.isChecked():
            device = 'laptop'
        else:
            device = 'elitedesk'
        settings.setValue("device/name", device)
        mode = 'ado' if device == 'desktop' else 'vevo'
        settings.setValue("role/mode", mode)
        settings.setValue("network/port", self.port.text())
        settings.setValue("monitor/host_code", self.host_code.text())
        settings.setValue("monitor/client_code", self.client_code.text())
        autostart_enabled = self.autostart_check.isChecked()
        settings.setValue("other/autostart", autostart_enabled)
        settings.setValue("other/temp_path", self.temp_path_edit.text())
        # JAVÍTÁS: Itt hívjuk meg a registry-kezelő függvényt
        try:
            set_autostart(autostart_enabled)
        except Exception as e:
            logging.error(f"Nem sikerült az autostart beállítása: {e}")

    def load_settings(self):
        settings = QSettings(ORG_NAME, APP_NAME)
        device = settings.value("device/name", "desktop")
        self.radio_desktop.setChecked(device == 'desktop')
        self.radio_laptop.setChecked(device == 'laptop')
        self.radio_elitedesk.setChecked(device == 'elitedesk')
        self.port.setText(settings.value("network/port", str(DEFAULT_PORT)))
        self.host_code.setText(settings.value("monitor/host_code", "17"))
        self.client_code.setText(settings.value("monitor/client_code", "18"))
        self.autostart_check.setChecked(
            settings.value("other/autostart", False, type=bool)
        )
        default_temp_path = QStandardPaths.writableLocation(QStandardPaths.TempLocation)
        self.temp_path_edit.setText(settings.value("other/temp_path", default_temp_path))
        self.temp_path_edit.textChanged.connect(self.save_settings)
        self.radio_desktop.toggled.connect(self.save_settings)
        self.radio_laptop.toggled.connect(self.save_settings)
        self.radio_elitedesk.toggled.connect(self.save_settings)
        self.port.textChanged.connect(self.save_settings)
        self.host_code.textChanged.connect(self.save_settings)
        self.client_code.textChanged.connect(self.save_settings)
        self.autostart_check.toggled.connect(self.save_settings)

    def set_controls_enabled(self, enabled):
        self.radio_desktop.setEnabled(enabled)
        self.radio_laptop.setEnabled(enabled)
        self.radio_elitedesk.setEnabled(enabled)
        self.port.setEnabled(enabled)
        self.host_code.setEnabled(enabled)
        self.client_code.setEnabled(enabled)
        self.autostart_check.setEnabled(enabled)

    def on_status_update(self, message):
        self.status_label.setText(message)
        logging.info(f"GUI Status Update: {message}")

    def get_temp_icon(self):
        """Return the application icon."""
        return QIcon(ICON_PATH)

    def init_tray_icon(self):
        self.tray_icon = QSystemTrayIcon(self.get_temp_icon(), self)
        self.tray_icon.setToolTip("KVM Switch")

        tray_menu = QMenu()
        show_action = QAction("Vezérlőpult", self)
        show_action.triggered.connect(self.show)
        quit_action = QAction("Kilépés", self)
        quit_action.triggered.connect(self.quit_application)

        tray_menu.addAction(show_action)
        tray_menu.addAction(quit_action)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        self.tray_icon.activated.connect(
            lambda reason: self.show()
            if reason == QSystemTrayIcon.ActivationReason.Trigger
            else None
        )

    def closeEvent(self, event):
        """Minimize the window to the tray on close."""
        event.ignore()
        self.hide()

    def quit_application(self):
        logging.info("Kilépés menüpont kiválasztva. Program leállítása.")
        self.stop_kvm_service()
        time.sleep(0.2)
        QApplication.instance().quit()

    def browse_temp_directory(self):
        """Allow selecting only drive roots and create the temp folder."""
        import string

        # Detect available drives on Windows
        drives = [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]

        if not drives:
            QMessageBox.warning(self, "Hiba", "Nem találhatók elérhető meghajtók.")
            return

        drive, ok = QInputDialog.getItem(
            self,
            "Lemez kiválasztása",
            "Válassz meghajtót az ideiglenes fájlokhoz:",
            drives,
            editable=False,
        )

        if ok and drive:
            target_dir = os.path.join(drive, *TEMP_DIR_PARTS)
            try:
                os.makedirs(target_dir, exist_ok=True)
            except OSError as e:
                QMessageBox.warning(
                    self,
                    "Hiba",
                    f"Nem sikerült a mappát létrehozni: {e}"
                )
                return

            self.temp_path_edit.setText(target_dir)
            self.save_settings()

    def share_network_file(self, cut: bool = False):
        if not self.kvm_worker:
            return
        files, _ = QFileDialog.getOpenFileNames(self, "Fájlok kiválasztása")
        if not files:
            folder = QFileDialog.getExistingDirectory(self, "Mappa kiválasztása")
            if not folder:
                return
            files = [folder]
        self.show_progress_dialog("Fájl küldése")
        op = 'cut' if cut else 'copy'
        self.kvm_worker.share_files(files, op)

    def paste_network_file(self):
        if not self.kvm_worker:
            return
        dest = QFileDialog.getExistingDirectory(self, "Cél mappa kiválasztása")
        if not dest:
            return
        self.show_progress_dialog("Fájl fogadása")
        self.kvm_worker.request_paste(dest)

    def show_progress_dialog(self, title: str):
        if self.progress_dialog:
            self.progress_dialog.close()
        self.progress_dialog = QProgressDialog("", "Mégse", 0, 100, self)
        self.progress_dialog.setWindowTitle(title)
        self.progress_dialog.canceled.connect(self.cancel_transfer)
        self.progress_dialog.setAutoClose(False)
        self.progress_dialog.setAutoReset(False)
        self.progress_dialog.setMinimumDuration(0)
        logging.info(
            "[GUI_DEBUG] show_progress_dialog called with title: %s. Current worker role: %s",
            title,
            self.kvm_worker.settings.get('role') if self.kvm_worker else 'N/A',
        )
        self.progress_dialog.setLabelText(f"{title} előkészítése...")
        logging.info("[GUI_DEBUG] show_progress_dialog: Label set to: %s", self.progress_dialog.labelText())
        self.progress_dialog.show()

    def update_progress_display(self, percentage: int, label: str):
        """Receives a pre-calculated percentage and label, and applies them directly."""
        if not self.progress_dialog or not self.progress_dialog.isVisible():
            return

        logging.info("[GUI_DEBUG] update_progress_display: Percent: %d, Label: %s", percentage, label)

        self.progress_dialog.setMaximum(100)
        self.progress_dialog.setValue(percentage)
        self.progress_dialog.setLabelText(label)

        if percentage >= 100:
            logging.info("[GUI_DEBUG] Progress complete. Starting 5s close timer.")
            try:
                cancel_button = self.progress_dialog.findChild(QPushButton)
                if cancel_button:
                    cancel_button.setEnabled(False)
                    cancel_button.setText("Kész")
            except Exception:
                pass
            QTimer.singleShot(5000, self._close_progress_dialog_if_exists)

    def _close_progress_dialog_if_exists(self):
        if self.progress_dialog:
            self.progress_dialog.close()
            self.progress_dialog = None

    def cancel_transfer(self):
        if self.kvm_worker:
            self.kvm_worker.cancel_file_transfer()
        if self.progress_dialog:
            self.progress_dialog.close()
            self.progress_dialog = None

    def on_transfer_error(self, msg: str):
        self.on_status_update(f"Hiba: {msg}")
        if self.progress_dialog:
            self.progress_dialog.close()
            self.progress_dialog = None
