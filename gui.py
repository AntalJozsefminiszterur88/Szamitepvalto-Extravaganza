# gui.py - VÉGLEGES
# Hozzáadva a tényleges autostart logika.

import sys
import time
import logging
import os

# Windows specific module only available on that platform
if sys.platform.startswith("win"):
    import winreg  # type: ignore
else:  # pragma: no cover - platform specific
    winreg = None
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
    QMessageBox,
)
from PySide6.QtGui import QIcon, QAction, QPixmap
from PySide6.QtCore import QSize, QSettings, QThread, Qt

from worker import KVMWorker
from config import APP_NAME, ORG_NAME, DEFAULT_PORT, ICON_PATH

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
    elif sys.platform.startswith("linux"):

        autostart_dir = os.path.join(os.path.expanduser("~"), ".config", "autostart")
        os.makedirs(autostart_dir, exist_ok=True)
        desktop_file = os.path.join(autostart_dir, "KVM_Switch.desktop")

        if enabled:
            if getattr(sys, "frozen", False):
                exec_cmd = f"{sys.executable} --tray"
            else:
                script = os.path.join(os.path.dirname(__file__), "main.py")
                exec_cmd = f"{sys.executable} {script} --tray"
            desktop_contents = (
                "[Desktop Entry]\n"
                "Type=Application\n"
                f"Exec={exec_cmd}\n"
                "Hidden=false\n"
                "NoDisplay=false\n"
                "X-GNOME-Autostart-enabled=true\n"
                "Name=KVM Switch\n"
            )
            with open(desktop_file, "w", encoding="utf-8") as f:
                f.write(desktop_contents)
            logging.info("Autostart engedélyezve Linuxon: %s", desktop_file)
        else:
            try:
                os.remove(desktop_file)
                logging.info("Automatikus indulás kikapcsolva Linuxon.")
            except FileNotFoundError:
                logging.info("Autostart kikapcsolása: a fájl nem létezett.")
    else:
        logging.info("Autostart beállítás kihagyva: nem támogatott platform.")

class MainWindow(QMainWindow):
    __slots__ = (
        'radio_desktop', 'radio_laptop', 'radio_elitedesk', 'port',
        'host_code', 'client_code', 'hotkey_label', 'autostart_check',
        'start_button', 'status_label', 'kvm_thread', 'kvm_worker',
        'tray_icon'
    )

    # A MainWindow többi része változatlan...
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KVM Switch Vezérlőpult v7")
        self.setWindowIcon(QIcon(ICON_PATH))
        # Prevent resizing during runtime
        self.setFixedSize(QSize(450, 400))

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
            "Laptop: Ctrl + Numpad 0 | ElitDesk: Ctrl + Numpad 1"
        )
        other_layout.addWidget(self.hotkey_label, 0, 1)
        self.autostart_check = QCheckBox(
            "Automatikus indulás a rendszerrel"
        )
        other_layout.addWidget(self.autostart_check, 1, 0, 1, 2)
        other_box.setLayout(other_layout)
        main_layout.addWidget(other_box)

        self.start_button = QPushButton("KVM Szolgáltatás Indítása")
        self.start_button.clicked.connect(self.toggle_kvm_service)
        main_layout.addWidget(self.start_button)

        self.status_label = QLabel("Állapot: Inaktív")
        self.status_label.setWordWrap(True)
        self.status_label.setAlignment(Qt.AlignTop)
        self.status_label.setFixedHeight(70)
        main_layout.addWidget(self.status_label)

        self.kvm_thread = None
        self.kvm_worker = None
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
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Bezárás")
        dialog.setText("Mit szeretne tenni?")
        minimize_btn = dialog.addButton(
            "Tálcára helyezés", QMessageBox.AcceptRole
        )
        quit_btn = dialog.addButton("Kilépés", QMessageBox.DestructiveRole)
        cancel_btn = dialog.addButton("Mégse", QMessageBox.RejectRole)
        dialog.setDefaultButton(minimize_btn)
        dialog.exec()

        clicked = dialog.clickedButton()
        if clicked == minimize_btn:
            event.ignore()
            self.hide()
        elif clicked == quit_btn:
            event.accept()
            self.quit_application()
        else:
            event.ignore()
    def quit_application(self):
        logging.info("Kilépés menüpont kiválasztva. Program leállítása.")
        self.stop_kvm_service()
        time.sleep(0.2)
        QApplication.instance().quit()
