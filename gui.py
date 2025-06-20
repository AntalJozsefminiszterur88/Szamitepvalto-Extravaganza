# gui.py - VÉGLEGES
# Hozzáadva a tényleges autostart logika.

import sys
import time
import logging
import winreg  # A Registry kezeléséhez (csak Windows-on működik)
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QGroupBox,
    QRadioButton,
    QLabel,
    QLineEdit,
    QCheckBox,
    QPushButton,
    QGridLayout,
    QSystemTrayIcon,
    QMenu,
)
from PySide6.QtGui import QIcon, QAction, QPixmap
from PySide6.QtCore import QSize, QSettings, QThread

from worker import KVMWorker
from config import APP_NAME, ORG_NAME, DEFAULT_PORT, ICON_PATH

def set_autostart(enabled):
    """Be- vagy kikapcsolja az automatikus indulást a Windows Registry-ben."""
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    app_name = "KVM_Switch"
    try:
        reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
        if enabled:
            # sys.executable a python.exe útvonala, `__file__` a szkript útvonala
            app_path = f'"{sys.executable}" "{__file__}"'
            winreg.SetValueEx(reg_key, app_name, 0, winreg.REG_SZ, app_path)
            logging.info(f"Automatikus indulás bekapcsolva. Útvonal: {app_path}")
        else:
            winreg.DeleteValue(reg_key, app_name)
            logging.info("Automatikus indulás kikapcsolva.")
        winreg.CloseKey(reg_key)
    except FileNotFoundError:
        logging.warning("Automatikus indulás kikapcsolva (kulcs nem létezett).")
    except Exception as e:
        logging.error(f"Hiba az automatikus indulás beállításakor: {e}")

class MainWindow(QMainWindow):
    # A MainWindow többi része változatlan...
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KVM Switch Vezérlőpult v7")
        self.setWindowIcon(QIcon(ICON_PATH))

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        role_box = QGroupBox("Szerepkör")
        role_layout = QVBoxLayout()
        self.radio_ado = QRadioButton("Adó (ez a gép irányít)")
        self.radio_vevo = QRadioButton("Vevő (ezt a gépet irányítják)")
        role_layout.addWidget(self.radio_ado)
        role_layout.addWidget(self.radio_vevo)
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
            "Automatikus indulás a Windows-szal"
        )
        other_layout.addWidget(self.autostart_check, 1, 0, 1, 2)
        other_box.setLayout(other_layout)
        main_layout.addWidget(other_box)

        self.start_button = QPushButton("KVM Szolgáltatás Indítása")
        self.start_button.clicked.connect(self.toggle_kvm_service)
        main_layout.addWidget(self.start_button)

        self.status_label = QLabel("Állapot: Inaktív")
        main_layout.addWidget(self.status_label)

        self.kvm_thread = None
        self.kvm_worker = None
        self.init_tray_icon()
        self.load_settings()
    def get_settings(self):
        return {
            'role': 'ado' if self.radio_ado.isChecked() else 'vevo',
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
        settings.setValue("role/is_ado", self.radio_ado.isChecked())
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
        is_ado = settings.value("role/is_ado", True, type=bool)
        self.radio_ado.setChecked(is_ado)
        self.radio_vevo.setChecked(not is_ado)
        self.port.setText(settings.value("network/port", str(DEFAULT_PORT)))
        self.host_code.setText(settings.value("monitor/host_code", "17"))
        self.client_code.setText(settings.value("monitor/client_code", "18"))
        self.autostart_check.setChecked(
            settings.value("other/autostart", False, type=bool)
        )
        self.radio_ado.toggled.connect(self.save_settings)
        self.port.textChanged.connect(self.save_settings)
        self.host_code.textChanged.connect(self.save_settings)
        self.client_code.textChanged.connect(self.save_settings)
        self.autostart_check.toggled.connect(self.save_settings)
    def set_controls_enabled(self, enabled):
        self.radio_ado.setEnabled(enabled)
        self.radio_vevo.setEnabled(enabled)
        self.port.setEnabled(enabled)
        self.host_code.setEnabled(enabled)
        self.client_code.setEnabled(enabled)
        self.autostart_check.setEnabled(enabled)
        self.start_button.setEnabled(enabled)
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
        event.ignore()
        self.hide()
    def quit_application(self):
        logging.info("Kilépés menüpont kiválasztva. Program leállítása.")
        self.stop_kvm_service()
        time.sleep(0.2)
        QApplication.instance().quit()
