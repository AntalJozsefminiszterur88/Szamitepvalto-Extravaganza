# gui.py - VÉGLEGES
# Hozzáadva a tényleges autostart logika.

import sys
import time
import logging
import os
import subprocess

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
    QToolTip,
)
from PySide6.QtGui import QIcon, QAction, QCursor
from PySide6.QtCore import QSize, QSettings, QThread, Qt, QTimer


IS_WINDOWS = sys.platform.startswith("win")

if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    _MOUSEEVENTF_MOVE = 0x0001

    try:
        _user32 = ctypes.WinDLL("user32", use_last_error=True)
        _mouse_event = _user32.mouse_event

        try:
            _ulong_ptr_type = wintypes.ULONG_PTR  # type: ignore[attr-defined]
        except AttributeError:
            _ulong_ptr_type = (
                ctypes.c_ulonglong
                if ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulonglong)
                else ctypes.c_ulong
            )

        _mouse_event.argtypes = [
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            _ulong_ptr_type,
        ]
        _mouse_event.restype = None
    except (AttributeError, OSError) as exc:  # pragma: no cover - platform dependent
        logging.debug("Nem sikerült inicializálni a Windows mouse_event hívást: %s", exc)
        _mouse_event = None
else:
    _mouse_event = None


def _nudge_mouse_cursor() -> bool:
    """Generate a native mouse move event in place if possible."""
    if not IS_WINDOWS or _mouse_event is None:
        return False
    try:  # pragma: no cover - Windows specifikus hívás
        _mouse_event(_MOUSEEVENTF_MOVE, 0, 0, 0, 0)
    except OSError as exc:
        logging.debug("Windows mouse_event hívás sikertelen: %s", exc)
        return False
    return True


from worker import KVMWorker
from config import APP_NAME, ORG_NAME, DEFAULT_PORT, ICON_PATH


# gui.py -> JAVÍTOTT, HELYES IDÉZŐJELEZÉSŰ set_autostart függvény

def set_autostart(enabled: bool) -> None:
    """Enable or disable autostart using the Task Scheduler for higher priority."""
    app_name = "MyKVM_Start"  # A feladat neve a Feladatütemezőben

    try:
        if enabled:
            # Összeállítjuk az indítandó parancsot és az argumentumait
            if getattr(sys, "frozen", False):  # Ha PyInstaller exe-ként fut
                executable = f'"{sys.executable}"'
                arguments = '--tray'
            else:  # Ha sima python szkriptként fut
                executable = f'"{sys.executable.replace("python.exe", "pythonw.exe")}"'
                script_path = os.path.join(os.path.dirname(__file__), "main.py")
                arguments = f'"{script_path}" --tray'

            # --- JAVÍTOTT RÉSZ ---
            # A teljes futtatandó parancs egyetlen stringként,
            # amit a schtasks helyesen tud értelmezni.
            task_run_command = f"{executable} {arguments}"

            command = [
                'schtasks', '/Create', '/TN', app_name,
                '/TR', task_run_command,  # Itt már a tiszta stringet adjuk át
                '/SC', 'ONLOGON', '/RL', 'HIGHEST', '/F'
            ]

            logging.info(f"Autostart feladat létrehozása: {' '.join(command)}")
            # A shell=True itt fontos, hogy a Windows helyesen értelmezze a parancsot
            result = subprocess.run(command, check=True, shell=True, capture_output=True, text=True)
            logging.info("Automatikus indulás (Feladatütemező) sikeresen beállítva. Kimenet: %s", result.stdout)

        else:
            command = ['schtasks', '/Delete', '/TN', app_name, '/F']
            logging.info(f"Autostart feladat törlése: {' '.join(command)}")
            result = subprocess.run(command, check=True, shell=True, capture_output=True, text=True)
            logging.info("Automatikus indulás (Feladatütemező) sikeresen törölve. Kimenet: %s", result.stdout)

    except subprocess.CalledProcessError as e:
        # Ha a parancs hibával tér vissza, kiírjuk a hibaüzenetét is
        logging.error("Hiba az automatikus indulás beállításakor (schtasks). Visszatérési kód: %d", e.returncode)
        logging.error("Schtasks HIBA kimenet: %s", e.stderr)
        # Itt jön a jogosultsági probléma gyanúja
        if e.returncode == 1 and ("Access is denied" in e.stderr or "A hozzáférés megtagadva" in e.stderr):
            logging.error(">>> A hiba oka valószínűleg a hiányzó RENDSZERGAZDAI JOGOSULTSÁG. <<<")
            # Itt jelezhetnénk a felhasználónak is a GUI-n, ha szükséges
    except FileNotFoundError:
        logging.info("Autostart beállítás kihagyva: nem támogatott platform (schtasks nem található).")


class MainWindow(QMainWindow):
    __slots__ = (
        'radio_desktop', 'radio_laptop', 'radio_elitedesk', 'port',
        'host_code', 'client_code', 'hotkey_label', 'autostart_check',
        'start_button', 'status_label', 'kvm_thread', 'kvm_worker',
        'tray_icon', 'tray_hover_timer', '_tray_hover_visible',
        '_tray_hover_via_tooltip'
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
        self.radio_desktop = QRadioButton("Asztali gép (bemeneti forrás)")
        self.radio_laptop = QRadioButton("Laptop (kliens)")
        self.radio_elitedesk = QRadioButton("EliteDesk (központi vezérlő)")
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
            "Pico gombok: F13 → Asztali gép | F14 → Laptop | F15 → EliteDesk. "
            "Billentyűzet: Shift + Num0 vissza asztalra, Shift + Num1 laptop, Shift + Num2 EliteDesk."
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
        self.status_label.setFixedHeight(90)
        main_layout.addWidget(self.status_label)

        self.kvm_thread = None
        self.kvm_worker = None
        self.init_tray_icon()
        self.load_settings()

    def get_settings(self):
        if self.radio_elitedesk.isChecked():
            mode = 'ado'
            device = 'elitedesk'
        elif self.radio_desktop.isChecked():
            mode = 'input_provider'
            device = 'desktop'
        else:
            mode = 'vevo'
            device = 'laptop'
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
        """Start the background KVM worker and temporarily disable the start
        button to avoid duplicate launches from rapid clicks."""
        self.kvm_thread = QThread()
        self.kvm_worker = KVMWorker(self.get_settings())
        self.kvm_worker.moveToThread(self.kvm_thread)
        self.kvm_thread.started.connect(self.kvm_worker.run)
        self.kvm_worker.finished.connect(self.on_service_stopped)
        self.kvm_worker.status_update.connect(self.on_status_update)
        self.kvm_thread.start()
        self.start_button.setText("KVM Szolgáltatás Leállítása")
        # Prevent accidental double starts
        self.start_button.setEnabled(False)
        QTimer.singleShot(1000, lambda: self.start_button.setEnabled(True))
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
        if self.radio_elitedesk.isChecked():
            device = 'elitedesk'
            mode = 'ado'
        elif self.radio_desktop.isChecked():
            device = 'desktop'
            mode = 'input_provider'
        else:
            device = 'laptop'
            mode = 'vevo'
        settings.setValue("device/name", device)
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
        # Ensure the autostart registry entry always references the
        # currently running executable if the option is enabled.
        if self.autostart_check.isChecked():
            try:
                set_autostart(True)
            except Exception as e:
                logging.error("Nem sikerült az autostart frissítése: %s", e)
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
        self._tray_hover_visible = False
        self._tray_hover_via_tooltip = False
        self.tray_hover_timer = QTimer(self)
        self.tray_hover_timer.setInterval(200)
        self.tray_hover_timer.timeout.connect(self._update_tray_hover_tooltip)
        self.tray_hover_timer.start()

    def _update_tray_hover_tooltip(self):
        """Ensure the tray tooltip is shown even for synthetic hover events."""
        if not self.tray_icon or not self.tray_icon.isVisible():
            if self._tray_hover_visible:
                self._hide_manual_tray_tooltip()
                self._tray_hover_visible = False
            return

        geometry_func = getattr(self.tray_icon, 'geometry', None)
        if not callable(geometry_func):
            if self._tray_hover_visible:
                self._hide_manual_tray_tooltip()
                self._tray_hover_visible = False
            return

        tray_rect = geometry_func()
        if tray_rect is None or tray_rect.isNull():
            if self._tray_hover_visible:
                self._hide_manual_tray_tooltip()
                self._tray_hover_visible = False
            return

        cursor_pos = QCursor.pos()
        if tray_rect.contains(cursor_pos):
            if not self._tray_hover_visible:
                used_native_hover = False
                if IS_WINDOWS:
                    used_native_hover = self._trigger_windows_tray_hover()
                if not used_native_hover:
                    tooltip_text = self.tray_icon.toolTip()
                    if tooltip_text:
                        QToolTip.showText(cursor_pos, tooltip_text)
                        self._tray_hover_via_tooltip = True
                else:
                    self._tray_hover_via_tooltip = False
                self._tray_hover_visible = True
        elif self._tray_hover_visible:
            self._hide_manual_tray_tooltip()
            self._tray_hover_visible = False

    def _hide_manual_tray_tooltip(self) -> None:
        if self._tray_hover_via_tooltip:
            QToolTip.hideText()
            self._tray_hover_via_tooltip = False

    def _trigger_windows_tray_hover(self) -> bool:
        return _nudge_mouse_cursor()

    def closeEvent(self, event):
        """Minimize the window to the tray on close."""
        event.ignore()
        self.hide()

    def quit_application(self):
        logging.critical("Alkalmazás szabályos leállítása a felhasználó által (Kilépés menü).")
        logging.info("Kilépés menüpont kiválasztva. Program leállítása.")
        if hasattr(self, 'tray_hover_timer') and self.tray_hover_timer:
            self.tray_hover_timer.stop()
        if self._tray_hover_visible:
            self._hide_manual_tray_tooltip()
            self._tray_hover_visible = False
        self.stop_kvm_service()
        time.sleep(0.2)
        QApplication.instance().quit()
