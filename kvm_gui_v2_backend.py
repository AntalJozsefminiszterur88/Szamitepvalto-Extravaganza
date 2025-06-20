# kvm_switch_v4_debug.py - HIBakereső VÁLTOZAT
# Javítva: A szerver azonnal figyel a kapcsolatra.
# ÚJ: Részletes naplózás fájlba és konzolra.

import sys
import time
import socket
import json
import threading
import logging
from pynput import mouse, keyboard
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser
from monitorcontrol import get_monitors

from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QGroupBox, QRadioButton, QLabel, QLineEdit, QCheckBox, QPushButton, QGridLayout, QSystemTrayIcon, QMenu)
from PySide6.QtGui import QIcon, QAction, QPixmap
from PySide6.QtCore import QSize, QSettings, QThread, QObject, Signal

# --- NAPLÓZÁS BEÁLLÍTÁSA ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s',
    handlers=[
        logging.FileHandler("kvm_switch.log"), # Naplózás fájlba
        logging.StreamHandler(sys.stdout)     # Naplózás a konzolra is
    ]
)

class KVMWorker(QObject):
    # ... (A KVMWorker definíciója nagyrészt ugyanaz, de tele lesz logging üzenetekkel)
    finished = Signal()
    status_update = Signal(str)

    def __init__(self, settings):
        super().__init__(); self.settings = settings; self._running = True
        self.kvm_active = False; self.client_socket = None
        self.pynput_listeners = []; self.zeroconf = Zeroconf()

    def stop(self):
        logging.info("stop() metódus meghívva."); self._running = False; self.zeroconf.close()
        for listener in self.pynput_listeners:
            try: listener.stop()
            except: pass
        if self.client_socket:
            try: self.client_socket.close()
            except: pass

    def run(self):
        logging.info(f"Worker elindítva {self.settings['role']} módban.")
        if self.settings['role'] == 'ado': self.run_server()
        else: self.run_client()
        self.finished.emit()

    def run_server(self):
        # JAVÍTÁS: A TCP szervert azonnal elindítjuk, hogy fogadni tudja a kapcsolatot.
        server_thread = threading.Thread(target=self.accept_connections, daemon=True)
        server_thread.start()

        # Ezután regisztráljuk a szolgáltatást
        info = ServiceInfo("_kvmswitch._tcp.local.", f"KVM Adó._kvmswitch._tcp.local.", addresses=[socket.inet_aton(socket.gethostbyname(socket.gethostname()))], port=self.settings['port'])
        self.zeroconf.register_service(info)
        self.status_update.emit(f"Adó szolgáltatás regisztrálva. Gyorsbillentyű: Ctrl + Numpad 0")
        logging.info("Zeroconf szolgáltatás regisztrálva.")

        # Gyorsbillentyű figyelése
        hotkey_vks = {162, 96}; current_vks = set()
        def on_hotkey_press(key):
            if hasattr(key, 'vk'): current_vks.add(key.vk)
            if hotkey_vks.issubset(current_vks): self.toggle_kvm_active()
        def on_hotkey_release(key):
            if hasattr(key, 'vk'): current_vks.discard(key.vk)
        
        hotkey_listener = keyboard.Listener(on_press=on_hotkey_press, on_release=on_hotkey_release)
        self.pynput_listeners.append(hotkey_listener); hotkey_listener.start()
        logging.info("Gyorsbillentyű figyelő elindítva.")

        while self._running: time.sleep(0.5)
        hotkey_listener.stop(); logging.info("Adó szolgáltatás leállt.")

    def accept_connections(self):
        logging.info(f"TCP szerver elindítva a {self.settings['port']} porton, várakozás a kliensre.")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('', self.settings['port'])); server_socket.listen(1)
            while self._running:
                try:
                    # Ez a rész most már nem blokkolja a programot
                    self.client_socket, addr = server_socket.accept()
                    logging.info(f"Kliens csatlakozva: {addr}. A kapcsolat él.")
                    self.status_update.emit(f"Kliens csatlakozva: {addr}. Várakozás gyorsbillentyűre.")
                    # Itt lehetne kezelni a bejövő adatokat, ha a kliens is küldene
                    while self._running: time.sleep(1) 
                except Exception as e:
                    if self._running: logging.error(f"Hiba a kliens fogadásakor: {e}")
                    break

    def toggle_kvm_active(self):
        if not self.client_socket:
            self.status_update.emit("Hiba: Nincs csatlakozott kliens a váltáshoz!")
            logging.warning("Váltási kísérlet kliens kapcsolat nélkül.")
            return

        self.kvm_active = not self.kvm_active
        if self.kvm_active:
            self.status_update.emit("Állapot: Aktív. Váltás a kliensre..."); logging.info("KVM aktiválva.")
            threading.Thread(target=self.start_kvm_streaming, daemon=True).start()
        else:
            self.status_update.emit("Állapot: Inaktív. Visszaváltás a hosztra..."); logging.info("KVM deaktiválva.")
            for listener in self.pynput_listeners:
                if isinstance(listener, mouse.Listener) or isinstance(listener, keyboard.Listener) and listener != self.pynput_listeners[0]:
                    listener.stop()
            try:
                with list(get_monitors())[0] as monitor:
                    monitor.set_input_source(self.settings['monitor_codes']['host'])
            except Exception as e:
                self.status_update.emit(f"Monitor hiba: {e}"); logging.error(f"Monitor hiba: {e}")
    
    def start_kvm_streaming(self):
        logging.info("Irányítás átadása megkezdve."); try:
            with list(get_monitors())[0] as m: m.set_input_source(self.settings['monitor_codes']['client'])
        except Exception as e: logging.error(f"Monitor hiba: {e}"); self.status_update.emit(f"Monitor hiba: {e}"); self.toggle_kvm_active(); return
        last_pos = {'x': 0, 'y': 0}
        def send(data):
            try: self.client_socket.sendall(json.dumps(data).encode('utf-8') + b'\n'); return True
            except: self.toggle_kvm_active(); return False
        def on_m(x,y): dx=x-last_pos['x']; dy=y-last_pos['y']; last_pos['x'],last_pos['y']=x,y; return send({'type':'move_relative','dx':dx,'dy':dy})
        def on_c(x,y,b,p): return send({'type':'click','button':b.name,'pressed':p})
        def on_s(x,y,dx,dy): return send({'type':'scroll','dx':dx,'dy':dy})
        def on_k(k,p): key_type,key_val=('char',k.char) if hasattr(k,'char') and k.char is not None else ('special',k.name); return send({'type':'key','key_type':key_type,'key':key_val,'pressed':p})
        m_l=mouse.Listener(on_move=on_m, on_click=on_c, on_scroll=on_s, suppress=True)
        k_l=keyboard.Listener(on_press=lambda k:on_k(k,True), on_release=lambda k:on_k(k,False), suppress=True)
        self.pynput_listeners.extend([m_l,k_l]); m_l.start(); k_l.start(); m_l.join(); k_l.join()

    def run_client(self):
        class ServiceListener:
            def __init__(self, worker): self.worker, self.server_ip = worker, None
            def add_service(self, zc, type, name):
                info = zc.get_service_info(type, name)
                if info and self.server_ip is None:
                    self.server_ip=socket.inet_ntoa(info.addresses[0]); logging.info(f"Adó szolgáltatás megtalálva a {self.server_ip} címen.")
                    self.worker.status_update.emit(f"Adó megtalálva: {self.server_ip}. Csatlakozás...")
                    threading.Thread(target=self.worker.connect_to_server, args=(self.server_ip,), daemon=True).start()
            def update_service(self, zc, type, name): pass
            def remove_service(self, zc, type, name):
                self.server_ip = None; self.worker.status_update.emit("Az Adó szolgáltatás eltűnt, újra keresem...")
                logging.warning("Adó szolgáltatás eltűnt.")

        browser = ServiceBrowser(self.zeroconf, "_kvmswitch._tcp.local.", ServiceListener(self))
        logging.info("Vevő elindítva, keresi az Adó szolgáltatást."); self.status_update.emit("Vevő mód: Keresem az Adó szolgáltatást...")
        while self._running: time.sleep(0.5)

    def connect_to_server(self, server_ip):
        logging.info(f"Csatlakozási kísérlet ide: {server_ip}:{self.settings['port']}")
        mouse_controller = mouse.Controller(); keyboard_controller = keyboard.Controller()
        button_map = {'left': mouse.Button.left, 'right': mouse.Button.right, 'middle': mouse.Button.middle}
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((server_ip, self.settings['port'])); logging.info("TCP kapcsolat sikeresen létrejött.")
                self.status_update.emit(f"Csatlakozva az adóhoz. Irányítás átvéve.")
                fileobj = s.makefile('r')
                with fileobj:
                    for line in fileobj:
                        if not self._running: break
                        try:
                            data = json.loads(line.strip()); event_type = data.get('type')
                            if event_type == 'move_relative': mouse_controller.move(data['dx'], data['dy'])
                            elif event_type == 'click': b=button_map.get(data['button']); (mouse_controller.press if data['pressed'] else mouse_controller.release)(b)
                            elif event_type == 'scroll': mouse_controller.scroll(data['dx'], data['dy'])
                            elif event_type == 'key':
                                k_info=data['key']; k_press = k_info if data['key_type']=='char' else getattr(keyboard.Key, k_info, None)
                                if k_press: (keyboard_controller.press if data['pressed'] else keyboard_controller.release)(k_press)
                        except (json.JSONDecodeError, AttributeError): logging.warning(f"Hibás adatcsomag fogadva: {line.strip()}")
        except Exception as e:
            logging.error(f"Csatlakozás sikertelen: {e}", exc_info=True)
            self.status_update.emit(f"Kapcsolat sikertelen: {e}")

# A MainWindow osztály teljesen változatlan marad. Csak másold be a korábbi verzióból.
class MainWindow(QMainWindow):
    # ... A TELJES MainWindow KÓD IDE JÖN, VÁLTOZATLANUL ...
    def __init__(self):
        super().__init__();self.setWindowTitle("KVM Switch Vezérlőpult v4");central_widget = QWidget();self.setCentralWidget(central_widget);main_layout = QVBoxLayout(central_widget);role_box = QGroupBox("Szerepkör");role_layout = QVBoxLayout();self.radio_ado = QRadioButton("Adó (ez a gép irányít)");self.radio_vevo = QRadioButton("Vevő (ezt a gépet irányítják)");role_layout.addWidget(self.radio_ado);role_layout.addWidget(self.radio_vevo);role_box.setLayout(role_layout);main_layout.addWidget(role_box);network_box = QGroupBox("Hálózati Beállítások");network_layout = QGridLayout();network_layout.addWidget(QLabel("Port:"), 0, 0);self.port = QLineEdit();network_layout.addWidget(self.port, 0, 1);network_box.setLayout(network_layout);main_layout.addWidget(network_box);monitor_box = QGroupBox("Monitor Kódok (Adó módban)");monitor_layout = QGridLayout();monitor_layout.addWidget(QLabel("Hoszt (Windows) kód:"), 0, 0);self.host_code = QLineEdit("17");monitor_layout.addWidget(self.host_code, 0, 1);monitor_layout.addWidget(QLabel("Kliens (másik gép) kód:"), 1, 0);self.client_code = QLineEdit("18");monitor_layout.addWidget(self.client_code, 1, 1);monitor_box.setLayout(monitor_layout);main_layout.addWidget(monitor_box);other_box = QGroupBox("Egyéb Beállítások");other_layout = QGridLayout();other_layout.addWidget(QLabel("Gyorsbillentyű (Adó módban):"), 0, 0);self.hotkey_label = QLabel("Ctrl + Numpad 0");other_layout.addWidget(self.hotkey_label, 0, 1);self.autostart_check = QCheckBox("Automatikus indulás a Windows-szal");other_layout.addWidget(self.autostart_check, 1, 0, 1, 2);other_box.setLayout(other_layout);main_layout.addWidget(other_box);self.start_button = QPushButton("KVM Szolgáltatás Indítása");self.start_button.clicked.connect(self.toggle_kvm_service);main_layout.addWidget(self.start_button);self.status_label = QLabel("Állapot: Inaktív");main_layout.addWidget(self.status_label);self.kvm_thread = None;self.kvm_worker = None;self.init_tray_icon();self.load_settings()
    def get_settings(self): return {'role': 'ado' if self.radio_ado.isChecked() else 'vevo','port': int(self.port.text()),'monitor_codes': {'host': int(self.host_code.text()),'client': int(self.client_code.text())}}
    def toggle_kvm_service(self):
        if self.kvm_thread and self.kvm_thread.isRunning(): self.stop_kvm_service()
        else: self.start_kvm_service()
    def start_kvm_service(self):
        self.kvm_thread = QThread();self.kvm_worker = KVMWorker(self.get_settings());self.kvm_worker.moveToThread(self.kvm_thread);self.kvm_thread.started.connect(self.kvm_worker.run);self.kvm_worker.finished.connect(self.kvm_thread.quit);self.kvm_worker.finished.connect(self.kvm_worker.deleteLater);self.kvm_thread.finished.connect(self.kvm_thread.deleteLater);self.kvm_worker.finished.connect(self.on_service_stopped);self.kvm_worker.status_update.connect(self.on_status_update);self.kvm_thread.start();self.start_button.setText("KVM Szolgáltatás Leállítása");self.set_controls_enabled(False)
    def stop_kvm_service(self):
        if self.kvm_worker: self.kvm_worker.stop()
    def on_service_stopped(self):
        self.kvm_thread, self.kvm_worker = None, None;self.start_button.setText("KVM Szolgáltatás Indítása");self.on_status_update("Állapot: Inaktív");self.set_controls_enabled(True)
    def save_settings(self): settings = QSettings("MyKVM", "KVMApp");settings.setValue("role/is_ado", self.radio_ado.isChecked());settings.setValue("network/port", self.port.text());settings.setValue("monitor/host_code", self.host_code.text());settings.setValue("monitor/client_code", self.client_code.text());settings.setValue("other/autostart", self.autostart_check.isChecked())
    def load_settings(self): settings = QSettings("MyKVM", "KVMApp");self.radio_ado.setChecked(settings.value("role/is_ado", True, type=bool));self.port.setText(settings.value("network/port", "65432"));self.host_code.setText(settings.value("monitor/host_code", "17"));self.client_code.setText(settings.value("monitor/client_code", "18"));self.autostart_check.setChecked(settings.value("other/autostart", False, type=bool));self.radio_ado.toggled.connect(self.save_settings);self.port.textChanged.connect(self.save_settings);self.host_code.textChanged.connect(self.save_settings);self.client_code.textChanged.connect(self.save_settings);self.autostart_check.toggled.connect(self.save_settings)
    def set_controls_enabled(self, enabled): self.radio_ado.setEnabled(enabled);self.radio_vevo.setEnabled(enabled);self.port.setEnabled(enabled);self.host_code.setEnabled(enabled);self.client_code.setEnabled(enabled);self.autostart_check.setEnabled(enabled)
    def on_status_update(self, message): self.status_label.setText(message)
    def get_temp_icon(self): pixmap = QPixmap(QSize(32, 32));pixmap.fill(self.palette().color(self.backgroundRole()));return QIcon(pixmap)
    def init_tray_icon(self): self.tray_icon = QSystemTrayIcon(self.get_temp_icon(), self);self.tray_icon.setToolTip("KVM Switch");tray_menu = QMenu();show_action = QAction("Vezérlőpult", self);show_action.triggered.connect(self.show);quit_action = QAction("Kilépés", self);quit_action.triggered.connect(self.quit_application);tray_menu.addAction(show_action);tray_menu.addAction(quit_action);self.tray_icon.setContextMenu(tray_menu);self.tray_icon.show();self.tray_icon.activated.connect(lambda r: self.show() if r == QSystemTrayIcon.ActivationReason.Trigger else None)
    def closeEvent(self, event): event.ignore();self.hide()
    def quit_application(self): self.stop_kvm_service();time.sleep(0.1);QApplication.instance().quit()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
