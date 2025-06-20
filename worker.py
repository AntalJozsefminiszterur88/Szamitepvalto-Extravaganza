# worker.py - VÉGLEGES JAVÍTOTT VERZIÓ
# Javítva: Streaming listener `AttributeError`, "sticky key" hiba, visszaváltási logika, egér-akadás.

import socket, json, time, threading, logging, tkinter
from pynput import mouse, keyboard
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser
from monitorcontrol import get_monitors
from PySide6.QtCore import QObject, Signal
from config import SERVICE_TYPE, SERVICE_NAME_PREFIX, VK_CTRL, VK_NUMPAD0

class KVMWorker(QObject):
    finished = Signal()
    status_update = Signal(str)

    def __init__(self, settings):
        super().__init__()
        self.settings = settings
        self._running = True
        self.kvm_active = False
        self.client_socket = None
        self.pynput_listeners = []
        self.zeroconf = Zeroconf()
        self.streaming_thread = None

    def stop(self):
        logging.info("stop() metódus meghívva.")
        self._running = False
        if self.kvm_active:
            self.deactivate_kvm(switch_monitor=False) # Leállításkor ne váltson monitort
        try:
            self.zeroconf.close()
        except:
            pass
        for listener in self.pynput_listeners:
            try:
                listener.stop()
            except:
                pass
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass

    def run(self):
        logging.info(f"Worker elindítva {self.settings['role']} módban.")
        if self.settings['role'] == 'ado':
            self.run_server()
        else:
            self.run_client()
        self.finished.emit()

    def run_server(self):
        accept_thread = threading.Thread(target=self.accept_connections, daemon=True, name="AcceptThread")
        accept_thread.start()
        
        info = ServiceInfo(
            SERVICE_TYPE,
            f"{SERVICE_NAME_PREFIX}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(socket.gethostbyname(socket.gethostname()))],
            port=self.settings['port']
        )
        self.zeroconf.register_service(info)
        self.status_update.emit(f"Adó szolgáltatás regisztrálva. Gyorsbillentyű: Ctrl + Numpad 0")
        logging.info("Zeroconf szolgáltatás regisztrálva.")

        hotkey_ids = {keyboard.Key.ctrl_l, 96}
        hotkey_ids_r = {keyboard.Key.ctrl_r, 96}
        current_pressed_ids = set()

        def get_id(key):
            return key.vk if hasattr(key, 'vk') and key.vk is not None else key

        def on_press(key):
            key_id = get_id(key)
            current_pressed_ids.add(key_id)
            if hotkey_ids.issubset(current_pressed_ids) or hotkey_ids_r.issubset(current_pressed_ids):
                logging.info("!!! Gyorsbillentyű-kombináció ÉSZLELVE! Váltás... !!!")
                self.toggle_kvm_active()

        def on_release(key):
            key_id = get_id(key)
            current_pressed_ids.discard(key_id)
        
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
                server_socket.bind(('', self.settings['port']))
                server_socket.listen(1)
                logging.info(f"TCP szerver elindítva a {self.settings['port']} porton.")
                while self._running:
                    self.client_socket, addr = server_socket.accept()
                    logging.info(f"Kliens csatlakozva: {addr}.")
                    self.status_update.emit(f"Kliens csatlakozva: {addr}. Várakozás gyorsbillentyűre.")
                    while self._running and self.client_socket:
                        try:
                            if self.client_socket.recv(1, socket.MSG_PEEK) == b'':
                                break
                        except (socket.error, BrokenPipeError):
                            break
                        time.sleep(1)
                    logging.warning("Kliens lecsatlakozott.")
                    if self.kvm_active:
                        self.deactivate_kvm()
                    self.client_socket = None
        except Exception as e:
            if self._running:
                logging.error(f"Hiba a kliens fogadásakor: {e}", exc_info=True)

    def toggle_kvm_active(self):
        if not self.kvm_active:
            self.activate_kvm()
        else:
            self.deactivate_kvm()

    def activate_kvm(self):
        if not self.client_socket:
            self.status_update.emit("Hiba: Nincs csatlakozott kliens a váltáshoz!")
            logging.warning("Váltási kísérlet kliens kapcsolat nélkül.")
            return
        
        self.kvm_active = True
        self.status_update.emit("Állapot: Aktív...")
        logging.info("KVM aktiválva.")
        self.streaming_thread = threading.Thread(target=self.start_kvm_streaming, daemon=True, name="StreamingThread")
        self.streaming_thread.start()

    def deactivate_kvm(self, switch_monitor=True):
        self.kvm_active = False
        self.status_update.emit("Állapot: Inaktív...")
        logging.info("KVM deaktiválva.")
        
        # A monitor visszaváltást a toggle metódus végzi, miután a streaming szál leállt
        if switch_monitor:
            # Itt egy kis időt adunk a streaming szálnak a leállásra, mielőtt váltunk
            time.sleep(0.2)
            try:
                with list(get_monitors())[0] as monitor:
                    monitor.set_input_source(self.settings['monitor_codes']['host'])
                    logging.info("Monitor sikeresen visszaváltva a hosztra.")
            except Exception as e:
                self.status_update.emit(f"Monitor hiba: {e}")
                logging.error(f"Monitor hiba: {e}", exc_info=True)
    
    def start_kvm_streaming(self):
        logging.info("Irányítás átadása megkezdve.")
        try:
            with list(get_monitors())[0] as monitor:
                monitor.set_input_source(self.settings['monitor_codes']['client'])
        except Exception as e:
            logging.error(f"Monitor hiba: {e}", exc_info=True)
            self.status_update.emit(f"Monitor hiba: {e}")
            self.deactivate_kvm()
            return
        
        host_mouse_controller = mouse.Controller()
        try:
            root = tkinter.Tk()
            root.withdraw()
            center_x, center_y = root.winfo_screenwidth()//2, root.winfo_screenheight()//2
            root.destroy()
        except:
            center_x, center_y = 800, 600
        
        host_mouse_controller.position = (center_x, center_y)
        last_pos = {'x': center_x, 'y': center_y}
        is_warping = False

        def send(data):
            if not self.kvm_active: return False
            try:
                self.client_socket.sendall(json.dumps(data).encode('utf-8') + b'\n')
                return True
            except:
                self.deactivate_kvm()
                return False

        def on_move(x, y):
            nonlocal is_warping
            if is_warping:
                is_warping = False
                return
            dx = x - last_pos['x']
            dy = y - last_pos['y']
            if dx != 0 or dy != 0:
                send({'type': 'move_relative', 'dx': dx, 'dy': dy})
            is_warping = True
            host_mouse_controller.position = (center_x, center_y)
            last_pos['x'], last_pos['y'] = center_x, center_y

        def on_click(x,y,b,p):
            send({'type':'click','button':b.name,'pressed':p})

        def on_scroll(x,y,dx,dy):
            send({'type':'scroll','dx':dx,'dy':dy})
        
        def on_key(k, p):
            """Forward keyboard events to the client without raising errors."""
            try:
                if hasattr(k, "char") and k.char is not None:
                    key_type = "char"
                    key_val = k.char
                elif hasattr(k, "name"):
                    key_type = "special"
                    key_val = k.name
                elif hasattr(k, "vk"):
                    key_type = "vk"
                    key_val = k.vk
                else:
                    logging.warning(f"Ismeretlen billentyű: {k}")
                    return False

                if not send({"type": "key", "key_type": key_type, "key": key_val, "pressed": p}):
                    return False
            except Exception as e:
                logging.error(f"Hiba az on_key függvényben: {e}", exc_info=True)
                return False

        m_listener = mouse.Listener(on_move=on_move, on_click=on_click, on_scroll=on_scroll, suppress=True)
        k_listener = keyboard.Listener(on_press=lambda k:on_key(k,True), on_release=lambda k:on_key(k,False), suppress=True)
        
        m_listener.start()
        k_listener.start()
        
        while self.kvm_active and self._running:
            time.sleep(0.1)
        
        m_listener.stop()
        k_listener.stop()
        logging.info("Streaming listenerek leálltak.")

    def run_client(self):
        class ServiceListener:
            def __init__(self, worker):
                self.worker = worker
                self.server_ip = None
            def add_service(self, zc, type, name):
                info = zc.get_service_info(type, name)
                if info and self.server_ip is None:
                    self.server_ip=socket.inet_ntoa(info.addresses[0])
                    logging.info(f"Adó szolgáltatás megtalálva a {self.server_ip} címen.")
                    self.worker.status_update.emit(f"Adó megtalálva: {self.server_ip}. Csatlakozás...")
                    threading.Thread(target=self.worker.connect_to_server, args=(self.server_ip,), daemon=True, name="ConnectThread").start()
            def update_service(self, zc, type, name):
                pass
            def remove_service(self, zc, type, name):
                self.server_ip=None
                self.worker.status_update.emit("Az Adó szolgáltatás eltűnt, újra keresem...")
                logging.warning("Adó szolgáltatás eltűnt.")

        browser = ServiceBrowser(self.zeroconf, SERVICE_TYPE, ServiceListener(self))
        self.status_update.emit("Vevő mód: Keresem az Adó szolgáltatást...")
        while self._running:
            time.sleep(0.5)

    def connect_to_server(self, server_ip):
        mouse_controller = mouse.Controller()
        keyboard_controller = keyboard.Controller()
        button_map = {'left': mouse.Button.left, 'right': mouse.Button.right, 'middle': mouse.Button.middle}
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((server_ip, self.settings['port']))
                logging.info("TCP kapcsolat sikeres.")
                self.status_update.emit(f"Csatlakozva. Irányítás átvéve.")
                fileobj = s.makefile('r')
                with fileobj:
                    for line in fileobj:
                        if not self._running: break
                        try:
                            data = json.loads(line.strip())
                            event_type = data.get('type')
                            if event_type == 'move_relative':
                                mouse_controller.move(data['dx'], data['dy'])
                            elif event_type == 'click':
                                b=button_map.get(data['button'])
                                if b:
                                    (mouse_controller.press if data['pressed'] else mouse_controller.release)(b)
                            elif event_type == 'scroll':
                                mouse_controller.scroll(data['dx'], data['dy'])
                            elif event_type == 'key':
                                k_info=data['key']
                                if data['key_type'] == 'char':
                                    k_press = k_info
                                elif data['key_type'] == 'special':
                                    k_press = getattr(keyboard.Key, k_info, None)
                                elif data['key_type'] == 'vk':
                                    k_press = keyboard.KeyCode.from_vk(int(k_info))
                                else:
                                    k_press = None
                                if k_press:
                                    (keyboard_controller.press if data['pressed'] else keyboard_controller.release)(k_press)
                        except (json.JSONDecodeError, AttributeError):
                            logging.warning(f"Hibás adatcsomag: {line.strip()}")
        except Exception as e:
            logging.error(f"Csatlakozás sikertelen: {e}", exc_info=True)
            self.status_update.emit(f"Kapcsolat sikertelen: {e}")
