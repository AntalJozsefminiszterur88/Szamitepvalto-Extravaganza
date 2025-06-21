# worker.py - VÉGLEGES JAVÍTOTT VERZIÓ
# Javítva: Streaming listener `AttributeError`, "sticky key" hiba, visszaváltási logika, egér-akadás.

import socket, time, threading, logging, tkinter, queue, struct
import msgpack
from pynput import mouse, keyboard
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser
from monitorcontrol import get_monitors
from PySide6.QtCore import QObject, Signal
from config import SERVICE_TYPE, SERVICE_NAME_PREFIX, VK_CTRL, VK_CTRL_R, VK_NUMPAD0, VK_NUMPAD1, VK_F12

# Delay between iterations in the streaming loop to lower CPU usage
STREAM_LOOP_DELAY = 0.05

class KVMWorker(QObject):
    __slots__ = (
        'settings', '_running', 'kvm_active', 'client_sockets', 'client_infos',
        'active_client', 'pynput_listeners', 'zeroconf', 'streaming_thread',
        'switch_monitor', 'local_ip', 'server_ip', 'connection_thread',
        'device_name'
    )

    finished = Signal()
    status_update = Signal(str)

    def __init__(self, settings):
        super().__init__()
        self.settings = settings
        self._running = True
        self.kvm_active = False
        # Active client connections (multiple receivers can connect)
        self.client_sockets = []
        # Mapping from socket to human readable client name
        self.client_infos = {}
        # Currently selected client to forward events to
        self.active_client = None
        self.pynput_listeners = []
        self.zeroconf = Zeroconf()
        self.streaming_thread = None
        self.switch_monitor = True
        self.local_ip = socket.gethostbyname(socket.gethostname())
        self.server_ip = None
        self.connection_thread = None
        self.device_name = settings.get('device_name', socket.gethostname())

    def release_hotkey_keys(self):
        """Release potential stuck hotkey keys."""
        kc = keyboard.Controller()
        keys = [
            keyboard.Key.ctrl_l,
            keyboard.Key.ctrl_r,
            keyboard.KeyCode.from_vk(VK_NUMPAD0),
            keyboard.KeyCode.from_vk(VK_NUMPAD1),
        ]
        for k in keys:
            try:
                kc.press(k)
                kc.release(k)
            except Exception:
                pass

    def set_active_client_by_name(self, name):
        """Select a connected client by name as the active target."""
        for sock, cname in self.client_infos.items():
            if cname.lower().startswith(name.lower()):
                self.active_client = sock
                logging.info(f"Active client set to {cname}")
                return True
        logging.warning(f"No client matching '{name}' found")
        return False

    def toggle_client_control(self, name: str, *, switch_monitor: bool = True) -> None:
        """Activate or deactivate control for a specific client."""
        current = self.client_infos.get(self.active_client, "").lower()
        target = name.lower()
        if self.kvm_active and current.startswith(target):
            self.deactivate_kvm()
            return
        if self.kvm_active:
            self.deactivate_kvm()
        if self.set_active_client_by_name(name):
            self.activate_kvm(switch_monitor=switch_monitor)

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
        for sock in list(getattr(self, 'client_sockets', [])):
            try:
                sock.close()
            except Exception:
                pass
        self.client_infos.clear()
        self.active_client = None
        if self.connection_thread and self.connection_thread.is_alive():
            self.connection_thread.join(timeout=1)
        # Extra safety to avoid stuck modifier keys on exit
        self.release_hotkey_keys()

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
        self.status_update.emit(f"Adó szolgáltatás regisztrálva. Gyorsbillentyű: Laptop - Ctrl + Numpad 0, ElitDesk - Ctrl + Numpad 1")
        logging.info("Zeroconf szolgáltatás regisztrálva.")

        hotkey_laptop = {keyboard.Key.ctrl_l, VK_NUMPAD0}
        hotkey_laptop_r = {keyboard.Key.ctrl_r, VK_NUMPAD0}
        hotkey_elitdesk = {keyboard.Key.ctrl_l, VK_NUMPAD1}
        hotkey_elitdesk_r = {keyboard.Key.ctrl_r, VK_NUMPAD1}
        current_pressed_ids = set()

        def get_id(key):
            return key.vk if hasattr(key, 'vk') and key.vk is not None else key

        def on_press(key):
            key_id = get_id(key)
            current_pressed_ids.add(key_id)
            if hotkey_laptop.issubset(current_pressed_ids) or hotkey_laptop_r.issubset(current_pressed_ids):
                logging.info("!!! Laptop gyorsbillentyű észlelve! Váltás... !!!")
                self.toggle_client_control('laptop', switch_monitor=False)
                current_pressed_ids.clear()
                self.release_hotkey_keys()
            elif hotkey_elitdesk.issubset(current_pressed_ids) or hotkey_elitdesk_r.issubset(current_pressed_ids):
                logging.info("!!! ElitDesk gyorsbillentyű észlelve! Váltás... !!!")
                self.toggle_client_control('elitedesk', switch_monitor=True)
                current_pressed_ids.clear()
                self.release_hotkey_keys()

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
                server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                server_socket.bind(('', self.settings['port']))
                server_socket.listen(5)
                logging.info(f"TCP szerver elindítva a {self.settings['port']} porton.")

                while self._running:
                    client_sock, addr = server_socket.accept()
                    client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    self.client_sockets.append(client_sock)
                    if self.active_client is None:
                        self.active_client = client_sock
                    logging.info(f"Kliens csatlakozva: {addr}.")
                    self.status_update.emit(f"Kliens csatlakozva: {addr}. Várakozás gyorsbillentyűre.")

                    threading.Thread(target=self.monitor_client, args=(client_sock, addr), daemon=True).start()
        except Exception as e:
            if self._running:
                logging.error(f"Hiba a kliens fogadásakor: {e}", exc_info=True)

    def monitor_client(self, sock, addr):
        """Monitor a single client connection, handle commands and remove it on disconnect."""
        sock.settimeout(1.0)
        buffer = b''

        def recv_all(s, n):
            data = b''
            while len(data) < n:
                chunk = s.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
            return data

        # Expect an initial handshake with the client name
        client_name = str(addr)
        try:
            raw_len = recv_all(sock, 4)
            if raw_len:
                msg_len = struct.unpack('!I', raw_len)[0]
                payload = recv_all(sock, msg_len)
                if payload:
                    hello = msgpack.unpackb(payload, raw=False)
                    client_name = hello.get('device_name', client_name)
        except Exception:
            pass
        self.client_infos[sock] = client_name
        logging.info(f"Client connected: {client_name} ({addr})")

        try:
            while self._running:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buffer += chunk
                    while len(buffer) >= 4:
                        msg_len = struct.unpack('!I', buffer[:4])[0]
                        if len(buffer) < 4 + msg_len:
                            break
                        payload = buffer[4:4 + msg_len]
                        buffer = buffer[4 + msg_len:]
                        try:
                            data = msgpack.unpackb(payload, raw=False)
                            cmd = data.get('command')
                            if cmd == 'switch_elitedesk':
                                self.toggle_client_control('elitedesk', switch_monitor=True)
                            elif cmd == 'switch_laptop':
                                self.toggle_client_control('laptop', switch_monitor=False)
                        except Exception:
                            logging.warning("Hibas parancs a klienstol")
                except socket.timeout:
                    continue
                except (socket.error, BrokenPipeError):
                    break
        finally:
            logging.warning(f"Kliens lecsatlakozott: {addr}.")
            try:
                sock.close()
            except Exception:
                pass
            if sock in self.client_sockets:
                self.client_sockets.remove(sock)
            if sock in self.client_infos:
                del self.client_infos[sock]
            if sock == self.active_client:
                self.active_client = None
            if self.kvm_active and not self.client_sockets:
                self.deactivate_kvm()

    def toggle_kvm_active(self, switch_monitor=True):
        """Toggle KVM state with optional monitor switching."""
        if not self.kvm_active:
            self.activate_kvm(switch_monitor=switch_monitor)
        else:
            self.deactivate_kvm(switch_monitor=switch_monitor)
        self.release_hotkey_keys()

    def activate_kvm(self, switch_monitor=True):
        if not self.client_sockets:
            self.status_update.emit("Hiba: Nincs csatlakozott kliens a váltáshoz!")
            logging.warning("Váltási kísérlet kliens kapcsolat nélkül.")
            return

        self.switch_monitor = switch_monitor
        self.kvm_active = True
        self.status_update.emit("Állapot: Aktív...")
        logging.info("KVM aktiválva.")
        self.streaming_thread = threading.Thread(target=self._streaming_loop, daemon=True, name="StreamingThread")
        self.streaming_thread.start()

    def _streaming_loop(self):
        """Keep streaming active and restart if it stops unexpectedly."""
        while self.kvm_active and self._running:
            self.start_kvm_streaming()
            if self.kvm_active and self._running:
                logging.warning("Egér szinkronizáció megszakadt, újraindítás...")
                time.sleep(1)

    def deactivate_kvm(self, switch_monitor=None):
        self.kvm_active = False
        self.status_update.emit("Állapot: Inaktív...")
        logging.info("KVM deaktiválva.")

        # A monitor visszaváltást a toggle metódus végzi, miután a streaming szál leállt
        switch = switch_monitor if switch_monitor is not None else getattr(self, 'switch_monitor', True)
        if switch:
            # Itt egy kis időt adunk a streaming szálnak a leállásra, mielőtt váltunk
            time.sleep(0.2)
            try:
                with list(get_monitors())[0] as monitor:
                    monitor.set_input_source(self.settings['monitor_codes']['host'])
                    logging.info("Monitor sikeresen visszaváltva a hosztra.")
            except Exception as e:
                self.status_update.emit(f"Monitor hiba: {e}")
                logging.error(f"Monitor hiba: {e}", exc_info=True)
        # Ensure hotkey keys are released when deactivating
        self.release_hotkey_keys()
    
    def start_kvm_streaming(self):
        logging.info("Irányítás átadása megkezdve.")
        if getattr(self, 'switch_monitor', True):
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

        send_queue = queue.Queue()

        def sender():
            while self.kvm_active and self._running:
                try:
                    payload = send_queue.get(timeout=0.1)
                except queue.Empty:
                    continue
                if payload is None:
                    logging.debug("Sender thread exiting")
                    break
                to_remove = []
                targets = [self.active_client] if self.active_client else list(self.client_sockets)
                for sock in list(targets):
                    if sock not in self.client_sockets:
                        continue
                    try:
                        sock.sendall(struct.pack('!I', len(payload)) + payload)
                        logging.debug(
                            f"Sent {len(payload)} bytes to {self.client_infos.get(sock, sock.getpeername())}"
                        )
                    except Exception as e:
                        try:
                            event = msgpack.unpackb(payload, raw=False)
                        except Exception:
                            event = '<unpack failed>'
                        logging.error(
                            f"Failed sending event {event} to {self.client_infos.get(sock, sock.getpeername())}: {e}",
                            exc_info=True,
                        )
                        to_remove.append(sock)
                for s in to_remove:
                    try:
                        s.close()
                    except Exception:
                        pass
                    if s in self.client_sockets:
                        self.client_sockets.remove(s)
                    if s in self.client_infos:
                        del self.client_infos[s]
                    if s == self.active_client:
                        self.active_client = None
                if to_remove and not self.client_sockets:
                    self.deactivate_kvm()
                    break

        sender_thread = threading.Thread(target=sender, daemon=True)
        sender_thread.start()

        def send(data):
            """Queue an event for sending and log the details."""
            if not self.kvm_active:
                logging.warning("Send called while KVM inactive")
                return False
            try:
                packed = msgpack.packb(data, use_bin_type=True)
                send_queue.put(packed)
                if data.get('type') == 'move_relative':
                    logging.info(
                        f"Egér pozíció elküldve: dx={data['dx']} dy={data['dy']}"
                    )
                else:
                    logging.debug(f"Queued event: {data}")
                return True
            except Exception as e:
                logging.error(f"Failed to queue event {data}: {e}", exc_info=True)
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
        
        pressed_keys = set()
        current_vks = set()

        def get_vk(key):
            if hasattr(key, "vk") and key.vk is not None:
                return key.vk
            if hasattr(key, "value") and hasattr(key.value, "vk"):
                return key.value.vk
            return None


        def on_key(k, p):
            """Forward keyboard events to the client and kezelje a gyorsbillentyűt."""
            try:
                vk = get_vk(k)
                if vk is not None:
                    if p:
                        current_vks.add(vk)
                    else:
                        current_vks.discard(vk)

                if ((VK_CTRL in current_vks or VK_CTRL_R in current_vks) and VK_NUMPAD0 in current_vks):
                    self.release_hotkey_keys()
                    self.toggle_kvm_active(False)
                    return
                if ((VK_CTRL in current_vks or VK_CTRL_R in current_vks) and VK_NUMPAD1 in current_vks):
                    self.release_hotkey_keys()
                    self.toggle_kvm_active(True)
                    return

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

                key_id = (key_type, key_val)
                if p:
                    pressed_keys.add(key_id)
                else:
                    pressed_keys.discard(key_id)

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
            time.sleep(STREAM_LOOP_DELAY)

        for ktype, kval in list(pressed_keys):
            send({"type": "key", "key_type": ktype, "key": kval, "pressed": False})
        pressed_keys.clear()

        m_listener.stop()
        k_listener.stop()
        send_queue.put(None)
        sender_thread.join()
        logging.info("Streaming listenerek leálltak.")

    def run_client(self):
        class ServiceListener:
            def __init__(self, worker):
                self.worker = worker
            def add_service(self, zc, type, name):
                info = zc.get_service_info(type, name)
                if info:
                    ip = socket.inet_ntoa(info.addresses[0])
                    if ip == self.worker.local_ip:
                        return  # ignore our own service
                    self.worker.server_ip = ip
                    logging.info(f"Adó szolgáltatás megtalálva a {ip} címen.")
                    self.worker.status_update.emit(f"Adó megtalálva: {ip}. Csatlakozás...")
                    if not (self.worker.connection_thread and self.worker.connection_thread.is_alive()):
                        self.worker.connection_thread = threading.Thread(target=self.worker.connect_to_server, daemon=True, name="ConnectThread")
                        self.worker.connection_thread.start()
            def update_service(self, zc, type, name):
                pass
            def remove_service(self, zc, type, name):
                self.worker.server_ip = None
                self.worker.status_update.emit("Az Adó szolgáltatás eltűnt, újra keresem...")
                logging.warning("Adó szolgáltatás eltűnt.")

        browser = ServiceBrowser(self.zeroconf, SERVICE_TYPE, ServiceListener(self))
        self.status_update.emit("Vevő mód: Keresem az Adó szolgáltatást...")
        while self._running:
            time.sleep(0.5)

    def connect_to_server(self):
        mouse_controller = mouse.Controller()
        keyboard_controller = keyboard.Controller()
        pressed_keys = set()
        button_map = {
            'left': mouse.Button.left,
            'right': mouse.Button.right,
            'middle': mouse.Button.middle,
        }
        hk_listener = None

        while self._running:
            ip = self.server_ip
            if not ip:
                time.sleep(0.5)
                continue

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    logging.info(f"Connecting to {ip}:{self.settings['port']}")
                    s.connect((ip, self.settings['port']))

                    try:
                        hello = msgpack.packb({'device_name': self.device_name}, use_bin_type=True)
                        s.sendall(struct.pack('!I', len(hello)) + hello)
                        logging.debug("Handshake sent to server")
                    except Exception as e:
                        logging.error(f"Failed to send handshake: {e}")

                    logging.info("TCP kapcsolat sikeres.")
                    self.status_update.emit("Csatlakozva. Irányítás átvéve.")

                    def send_command(cmd):
                        try:
                            packed = msgpack.packb({'command': cmd}, use_bin_type=True)
                            s.sendall(struct.pack('!I', len(packed)) + packed)
                        except Exception:
                            logging.error("Nem sikerult parancsot kuldeni", exc_info=True)

                    hotkey_cmd_l = {keyboard.Key.ctrl_l, keyboard.Key.shift_l, keyboard.KeyCode.from_vk(VK_F12)}
                    hotkey_cmd_r = {keyboard.Key.ctrl_r, keyboard.Key.shift_r, keyboard.KeyCode.from_vk(VK_F12)}
                    pressed_ids = set()

                    def get_id(key):
                        return key.vk if hasattr(key, 'vk') and key.vk is not None else key

                    def hk_press(key):
                        pressed_ids.add(get_id(key))
                        if hotkey_cmd_l.issubset(pressed_ids) or hotkey_cmd_r.issubset(pressed_ids):
                            send_command('switch_elitedesk')

                    def hk_release(key):
                        pressed_ids.discard(get_id(key))

                    hk_listener = keyboard.Listener(on_press=hk_press, on_release=hk_release)
                    hk_listener.start()

                    def recv_all(sock, n):
                        data = b''
                        while len(data) < n:
                            chunk = sock.recv(n - len(data))
                            if not chunk:
                                return None
                            data += chunk
                        return data

                    while self._running and self.server_ip == ip:
                        raw_len = recv_all(s, 4)
                        if not raw_len:
                            break
                        msg_len = struct.unpack('!I', raw_len)[0]
                        payload = recv_all(s, msg_len)
                        if payload is None:
                            break
                        try:
                            data = msgpack.unpackb(payload, raw=False)
                            logging.debug(f"Received event: {data}")
                            event_type = data.get('type')
                            if event_type == 'move_relative':
                                mouse_controller.move(data['dx'], data['dy'])
                            elif event_type == 'click':
                                b = button_map.get(data['button'])
                                if b:
                                    (mouse_controller.press if data['pressed'] else mouse_controller.release)(b)
                            elif event_type == 'scroll':
                                mouse_controller.scroll(data['dx'], data['dy'])
                            elif event_type == 'key':
                                k_info = data['key']
                                if data['key_type'] == 'char':
                                    k_press = k_info
                                elif data['key_type'] == 'special':
                                    k_press = getattr(keyboard.Key, k_info, None)
                                elif data['key_type'] == 'vk':
                                    k_press = keyboard.KeyCode.from_vk(int(k_info))
                                else:
                                    k_press = None
                                if k_press:
                                    if data['pressed']:
                                        keyboard_controller.press(k_press)
                                        pressed_keys.add(k_press)
                                    else:
                                        keyboard_controller.release(k_press)
                                        pressed_keys.discard(k_press)
                        except Exception:
                            logging.warning("Hibás adatcsomag")

            except Exception as e:
                if self._running:
                    logging.error(f"Csatlakozás sikertelen: {e}", exc_info=True)
                    self.status_update.emit(f"Kapcsolat sikertelen: {e}. Újrapróbálkozás...")

            finally:
                logging.info("Connection to server closed")
                for k in list(pressed_keys):
                    try:
                        keyboard_controller.release(k)
                    except Exception:
                        pass
                if hk_listener is not None:
                    try:
                        hk_listener.stop()
                    except Exception:
                        pass
                self.release_hotkey_keys()
                time.sleep(1)
