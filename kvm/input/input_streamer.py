import socket
import queue
import struct
import time
import logging
import threading
import tkinter

import msgpack
from pynput import mouse, keyboard
from monitorcontrol import get_monitors

from ..config import VK_NUMPAD0, VK_NUMPAD1, VK_NUMPAD2, VK_LSHIFT, VK_RSHIFT

STREAM_LOOP_DELAY = 0.05
SEND_QUEUE_MAXSIZE = 200


class InputStreamer:
    def __init__(self, worker):
        self.worker = worker
        self.thread = None
        self.sender_thread = None
        self.m_listener = None
        self.k_listener = None
        self.send_queue = None
        self.unsent_events = []
        self.host_mouse_controller = None
        self.center_x = 0
        self.center_y = 0
        self.last_pos = None
        self.is_warping = False
        self.pressed_keys = set()
        self.current_vks = set()
        self.current_special_keys = set()

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.thread = threading.Thread(target=self._run, daemon=True, name="InputStreamer")
        self.thread.start()

    def stop(self):
        self.worker.kvm_active = False
        if self.m_listener:
            try:
                self.m_listener.stop()
            except Exception:
                pass
        if self.k_listener:
            try:
                self.k_listener.stop()
            except Exception:
                pass
        if self.send_queue:
            self.send_queue.put(None)
        if self.thread and self.thread.is_alive():
            try:
                self.thread.join(timeout=0.1)
            except Exception:
                pass
        if self.sender_thread and self.sender_thread.is_alive():
            try:
                self.sender_thread.join(timeout=0.1)
            except Exception:
                pass
        self.thread = None
        self.sender_thread = None
        self.m_listener = None
        self.k_listener = None
        self.send_queue = None

    def _run(self):
        worker = self.worker
        logging.info("start_kvm_streaming: initiating control transfer")
        if getattr(worker, 'switch_monitor', True):
            try:
                with list(get_monitors())[0] as monitor:
                    monitor.set_input_source(worker.settings['monitor_codes']['client'])
            except Exception as e:
                logging.error(f"Monitor hiba: {e}", exc_info=True)
                worker.status_update.emit(f"Monitor hiba: {e}")
                worker.deactivate_kvm(reason="monitor switch failed")
                return

        self.host_mouse_controller = mouse.Controller()
        worker._host_mouse_controller = self.host_mouse_controller
        worker._orig_mouse_pos = self.host_mouse_controller.position
        try:
            root = tkinter.Tk()
            root.withdraw()
            self.center_x, self.center_y = (
                root.winfo_screenwidth() // 2,
                root.winfo_screenheight() // 2,
            )
            root.destroy()
        except Exception:
            self.center_x, self.center_y = 800, 600

        self.host_mouse_controller.position = (self.center_x, self.center_y)
        self.last_pos = {'x': self.center_x, 'y': self.center_y}
        self.is_warping = False

        self.send_queue = queue.Queue(maxsize=SEND_QUEUE_MAXSIZE)
        self.unsent_events = []
        self.pressed_keys = set()
        self.current_vks = set()
        self.current_special_keys = set()

        self.sender_thread = threading.Thread(target=self._sender, daemon=True)
        self.sender_thread.start()

        self.m_listener = mouse.Listener(
            on_move=self._on_move,
            on_click=self._on_click,
            on_scroll=self._on_scroll,
            suppress=True,
        )
        self.k_listener = keyboard.Listener(
            on_press=lambda k: self._on_key(k, True),
            on_release=lambda k: self._on_key(k, False),
            suppress=True,
        )

        self.m_listener.start()
        self.k_listener.start()

        while worker.kvm_active and worker._running:
            time.sleep(STREAM_LOOP_DELAY)

        for ktype, kval in list(self.pressed_keys):
            self._send_event({'type': 'key', 'key_type': ktype, 'key': kval, 'pressed': False})
        self.pressed_keys.clear()

        if self.m_listener:
            self.m_listener.stop()
        if self.k_listener:
            self.k_listener.stop()
        if self.send_queue:
            self.send_queue.put(None)
        if self.sender_thread:
            self.sender_thread.join()
        if self.send_queue:
            while not self.send_queue.empty():
                leftover = self.send_queue.get()
                if leftover and isinstance(leftover, tuple):
                    _, evt = leftover
                else:
                    evt = None
                if evt:
                    self.unsent_events.append(evt)

        if self.unsent_events:
            logging.warning("Unsent or failed events: %s", self.unsent_events)

        logging.info("Streaming listenerek leálltak.")

    def _sender(self):
        worker = self.worker
        while worker.kvm_active and worker._running:
            try:
                payload = self.send_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            if payload is None:
                logging.debug("Sender thread exiting")
                break
            if isinstance(payload, tuple):
                packed, event = payload
            else:
                packed, event = payload, None
            to_remove = []
            active_lost = False
            targets = [worker.active_client] if worker.active_client else list(worker.client_sockets)
            for sock in list(targets):
                if sock not in worker.client_sockets:
                    continue
                try:
                    sock.settimeout(0.1)
                    sock.sendall(struct.pack('!I', len(packed)) + packed)
                    sock.settimeout(1.0)
                    if event and event.get('type') == 'move_relative':
                        logging.debug(
                            "Mouse move sent to %s: dx=%s dy=%s",
                            worker.client_infos.get(sock, sock.getpeername()),
                            event.get('dx'),
                            event.get('dy'),
                        )
                    else:
                        logging.debug(
                            "Sent %d bytes to %s",
                            len(packed),
                            worker.client_infos.get(sock, sock.getpeername()),
                        )
                except (socket.timeout, BlockingIOError):
                    logging.warning(
                        "Client not reading, disconnecting %s",
                        worker.client_infos.get(sock, sock.getpeername()),
                    )
                    to_remove.append(sock)
                except Exception as e:
                    try:
                        event = msgpack.unpackb(packed, raw=False)
                    except Exception:
                        event = '<unpack failed>'
                    logging.error(
                        f"Failed sending event {event} to {worker.client_infos.get(sock, sock.getpeername())}: {e}",
                        exc_info=True,
                    )
                    if event != '<unpack failed>':
                        self.unsent_events.append(event)
                    to_remove.append(sock)
            for s in to_remove:
                try:
                    s.close()
                except Exception:
                    pass
                if s in worker.client_sockets:
                    worker.client_sockets.remove(s)
                if s in worker.client_infos:
                    del worker.client_infos[s]
                if s == worker.active_client:
                    worker.active_client = None
                    active_lost = True
            if active_lost:
                worker.status_update.emit(
                    "Kapcsolat megszakadt. Várakozás új kliensre..."
                )
            if to_remove and not worker.client_sockets:
                worker.deactivate_kvm(reason="all clients disconnected")
                break

    def _send_event(self, data):
        worker = self.worker
        if not worker.kvm_active:
            logging.warning(
                "Send called while KVM inactive. Event=%s active_client=%s connected_clients=%d",
                data,
                worker.client_infos.get(worker.active_client),
                len(worker.client_sockets),
            )
            self.unsent_events.append(data)
            return False
        try:
            packed = msgpack.packb(data, use_bin_type=True)
            if self.send_queue.full():
                try:
                    self.send_queue.get_nowait()
                except queue.Empty:
                    pass
                logging.debug("Send queue full, dropping oldest event")
            self.send_queue.put_nowait((packed, data))
            if data.get('type') == 'move_relative':
                logging.debug(
                    f"Egér pozíció elküldve: dx={data['dx']} dy={data['dy']}"
                )
            else:
                logging.debug(f"Queued event: {data}")
            return True
        except Exception as e:
            logging.error(f"Failed to queue event {data}: {e}", exc_info=True)
            self.unsent_events.append(data)
            worker.deactivate_kvm(reason="queue error")
            return False

    def _on_move(self, x, y):
        if self.is_warping:
            self.is_warping = False
            return
        dx = x - self.last_pos['x']
        dy = y - self.last_pos['y']
        if dx != 0 or dy != 0:
            self._send_event({'type': 'move_relative', 'dx': dx, 'dy': dy})
        self.is_warping = True
        self.host_mouse_controller.position = (self.center_x, self.center_y)
        self.last_pos['x'], self.last_pos['y'] = self.center_x, self.center_y

    def _on_click(self, x, y, b, p):
        self._send_event({'type': 'click', 'button': b.name, 'pressed': p})

    def _on_scroll(self, x, y, dx, dy):
        self._send_event({'type': 'scroll', 'dx': dx, 'dy': dy})

    def _get_vk(self, key):
        if hasattr(key, 'vk') and key.vk is not None:
            return key.vk
        if hasattr(key, 'value') and hasattr(key.value, 'vk'):
            return key.value.vk
        return None

    def _on_key(self, k, p):
        worker = self.worker
        try:
            vk = self._get_vk(k)
            if vk is not None:
                if p:
                    self.current_vks.add(vk)
                else:
                    self.current_vks.discard(vk)
            if isinstance(k, keyboard.Key):
                if p:
                    self.current_special_keys.add(k)
                else:
                    self.current_special_keys.discard(k)

            if (
                {keyboard.Key.shift, keyboard.Key.insert}.issubset(self.current_special_keys)
                or {keyboard.Key.shift_r, keyboard.Key.insert}.issubset(self.current_special_keys)
                or (
                    (VK_LSHIFT in self.current_vks or VK_RSHIFT in self.current_vks)
                    and VK_NUMPAD0 in self.current_vks
                )
            ):
                logging.info("!!! Visszaváltás a hosztra (Shift+Numpad0) észlelve a streaming alatt !!!")
                for vk_code in [VK_LSHIFT, VK_RSHIFT, VK_NUMPAD0]:
                    if vk_code in self.current_vks:
                        self._send_event({"type": "key", "key_type": "vk", "key": vk_code, "pressed": False})
                        self.pressed_keys.discard(("vk", vk_code))
                self.current_vks.clear()
                worker.deactivate_kvm(switch_monitor=True, reason='streaming hotkey')
                return
            if (
                {keyboard.Key.shift, keyboard.Key.end}.issubset(self.current_special_keys)
                or {keyboard.Key.shift_r, keyboard.Key.end}.issubset(self.current_special_keys)
                or (
                    (VK_LSHIFT in self.current_vks or VK_RSHIFT in self.current_vks)
                    and VK_NUMPAD1 in self.current_vks
                )
            ):
                logging.debug(f"Hotkey detected for laptop with current_vks={self.current_vks}")
                for vk_code in [VK_LSHIFT, VK_RSHIFT, VK_NUMPAD1]:
                    if vk_code in self.current_vks:
                        self._send_event({"type": "key", "key_type": "vk", "key": vk_code, "pressed": False})
                        self.pressed_keys.discard(("vk", vk_code))
                self.current_vks.clear()
                worker.toggle_client_control('laptop', switch_monitor=False, release_keys=False)
                return
            if (
                {keyboard.Key.shift, VK_NUMPAD2}.issubset(self.current_special_keys.union(self.current_vks))
                or {keyboard.Key.shift_r, VK_NUMPAD2}.issubset(self.current_special_keys.union(self.current_vks))
                or (
                    (VK_LSHIFT in self.current_vks or VK_RSHIFT in self.current_vks)
                    and VK_NUMPAD2 in self.current_vks
                )
            ):
                logging.debug(f"Hotkey detected for elitedesk with current_vks={self.current_vks}")
                for vk_code in [VK_LSHIFT, VK_RSHIFT, VK_NUMPAD2]:
                    if vk_code in self.current_vks:
                        self._send_event({"type": "key", "key_type": "vk", "key": vk_code, "pressed": False})
                        self.pressed_keys.discard(("vk", vk_code))
                self.current_vks.clear()
                worker.toggle_client_control('elitedesk', switch_monitor=True, release_keys=False)
                return

            if hasattr(k, 'char') and k.char is not None:
                key_type = 'char'
                key_val = k.char
            elif hasattr(k, 'name'):
                key_type = 'special'
                key_val = k.name
            elif hasattr(k, 'vk'):
                key_type = 'vk'
                key_val = k.vk
            else:
                logging.warning(f"Ismeretlen billentyű: {k}")
                return False

            key_id = (key_type, key_val)
            if p:
                self.pressed_keys.add(key_id)
            else:
                self.pressed_keys.discard(key_id)

            if not self._send_event({"type": "key", "key_type": key_type, "key": key_val, "pressed": p}):
                return False
        except Exception as e:
            logging.error(f"Hiba az on_key függvényben: {e}", exc_info=True)
            return False
