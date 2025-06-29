# InputStreamer module

import threading
import queue
import struct
import time
import logging
import tkinter

from typing import Optional

import msgpack
from pynput import mouse, keyboard
from monitorcontrol import get_monitors

from config import (
    VK_LSHIFT,
    VK_RSHIFT,
    VK_NUMPAD0,
    VK_NUMPAD1,
    VK_NUMPAD2,
)

STREAM_LOOP_DELAY = 0.05
SEND_QUEUE_MAXSIZE = 200


class InputStreamer:
    def __init__(self, worker):
        self.worker = worker
        self.thread: Optional[threading.Thread] = None
        self.sender_thread: Optional[threading.Thread] = None
        self.m_listener = None
        self.k_listener = None
        self.send_queue = None
        self.running = False

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.running = True
        self.thread = threading.Thread(target=self._streaming_loop, daemon=True, name="InputStreamerThread")
        self.thread.start()

    def stop(self):
        self.running = False
        if self.m_listener:
            try:
                self.m_listener.stop()
            except Exception:
                pass
            self.m_listener = None
        if self.k_listener:
            try:
                self.k_listener.stop()
            except Exception:
                pass
            self.k_listener = None
        if self.send_queue and self.sender_thread:
            try:
                self.send_queue.put(None)
            except Exception:
                pass
            self.sender_thread.join(timeout=1)
            self.sender_thread = None
            self.send_queue = None
        if self.thread:
            self.thread.join(timeout=1)
            self.thread = None

    def _streaming_loop(self):
        while self.worker.kvm_active and self.worker._running and self.running:
            self._stream_once()
            if self.worker.kvm_active and self.worker._running and self.running:
                logging.warning("Egér szinkronizáció megszakadt, újraindítás...")
                time.sleep(1)

    def _send(self, data, unsent_events):
        worker = self.worker
        if not worker.kvm_active:
            logging.warning(
                "Send called while KVM inactive. Event=%s active_client=%s connected_clients=%d",
                data,
                worker.client_infos.get(worker.active_client),
                len(worker.client_sockets),
            )
            unsent_events.append(data)
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
                logging.debug(f"Egér pozíció elküldve: dx={data['dx']} dy={data['dy']}")
            else:
                logging.debug(f"Queued event: {data}")
            return True
        except Exception as e:
            logging.error(f"Failed to queue event {data}: {e}", exc_info=True)
            unsent_events.append(data)
            worker.deactivate_kvm(reason="queue error")
            return False

    def _on_move(self, x, y, host_mouse_controller, center_x, center_y, last_pos, is_warping, unsent_events):
        if is_warping[0]:
            is_warping[0] = False
            return
        dx = x - last_pos['x']
        dy = y - last_pos['y']
        if dx != 0 or dy != 0:
            self._send({'type': 'move_relative', 'dx': dx, 'dy': dy}, unsent_events)
        is_warping[0] = True
        host_mouse_controller.position = (center_x, center_y)
        last_pos['x'], last_pos['y'] = center_x, center_y

    def _on_click(self, x, y, b, p, unsent_events):
        self._send({'type': 'click', 'button': b.name, 'pressed': p}, unsent_events)

    def _on_scroll(self, x, y, dx, dy, unsent_events):
        self._send({'type': 'scroll', 'dx': dx, 'dy': dy}, unsent_events)

    def _on_key(self, k, p, pressed_keys, current_vks, current_special_keys, unsent_events):
        worker = self.worker

        def get_vk(key):
            if hasattr(key, "vk") and key.vk is not None:
                return key.vk
            if hasattr(key, "value") and hasattr(key.value, "vk"):
                return key.value.vk
            return None

        try:
            vk = get_vk(k)
            if vk is not None:
                if p:
                    current_vks.add(vk)
                else:
                    current_vks.discard(vk)
            if isinstance(k, keyboard.Key):
                if p:
                    current_special_keys.add(k)
                else:
                    current_special_keys.discard(k)

            hotkey_desktop_l_numoff = {keyboard.Key.shift, keyboard.Key.insert}
            hotkey_desktop_r_numoff = {keyboard.Key.shift_r, keyboard.Key.insert}
            hotkey_laptop_l_numoff = {keyboard.Key.shift, keyboard.Key.end}
            hotkey_laptop_r_numoff = {keyboard.Key.shift_r, keyboard.Key.end}
            hotkey_elitdesk_l_numoff = {keyboard.Key.shift, VK_NUMPAD2}
            hotkey_elitdesk_r_numoff = {keyboard.Key.shift_r, VK_NUMPAD2}

            hotkey_desktop_l_numon = {VK_LSHIFT, VK_NUMPAD0}
            hotkey_desktop_r_numon = {VK_RSHIFT, VK_NUMPAD0}
            hotkey_laptop_l_numon = {VK_LSHIFT, VK_NUMPAD1}
            hotkey_laptop_r_numon = {VK_RSHIFT, VK_NUMPAD1}
            hotkey_elitdesk_l_numon = {VK_LSHIFT, VK_NUMPAD2}
            hotkey_elitdesk_r_numon = {VK_RSHIFT, VK_NUMPAD2}

            if (
                hotkey_desktop_l_numoff.issubset(current_special_keys)
                or hotkey_desktop_r_numoff.issubset(current_special_keys)
                or (
                    (VK_LSHIFT in current_vks or VK_RSHIFT in current_vks)
                    and VK_NUMPAD0 in current_vks
                )
            ):
                logging.info("!!! Visszaváltás a hosztra (Shift+Numpad0) észlelve a streaming alatt !!!")
                for vk_code in [VK_LSHIFT, VK_RSHIFT, VK_NUMPAD0]:
                    if vk_code in current_vks:
                        self._send({"type": "key", "key_type": "vk", "key": vk_code, "pressed": False}, unsent_events)
                        pressed_keys.discard(("vk", vk_code))
                current_vks.clear()
                worker.deactivate_kvm(switch_monitor=True, reason='streaming hotkey')
                return
            if (
                hotkey_laptop_l_numoff.issubset(current_special_keys)
                or hotkey_laptop_r_numoff.issubset(current_special_keys)
                or (
                    (VK_LSHIFT in current_vks or VK_RSHIFT in current_vks)
                    and VK_NUMPAD1 in current_vks
                )
            ):
                logging.debug(f"Hotkey detected for laptop with current_vks={current_vks}")
                for vk_code in [VK_LSHIFT, VK_RSHIFT, VK_NUMPAD1]:
                    if vk_code in current_vks:
                        self._send({"type": "key", "key_type": "vk", "key": vk_code, "pressed": False}, unsent_events)
                        pressed_keys.discard(("vk", vk_code))
                current_vks.clear()
                worker.toggle_client_control('laptop', switch_monitor=False, release_keys=False)
                return
            if (
                hotkey_elitdesk_l_numoff.issubset(current_special_keys.union(current_vks))
                or hotkey_elitdesk_r_numoff.issubset(current_special_keys.union(current_vks))
                or (
                    (VK_LSHIFT in current_vks or VK_RSHIFT in current_vks)
                    and VK_NUMPAD2 in current_vks
                )
            ):
                logging.debug(f"Hotkey detected for elitedesk with current_vks={current_vks}")
                for vk_code in [VK_LSHIFT, VK_RSHIFT, VK_NUMPAD2]:
                    if vk_code in current_vks:
                        self._send({"type": "key", "key_type": "vk", "key": vk_code, "pressed": False}, unsent_events)
                        pressed_keys.discard(("vk", vk_code))
                current_vks.clear()
                worker.toggle_client_control('elitedesk', switch_monitor=True, release_keys=False)
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

            if not self._send({"type": "key", "key_type": key_type, "key": key_val, "pressed": p}, unsent_events):
                return False
        except Exception as e:
            logging.error(f"Hiba az on_key függvényben: {e}", exc_info=True)
            return False
        return True

    def _sender_loop(self, unsent_events):
        worker = self.worker
        while worker.kvm_active and worker._running and self.running:
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
                        unsent_events.append(event)
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

    def _stream_once(self):
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

        host_mouse_controller = mouse.Controller()
        worker._host_mouse_controller = host_mouse_controller
        worker._orig_mouse_pos = host_mouse_controller.position
        try:
            root = tkinter.Tk()
            root.withdraw()
            center_x, center_y = root.winfo_screenwidth() // 2, root.winfo_screenheight() // 2
            root.destroy()
        except Exception:
            center_x, center_y = 800, 600

        host_mouse_controller.position = (center_x, center_y)
        last_pos = {'x': center_x, 'y': center_y}
        is_warping = [False]

        self.send_queue = queue.Queue(maxsize=SEND_QUEUE_MAXSIZE)
        unsent_events = []

        self.sender_thread = threading.Thread(target=self._sender_loop, args=(unsent_events,), daemon=True)
        self.sender_thread.start()

        self.m_listener = mouse.Listener(
            on_move=lambda x, y: self._on_move(x, y, host_mouse_controller, center_x, center_y, last_pos, is_warping, unsent_events),
            on_click=lambda x, y, b, p: self._on_click(x, y, b, p, unsent_events),
            on_scroll=lambda x, y, dx, dy: self._on_scroll(x, y, dx, dy, unsent_events),
            suppress=True,
        )
        self.k_listener = keyboard.Listener(
            on_press=lambda k: self._on_key(k, True, pressed_keys, current_vks, current_special_keys, unsent_events),
            on_release=lambda k: self._on_key(k, False, pressed_keys, current_vks, current_special_keys, unsent_events),
            suppress=True,
        )

        pressed_keys = set()
        current_vks = set()
        current_special_keys = set()

        self.m_listener.start()
        self.k_listener.start()

        while worker.kvm_active and worker._running and self.running:
            time.sleep(STREAM_LOOP_DELAY)

        for ktype, kval in list(pressed_keys):
            self._send({"type": "key", "key_type": ktype, "key": kval, "pressed": False}, unsent_events)
        pressed_keys.clear()

        self.m_listener.stop()
        self.k_listener.stop()
        self.send_queue.put(None)
        self.sender_thread.join()
        while not self.send_queue.empty():
            leftover = self.send_queue.get()
            if leftover and isinstance(leftover, tuple):
                _, evt = leftover
            else:
                evt = None
            if evt:
                unsent_events.append(evt)

        if unsent_events:
            logging.warning("Unsent or failed events: %s", unsent_events)

        logging.info("Streaming listenerek leálltak.")

