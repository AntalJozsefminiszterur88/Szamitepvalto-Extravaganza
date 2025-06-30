import logging
import queue
import struct
import threading
import time

import msgpack
from pynput import keyboard, mouse
from monitorcontrol import get_monitors

from ..config import VK_LSHIFT, VK_RSHIFT, VK_NUMPAD0, VK_NUMPAD1, VK_NUMPAD2

STREAM_LOOP_DELAY = 0.05


class InputStreamer:
    """Capture local input and forward to the remote side."""

    def __init__(self, worker):
        self.worker = worker
        self.thread = None
        self.sender_thread = None
        self.send_queue = queue.Queue()
        self.k_listener = None
        self.m_listener = None
        self.vk_codes = set()
        self.special_keys = set()
        self.pressed_keys = set()
        self.last_pos = None
        self.center_x = 0
        self.center_y = 0
        self.host_mouse = mouse.Controller()
        self.is_warping = False

    # ------------------------------------------------------------------
    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self.worker.kvm_active = False
        if self.k_listener:
            try:
                self.k_listener.stop()
            except Exception:
                pass
            self.k_listener = None
        if self.m_listener:
            try:
                self.m_listener.stop()
            except Exception:
                pass
            self.m_listener = None
        if self.sender_thread:
            self.send_queue.put(None)
            self.sender_thread.join()
            self.sender_thread = None
        self.vk_codes.clear()
        self.special_keys.clear()
        self.pressed_keys.clear()

    # ------------------------------------------------------------------
    def _run(self):
        self.worker.kvm_active = True
        self.sender_thread = threading.Thread(target=self._sender_loop, daemon=True)
        self.sender_thread.start()

        # switch monitor if requested
        if self.worker.switch_monitor:
            try:
                with list(get_monitors())[0] as mon:
                    mon.set_input_source(self.worker.settings['monitor_codes']['client'])
            except Exception as e:
                logging.error("Monitor switch failed: %s", e)
                self.worker.status_update.emit(f"Monitor hiba: {e}")

        try:
            import tkinter
            root = tkinter.Tk()
            root.withdraw()
            self.center_x = root.winfo_screenwidth() // 2
            self.center_y = root.winfo_screenheight() // 2
            root.destroy()
        except Exception:
            self.center_x, self.center_y = 800, 600

        self.host_mouse.position = (self.center_x, self.center_y)
        self.last_pos = {'x': self.center_x, 'y': self.center_y}
        self.is_warping = False

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

        while self.worker.kvm_active and self.worker._running:
            time.sleep(STREAM_LOOP_DELAY)

        self.stop()

    # ------------------------------------------------------------------
    def _sender_loop(self):
        while self.worker.kvm_active and self.worker._running:
            try:
                event = self.send_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            if event is None:
                break
            packed = msgpack.packb(event, use_bin_type=True)
            target_socks = []
            if self.worker.settings['role'] == 'ado':
                if self.worker.active_client:
                    target_socks = [self.worker.active_client]
            else:
                if self.worker.server_socket:
                    target_socks = [self.worker.server_socket]
            for sock in list(target_socks):
                try:
                    sock.sendall(struct.pack('!I', len(packed)) + packed)
                except Exception as e:
                    logging.error("Failed sending event: %s", e)

    def _send_event(self, evt):
        try:
            self.send_queue.put_nowait(evt)
        except queue.Full:
            try:
                self.send_queue.get_nowait()
            except queue.Empty:
                pass
            self.send_queue.put_nowait(evt)

    # ------------------------------------------------------------------
    def _get_vk(self, key):
        if hasattr(key, 'vk') and key.vk is not None:
            return key.vk
        if hasattr(key, 'value') and hasattr(key.value, 'vk'):
            return key.value.vk
        return None

    def _on_key(self, key, pressed):
        vk = self._get_vk(key)
        if vk is not None:
            if pressed:
                self.vk_codes.add(vk)
            else:
                self.vk_codes.discard(vk)
        if isinstance(key, keyboard.Key):
            if pressed:
                self.special_keys.add(key)
            else:
                self.special_keys.discard(key)

        logging.debug(
            f"InputStreamer Key: {key} pressed={pressed} VKs={self.vk_codes} Specials={self.special_keys}"
        )

        if (
            {keyboard.Key.shift, keyboard.Key.insert}.issubset(self.special_keys)
            or {keyboard.Key.shift_r, keyboard.Key.insert}.issubset(self.special_keys)
            or (
                VK_NUMPAD0 in self.vk_codes
                and (VK_LSHIFT in self.vk_codes or VK_RSHIFT in self.vk_codes)
            )
        ):
            logging.info("Streaming hotkey detected - returning to host")
            for vk_code in [VK_LSHIFT, VK_RSHIFT, VK_NUMPAD0]:
                if vk_code in self.vk_codes:
                    self._send_event({'type': 'key', 'key_type': 'vk', 'key': vk_code, 'pressed': False})
                    self.pressed_keys.discard(('vk', vk_code))
            self.vk_codes.clear()
            self.worker.deactivate_kvm(switch_monitor=True, reason='stream hotkey')
            return

        if (
            {keyboard.Key.shift, keyboard.Key.end}.issubset(self.special_keys)
            or {keyboard.Key.shift_r, keyboard.Key.end}.issubset(self.special_keys)
            or (
                VK_NUMPAD1 in self.vk_codes
                and (VK_LSHIFT in self.vk_codes or VK_RSHIFT in self.vk_codes)
            )
        ):
            logging.info("Streaming hotkey detected - switch to laptop")
            for vk_code in [VK_LSHIFT, VK_RSHIFT, VK_NUMPAD1]:
                if vk_code in self.vk_codes:
                    self._send_event({'type': 'key', 'key_type': 'vk', 'key': vk_code, 'pressed': False})
                    self.pressed_keys.discard(('vk', vk_code))
            self.vk_codes.clear()
            self.worker.toggle_client_control('laptop', switch_monitor=False, release_keys=False)
            return

        if (
            {keyboard.Key.shift, keyboard.Key.down}.issubset(self.special_keys)
            or {keyboard.Key.shift_r, keyboard.Key.down}.issubset(self.special_keys)
            or (
                VK_NUMPAD2 in self.vk_codes
                and (VK_LSHIFT in self.vk_codes or VK_RSHIFT in self.vk_codes)
            )
        ):
            logging.info("Streaming hotkey detected - switch to elitedesk")
            for vk_code in [VK_LSHIFT, VK_RSHIFT, VK_NUMPAD2]:
                if vk_code in self.vk_codes:
                    self._send_event({'type': 'key', 'key_type': 'vk', 'key': vk_code, 'pressed': False})
                    self.pressed_keys.discard(('vk', vk_code))
            self.vk_codes.clear()
            self.worker.toggle_client_control('elitedesk', switch_monitor=True, release_keys=False)
            return

        if pressed:
            self.pressed_keys.add(('vk', vk) if vk is not None else ('key', str(key)))
        else:
            self.pressed_keys.discard(('vk', vk) if vk is not None else ('key', str(key)))

        if hasattr(key, 'char') and key.char is not None:
            evt = {'type': 'key', 'key_type': 'char', 'key': key.char, 'pressed': pressed}
        elif hasattr(key, 'name'):
            evt = {'type': 'key', 'key_type': 'special', 'key': key.name, 'pressed': pressed}
        elif vk is not None:
            evt = {'type': 'key', 'key_type': 'vk', 'key': vk, 'pressed': pressed}
        else:
            return
        self._send_event(evt)

    def _on_move(self, x, y):
        if self.is_warping:
            self.is_warping = False
            return
        dx = x - self.last_pos['x']
        dy = y - self.last_pos['y']
        if dx or dy:
            self._send_event({'type': 'move_relative', 'dx': dx, 'dy': dy})
        self.is_warping = True
        self.host_mouse.position = (self.center_x, self.center_y)
        self.last_pos['x'] = self.center_x
        self.last_pos['y'] = self.center_y

    def _on_click(self, x, y, button, pressed):
        self._send_event({'type': 'click', 'button': button.name, 'pressed': pressed})

    def _on_scroll(self, x, y, dx, dy):
        self._send_event({'type': 'scroll', 'dx': dx, 'dy': dy})
