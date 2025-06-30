import logging
import queue
import struct
import socket
import threading
import time
import tkinter

import msgpack
from pynput import keyboard, mouse

from ..config import VK_LSHIFT, VK_RSHIFT, VK_NUMPAD0, VK_NUMPAD1, VK_NUMPAD2

# Constants for the streamer
STREAM_LOOP_DELAY = 0.05
SEND_QUEUE_MAXSIZE = 200

class InputStreamer:
    """
    Captures and sends input events during an active KVM session using a robust
    queue-based sender and mouse warping logic.
    """

    def __init__(self, worker):
        self.worker = worker
        self.m_listener = None
        self.k_listener = None
        self.sender_thread = None
        self.send_queue = None
        
        self.host_mouse_controller = None
        self.center_x, self.center_y = 800, 600
        self.last_pos = {'x': 0, 'y': 0}
        self.is_warping = False

        self.pressed_keys_for_release = set()
        self.current_vks = set()
        self.current_special_keys = set()
        
    def start(self):
        if self.k_listener and self.k_listener.is_alive():
            return

        logging.info("Input streamer starting...")
        
        # --- Initialize state for a new session ---
        self.send_queue = queue.Queue(maxsize=SEND_QUEUE_MAXSIZE)
        self.pressed_keys_for_release.clear()
        self.current_vks.clear()
        self.current_special_keys.clear()

        # --- Setup Mouse Warping ---
        self.host_mouse_controller = mouse.Controller()
        try:
            root = tkinter.Tk()
            root.withdraw()
            self.center_x = root.winfo_screenwidth() // 2
            self.center_y = root.winfo_screenheight() // 2
            root.destroy()
        except Exception:
            logging.warning("Could not get screen dimensions for mouse warping, using defaults.")

        self.host_mouse_controller.position = (self.center_x, self.center_y)
        self.last_pos = {'x': self.center_x, 'y': self.center_y}
        self.is_warping = False

        # --- Start Listeners and Sender Thread ---
        self.sender_thread = threading.Thread(target=self._sender, daemon=True, name="SenderThread")
        self.sender_thread.start()
        
        self.m_listener = mouse.Listener(
            on_move=self._on_move, on_click=self._on_click, on_scroll=self._on_scroll, suppress=True
        )
        self.k_listener = keyboard.Listener(
            on_press=lambda k: self._on_key(k, True), on_release=lambda k: self._on_key(k, False), suppress=True
        )
        self.m_listener.start()
        self.k_listener.start()
        logging.info("Input streamer running.")

    def stop(self):
        if not self.k_listener: return

        logging.info("Input streamer stopping...")
        if self.m_listener: self.m_listener.stop()
        if self.k_listener: self.k_listener.stop()
        
        # Signal sender thread to exit
        if self.send_queue: self.send_queue.put(None)

        # Release any keys held down on the client
        for ktype, kval in list(self.pressed_keys_for_release):
            self._send_event({'type': 'key', 'key_type': ktype, 'key': kval, 'pressed': False})
        
        # Wait briefly for sender to process final release messages
        if self.sender_thread: self.sender_thread.join(timeout=0.2)
        
        self.m_listener = None
        self.k_listener = None
        self.sender_thread = None

    def _sender(self):
        """Dedicated thread to send events from the queue to the active client."""
        while self.worker.kvm_active:
            try:
                event_data = self.send_queue.get(timeout=1.0)
                if event_data is None: # Shutdown signal
                    break
                
                packed_data = msgpack.packb(event_data, use_bin_type=True)
                
                # Send to the currently active client
                active_sock = self.worker.active_client
                if active_sock:
                    try:
                        active_sock.sendall(struct.pack('!I', len(packed_data)) + packed_data)
                    except (socket.error, BrokenPipeError) as e:
                        logging.warning(f"Connection to active client lost: {e}")
                        self.worker.handle_client_disconnection(active_sock)
            except queue.Empty:
                continue
        logging.info("Sender thread has stopped.")

    def _send_event(self, data):
        """Puts an event dictionary into the send queue."""
        if not self.worker.kvm_active or self.send_queue is None:
            return
        try:
            if self.send_queue.full():
                self.send_queue.get_nowait() # Discard oldest if full
            self.send_queue.put_nowait(data)
        except queue.Full:
            pass # Should not happen with the get_nowait call, but as a safeguard

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
        self.last_pos = {'x': self.center_x, 'y': self.center_y}

    def _on_click(self, x, y, button, pressed):
        self._send_event({'type': 'click', 'button': button.name, 'pressed': pressed})

    def _on_scroll(self, x, y, dx, dy):
        self._send_event({'type': 'scroll', 'dx': dx, 'dy': dy})

    def _on_key(self, key, pressed):
        # --- Hotkey detection logic (using two-set method) ---
        try:
            vk = key.vk
            if pressed: self.current_vks.add(vk)
            else: self.current_vks.discard(vk)
        except AttributeError:
            if pressed: self.current_special_keys.add(key)
            else: self.current_special_keys.discard(key)

        if (VK_LSHIFT in self.current_vks or VK_RSHIFT in self.current_vks) and (VK_NUMPAD0 in self.current_vks):
            if pressed:
                logging.info("!!! Return-to-host hotkey detected during streaming !!!")
                self.worker.deactivate_kvm(switch_monitor=True, reason="streaming_hotkey")
            return # Do not forward the hotkey

        # --- Forward regular key events ---
        key_type, key_val = None, None
        if hasattr(key, "char") and key.char is not None:
            key_type, key_val = "char", key.char
        elif isinstance(key, keyboard.Key):
            key_type, key_val = "special", key.name
        elif hasattr(key, "vk"):
            key_type, key_val = "vk", key.vk
        else:
            return # Unknown key

        key_id = (key_type, key_val)
        if pressed: self.pressed_keys_for_release.add(key_id)
        else: self.pressed_keys_for_release.discard(key_id)
        
        self._send_event({"type": "key", "key_type": key_type, "key": key_val, "pressed": pressed})
