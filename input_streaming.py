# input_streaming.py - FINAL REFACTORED VERSION
# Uses centralized _remove_client and has optimized key handling.

import logging
import queue
import struct
import time
import tkinter
import threading
import socket

import msgpack
from monitorcontrol import get_monitors
from pynput import mouse, keyboard

from config import VK_LSHIFT, VK_RSHIFT, VK_NUMPAD0, VK_NUMPAD1, VK_NUMPAD2

STREAM_LOOP_DELAY = 0.005 # Finetuned for better responsiveness
SEND_QUEUE_MAXSIZE = 500


def stream_inputs(worker):
    """Handle mouse and keyboard event forwarding for a KVMWorker."""
    if worker.switch_monitor:
        try:
            with list(get_monitors())[0] as monitor:
                monitor.set_input_source(worker.settings['monitor_codes']['client'])
        except Exception as e:
            worker.status_update.emit(f"Monitor hiba: {e}")
            worker.deactivate_kvm(reason="monitor switch failed")
            return

    host_mouse_controller = mouse.Controller()
    worker._host_mouse_controller = host_mouse_controller
    worker._orig_mouse_pos = host_mouse_controller.position
    
    try:
        root = tkinter.Tk()
        root.withdraw()
        center_x, center_y = (root.winfo_screenwidth() // 2, root.winfo_screenheight() // 2)
        root.destroy()
    except Exception:
        center_x, center_y = 800, 600

    host_mouse_controller.position = (center_x, center_y)
    last_pos = {'x': center_x, 'y': center_y}
    is_warping = False

    send_queue = queue.Queue(maxsize=SEND_QUEUE_MAXSIZE)

    def sender():
        while worker.kvm_active and worker._running:
            try:
                packed = send_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            if packed is None:
                break
            
            sock = worker.active_client
            if sock:
                try:
                    sock.sendall(struct.pack('!I', len(packed)) + packed)
                except (socket.timeout, BlockingIOError, ConnectionResetError, BrokenPipeError) as e:
                    worker._remove_client(sock, f"send error: {e}")
                except Exception as e:
                    logging.error("Váratlan küldési hiba: %s", e)
                    worker._remove_client(sock, f"unexpected send error: {e}")

    sender_thread = threading.Thread(target=sender, daemon=True, name="EventSender")
    sender_thread.start()

    def send(data):
        if not worker.kvm_active: return
        try:
            packed = msgpack.packb(data, use_bin_type=True)
            if send_queue.full():
                send_queue.get_nowait() # Drop oldest
            send_queue.put_nowait(packed)
        except queue.Full:
            pass # Ignore if still full after dropping one
        except Exception as e:
            logging.error("Hiba az esemény sorba állításakor: %s", e)

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

    def on_click(x, y, b, p):
        send({'type': 'click', 'button': b.name, 'pressed': p})

    def on_scroll(x, y, dx, dy):
        send({'type': 'scroll', 'dx': dx, 'dy': dy})

    pressed_keys = set()
    current_vks = set()
    current_special_keys = set()

    def on_key(k, p):
        try:
            vk = getattr(k, "vk", None)
            if vk is not None:
                (current_vks.add if p else current_vks.discard)(vk)
            if isinstance(k, keyboard.Key):
                (current_special_keys.add if p else current_special_keys.discard)(k)

            # --- Hotkey detection for switching/deactivating ---
            hotkeys = {
                'desktop': ((VK_LSHIFT in current_vks or VK_RSHIFT in current_vks) and VK_NUMPAD0 in current_vks) or {keyboard.Key.shift, keyboard.Key.insert}.issubset(current_special_keys) or {keyboard.Key.shift_r, keyboard.Key.insert}.issubset(current_special_keys),
                'laptop': ((VK_LSHIFT in current_vks or VK_RSHIFT in current_vks) and VK_NUMPAD1 in current_vks) or {keyboard.Key.shift, keyboard.Key.end}.issubset(current_special_keys) or {keyboard.Key.shift_r, keyboard.Key.end}.issubset(current_special_keys),
                'elitedesk': ((VK_LSHIFT in current_vks or VK_RSHIFT in current_vks) and VK_NUMPAD2 in current_vks) or {keyboard.Key.shift, VK_NUMPAD2}.issubset(current_special_keys.union(current_vks)) or {keyboard.Key.shift_r, VK_NUMPAD2}.issubset(current_special_keys.union(current_vks)),
            }

            triggered_action = None
            if hotkeys['desktop']:
                triggered_action = lambda: worker.deactivate_kvm(switch_monitor=True, reason='streaming hotkey')
            elif hotkeys['laptop']:
                triggered_action = lambda: worker.toggle_client_control('laptop', switch_monitor=False, release_keys=False)
            elif hotkeys['elitedesk']:
                triggered_action = lambda: worker.toggle_client_control('elitedesk', switch_monitor=True, release_keys=False)

            if triggered_action:
                logging.info("Streaming gyorsbillentyű észlelve, akció végrehajtása...")
                # Release the keys on the client BEFORE switching
                for vk_code in list(current_vks):
                    send({"type": "key", "key_type": "vk", "key": vk_code, "pressed": False})
                triggered_action()
                return # Stop processing this key event

            # --- Regular key sending ---
            if hasattr(k, "char") and k.char is not None:
                key_type, key_val = "char", k.char
            elif hasattr(k, "name"):
                key_type, key_val = "special", k.name
            elif hasattr(k, "vk"):
                key_type, key_val = "vk", k.vk
            else:
                return

            key_id = (key_type, key_val)
            if p:
                if key_id not in pressed_keys:
                    pressed_keys.add(key_id)
                    send({"type": "key", "key_type": key_type, "key": key_val, "pressed": True})
            else:
                if key_id in pressed_keys:
                    pressed_keys.discard(key_id)
                    send({"type": "key", "key_type": "key_type", "key": key_val, "pressed": False})
        
        except Exception as e:
            logging.error("Hiba az on_key függvényben: %s", e, exc_info=True)

    try:
        m_listener = mouse.Listener(on_move=on_move, on_click=on_click, on_scroll=on_scroll, suppress=True)
        k_listener = keyboard.Listener(on_press=lambda k: on_key(k, True), on_release=lambda k: on_key(k, False), suppress=True)
        m_listener.start()
        k_listener.start()
    except Exception as e:
        logging.error("Nem sikerült elindítani az input listenereket: %s", e, exc_info=True)
        worker.deactivate_kvm(reason="listener start failed")
        return

    while worker.kvm_active and worker._running:
        time.sleep(STREAM_LOOP_DELAY)

    # Cleanup
    for ktype, kval in list(pressed_keys):
        send({"type": "key", "key_type": ktype, "key": kval, "pressed": False})
    
    m_listener.stop()
    k_listener.stop()
    send_queue.put(None)
    sender_thread.join()

    logging.info("Streaming listenerek leálltak.")
