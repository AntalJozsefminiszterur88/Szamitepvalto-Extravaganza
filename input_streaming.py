# Input streaming utilities for KVMWorker

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

# Delay between iterations in the streaming loop to lower CPU usage
STREAM_LOOP_DELAY = 0.01  # tuned for smoother mouse control
# Maximum number of events queued for sending before old ones are dropped
SEND_QUEUE_MAXSIZE = 200


def stream_inputs(worker):
    """Handle mouse and keyboard event forwarding for a KVMWorker."""
    if getattr(worker, 'switch_monitor', True):
        try:
            with list(get_monitors())[0] as monitor:
                monitor.set_input_source(worker.settings['monitor_codes']['client'])
        except Exception as e:
            logging.error("Monitor hiba: %s", e, exc_info=True)
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
    is_warping = False

    send_queue = queue.Queue(maxsize=SEND_QUEUE_MAXSIZE)
    unsent_events = []

    def sender():
        while worker.kvm_active and worker._running:
            try:
                payload = send_queue.get(timeout=0.1)
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
                except (socket.timeout, BlockingIOError):
                    logging.warning("Client not reading, disconnecting %s", worker.client_infos.get(sock, sock.getpeername()))
                    to_remove.append(sock)
                except Exception as e:
                    try:
                        event = msgpack.unpackb(packed, raw=False)
                    except Exception:
                        event = '<unpack failed>'
                    logging.error(
                        "Failed sending event %s to %s: %s",
                        event,
                        worker.client_infos.get(sock, sock.getpeername()),
                        e,
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
                worker.status_update.emit("Kapcsolat megszakadt. Várakozás új kliensre...")
            if to_remove and not worker.client_sockets:
                worker.deactivate_kvm(reason="all clients disconnected")
                break

    sender_thread = threading.Thread(target=sender, daemon=True)
    sender_thread.start()

    def send(data):
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
            if send_queue.full():
                try:
                    send_queue.get_nowait()
                except queue.Empty:
                    pass
                logging.debug("Send queue full, dropping oldest event")
            send_queue.put_nowait((packed, data))
            return True
        except Exception as e:
            logging.error("Failed to queue event %s: %s", data, e, exc_info=True)
            unsent_events.append(data)
            worker.deactivate_kvm(reason="queue error")
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

    def on_click(x, y, b, p):
        send({'type': 'click', 'button': b.name, 'pressed': p})

    def on_scroll(x, y, dx, dy):
        send({'type': 'scroll', 'dx': dx, 'dy': dy})

    pressed_keys = set()
    current_vks = set()
    current_special_keys = set()

    def get_vk(key):
        if hasattr(key, "vk") and key.vk is not None:
            return key.vk
        if hasattr(key, "value") and hasattr(key.value, "vk"):
            return key.value.vk
        return None

    hotkey_desktop_l_numoff = {keyboard.Key.shift, keyboard.Key.insert}
    hotkey_desktop_r_numoff = {keyboard.Key.shift_r, keyboard.Key.insert}
    hotkey_laptop_l_numoff = {keyboard.Key.shift, keyboard.Key.end}
    hotkey_laptop_r_numoff = {keyboard.Key.shift_r, keyboard.Key.end}
    hotkey_elitdesk_l_numoff = {keyboard.Key.shift, VK_NUMPAD2}
    hotkey_elitdesk_r_numoff = {keyboard.Key.shift_r, VK_NUMPAD2}

    def on_key(k, p):
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

            if (
                hotkey_desktop_l_numoff.issubset(current_special_keys)
                or hotkey_desktop_r_numoff.issubset(current_special_keys)
                or ((VK_LSHIFT in current_vks or VK_RSHIFT in current_vks) and VK_NUMPAD0 in current_vks)
            ):
                for vk_code in [VK_LSHIFT, VK_RSHIFT, VK_NUMPAD0]:
                    if vk_code in current_vks:
                        send({"type": "key", "key_type": "vk", "key": vk_code, "pressed": False})
                        pressed_keys.discard(("vk", vk_code))
                current_vks.clear()
                worker.deactivate_kvm(switch_monitor=True, reason='streaming hotkey')
                return

            if (
                hotkey_laptop_l_numoff.issubset(current_special_keys)
                or hotkey_laptop_r_numoff.issubset(current_special_keys)
                or ((VK_LSHIFT in current_vks or VK_RSHIFT in current_vks) and VK_NUMPAD1 in current_vks)
            ):
                for vk_code in [VK_LSHIFT, VK_RSHIFT, VK_NUMPAD1]:
                    if vk_code in current_vks:
                        send({"type": "key", "key_type": "vk", "key": vk_code, "pressed": False})
                        pressed_keys.discard(("vk", vk_code))
                current_vks.clear()
                worker.toggle_client_control('laptop', switch_monitor=False, release_keys=False)
                return

            if (
                hotkey_elitdesk_l_numoff.issubset(current_special_keys.union(current_vks))
                or hotkey_elitdesk_r_numoff.issubset(current_special_keys.union(current_vks))
                or ((VK_LSHIFT in current_vks or VK_RSHIFT in current_vks) and VK_NUMPAD2 in current_vks)
            ):
                for vk_code in [VK_LSHIFT, VK_RSHIFT, VK_NUMPAD2]:
                    if vk_code in current_vks:
                        send({"type": "key", "key_type": "vk", "key": vk_code, "pressed": False})
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
                return False

            key_id = (key_type, key_val)
            if p:
                pressed_keys.add(key_id)
            else:
                pressed_keys.discard(key_id)

            if not send({"type": "key", "key_type": key_type, "key": key_val, "pressed": p}):
                return False
        except Exception as e:
            logging.error("Hiba az on_key függvényben: %s", e, exc_info=True)
            return False

    m_listener = mouse.Listener(on_move=on_move, on_click=on_click, on_scroll=on_scroll, suppress=True)
    k_listener = keyboard.Listener(on_press=lambda k: on_key(k, True), on_release=lambda k: on_key(k, False), suppress=True)

    m_listener.start()
    k_listener.start()

    while worker.kvm_active and worker._running:
        time.sleep(STREAM_LOOP_DELAY)

    for ktype, kval in list(pressed_keys):
        send({"type": "key", "key_type": ktype, "key": kval, "pressed": False})
    pressed_keys.clear()

    m_listener.stop()
    k_listener.stop()
    send_queue.put(None)
    sender_thread.join()
    while not send_queue.empty():
        leftover = send_queue.get()
        if leftover and isinstance(leftover, tuple):
            _, evt = leftover
        else:
            evt = None
        if evt:
            unsent_events.append(evt)

    if unsent_events:
        logging.warning("Unsent or failed events: %s", unsent_events)

    logging.info("Streaming listenerek leálltak.")

