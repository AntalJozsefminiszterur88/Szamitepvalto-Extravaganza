"""Host-side input capture for streaming control events to clients."""

from __future__ import annotations

import ctypes
import logging
import os
import queue
import threading
import time
from collections import deque
from typing import Any, Callable, Iterable, Optional

import msgpack
from pynput import keyboard, mouse

from config.constants import (
    VK_INSERT,
    VK_LSHIFT,
    VK_NUMPAD0,
    VK_RSHIFT,
)

STREAM_LOOP_DELAY = 0.05
SEND_QUEUE_MAXSIZE = 200
MOUSE_SYNC_INACTIVITY_TIMEOUT = 1.0


class HostInputCapture:
    """Capture host-side input events and forward them to connected clients."""

    def __init__(
        self,
        send_callback: Callable[[bytes, Optional[dict]], bool],
        *,
        state,
        monitor_controller,
        status_update,
        deactivate_callback: Callable[..., None],
        toggle_client_control: Callable[[str, bool], None],
        send_provider_function_key: Optional[Callable[[keyboard.Key, str], bool]] = None,
        is_running: Callable[[], bool],
        get_switch_monitor: Callable[[], bool],
        force_numpad_vk: Optional[Iterable[int]] = None,
    ) -> None:
        self._send_callback = send_callback
        self._state = state
        self._monitor_controller = monitor_controller
        self._status_update = status_update
        self._deactivate_callback = deactivate_callback
        self._toggle_client_control = toggle_client_control
        self._send_provider_function_key = send_provider_function_key
        self._is_running = is_running
        self._get_switch_monitor = get_switch_monitor
        self._force_numpad_vk = set(force_numpad_vk or [])

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        self._host_mouse_controller: Optional[mouse.Controller] = None
        self._orig_mouse_pos: Optional[tuple[int, int]] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def start(self) -> None:
        if self.is_running():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._streaming_loop,
            daemon=True,
            name="StreamingThread",
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=2.0)
        self._thread = None
        self.restore_mouse_position()

    def is_running(self) -> bool:
        thread = self._thread
        return bool(thread and thread.is_alive())

    @property
    def thread(self) -> Optional[threading.Thread]:
        return self._thread

    def restore_mouse_position(self) -> None:
        controller = self._host_mouse_controller
        if controller and self._orig_mouse_pos:
            try:
                controller.position = self._orig_mouse_pos
            except Exception as exc:
                logging.error("Failed to restore mouse position: %s", exc, exc_info=True)
        self._host_mouse_controller = None
        self._orig_mouse_pos = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _streaming_loop(self) -> None:
        while (
            self._state.is_active()
            and self._is_running()
            and not self._stop_event.is_set()
        ):
            self._run_streaming()
            if (
                self._state.is_active()
                and self._is_running()
                and not self._stop_event.is_set()
            ):
                logging.warning("Egér szinkronizáció megszakadt, újraindítás...")
                time.sleep(1)

    def _run_streaming(self) -> None:
        logging.info("start_kvm_streaming: initiating control transfer")
        if self._get_switch_monitor():
            success, error = self._monitor_controller.switch_to_client()
            if not success:
                message = error or "bemenet váltása sikertelen"
                self._status_update.emit(f"Monitor hiba: {message}")
                logging.error("Monitor hiba a kliensre váltáskor: %s", message)
                self._deactivate_callback(reason="monitor switch failed")
                return

        host_mouse_controller = mouse.Controller()
        self._host_mouse_controller = host_mouse_controller
        self._orig_mouse_pos = host_mouse_controller.position
        try:
            if os.name == 'nt':
                user32 = ctypes.windll.user32
                width = user32.GetSystemMetrics(0)
                height = user32.GetSystemMetrics(1)
                center_x = width // 2
                center_y = height // 2
            else:
                center_x, center_y = 960, 540  # Fallback
        except Exception:
            center_x, center_y = 800, 600

        host_mouse_controller.position = (center_x, center_y)
        last_pos = {'x': center_x, 'y': center_y}
        is_warping = False

        accumulated_movement = {'dx': 0, 'dy': 0}
        movement_lock = threading.Lock()

        sync_state_lock = threading.Lock()
        sync_state = {
            'last_activity': time.monotonic(),
            'paused': False,
            'resume_requested': False,
        }

        send_queue: queue.Queue[Any] = queue.Queue(maxsize=SEND_QUEUE_MAXSIZE)
        unsent_events: deque[Any] = deque(maxlen=50)
        unsent_events_total = 0

        def record_unsent(event: Any) -> None:
            nonlocal unsent_events_total
            unsent_events_total += 1
            summary: Any = event
            try:
                if isinstance(event, dict):
                    summary = {}
                    for key, value in event.items():
                        if isinstance(value, (bytes, bytearray)):
                            summary[key] = f"<{len(value)} bytes>"
                        elif isinstance(value, str) and len(value) > 200:
                            summary[key] = f"<string len={len(value)}>"
                        else:
                            summary[key] = value
                elif isinstance(event, (bytes, bytearray)):
                    summary = f"<{len(event)} bytes>"
            except Exception:
                summary = repr(event)
            unsent_events.append(summary)

        def send(data: dict) -> bool:
            if not self._state.is_active():
                logging.warning(
                    "Send called while KVM inactive. Event=%s active_client=%s connected_clients=%d",
                    data,
                    getattr(self._state, 'get_client_name', lambda *_: 'unknown')(
                        self._state.get_active_client() if hasattr(self._state, 'get_active_client') else None
                    ),
                    len(self._state.get_client_sockets()) if hasattr(self._state, 'get_client_sockets') else 0,
                )
                record_unsent(data)
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
                if data.get('type') != 'move_relative':
                    logging.debug("Queued event: %s", data)
                return True
            except Exception as exc:
                logging.error("Failed to queue event %s: %s", data, exc, exc_info=True)
                record_unsent(data)
                self._deactivate_callback(reason="queue error")
                return False

        def sender() -> None:
            last_tick = time.monotonic()
            while (
                self._state.is_active()
                and self._is_running()
                and not self._stop_event.is_set()
            ):
                events: list[tuple[bytes, Optional[dict]]] = []
                try:
                    payload = send_queue.get(timeout=0.01)
                    got_q = True
                except queue.Empty:
                    payload = None
                    got_q = False

                if got_q and payload is None:
                    logging.debug("Sender thread exiting")
                    break
                if got_q and payload is not None:
                    if isinstance(payload, tuple):
                        events.append(payload)
                    else:
                        events.append((payload, None))

                dx = dy = 0
                now = time.monotonic()
                if now - last_tick >= 0.015:
                    with movement_lock:
                        dx = accumulated_movement['dx']
                        dy = accumulated_movement['dy']
                        accumulated_movement['dx'] = 0
                        accumulated_movement['dy'] = 0
                    last_tick = now

                sync_message = None
                with sync_state_lock:
                    paused = sync_state['paused']
                    last_activity = sync_state['last_activity']
                    if sync_state['resume_requested']:
                        sync_state['resume_requested'] = False
                        sync_state['paused'] = False
                        paused = False
                        sync_message = {'type': 'sync_resume'}
                    elif not paused and (now - last_activity) >= MOUSE_SYNC_INACTIVITY_TIMEOUT:
                        sync_state['paused'] = True
                        paused = True
                        sync_message = {'type': 'sync_pause'}

                if sync_message is not None:
                    logging.debug(
                        "Mouse synchronization state changed: %s",
                        sync_message['type'],
                    )
                    events.append((msgpack.packb(sync_message, use_bin_type=True), sync_message))

                if (dx != 0 or dy != 0) and not paused:
                    move_evt = {'type': 'move_relative', 'dx': dx, 'dy': dy}
                    events.append((msgpack.packb(move_evt, use_bin_type=True), move_evt))
                elif (dx != 0 or dy != 0) and paused:
                    logging.debug(
                        "Mouse movement suppressed due to inactivity pause: dx=%s dy=%s",
                        dx,
                        dy,
                    )

                if not events:
                    continue

                for packed, event in events:
                    if self._stop_event.is_set():
                        break
                    try:
                        success = self._send_callback(packed, event)
                    except Exception as exc:  # pragma: no cover - defensive guard
                        logging.error("Failed to send event via callback: %s", exc, exc_info=True)
                        success = False
                    if not success:
                        if event is not None:
                            record_unsent(event)
                        if self._state.is_active():
                            self._deactivate_callback(reason="send callback failure")
                        break
                else:
                    continue
                break

        sender_thread = threading.Thread(target=sender, daemon=True)
        sender_thread.start()

        def on_move(x: int, y: int) -> None:
            nonlocal is_warping
            if self._stop_event.is_set():
                return
            if is_warping:
                is_warping = False
                return

            dx = x - last_pos['x']
            dy = y - last_pos['y']

            if dx != 0 or dy != 0:
                with movement_lock:
                    accumulated_movement['dx'] += dx
                    accumulated_movement['dy'] += dy

            with sync_state_lock:
                sync_state['last_activity'] = time.monotonic()
                if sync_state['paused']:
                    sync_state['resume_requested'] = True

            try:
                is_warping = True
                host_mouse_controller.position = (center_x, center_y)
                last_pos['x'] = center_x
                last_pos['y'] = center_y
            except Exception as exc:
                logging.debug("Failed to recenter host cursor: %s", exc, exc_info=True)
                is_warping = False
                last_pos['x'] = x
                last_pos['y'] = y

        def on_click(x: int, y: int, button: mouse.Button, pressed: bool) -> None:
            if self._stop_event.is_set():
                return
            send({'type': 'click', 'button': getattr(button, 'name', 'left'), 'pressed': pressed})

        def on_scroll(x: int, y: int, dx: int, dy: int) -> None:
            if self._stop_event.is_set():
                return
            send({'type': 'scroll', 'dx': dx, 'dy': dy})

        pressed_keys: set[tuple[str, int | str]] = set()
        current_vks: set[int] = set()
        numpad_vks: set[int] = set()

        def get_vk(key: keyboard.Key | keyboard.KeyCode) -> Optional[int]:
            if hasattr(key, 'vk') and key.vk is not None:
                return key.vk
            if hasattr(key, 'value') and hasattr(key.value, 'vk'):
                return key.value.vk
            return None

        def on_key(key: keyboard.Key | keyboard.KeyCode, pressed: bool) -> Optional[bool]:
            if self._stop_event.is_set():
                return False
            try:
                if pressed:
                    if key == keyboard.Key.f13:
                        logging.info(
                            "!!! Visszaváltás a hosztra (Pico F13) észlelve a streaming alatt !!!",
                        )
                        self._deactivate_callback(switch_monitor=True, reason='streaming pico F13')
                        return False
                    if key == keyboard.Key.f14:
                        logging.info(
                            "!!! Váltás laptopra (Pico F14) észlelve a streaming alatt !!!",
                        )
                        self._toggle_client_control('laptop', switch_monitor=False)
                        return False
                    if key == keyboard.Key.f15:
                        logging.info(
                            "!!! Váltás EliteDeskre (Pico F15) észlelve a streaming alatt !!!",
                        )
                        self._toggle_client_control('elitedesk', switch_monitor=True)
                        return False
                    if key == keyboard.Key.f22:
                        logging.info(
                            "F22 pressed during streaming; forwarding to desktop input provider.",
                        )
                        forwarded = False
                        if self._send_provider_function_key:
                            forwarded = self._send_provider_function_key(
                                keyboard.Key.f22,
                                "streaming F22",
                            )
                        if not forwarded:
                            logging.warning(
                                "Failed to forward F22 to desktop input provider during streaming.",
                            )
                        return True
                    if key in (keyboard.Key.f18, keyboard.Key.f19, keyboard.Key.f20, keyboard.Key.f22):
                        logging.info(
                            "Audio/mute hotkey %s captured locally during streaming", key,
                        )
                        return False
                if key == keyboard.Key.f22:
                    return True

                vk = get_vk(key)
                if vk is not None:
                    if pressed:
                        current_vks.add(vk)
                        if getattr(key, '_flags', 0) == 0:
                            numpad_vks.add(vk)
                    else:
                        current_vks.discard(vk)
                        numpad_vks.discard(vk)

                is_shift = VK_LSHIFT in current_vks or VK_RSHIFT in current_vks
                is_num0 = (
                    VK_NUMPAD0 in current_vks
                    or (VK_INSERT in current_vks and VK_INSERT in numpad_vks)
                )

                if is_shift and is_num0:
                    logging.info(
                        "!!! Visszaváltás a hosztra (Shift+Numpad0) észlelve a streaming alatt !!!",
                    )
                    for vk_code in [VK_LSHIFT, VK_RSHIFT, VK_NUMPAD0, VK_INSERT]:
                        if vk_code in current_vks:
                            send({
                                'type': 'key',
                                'key_type': 'vk',
                                'key': vk_code,
                                'pressed': False,
                            })
                    current_vks.clear()
                    self._deactivate_callback(switch_monitor=True, reason='streaming hotkey')
                    return False

                forced_vk = None
                if hasattr(key, 'vk') and key.vk in self._force_numpad_vk:
                    forced_vk = key.vk
                elif (
                    hasattr(key, 'value')
                    and hasattr(key.value, 'vk')
                    and key.value.vk in self._force_numpad_vk
                ):
                    forced_vk = key.value.vk

                if forced_vk is not None:
                    key_type = 'vk'
                    key_val = forced_vk
                elif hasattr(key, 'char') and key.char is not None:
                    key_type = 'char'
                    key_val = key.char
                elif hasattr(key, 'name'):
                    key_type = 'special'
                    key_val = key.name
                elif hasattr(key, 'vk'):
                    key_type = 'vk'
                    key_val = key.vk
                else:
                    logging.warning("Ismeretlen billentyű: %s", key)
                    return False

                key_id = (key_type, key_val)
                if pressed:
                    pressed_keys.add(key_id)
                else:
                    pressed_keys.discard(key_id)

                if not send({'type': 'key', 'key_type': key_type, 'key': key_val, 'pressed': pressed}):
                    return False
            except Exception as exc:
                logging.error("Hiba az on_key függvényben: %s", exc, exc_info=True)
                return False
            return True

        mouse_listener = mouse.Listener(
            on_move=on_move,
            on_click=on_click,
            on_scroll=on_scroll,
            suppress=True,
        )
        keyboard_listener = keyboard.Listener(
            on_press=lambda key: on_key(key, True),
            on_release=lambda key: on_key(key, False),
            suppress=True,
        )

        mouse_listener.start()
        keyboard_listener.start()

        try:
            while (
                self._state.is_active()
                and self._is_running()
                and not self._stop_event.is_set()
            ):
                time.sleep(STREAM_LOOP_DELAY)
                if not mouse_listener.is_alive() or not keyboard_listener.is_alive():
                    if not self._stop_event.is_set():
                        logging.warning(
                            "Input listener thread stopped unexpectedly; restarting mouse sync",
                        )
                        break
                if not sender_thread.is_alive():
                    if not self._stop_event.is_set():
                        logging.warning(
                            "Input sender thread stopped unexpectedly; restarting mouse sync",
                        )
                        break
        finally:
            for key_type, key_val in list(pressed_keys):
                send({'type': 'key', 'key_type': key_type, 'key': key_val, 'pressed': False})
            pressed_keys.clear()

            mouse_listener.stop()
            keyboard_listener.stop()
            send_queue.put(None)
            sender_thread.join()
            while not send_queue.empty():
                leftover = send_queue.get()
                if leftover and isinstance(leftover, tuple):
                    _, evt = leftover
                else:
                    evt = None
                if evt:
                    record_unsent(evt)

            if unsent_events_total:
                logging.warning(
                    "Unsent or failed events (total=%d, showing_last=%d): %s",
                    unsent_events_total,
                    len(unsent_events),
                    list(unsent_events),
                )

            logging.info("Streaming listenerek leálltak.")
            self.restore_mouse_position()
