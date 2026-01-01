"""Message handling utilities for the KVM orchestrator."""

from __future__ import annotations

import logging
import os
import time
from datetime import date
from typing import Any, Callable, Dict, Optional

from pynput import keyboard

from kvm_core.clipboard import ClipboardManager
from kvm_core.input.receiver import InputReceiver
from kvm_core.state import KVMState
from config.log_aggregator import LogAggregator
from utils.stability_monitor import StabilityMonitor
from utils.path_helpers import resolve_documents_directory
from config.constants import BRAND_NAME
from utils.logging_setup import LOG_SUBDIRECTORY


class MessageHandler:
    """Process peer messages for the orchestrator."""

    def __init__(
        self,
        *,
        get_role: Callable[[], Optional[str]],
        toggle_client_control: Callable[..., Any],
        get_clipboard_manager: Callable[[], Optional[ClipboardManager]],
        handle_provider_event: Callable[[dict], None],
        input_receiver: InputReceiver,
        start_input_provider_stream: Callable[[str], None],
        stop_input_provider_stream: Callable[[], None],
        simulate_provider_key_tap: Callable[..., None],
        get_input_provider_socket: Callable[[], Any],
        set_input_provider_socket: Callable[[Any], None],
        state: KVMState,
        send_to_server: Callable[[dict], bool],
        get_device_name: Callable[[], str],
        log_aggregator: Optional[LogAggregator] = None,
        stability_monitor: Optional[StabilityMonitor] = None,
    ) -> None:
        self._get_role = get_role
        self._toggle_client_control = toggle_client_control
        self._get_clipboard_manager = get_clipboard_manager
        self._handle_provider_event = handle_provider_event
        self._input_receiver = input_receiver
        self._start_input_provider_stream = start_input_provider_stream
        self._stop_input_provider_stream = stop_input_provider_stream
        self._simulate_provider_key_tap = simulate_provider_key_tap
        self._get_input_provider_socket = get_input_provider_socket
        self._set_input_provider_socket = set_input_provider_socket
        self._state = state
        self._send_to_server = send_to_server
        self._get_device_name = get_device_name
        self._log_aggregator = log_aggregator
        self._stability_monitor = stability_monitor

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _handle_statistics_request(self, period: str) -> None:
        if not self._stability_monitor or not self._send_to_server:
            return
        snapshot = self._stability_monitor.generate_statistics_snapshot(period)
        payload = {
            "type": "statistics_report",
            "period": period,
            "source": self._get_device_name(),
            "methods": snapshot.get("methods", []),
            "counters": snapshot.get("counters", {}),
        }
        if not self._send_to_server(payload):
            logging.warning("Failed to send statistics report for period %s", period)

    def handle(self, peer_socket, data: dict) -> None:
        """Handle a single message from a peer."""
        try:
            role = self._get_role()
            cmd = data.get('command')
            msg_type = data.get('type')
            clipboard_manager = self._get_clipboard_manager()

            if role == 'ado':
                if msg_type == 'remote_log':
                    if self._log_aggregator:
                        source = data.get('source') or self._state.get_client_name(peer_socket, 'ismeretlen')
                        level = str(data.get('level', 'WARNING'))
                        message = str(data.get('message', ''))
                        self._log_aggregator.add_remote_log(str(source), level, message)
                    return
                if cmd == 'upload_crash_report':
                    content = data.get('content')
                    if content is None:
                        logging.warning("Received empty crash report payload")
                        return
                    source = data.get('source') or self._state.get_client_name(peer_socket, 'ismeretlen')
                    safe_source = str(source).replace(os.sep, "_").replace(" ", "_")
                    target_dir = None
                    if self._stability_monitor:
                        target_dir = self._stability_monitor.get_report_directory()
                    if not target_dir:
                        target_dir = os.path.join(
                            str(resolve_documents_directory()), BRAND_NAME, LOG_SUBDIRECTORY
                        )
                    try:
                        os.makedirs(target_dir, exist_ok=True)
                        filename = f"CRASH_{safe_source}_{date.today().isoformat()}.log"
                        target_path = os.path.join(target_dir, filename)
                        with open(target_path, "w", encoding="utf-8") as crash_file:
                            crash_file.write(str(content))
                        logging.info("Stored crash report from %s at %s", source, target_path)
                    except Exception:
                        logging.exception("Failed to persist crash report from %s", source)
                    return
                if msg_type == 'statistics_report':
                    if self._stability_monitor:
                        source = data.get('source') or self._state.get_client_name(peer_socket, 'ismeretlen')
                        period = str(data.get('period', 'daily'))
                        methods = list(data.get('methods', []))
                        counters_raw = data.get('counters', {})
                        counters: Dict[str, int] = {}
                        if isinstance(counters_raw, dict):
                            for key, value in counters_raw.items():
                                try:
                                    counters[str(key)] = int(value)
                                except (TypeError, ValueError):
                                    continue
                        stats_payload = {
                            'period': period,
                            'methods': methods,
                            'counters': counters,
                        }
                        self._stability_monitor.add_remote_statistics(str(source), stats_payload)
                    return
                if cmd == 'switch_elitedesk':
                    self._toggle_client_control('elitedesk', switch_monitor=True)
                    return
                if cmd == 'switch_laptop':
                    self._toggle_client_control('laptop', switch_monitor=False)
                    return
                if clipboard_manager and clipboard_manager.handle_network_message(peer_socket, data):
                    return
                msg_type = data.get('type')
                input_provider_socket = self._get_input_provider_socket()
                if (
                    msg_type in {'move_relative', 'click', 'scroll', 'key'}
                ):
                    if peer_socket == input_provider_socket:
                        self._handle_provider_event(data)
                        return
                    client_roles = self._state.get_client_roles()
                    if client_roles.get(peer_socket) == 'input_provider':
                        self._set_input_provider_socket(peer_socket)
                        logging.info(
                            "Auto-healed input provider socket for %s",
                            self._state.get_client_name(peer_socket, peer_socket),
                        )
                        self._handle_provider_event(data)
                        return
                logging.debug(
                    "Unhandled message type '%s' in controller context from %s",
                    data.get('type') or data.get('command'),
                    self._state.get_client_name(peer_socket, peer_socket),
                )
                return

            if role == 'input_provider':
                if cmd == 'start_stream':
                    target = data.get('target', 'elitedesk')
                    self._start_input_provider_stream(target)
                    return
                if cmd == 'stop_stream':
                    self._stop_input_provider_stream()
                    return
                if cmd == 'force_f22_trigger':
                    self._input_receiver.keyboard_controller.press(keyboard.Key.f22)
                    time.sleep(0.05)
                    self._input_receiver.keyboard_controller.release(keyboard.Key.f22)
                    return
                if cmd == 'host_key_tap':
                    key_type = data.get('key_type', 'vk')
                    key_value = data.get('key')
                    source = data.get('source')
                    self._simulate_provider_key_tap(key_type, key_value, source)
                    return
                if cmd == 'get_statistics':
                    period = str(data.get('period', 'daily'))
                    self._handle_statistics_request(period)
                    return
                if clipboard_manager and clipboard_manager.handle_network_message(peer_socket, data):
                    return
                logging.debug(
                    "Unhandled message type '%s' in input provider context",
                    data.get('type') or data.get('command'),
                )
                return

            if cmd == 'get_statistics':
                period = str(data.get('period', 'daily'))
                self._handle_statistics_request(period)
                return

            if clipboard_manager and clipboard_manager.handle_network_message(peer_socket, data):
                return

            if msg_type in {'move_relative', 'click', 'scroll', 'key'}:
                self._input_receiver.apply_event(data)
            else:
                logging.debug(
                    "Unhandled message type '%s' in peer message processor",
                    data.get('type') or data.get('command'),
                )
        except Exception as exc:
            logging.error("Failed to process message: %s", exc, exc_info=True)
