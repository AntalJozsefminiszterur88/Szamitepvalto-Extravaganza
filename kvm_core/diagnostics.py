"""Diagnostics and background monitoring utilities for the KVM orchestrator."""

from __future__ import annotations

import logging
import threading
import time
from typing import Optional, TYPE_CHECKING

import psutil

if TYPE_CHECKING:  # pragma: no cover
    from .orchestrator import KVMOrchestrator
    from .state import KVMState


class DiagnosticsManager:
    """Handles background diagnostic loops for the KVM orchestrator."""

    def __init__(
        self,
        orchestrator: "KVMOrchestrator",
        state: "KVMState",
    ) -> None:
        self._orchestrator = orchestrator
        self._state = state
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    @property
    def heartbeat_thread(self) -> Optional[threading.Thread]:
        return self._heartbeat_thread

    def start(self) -> None:
        """Start background diagnostic threads."""
        self._stop_event.clear()

        if self._heartbeat_thread is None or not self._heartbeat_thread.is_alive():
            self._heartbeat_thread = threading.Thread(
                target=self._heartbeat_loop,
                daemon=True,
                name="Heartbeat",
            )
            self._heartbeat_thread.start()

    def stop(self) -> None:
        """Stop diagnostic threads and wait for them to finish."""
        logging.info(f"Stopping {self.__class__.__name__}...")
        self._stop_event.set()
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            self._heartbeat_thread.join(timeout=1)
        self._heartbeat_thread = None
        logging.info(f"{self.__class__.__name__} stopped.")

    # ------------------------------------------------------------------
    # Diagnostic loops
    # ------------------------------------------------------------------
    def _heartbeat_loop(self) -> None:
        """Logs detailed diagnostics every 30 seconds."""
        process = psutil.Process()
        logging.info("Heartbeat monitor thread started.")
        while self._orchestrator._running and not self._stop_event.is_set():
            try:
                mem_usage = process.memory_info().rss / (1024 * 1024)
                cpu_usage = process.cpu_percent(interval=1.0)
                active_threads = threading.active_count()
                streaming_thread = self._orchestrator.streaming_thread
                msg_processor_thread = self._orchestrator.message_processor_thread
                stream_thread_alive = streaming_thread.is_alive() if streaming_thread else "N/A"
                msg_proc_alive = (
                    msg_processor_thread.is_alive() if msg_processor_thread else "N/A"
                )
                client_infos = self._state.get_client_infos()
                connected_clients_count = len(client_infos)
                client_names = list(client_infos.values())
                active_client_name = client_infos.get(
                    self._state.get_active_client(), "None"
                )
                log_message = (
                    f"HEARTBEAT - "
                    f"Mem: {mem_usage:.2f} MB, CPU: {cpu_usage:.1f}%, Threads: {active_threads} | "
                    f"KVM Active: {self._state.is_active()}, Target: {active_client_name} | "
                    f"Clients: {connected_clients_count} {client_names} | "
                    f"StreamThread: {stream_thread_alive}, MsgProc: {msg_proc_alive}"
                )
                logging.debug(log_message)
                for _ in range(29):
                    if self._stop_event.is_set() or not self._orchestrator._running:
                        break
                    time.sleep(1)
            except Exception as exc:  # pragma: no cover - logging only
                logging.error("Heartbeat monitor failed: %s", exc, exc_info=True)
                if self._stop_event.wait(30):
                    break
        logging.info("Heartbeat monitor thread stopped.")
