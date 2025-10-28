"""Centralised state management helpers for the KVM orchestrator."""

from __future__ import annotations

import threading
from typing import Dict, List, Optional


class KVMState:
    """Thread-safe container for the application state shared across subsystems."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._active = False
        self._active_client = None
        self._client_sockets: List = []
        self._client_infos: Dict = {}
        self._client_roles: Dict = {}
        self._pending_activation_target: Optional[str] = None
        self._provider_target: Optional[str] = None
        self._current_target: str = "desktop"

    # ------------------------------------------------------------------
    # General helpers
    # ------------------------------------------------------------------
    def is_active(self) -> bool:
        with self._lock:
            return self._active

    def set_active(self, is_active: bool) -> None:
        with self._lock:
            self._active = is_active

    # ------------------------------------------------------------------
    # Client management
    # ------------------------------------------------------------------
    def add_client(self, sock, info: str, role: Optional[str] = None) -> dict:
        """Register a connected client and optionally set it as active."""
        with self._lock:
            if sock not in self._client_sockets:
                self._client_sockets.append(sock)
            self._client_infos[sock] = info
            if role is not None:
                self._client_roles[sock] = role
            was_new_active = False
            if self._active_client is None and role != "input_provider":
                self._active_client = sock
                was_new_active = True
            return {
                "was_new_active": was_new_active,
                "active_client": self._active_client,
            }

    def remove_client(self, sock) -> dict:
        """Remove a disconnected client and update the active selection."""
        with self._lock:
            peer_name = self._client_infos.get(sock)
            was_active = sock == self._active_client
            if sock in self._client_sockets:
                self._client_sockets.remove(sock)
            self._client_infos.pop(sock, None)
            self._client_roles.pop(sock, None)
            peer_still_connected = (
                peer_name is not None and peer_name in self._client_infos.values()
            )
            if peer_still_connected and was_active:
                for existing_sock, name in self._client_infos.items():
                    if name == peer_name:
                        self._active_client = existing_sock
                        break
            elif was_active:
                self._active_client = self._client_sockets[0] if self._client_sockets else None
            return {
                "peer_name": peer_name,
                "was_active": was_active,
                "peer_still_connected": peer_still_connected,
                "active_client": self._active_client,
            }

    def clear_clients(self) -> None:
        with self._lock:
            self._client_sockets.clear()
            self._client_infos.clear()
            self._client_roles.clear()
            self._active_client = None

    def get_client_sockets(self) -> List:
        with self._lock:
            return list(self._client_sockets)

    def get_client_infos(self) -> Dict:
        with self._lock:
            return dict(self._client_infos)

    def get_client_roles(self) -> Dict:
        with self._lock:
            return dict(self._client_roles)

    def get_client_name(self, sock, default: Optional[str] = None) -> Optional[str]:
        with self._lock:
            return self._client_infos.get(sock, default)

    def get_active_client(self):
        with self._lock:
            return self._active_client

    def set_active_client(self, sock) -> None:
        with self._lock:
            self._active_client = sock

    def ensure_active_client(self) -> Optional[object]:
        """Return the active client, falling back to the first connected one."""
        with self._lock:
            if self._active_client is not None:
                return self._active_client
            if self._client_sockets:
                self._active_client = self._client_sockets[0]
            return self._active_client

    # ------------------------------------------------------------------
    # High-level target flags
    # ------------------------------------------------------------------
    def get_pending_activation_target(self) -> Optional[str]:
        with self._lock:
            return self._pending_activation_target

    def set_pending_activation_target(self, target: Optional[str]) -> None:
        with self._lock:
            self._pending_activation_target = target

    def get_provider_target(self) -> Optional[str]:
        with self._lock:
            return self._provider_target

    def set_provider_target(self, target: Optional[str]) -> None:
        with self._lock:
            self._provider_target = target

    def get_current_target(self) -> str:
        with self._lock:
            return self._current_target

    def set_current_target(self, target: str) -> None:
        with self._lock:
            self._current_target = target

