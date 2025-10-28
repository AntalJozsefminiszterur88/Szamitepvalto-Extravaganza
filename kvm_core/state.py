"""Centralized KVM state management."""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional


class KVMState:
    """Thread-safe container for orchestrator runtime state."""

    __slots__ = (
        "_lock",
        "_active",
        "_active_client",
        "_client_sockets",
        "_client_infos",
        "_client_roles",
        "_current_target",
    )

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._active: bool = False
        self._active_client: Optional[Any] = None
        self._client_sockets: List[Any] = []
        self._client_infos: Dict[Any, str] = {}
        self._client_roles: Dict[Any, str] = {}
        self._current_target: str = "desktop"

    # ------------------------------------------------------------------
    # Activation state helpers
    # ------------------------------------------------------------------
    def is_active(self) -> bool:
        with self._lock:
            return self._active

    def set_active(self, value: bool) -> None:
        with self._lock:
            self._active = value

    # ------------------------------------------------------------------
    # Target management
    # ------------------------------------------------------------------
    def get_target(self) -> str:
        with self._lock:
            return self._current_target

    def set_target(self, target: str) -> None:
        with self._lock:
            self._current_target = target

    # ------------------------------------------------------------------
    # Client handling
    # ------------------------------------------------------------------
    def get_active_client(self) -> Optional[Any]:
        with self._lock:
            return self._active_client

    def set_active_client(self, client: Optional[Any]) -> None:
        with self._lock:
            self._active_client = client

    def get_client_sockets(self) -> List[Any]:
        with self._lock:
            return list(self._client_sockets)

    def add_client(
        self,
        sock: Any,
        info: Optional[str] = None,
        *,
        role: Optional[str] = None,
        make_active: bool = False,
    ) -> None:
        with self._lock:
            if sock not in self._client_sockets:
                self._client_sockets.append(sock)
            if info is not None:
                self._client_infos[sock] = info
            if role is not None:
                self._client_roles[sock] = role
            if make_active:
                self._active_client = sock

    def remove_client(self, sock: Any) -> None:
        with self._lock:
            if sock in self._client_sockets:
                self._client_sockets.remove(sock)
            self._client_infos.pop(sock, None)
            self._client_roles.pop(sock, None)
            if self._active_client is sock:
                self._active_client = None

    def clear_clients(self) -> None:
        with self._lock:
            self._client_sockets.clear()
            self._client_infos.clear()
            self._client_roles.clear()
            self._active_client = None

    def get_client_info(self, sock: Any) -> Optional[str]:
        with self._lock:
            return self._client_infos.get(sock)

    def set_client_info(self, sock: Any, info: str) -> None:
        with self._lock:
            self._client_infos[sock] = info

    def get_client_infos(self) -> Dict[Any, str]:
        with self._lock:
            return dict(self._client_infos)

    def get_client_role(self, sock: Any) -> Optional[str]:
        with self._lock:
            return self._client_roles.get(sock)

    def set_client_role(self, sock: Any, role: str) -> None:
        with self._lock:
            self._client_roles[sock] = role

    def iter_clients(self):
        with self._lock:
            items = list(self._client_infos.items())
        for sock, info in items:
            yield sock, info

    # ------------------------------------------------------------------
    # Derived helpers
    # ------------------------------------------------------------------
    def has_clients(self) -> bool:
        with self._lock:
            return bool(self._client_sockets)
