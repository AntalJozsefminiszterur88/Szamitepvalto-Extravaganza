import logging
import queue
import socket
import threading
from typing import Callable, Dict, Iterable, List, Optional

from zeroconf import ServiceBrowser


class ServiceDiscovery:
    """Wrapper around Zeroconf service discovery for peer detection."""

    def __init__(
        self,
        zeroconf,
        service_type: str,
        local_ip_getter: Callable[[], str],
        local_port: int,
    ) -> None:
        self._zeroconf = zeroconf
        self._service_type = service_type
        self._local_ip_getter = local_ip_getter
        self._local_port = local_port
        self._peers: Dict[str, Dict[str, object]] = {}
        self._queue: "queue.Queue[str]" = queue.Queue()
        self._lock = threading.Lock()
        self._browser: Optional[ServiceBrowser] = None
        self._resolver_thread: Optional[threading.Thread] = None
        self._running = threading.Event()

    def start(self) -> None:
        """Start the Zeroconf browser and resolver worker."""
        if self._running.is_set():
            return
        self._running.set()

        self._browser = ServiceBrowser(
            self._zeroconf,
            self._service_type,
            self._Listener(self),
        )
        self._resolver_thread = threading.Thread(
            target=self._resolver_loop,
            daemon=True,
            name="Resolver",
        )
        self._resolver_thread.start()

    def stop(self) -> None:
        """Stop background threads and clear cached peers."""
        if not self._running.is_set():
            return
        self._running.clear()

        if self._browser is not None:
            try:
                self._browser.cancel()
            except Exception:
                pass
            self._browser = None

        if self._resolver_thread and self._resolver_thread.is_alive():
            self._resolver_thread.join(timeout=1.0)
        self._resolver_thread = None

        with self._lock:
            self._peers.clear()

        while True:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                break

    @property
    def peers(self) -> List[Dict[str, object]]:
        """Return a snapshot of the discovered peers."""
        with self._lock:
            return list(self._peers.values())

    @property
    def resolver_thread(self) -> Optional[threading.Thread]:
        return self._resolver_thread

    def _resolver_loop(self) -> None:
        while self._running.is_set():
            try:
                name = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                info = self._zeroconf.get_service_info(
                    self._service_type,
                    name,
                    3000,
                )
                if not info:
                    continue

                ip_address = self._extract_ipv4(info.addresses)
                if not ip_address:
                    continue

                local_ip = self._local_ip_getter()
                if ip_address == local_ip and info.port == self._local_port:
                    with self._lock:
                        self._peers.pop(name, None)
                    continue

                with self._lock:
                    self._peers[name] = {
                        "ip": ip_address,
                        "port": info.port,
                    }
            except Exception as exc:
                logging.debug("Resolver failed for %s: %s", name, exc)

    @staticmethod
    def _extract_ipv4(addresses: Iterable[bytes]) -> Optional[str]:
        for addr in addresses:
            if isinstance(addr, (bytes, bytearray)) and len(addr) == 4:
                try:
                    return socket.inet_ntoa(addr)
                except OSError:
                    continue
        return None

    class _Listener:
        def __init__(self, discovery: "ServiceDiscovery") -> None:
            self._discovery = discovery

        def add_service(self, zeroconf, type_, name):
            self._discovery._queue.put(name)

        def update_service(self, zeroconf, type_, name):
            self._discovery._queue.put(name)

        def remove_service(self, zeroconf, type_, name):
            with self._discovery._lock:
                self._discovery._peers.pop(name, None)

