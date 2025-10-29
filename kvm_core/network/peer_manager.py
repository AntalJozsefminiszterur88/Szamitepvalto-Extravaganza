import ipaddress
import logging
import socket
import ssl
import threading
import time
from typing import Callable, Dict, Iterable, Optional, Sequence

import msgpack
from PySide6.QtCore import QSettings

from config.constants import APP_NAME, ORG_NAME, SERVICE_TYPE
from kvm_core.network.discovery import ServiceDiscovery
from kvm_core.network.peer_connection import PeerConnection
from .secure_socket import *


from kvm_core.state import KVMState

class PeerManager:
    """Central controller coordinating peer discovery and connections."""

    def __init__(
        self,
        worker,
        state: KVMState,
        zeroconf,
        *,
        port: int,
        device_name: str,
        message_callback: Callable[[PeerConnection, dict], None],
    ) -> None:
        self._worker = worker
        self._state = state
        self._zeroconf = zeroconf
        self._port = port
        self._device_name = device_name
        self._message_callback = message_callback
        self._running = threading.Event()
        self._listening_socket: Optional[socket.socket] = None
        self.accept_thread: Optional[threading.Thread] = None
        self.connection_manager_thread: Optional[threading.Thread] = None
        self._connections: Dict[socket.socket, PeerConnection] = {}
        self._connections_lock = threading.Lock()

        role = worker.settings.get("role")
        self._server_context = None
        if role == "ado":
            try:
                self._server_context = create_server_context()
            except FileNotFoundError:
                logging.critical("Server TLS key missing for 'ado' role")
                raise

        self._client_context = create_client_context()
        self._discovery = ServiceDiscovery(
            zeroconf,
            SERVICE_TYPE,
            lambda: self._worker.local_ip,
            port,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def start(self) -> None:
        if self._running.is_set():
            return
        self._running.set()
        self._discovery.start()

        self.accept_thread = threading.Thread(
            target=self._accept_loop,
            daemon=True,
            name="AcceptThread",
        )
        self.accept_thread.start()

        self.connection_manager_thread = threading.Thread(
            target=self._connection_manager_loop,
            daemon=True,
            name="ConnMgr",
        )
        self.connection_manager_thread.start()

    def stop(self) -> None:
        if not self._running.is_set():
            return
        self._running.clear()
        self._discovery.stop()

        if self._listening_socket:
            try:
                self._listening_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self._listening_socket.close()
            except Exception:
                pass
            self._listening_socket = None

        for conn in list(self._connections.values()):
            self.disconnect_peer(conn, "manager stop")

        if self.accept_thread and self.accept_thread.is_alive():
            self.accept_thread.join(timeout=1.0)
        if self.connection_manager_thread and self.connection_manager_thread.is_alive():
            self.connection_manager_thread.join(timeout=1.0)

    # ------------------------------------------------------------------
    # Properties used by other components
    # ------------------------------------------------------------------
    @property
    def device_name(self) -> str:
        return self._device_name

    @property
    def role(self) -> Optional[str]:
        return self._worker.settings.get("role")

    @property
    def is_running(self) -> bool:
        return self._running.is_set() and self._worker._running

    @property
    def resolver_thread(self) -> Optional[threading.Thread]:
        return self._discovery.resolver_thread

    @property
    def discovered_peers(self) -> Sequence[Dict[str, object]]:
        return self._discovery.peers

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------
    def register_connection(
        self, connection: PeerConnection, peer_name: str, peer_role: Optional[str]
    ) -> bool:
        sock = connection.socket
        with self._connections_lock:
            self._connections[sock] = connection

        worker = self._worker
        state = self._state
        state.add_client(sock, peer_name, peer_role)

        if worker.settings.get("role") == "ado" and peer_role == "input_provider":
            worker.input_provider_socket = sock
            logging.info("Input provider connected: %s", peer_name)
        if worker.settings.get("role") == "input_provider" and peer_role == "ado":
            worker.server_socket = sock
            logging.info("Controller connection established: %s", peer_name)
        if worker.settings.get("role") == "vevo" and peer_role == "ado":
            worker.server_socket = sock
            logging.info("Laptop connected to controller: %s", peer_name)
            peer_ip = self._safe_peername(sock) or (
                connection.addr[0] if isinstance(connection.addr, tuple) else None
            )
            if (
                peer_ip
                and peer_ip != worker.last_server_ip
                and peer_ip != worker.local_ip
            ):
                worker.last_server_ip = peer_ip
                settings_store = QSettings(ORG_NAME, APP_NAME)
                settings_store.setValue("network/last_server_ip", peer_ip)
                logging.info("Laptop client stored last server IP: %s", peer_ip)

        pending_target = state.get_pending_activation_target()
        if (
            pending_target
            and pending_target == peer_name
            and not state.is_active()
        ):
            logging.info("Reconnected to %s, resuming KVM", peer_name)
            state.set_active_client(sock)
            state.set_pending_activation_target(None)
            worker.activate_kvm(switch_monitor=worker.switch_monitor)

        logging.info("Client connected: %s (%s)", peer_name, connection.addr)
        return True

    def unregister_connection(self, connection: PeerConnection, reason: str) -> None:
        connection._closed = True
        sock = connection.socket
        addr = connection.addr if isinstance(connection.addr, tuple) else None

        with self._connections_lock:
            self._connections.pop(sock, None)

        worker = self._worker
        state = self._state
        removal = state.remove_client(sock)
        peer_name = removal["peer_name"]
        was_active = removal["was_active"]
        peer_still_connected = removal["peer_still_connected"]

        if peer_still_connected:
            logging.debug("Closed redundant connection to %s (%s)", peer_name, reason)
            return

        suppress_switch_reasons = {"peer_connection_exit", "manager stop", "manual", "sender error"}

        if worker.settings.get("role") == "ado" and sock == worker.input_provider_socket:
            if state.is_active():
                switch_monitor = (
                    False
                    if reason in suppress_switch_reasons
                    else state.get_current_target() == "elitedesk"
                )
                worker.deactivate_kvm(
                    switch_monitor=switch_monitor,
                    reason="input provider disconnect",
                )
            worker.input_provider_socket = None
            state.set_pending_activation_target(None)
        if worker.settings.get("role") == "input_provider" and sock == worker.server_socket:
            worker.server_socket = None
            worker._stop_input_provider_stream()
        if worker.settings.get("role") == "vevo" and sock == worker.server_socket:
            worker.server_socket = None

        if was_active and state.is_active():
            logging.info("Active client disconnected, deactivating KVM")
            state.set_pending_activation_target(peer_name)
            switch_monitor = False if reason in suppress_switch_reasons else None
            worker.deactivate_kvm(switch_monitor=switch_monitor, reason=reason)
        elif was_active:
            state.set_active_client(None)
            state.set_pending_activation_target(None)

        if addr and worker._running:
            worker._schedule_reconnect(addr[0], self._port)

    # ------------------------------------------------------------------
    # Messaging utilities
    # ------------------------------------------------------------------
    def disconnect_peer(self, peer, reason: str = "manual") -> None:
        connection = self._resolve_connection(peer)
        if not connection:
            if isinstance(peer, socket.socket):
                try:
                    peer.close()
                except Exception:
                    pass
            return
        try:
            connection.stop()
        finally:
            self.unregister_connection(connection, reason)

    def broadcast(self, message: dict, exclude_peer: Optional[Iterable] = None) -> None:
        connections = list(self._connections.values())
        if not connections:
            return
        packed = msgpack.packb(message, use_bin_type=True)
        excluded = self._normalize_exclude(exclude_peer)
        for conn in connections:
            if conn in excluded or conn.socket in excluded:
                continue
            conn.send_packed(packed)

    def send_to_peer(self, peer, message: dict) -> bool:
        connection = self._resolve_connection(peer)
        if connection is None:
            return False
        return connection.send(message)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _accept_loop(self) -> None:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        while self._running.is_set():
            try:
                server_socket.bind(("", self._port))
                break
            except OSError as exc:
                logging.error("Port bind failed: %s. Retrying...", exc)
                time.sleep(5)

        server_socket.listen(5)
        server_socket.settimeout(1.0)
        self._listening_socket = server_socket
        logging.info("TCP server listening on %s", self._port)

        while self._running.is_set():
            try:
                client_sock, addr = server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            peer_ip = addr[0]
            secure_sock: Optional[socket.socket] = None
            try:
                client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                try:
                    local_addr = ipaddress.ip_address(self._worker.local_ip)
                    remote_addr = ipaddress.ip_address(peer_ip)
                except ValueError:
                    logging.warning(
                        f"Érvénytelen IP-cím a bejövő kapcsolatnál: {peer_ip}"
                    )
                    client_sock.close()
                    continue

                if local_addr > remote_addr:
                    try:
                        secure_sock = wrap_socket_server_side(
                            client_sock, self._server_context
                        )
                    except ssl.SSLError as e:
                        logging.error(
                            f"SSL hiba a bejövő kapcsolatnál ({addr[0]}): {e}"
                        )
                        client_sock.close()
                        continue

                    secure_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    self._spawn_connection(secure_sock, addr)
                else:
                    client_sock.close()
                    continue
            except Exception:
                try:
                    if secure_sock is not None:
                        secure_sock.close()
                    else:
                        client_sock.close()
                except Exception:
                    pass

        try:
            server_socket.close()
        except Exception:
            pass
        self._listening_socket = None

    def _spawn_connection(self, sock: socket.socket, addr) -> None:
        connection = PeerConnection(sock, addr, self, self._handle_incoming)
        connection.start()

    def _handle_incoming(self, connection: PeerConnection, data: dict) -> None:
        if not self.is_running:
            return
        self._message_callback(connection, data)

    def _connection_manager_loop(self) -> None:
        while self._running.is_set():
            peers = list(self._discovery.peers)

            worker = self._worker
            if worker.settings.get("role") == "vevo" and worker.last_server_ip:
                if worker.last_server_ip != worker.local_ip and not any(
                    peer.get("ip") == worker.last_server_ip for peer in peers
                ):
                    peers.append({"ip": worker.last_server_ip, "port": self._port})

            for peer in peers:
                ip = peer["ip"]
                port = peer["port"]

                if ip == self._worker.local_ip and port == self._port:
                    continue

                sockets = self._state.get_client_sockets()
                already = any(
                    self._safe_peername(s) == ip
                    for s in sockets
                    if s.fileno() != -1
                )
                if already:
                    continue

                try:
                    local_addr = ipaddress.ip_address(self._worker.local_ip)
                    remote_addr = ipaddress.ip_address(ip)
                    if local_addr > remote_addr:
                        continue
                except ValueError:
                    logging.warning(
                        f"Érvénytelen IP-cím a kapcsolatkezelőben: {ip}"
                    )
                    continue

                self.connect_to_peer(ip, port)
            time.sleep(2)

    def connect_to_peer(self, ip: str, port: int) -> None:
        secure_sock: Optional[socket.socket] = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:
                secure_sock = wrap_socket_client_side(
                    sock, self._client_context, server_hostname=ip
                )
            except ssl.SSLError as e:
                logging.error(f"SSL hiba a kimenő kapcsolatnál ({ip}): {e}")
                sock.close()
                return
            secure_sock.connect((ip, port))
        except Exception as exc:
            logging.error("Failed to connect to peer %s:%s: %s", ip, port, exc)
            try:
                if secure_sock is not None:
                    secure_sock.close()
                else:
                    sock.close()
            except Exception:
                pass
            return

        assert secure_sock is not None
        self._spawn_connection(secure_sock, (ip, port))

    def _normalize_exclude(self, exclude_peer: Optional[Iterable]) -> set:
        if exclude_peer is None:
            return set()
        if isinstance(exclude_peer, Iterable) and not isinstance(exclude_peer, (bytes, str)):
            return set(exclude_peer)
        return {exclude_peer}

    def _resolve_connection(self, peer) -> Optional[PeerConnection]:
        if isinstance(peer, PeerConnection):
            return peer
        with self._connections_lock:
            return self._connections.get(peer)

    @staticmethod
    def _safe_peername(sock: socket.socket) -> Optional[str]:
        try:
            return sock.getpeername()[0]
        except Exception:
            return None

