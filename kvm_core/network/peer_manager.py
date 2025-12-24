import json
import logging
import socket
import threading
import time
from typing import Callable, Dict, Iterable, Optional, Sequence

import msgpack
from PySide6.QtCore import QSettings

from config.constants import APP_NAME, ORG_NAME
from kvm_core.network.peer_connection import DataConnection, PeerConnection
from kvm_core.state import KVMState


class PeerManager:
    """Beacon-based peer manager for LAN discovery and connectivity."""

    def __init__(
        self,
        worker,
        state: KVMState,
        zeroconf,  # kept for signature compatibility
        *,
        port: int,
        data_port: Optional[int] = None,
        device_name: str,
        message_callback: Callable[[PeerConnection, dict], None],
    ) -> None:
        self._worker = worker
        self._state = state
        self._port = port
        self._data_port = data_port if data_port is not None else port + 1
        self._device_name = device_name
        self._message_callback = message_callback
        self._running = threading.Event()
        self._connections: Dict[socket.socket, PeerConnection] = {}
        self._data_connections: Dict[socket.socket, DataConnection] = {}
        self._pending_data_connections: Dict[str, DataConnection] = {}
        self._connections_lock = threading.Lock()

        self._listening_socket: Optional[socket.socket] = None
        self._data_listening_socket: Optional[socket.socket] = None
        self._broadcast_socket: Optional[socket.socket] = None
        self._udp_listener_socket: Optional[socket.socket] = None

        self.accept_thread: Optional[threading.Thread] = None
        self.data_accept_thread: Optional[threading.Thread] = None
        self.connection_manager_thread: Optional[threading.Thread] = None
        self.resolver_thread: Optional[threading.Thread] = None
        self._broadcast_thread: Optional[threading.Thread] = None

    def _get_lan_ip(self) -> Optional[str]:
        """Finds the local IP on the 192.168.x.x subnet."""
        try:
            hostname = socket.gethostname()
            _, _, ips = socket.gethostbyname_ex(hostname)
            for ip in ips:
                if ip.startswith("192.168."):
                    return ip
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def start(self) -> None:
        if self._running.is_set():
            return
        self._running.set()

        if self._is_server_role():
            self._start_server_components()
        else:
            self._start_client_components()

    def stop(self) -> None:
        logging.info("Stopping PeerManager...")
        if not self._running.is_set():
            logging.info("PeerManager stopped.")
            return
        self._running.clear()

        if self._broadcast_socket:
            try:
                self._broadcast_socket.close()
            except Exception:
                pass
            self._broadcast_socket = None

        if self._udp_listener_socket:
            try:
                self._udp_listener_socket.close()
            except Exception:
                pass
            self._udp_listener_socket = None

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

        if self._data_listening_socket:
            try:
                self._data_listening_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self._data_listening_socket.close()
            except Exception:
                pass
            self._data_listening_socket = None

        for conn in list(self._connections.values()):
            self.disconnect_peer(conn, "manager stop")

        for data_conn in list(self._data_connections.values()):
            data_conn.close()
        self._data_connections.clear()
        for pending_conn in list(self._pending_data_connections.values()):
            pending_conn.close()
        self._pending_data_connections.clear()

        self._join_thread(self.accept_thread)
        self._join_thread(self.data_accept_thread)
        self._join_thread(self.connection_manager_thread)
        self._join_thread(self._broadcast_thread)

        logging.info("PeerManager stopped.")

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
    def discovered_peers(self) -> Sequence[Dict[str, object]]:
        return []

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------
    def register_connection(
        self, connection: PeerConnection, peer_name: str, peer_role: Optional[str]
    ) -> bool:
        sock = connection.socket
        with self._connections_lock:
            self._connections[sock] = connection

        self._attach_pending_data_connection(connection)

        worker = self._worker
        state = self._state
        state.add_client(sock, peer_name, peer_role)

        if worker.settings.get("role") == "ado" and peer_role == "input_provider":
            worker.input_provider_socket = sock
            logging.info("Input provider connected: %s", peer_name)
        if worker.settings.get("role") == "input_provider" and peer_role == "ado":
            worker.server_socket = sock
            logging.info("Controller connection established: %s", peer_name)
            if hasattr(worker, "_on_server_connected"):
                worker._on_server_connected()
        if worker.settings.get("role") == "vevo" and peer_role == "ado":
            worker.server_socket = sock
            logging.info("Laptop connected to controller: %s", peer_name)
            if hasattr(worker, "_on_server_connected"):
                worker._on_server_connected()
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
        if pending_target and pending_target == peer_name and not state.is_active():
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
            data_conn = self._data_connections.pop(sock, None)
            if data_conn:
                data_conn.close()

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
            if hasattr(worker, "_on_server_disconnected"):
                worker._on_server_disconnected()
        if worker.settings.get("role") == "vevo" and sock == worker.server_socket:
            worker.server_socket = None
            if hasattr(worker, "_on_server_disconnected"):
                worker._on_server_disconnected()

        if was_active and state.is_active():
            logging.info("Active client disconnected, deactivating KVM")
            state.set_pending_activation_target(peer_name)
            switch_monitor = False if reason in suppress_switch_reasons else None
            worker.deactivate_kvm(switch_monitor=switch_monitor, reason=reason)
        elif was_active:
            state.set_active_client(None)
            state.set_pending_activation_target(None)

        if addr and worker._running and not self._is_server_role():
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

    def send_data(self, peer, data) -> bool:
        data_connection = self._resolve_data_connection(peer)
        if data_connection is None:
            return False
        return data_connection.send_data(data)

    # ------------------------------------------------------------------
    # Server components
    # ------------------------------------------------------------------
    def _start_server_components(self) -> None:
        self._broadcast_thread = threading.Thread(
            target=self._beacon_broadcast_loop,
            daemon=True,
            name="BroadcastThread",
        )
        self._broadcast_thread.start()

        self.accept_thread = threading.Thread(
            target=self._accept_loop,
            daemon=True,
            name="AcceptThread",
        )
        self.accept_thread.start()

        self.data_accept_thread = threading.Thread(
            target=self._accept_data_loop,
            daemon=True,
            name="DataAcceptThread",
        )
        self.data_accept_thread.start()

    def _beacon_broadcast_loop(self) -> None:
        """Sends UDP beacons, but binds to the correct LAN interface first."""
        logging.info("Starting intelligent beacon broadcast loop...")

        while self._running.is_set():
            source_ip = self._get_lan_ip()
            if not source_ip:
                logging.warning("Could not find a 192.168.x.x interface for broadcasting.")
                time.sleep(5)
                continue

            try:
                # Use subnet-specific broadcast for reliability
                broadcast_ip = ".".join(source_ip.split(".")[:3]) + ".255"

                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

                # CRITICAL: Bind to the specific LAN IP to force correct interface usage
                sock.bind((source_ip, 0))

                payload = json.dumps(
                    {
                        "type": "beacon",
                        "port": self._port,
                        "name": self._device_name,
                        "from_ip": source_ip,
                    }
                ).encode("utf-8")

                sock.sendto(payload, (broadcast_ip, 50000))
                # logging.debug(f"Beacon sent from {source_ip} to {broadcast_ip}")
                sock.close()

            except Exception as e:
                logging.error(f"Beacon broadcast failed: {e}")

            time.sleep(1.0)

    def _accept_loop(self) -> None:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        server_socket.settimeout(1.0)

        while self._running.is_set():
            try:
                server_socket.bind(("", self._port))
                break
            except OSError as exc:
                logging.error("Port bind failed: %s. Retrying...", exc)
                time.sleep(5)

        server_socket.listen(5)
        self._listening_socket = server_socket
        logging.info("TCP server listening on %s", self._port)

        while self._running.is_set():
            try:
                client_sock, addr = server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                self._spawn_connection(client_sock, addr)
            except Exception as exc:
                logging.error("Failed to handle incoming connection %s: %s", addr, exc)
                try:
                    client_sock.close()
                except Exception:
                    pass

        try:
            server_socket.close()
        except Exception:
            pass
        self._listening_socket = None

    def _accept_data_loop(self) -> None:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        server_socket.settimeout(1.0)

        while self._running.is_set():
            try:
                server_socket.bind(("", self._data_port))
                break
            except OSError as exc:
                logging.error("Data port bind failed: %s. Retrying...", exc)
                time.sleep(5)

        server_socket.listen(5)
        self._data_listening_socket = server_socket
        logging.info("Data TCP server listening on %s", self._data_port)

        while self._running.is_set():
            try:
                client_sock, addr = server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                data_connection = DataConnection(client_sock, addr, self)
                if not data_connection.perform_handshake():
                    data_connection.close()
                    continue
                self._attach_data_connection(data_connection)
            except Exception as exc:
                logging.error("Failed to handle incoming data connection %s: %s", addr, exc)
                try:
                    client_sock.close()
                except Exception:
                    pass

        try:
            server_socket.close()
        except Exception:
            pass
        self._data_listening_socket = None

    # ------------------------------------------------------------------
    # Client components
    # ------------------------------------------------------------------
    def _start_client_components(self) -> None:
        self.connection_manager_thread = threading.Thread(
            target=self._client_logic_loop,
            daemon=True,
            name="ClientLogicThread",
        )
        self.connection_manager_thread.start()

    def _client_logic_loop(self) -> None:
        """Listens for beacons and connects upon receiving one."""
        logging.info("Starting client beacon listener...")

        try:
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            udp_sock.bind(("", 50000))
            self._udp_listener_socket = udp_sock
        except Exception as e:
            logging.critical(f"FATAL: Could not bind UDP listener on port 50000: {e}")
            return

        while self._running.is_set():
            if self._has_active_connection():
                time.sleep(1)
                continue

            try:
                # Wait for a beacon
                data, addr = self._udp_listener_socket.recvfrom(1024)
                beacon = json.loads(data.decode("utf-8"))

                if beacon.get("type") == "beacon":
                    server_ip = addr[0]
                    server_port = beacon.get("port", self._port)
                    logging.info(f"Beacon received from {server_ip}, attempting connection...")

                    # Attempt connection upon receiving a valid beacon
                    self.connect_to_peer(server_ip, server_port)

            except Exception as e:
                # This can happen on shutdown, it's fine
                logging.debug(f"UDP listener error: {e}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def connect_to_peer(self, ip: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            sock.settimeout(5.0)
            logging.debug("Attempting TCP connection to %s:%s", ip, port)
            sock.connect((ip, port))
        except Exception as exc:
            logging.error("Failed to connect to %s:%s (%s)", ip, port, exc)
            try:
                sock.close()
            except Exception:
                pass
            return False

        self._spawn_connection(sock, (ip, port))
        self._connect_data_channel(ip, port)
        return True

    def _spawn_connection(self, sock: socket.socket, addr) -> None:
        connection = PeerConnection(sock, addr, self, self._handle_incoming)
        connection.start()

    def _handle_incoming(self, connection: PeerConnection, data: dict) -> None:
        if not self.is_running:
            return
        self._message_callback(connection, data)

    def _has_active_connection(self) -> bool:
        with self._connections_lock:
            return bool(self._connections)

    def _connect_data_channel(self, ip: str, port: int) -> None:
        data_port = port + 1
        data_sock = None
        try:
            data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            data_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            data_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            data_sock.settimeout(5.0)
            logging.debug("Attempting data TCP connection to %s:%s", ip, data_port)
            data_sock.connect((ip, data_port))
        except Exception as exc:
            logging.warning("Failed to connect data channel to %s:%s (%s)", ip, data_port, exc)
            try:
                if data_sock:
                    data_sock.close()
            except Exception:
                pass
            return

        data_connection = DataConnection(data_sock, (ip, data_port), self)
        if not data_connection.perform_handshake():
            data_connection.close()
            return
        self._attach_data_connection(data_connection)

    def _attach_data_connection(self, data_connection: DataConnection) -> None:
        with self._connections_lock:
            control_connection = None
            for conn in self._connections.values():
                if conn.peer_name == data_connection.peer_name:
                    control_connection = conn
                    break
                if (
                    isinstance(conn.addr, tuple)
                    and isinstance(data_connection.addr, tuple)
                    and conn.addr[0] == data_connection.addr[0]
                ):
                    control_connection = conn
                    break

            if control_connection:
                self._data_connections[control_connection.socket] = data_connection
                logging.info(
                    "Data channel connected for %s (%s)",
                    control_connection.peer_name,
                    data_connection.addr,
                )
                return

            self._pending_data_connections[data_connection.peer_name] = data_connection
            logging.info(
                "Data channel pending for %s (%s)",
                data_connection.peer_name,
                data_connection.addr,
            )

    def _attach_pending_data_connection(self, connection: PeerConnection) -> None:
        with self._connections_lock:
            data_connection = self._pending_data_connections.pop(connection.peer_name, None)
            if not data_connection and isinstance(connection.addr, tuple):
                for pending_name, pending_conn in list(self._pending_data_connections.items()):
                    if (
                        isinstance(pending_conn.addr, tuple)
                        and pending_conn.addr[0] == connection.addr[0]
                    ):
                        data_connection = pending_conn
                        self._pending_data_connections.pop(pending_name, None)
                        break

            if data_connection:
                self._data_connections[connection.socket] = data_connection
                logging.info(
                    "Data channel attached to %s (%s)",
                    connection.peer_name,
                    data_connection.addr,
                )

    @staticmethod
    def _normalize_exclude(exclude_peer: Optional[Iterable]) -> set:
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

    def _resolve_data_connection(self, peer) -> Optional[DataConnection]:
        if isinstance(peer, DataConnection):
            return peer
        if isinstance(peer, PeerConnection):
            key = peer.socket
        else:
            key = peer
        with self._connections_lock:
            data_conn = self._data_connections.get(key)
            if data_conn:
                return data_conn
            if isinstance(key, socket.socket):
                for candidate in self._data_connections.values():
                    if candidate.socket == key:
                        return candidate
            return None

    @staticmethod
    def _safe_peername(sock: socket.socket) -> Optional[str]:
        try:
            return sock.getpeername()[0]
        except Exception:
            return None

    def _is_server_role(self) -> bool:
        return self.role == "ado" or self.role == "server"

    @staticmethod
    def _join_thread(thread: Optional[threading.Thread]) -> None:
        if thread and thread.is_alive():
            thread.join(timeout=1.0)
