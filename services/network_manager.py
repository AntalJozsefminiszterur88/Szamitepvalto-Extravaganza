"""Network handling utilities for the KVM service."""

from __future__ import annotations

import ipaddress
import logging
import queue
import socket
import struct
import threading
import time
from typing import Optional, Tuple

import msgpack
from PySide6.QtCore import QObject, Signal
from zeroconf import IPVersion, ServiceBrowser, Zeroconf

from core.config import SERVICE_TYPE


class NetworkManager(QObject):
    """Encapsulates zeroconf discovery and socket communication."""

    data_received = Signal(object, dict)
    client_connected = Signal(object, str, object)
    client_disconnected = Signal(object, str)

    def __init__(self, service, settings, device_name: str, local_ip: str) -> None:
        super().__init__()
        self.service = service
        self.settings = settings
        self.device_name = device_name
        self.local_ip = local_ip

        self.zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
        self.resolver_queue: "queue.Queue[str]" = queue.Queue()
        self.discovered_peers: dict[str, dict[str, object]] = {}
        self.peers_lock = threading.Lock()
        self.clients_lock = threading.Lock()
        self.client_sockets: list[socket.socket] = []
        self.client_infos: dict[socket.socket, str] = {}
        self.client_roles: dict[socket.socket, Optional[str]] = {}
        self.connection_thread: Optional[threading.Thread] = None
        self.connection_manager_thread: Optional[threading.Thread] = None
        self.resolver_thread: Optional[threading.Thread] = None
        self.service_info = None

    # ------------------------------------------------------------------
    # Message helpers
    # ------------------------------------------------------------------
    def send_message(self, sock: socket.socket, data) -> bool:
        """Send a msgpack message through the given socket."""
        try:
            packed = msgpack.packb(data, use_bin_type=True)
            sock.sendall(struct.pack('!I', len(packed)) + packed)
            logging.debug(
                "Sent message type '%s' (%d bytes)",
                data.get('type'),
                len(packed),
            )
            return True
        except Exception as exc:
            logging.error(
                "Failed to send message type '%s': %s",
                data.get('type'),
                exc,
                exc_info=True,
            )
            return False

    def broadcast_message(self, data, exclude=None) -> None:
        """Broadcast a message to all connected clients."""
        if exclude is None:
            excluded = set()
        elif isinstance(exclude, (set, list, tuple)):
            excluded = set(exclude)
        else:
            excluded = {exclude}
        packed = msgpack.packb(data, use_bin_type=True)
        for sock in list(self.client_sockets):
            if sock in excluded:
                continue
            try:
                sock.sendall(struct.pack('!I', len(packed)) + packed)
                logging.debug(
                    "Broadcast message type '%s' to %s (%d bytes)",
                    data.get('type'),
                    self.client_infos.get(sock, 'unknown'),
                    len(packed),
                )
            except Exception as exc:
                logging.error("Failed to broadcast message: %s", exc)

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------
    def discover_peers(self) -> None:
        """Background zeroconf browser populating discovered_peers."""

        service = self.service

        class Listener:
            def __init__(self, manager: 'NetworkManager') -> None:
                self.manager = manager

            def add_service(self, zc, type_, name):
                self.manager.resolver_queue.put(name)

            def update_service(self, zc, type_, name):
                self.manager.resolver_queue.put(name)

            def remove_service(self, zc, type_, name):
                with self.manager.peers_lock:
                    self.manager.discovered_peers.pop(name, None)

        ServiceBrowser(self.zeroconf, SERVICE_TYPE, Listener(self))
        while service._running:
            time.sleep(0.1)

    def resolver_loop(self) -> None:
        """Resolve service names queued by discover_peers."""
        while self.service._running:
            try:
                name = self.resolver_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                info = self.zeroconf.get_service_info(SERVICE_TYPE, name, 3000)
                if not info:
                    continue
                ip = None
                for addr in info.addresses:
                    if isinstance(addr, bytes) and len(addr) == 4:
                        ip = socket.inet_ntoa(addr)
                        break
                if not ip:
                    continue
                port = info.port
                if ip == self.local_ip and port == self.settings['port']:
                    continue
                with self.peers_lock:
                    self.discovered_peers[name] = {'ip': ip, 'port': port}
            except Exception as exc:
                logging.debug("Resolver failed for %s: %s", name, exc)

    def connection_manager(self) -> None:
        """Continuously probe peers and attempt connections."""
        service = self.service
        while service._running:
            with self.peers_lock:
                peers = list(self.discovered_peers.values())

            if self.settings.get('role') == 'vevo' and service.last_server_ip:
                if service.last_server_ip != self.local_ip and not any(
                    peer.get('ip') == service.last_server_ip for peer in peers
                ):
                    peers.append({'ip': service.last_server_ip, 'port': self.settings['port']})

            for peer in peers:
                ip = peer['ip']
                port = peer['port']
                with self.clients_lock:
                    already = any(
                        sock.getpeername()[0] == ip
                        for sock in self.client_sockets
                        if sock.fileno() != -1
                    )
                if already:
                    continue
                self.connect_to_peer(ip, port)
            time.sleep(2)

    # ------------------------------------------------------------------
    # Connection handling
    # ------------------------------------------------------------------
    def connect_to_peer(self, ip: str, port: int) -> None:
        """Active outbound connection to another peer."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.connect((ip, port))
        except Exception as exc:
            logging.error("Failed to connect to peer %s:%s: %s", ip, port, exc)
            try:
                sock.close()
            except Exception:
                pass
            return

        threading.Thread(
            target=self.monitor_client,
            args=(sock, (ip, port)),
            daemon=True,
        ).start()

    def accept_connections(self) -> None:
        """Accept connections from peers; keep only if our IP wins the tie."""
        service = self.service
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        while service._running:
            try:
                server_socket.bind(('', self.settings['port']))
                break
            except OSError as exc:
                logging.error("Port bind failed: %s. Retrying...", exc)
                time.sleep(5)

        server_socket.listen(5)
        logging.info("TCP server listening on %s", self.settings['port'])

        while service._running:
            try:
                client_sock, addr = server_socket.accept()
            except OSError:
                break

            peer_ip = addr[0]
            try:
                local_addr = ipaddress.ip_address(self.local_ip)
                remote_addr = ipaddress.ip_address(peer_ip)
                if local_addr > remote_addr:
                    client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    threading.Thread(
                        target=self.monitor_client,
                        args=(client_sock, addr),
                        daemon=True,
                    ).start()
                else:
                    client_sock.close()
            except Exception:
                try:
                    client_sock.close()
                except Exception:
                    pass

        try:
            server_socket.close()
        except Exception:
            pass

    def monitor_client(self, sock: socket.socket, addr: Tuple[str, int]) -> None:
        """Monitor a single connection. Handles lifecycle and incoming data."""
        service = self.service
        sock.settimeout(30.0)

        def recv_all(s: socket.socket, n: int) -> Optional[bytes]:
            data = b''
            while len(data) < n:
                chunk = s.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
            return data

        client_name = str(addr)

        try:
            self.send_message(
                sock,
                {
                    'type': 'intro',
                    'device_name': self.device_name,
                    'role': self.settings.get('role'),
                },
            )
            raw_len = recv_all(sock, 4)
            if raw_len:
                msg_len = struct.unpack('!I', raw_len)[0]
                payload = recv_all(sock, msg_len)
                if payload:
                    hello = msgpack.unpackb(payload, raw=False)
                    client_name = hello.get('device_name', client_name)
                    client_role = hello.get('role')
                    self.client_roles[sock] = client_role
                    if (
                        self.settings.get('role') == 'vevo'
                        and client_role == 'ado'
                    ):
                        try:
                            peer_ip = sock.getpeername()[0]
                        except Exception:
                            peer_ip = addr[0] if isinstance(addr, tuple) else None
                        if (
                            peer_ip
                            and peer_ip != service.last_server_ip
                            and peer_ip != self.local_ip
                        ):
                            service.last_server_ip = peer_ip
                            settings_store = service.settings_store
                            if settings_store:
                                settings_store.setValue('network/last_server_ip', peer_ip)
                            logging.info(
                                "Laptop client stored last server IP: %s", peer_ip
                            )
                else:
                    client_role = None
            else:
                client_role = None
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            return

        with self.clients_lock:
            self.client_sockets.append(sock)
            self.client_infos[sock] = client_name

        self.client_connected.emit(sock, client_name, locals().get('client_role'))

        logging.info("Client connected: %s (%s)", client_name, addr)

        if self.settings.get('role') == 'ado':
            service.clipboard_manager.check_clipboard_expiration()
            payload = service.clipboard_manager.get_shared_clipboard_payload()
            if payload:
                try:
                    self.send_message(sock, payload)
                except Exception as exc:
                    logging.debug(
                        "Failed to send initial clipboard to %s: %s",
                        client_name,
                        exc,
                    )

        try:
            buffer = bytearray()
            logging.debug("monitor_client main loop starting for %s", client_name)
            while service._running:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buffer.extend(chunk)
                    while len(buffer) >= 4:
                        msg_len = struct.unpack('!I', buffer[:4])[0]
                        if len(buffer) < 4 + msg_len:
                            break
                        payload = bytes(buffer[4:4 + msg_len])
                        del buffer[:4 + msg_len]
                        try:
                            data = msgpack.unpackb(payload, raw=False)
                        except Exception as exc:
                            logging.error(
                                "Failed to unpack message from %s: %s",
                                client_name,
                                exc,
                                exc_info=True,
                            )
                            continue
                        self.data_received.emit(sock, data)
                except socket.timeout:
                    continue
                except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, socket.error):
                    break
                except Exception as exc:
                    logging.error(
                        "monitor_client recv error from %s: %s",
                        client_name,
                        exc,
                        exc_info=True,
                    )
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError) as exc:
            logging.warning("Network error for client %s: %s", client_name, exc)
        except Exception as exc:
            logging.error(
                "Unexpected error in monitor_client for %s: %s",
                client_name,
                exc,
                exc_info=True,
            )
        finally:
            logging.warning("Client disconnected: %s (%s).", client_name, addr)
            self._handle_disconnect(sock, "monitor_client")
            self.client_disconnected.emit(sock, client_name)

    def _handle_disconnect(self, sock: socket.socket, reason: str) -> None:
        """Cleanup after a socket disconnect."""
        with self.clients_lock:
            try:
                self.client_sockets.remove(sock)
            except ValueError:
                pass
            self.client_infos.pop(sock, None)
            self.client_roles.pop(sock, None)

        try:
            sock.close()
        except Exception:
            pass

        self.service._handle_disconnect(sock, reason)
