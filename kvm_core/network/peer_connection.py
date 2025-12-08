import logging
import socket
import struct
import threading
from typing import Callable, Optional

import msgpack


class PeerConnection(threading.Thread):
    """Thread handling a single peer connection."""

    def __init__(
        self,
        sock: socket.socket,
        addr,
        manager: "PeerManagerProtocol",
        message_callback: Callable[["PeerConnection", dict], None],
        ) -> None:
        super().__init__(daemon=True, name=f"Peer-{addr[0]}:{addr[1]}")
        self.socket = sock
        self.addr = addr
        self._manager = manager
        self._message_callback = message_callback
        self._running = threading.Event()
        self._running.set()
        self.peer_name: str = str(addr)
        self.peer_role: Optional[str] = None
        self._log = logging.getLogger(__name__)
        self._closed = False
        self._registered = False

        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            self._log.debug("Unable to set socket options for %s", self.peer_name)

    def run(self) -> None:
        try:
            self.socket.settimeout(30.0)
            if not self._perform_handshake():
                self.stop()
                self._closed = True
                return
            self._receive_loop()
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, OSError) as exc:
            is_closed_socket = False
            try:
                is_closed_socket = exc.errno == 10038
            except AttributeError:
                pass
            if not is_closed_socket and "10038" in str(exc):
                is_closed_socket = True

            if is_closed_socket:
                self._log.debug(
                    "Socket already closed for peer %s: %s", self.peer_name, exc
                )
            else:
                self._log.debug(
                    "Network error with peer %s: %s", self.peer_name, exc
                )
        except Exception as exc:
            self._log.error(
                "Unexpected error in PeerConnection (%s): %s",
                self.peer_name,
                exc,
                exc_info=True,
            )
        finally:
            if not self._closed and self._registered:
                self._manager.unregister_connection(self, "peer_connection_exit")
            self._log.debug("PeerConnection thread exit for %s", self.peer_name)

    def stop(self) -> None:
        self._running.clear()
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.socket.close()
        except Exception:
            pass

    def send(self, data: dict) -> bool:
        try:
            packed = msgpack.packb(data, use_bin_type=True)
        except Exception as exc:
            self._log.error("Failed to pack message for %s: %s", self.peer_name, exc)
            return False
        return self.send_packed(packed)

    def send_packed(self, packed: bytes) -> bool:
        try:
            self.socket.sendall(struct.pack("!I", len(packed)) + packed)
            return True
        except Exception as exc:
            self._log.error("Failed to send message to %s: %s", self.peer_name, exc)
            return False

    def _perform_handshake(self) -> bool:
        intro = {
            "type": "intro",
            "device_name": self._manager.device_name,
            "role": self._manager.role,
        }
        self._log.debug(
            "[Handshake] 'hello' küldése: név=%s, szerep=%s, cím=%s",
            intro["device_name"],
            intro["role"],
            self.addr,
        )
        if not self.send(intro):
            return False

        raw_len = self._recv_exact(4)
        if not raw_len:
            return False
        msg_len = struct.unpack("!I", raw_len)[0]
        payload = self._recv_exact(msg_len)
        if not payload:
            return False

        try:
            hello = msgpack.unpackb(payload, raw=False)
        except Exception as exc:
            self._log.error("Failed to unpack handshake from %s: %s", self.addr, exc)
            return False

        self.peer_name = hello.get("device_name", self.peer_name)
        self.peer_role = hello.get("role")
        self._log.debug(
            "[Handshake] 'hello' fogadva: név=%s, szerep=%s, cím=%s",
            self.peer_name,
            self.peer_role,
            self.addr,
        )
        if not self._manager.register_connection(self, self.peer_name, self.peer_role):
            return False

        self._registered = True

        return True

    def _receive_loop(self) -> None:
        buffer = bytearray()
        while self._running.is_set() and self._manager.is_running:
            try:
                chunk = self.socket.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                break
            buffer.extend(chunk)
            while len(buffer) >= 4:
                try:
                    msg_len = struct.unpack("!I", buffer[:4])[0]
                except struct.error:
                    self._log.error("Invalid length header from %s", self.peer_name)
                    buffer.clear()
                    break
                if len(buffer) < 4 + msg_len:
                    break
                payload = bytes(buffer[4 : 4 + msg_len])
                del buffer[: 4 + msg_len]
                try:
                    data = msgpack.unpackb(payload, raw=False)
                except Exception as exc:
                    self._log.error(
                        "Failed to unpack message from %s: %s",
                        self.peer_name,
                        exc,
                        exc_info=True,
                    )
                    continue
                self._message_callback(self, data)

    def _recv_exact(self, size: int) -> Optional[bytes]:
        data = b""
        while len(data) < size and self._running.is_set():
            chunk = self.socket.recv(size - len(data))
            if not chunk:
                return None
            data += chunk
        return data if len(data) == size else None


class PeerManagerProtocol:
    """Protocol-style helper to avoid circular imports at runtime."""

    device_name: str
    role: Optional[str]

    def register_connection(self, conn: PeerConnection, name: str, role: Optional[str]) -> bool: ...  # noqa: E701

    def unregister_connection(self, conn: PeerConnection, reason: str) -> None: ...  # noqa: E701

    @property
    def is_running(self) -> bool: ...  # noqa: E701

