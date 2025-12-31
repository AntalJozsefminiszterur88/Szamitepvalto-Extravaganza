import logging
import socket
import struct
import threading
import time
from typing import Callable, Optional

import msgpack


class PeerConnection(threading.Thread):
    """Thread handling a single peer connection."""

    HEARTBEAT_INTERVAL = 2.0
    CONNECTION_TIMEOUT = 6.0

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
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._send_lock = threading.Lock()
        self._timestamp_lock = threading.Lock()
        self.last_packet_received_at = time.time()
        self.peer_name: str = str(addr)
        self.peer_role: Optional[str] = None
        self._log = logging.getLogger(__name__)
        self._closed = False

    def run(self) -> None:
        try:
            self.socket.settimeout(30.0)
            if not self._perform_handshake():
                return
            self.socket.settimeout(self.HEARTBEAT_INTERVAL)
            self._start_heartbeat()
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
            self._stop_heartbeat()
            if not self._closed:
                self._manager.unregister_connection(self, "peer_connection_exit")
            self._log.debug("PeerConnection thread exit for %s", self.peer_name)

    def stop(self) -> None:
        self._running.clear()
        self._heartbeat_stop.set()
        try:
            with self._send_lock:
                self.socket.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            with self._send_lock:
                self.socket.close()
        except Exception:
            pass
        self._stop_heartbeat()

    def send(self, data: dict) -> bool:
        try:
            packed = msgpack.packb(data, use_bin_type=True)
        except Exception as exc:
            self._log.error("Failed to pack message for %s: %s", self.peer_name, exc)
            return False
        return self.send_packed(packed)

    def send_packed(self, packed: bytes) -> bool:
        try:
            with self._send_lock:
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

        self._touch_last_packet_received()
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

        return True

    def _start_heartbeat(self) -> None:
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            return
        self._heartbeat_stop.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True,
            name=f"PeerHeartbeat-{self.addr[0]}:{self.addr[1]}",
        )
        self._heartbeat_thread.start()

    def _stop_heartbeat(self) -> None:
        self._heartbeat_stop.set()
        thread = self._heartbeat_thread
        if (
            thread
            and thread.is_alive()
            and threading.current_thread() is not thread
        ):
            thread.join(timeout=self.HEARTBEAT_INTERVAL)

    def _heartbeat_loop(self) -> None:
        while (
            self._running.is_set()
            and self._manager.is_running
            and not self._heartbeat_stop.is_set()
        ):
            if self._heartbeat_stop.wait(self.HEARTBEAT_INTERVAL):
                break
            if not self._running.is_set() or not self._manager.is_running:
                break
            if not self.send({"type": "ping"}):
                self._log.warning("Heartbeat send failed for %s", self.peer_name)
                self.stop()
                break

    def _touch_last_packet_received(self) -> None:
        with self._timestamp_lock:
            self.last_packet_received_at = time.time()

    def _last_packet_age(self) -> float:
        with self._timestamp_lock:
            return time.time() - self.last_packet_received_at

    def _receive_loop(self) -> None:
        buffer = bytearray()
        while self._running.is_set() and self._manager.is_running:
            try:
                chunk = self.socket.recv(4096)
            except socket.timeout:
                if self._last_packet_age() > self.CONNECTION_TIMEOUT:
                    self._log.warning(
                        "Connection timed out - no heartbeat from %s", self.peer_name
                    )
                    self.stop()
                    break
                continue
            if not chunk:
                self.stop()
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
                self._touch_last_packet_received()
                msg_type = data.get("type") if isinstance(data, dict) else None
                if msg_type == "ping":
                    self.send({"type": "pong"})
                    continue
                if msg_type == "pong":
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
