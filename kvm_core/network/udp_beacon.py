import logging
import socket
import threading
import time
from typing import Callable, Optional

from config.constants import BEACON_INTERVAL, BEACON_MESSAGE, UDP_BEACON_PORT


class UDPBeaconBroadcaster:
    """Broadcast a UDP presence beacon for the ado role."""

    def __init__(self, *, is_running: Callable[[], bool]) -> None:
        self._is_running = is_running
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._loop,
            daemon=True,
            name="UDPBeaconBroadcaster",
        )
        self._thread.start()

    def _loop(self) -> None:
        while self._is_running():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.sendto(BEACON_MESSAGE, ("<broadcast>", UDP_BEACON_PORT))
            except OSError as exc:
                logging.warning("UDP beacon broadcast failed: %s", exc)
            time.sleep(BEACON_INTERVAL)


class UDPBeaconListener:
    """Listen for UDP beacons and report sender IPs."""

    def __init__(self, *, is_running: Callable[[], bool], on_beacon: Callable[[str], None]) -> None:
        self._is_running = is_running
        self._on_beacon = on_beacon
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._loop,
            daemon=True,
            name="UDPBeaconListener",
        )
        self._thread.start()

    def _loop(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("0.0.0.0", UDP_BEACON_PORT))
                sock.settimeout(1.0)
                while self._is_running():
                    try:
                        data, addr = sock.recvfrom(1024)
                    except socket.timeout:
                        continue
                    except OSError as exc:
                        logging.warning("UDP beacon listener error: %s", exc)
                        continue
                    if data != BEACON_MESSAGE:
                        continue
                    sender_ip = addr[0]
                    if sender_ip:
                        self._on_beacon(sender_ip)
        except OSError as exc:
            logging.warning("UDP beacon listener failed to start: %s", exc)
