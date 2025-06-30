import threading
import socket
import logging

_worker_ref = None


def set_worker_reference(worker):
    global _worker_ref
    _worker_ref = worker


def accept_connections(server_socket):
    """Accept connections and spawn monitoring threads."""
    while _worker_ref and _worker_ref._running:
        try:
            client_sock, addr = server_socket.accept()
        except OSError:
            break
        client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        _worker_ref.client_sockets.append(client_sock)
        if _worker_ref.active_client is None:
            _worker_ref.active_client = client_sock
        logging.info("Kliens csatlakozva: %s", addr)
        _worker_ref.status_update.emit(f"Kliens csatlakozva: {addr}. Várakozás gyorsbillentyűre.")
        th = threading.Thread(target=_worker_ref.monitor_client, args=(client_sock, addr), daemon=True)
        th.start()


class KVMServiceListener:
    """Zeroconf service discovery listener."""

    def __init__(self, worker):
        self.worker = worker
        self._threads = {}

    def add_service(self, zc, service_type, name):
        info = zc.get_service_info(service_type, name)
        if not info:
            return
        ip = socket.inet_ntoa(info.addresses[0])
        port = info.port
        if ip == self.worker.local_ip:
            return
        existing = self._threads.get(ip)
        if existing and existing.is_alive():
            return
        logging.info("Adó szolgáltatás megtalálva: %s:%s", ip, port)
        self.worker.status_update.emit(f"Adó megtalálva: {ip}. Csatlakozás...")
        t = threading.Thread(target=_worker_ref.connect_to_server, args=(ip, port), daemon=True)
        self._threads[ip] = t
        t.start()

    def update_service(self, zc, service_type, name):
        pass

    def remove_service(self, zc, service_type, name):
        info = zc.get_service_info(service_type, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            logging.warning("Adó szolgáltatás eltűnt: %s", ip)
            if ip == self.worker.last_server_ip:
                self.worker._start_reconnect_loop()
        else:
            logging.warning("Adó szolgáltatás eltűnt")
            self.worker._start_reconnect_loop()
