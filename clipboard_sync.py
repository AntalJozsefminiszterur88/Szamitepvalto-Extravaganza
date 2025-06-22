import argparse
import socket
import threading
import time
import pyperclip

BUFFER_SIZE = 4096
CHECK_INTERVAL = 0.5


def send_clip(conn, text):
    data = text.encode('utf-8')
    size = len(data).to_bytes(4, 'big')
    conn.sendall(size + data)


def recv_clip(conn):
    size_data = conn.recv(4)
    if not size_data:
        return None
    size = int.from_bytes(size_data, 'big')
    data = b''
    while len(data) < size:
        chunk = conn.recv(min(BUFFER_SIZE, size - len(data)))
        if not chunk:
            return None
        data += chunk
    return data.decode('utf-8')


class ClipboardServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.clients = []
        self.last_clip = pyperclip.paste()
        self.lock = threading.Lock()

    def broadcast(self, text, exclude=None):
        for c in list(self.clients):
            if c is exclude:
                continue
            try:
                send_clip(c, text)
            except Exception:
                self.clients.remove(c)

    def handle_client(self, conn):
        with conn:
            while True:
                clip = recv_clip(conn)
                if clip is None:
                    break
                with self.lock:
                    if clip != self.last_clip:
                        self.last_clip = clip
                        pyperclip.copy(clip)
                        self.broadcast(clip, exclude=conn)

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            threading.Thread(target=self.monitor_clipboard, daemon=True).start()
            print(f"Clipboard server listening on {self.host}:{self.port}")
            while True:
                conn, _ = s.accept()
                self.clients.append(conn)
                threading.Thread(target=self.handle_client, args=(conn,), daemon=True).start()

    def monitor_clipboard(self):
        while True:
            clip = pyperclip.paste()
            with self.lock:
                if clip != self.last_clip:
                    self.last_clip = clip
                    self.broadcast(clip)
            time.sleep(CHECK_INTERVAL)


class ClipboardClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.last_clip = pyperclip.paste()
        self.sock = None

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port))
        threading.Thread(target=self.listen_server, daemon=True).start()
        self.monitor_clipboard()

    def listen_server(self):
        conn = self.sock
        while True:
            try:
                clip = recv_clip(conn)
            except Exception:
                break
            if clip is None:
                break
            if clip != self.last_clip:
                self.last_clip = clip
                pyperclip.copy(clip)
        conn.close()

    def monitor_clipboard(self):
        conn = self.sock
        while True:
            clip = pyperclip.paste()
            if clip != self.last_clip:
                self.last_clip = clip
                try:
                    send_clip(conn, clip)
                except Exception:
                    break
            time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple clipboard sync tool")
    subparsers = parser.add_subparsers(dest='role', required=True)

    server_parser = subparsers.add_parser('server', help='Run clipboard server')
    server_parser.add_argument('--host', default='0.0.0.0')
    server_parser.add_argument('--port', type=int, default=8765)

    client_parser = subparsers.add_parser('client', help='Run clipboard client')
    client_parser.add_argument('host', help='Server IP or hostname')
    client_parser.add_argument('--port', type=int, default=8765)

    args = parser.parse_args()

    if args.role == 'server':
        ClipboardServer(args.host, args.port).run()
    else:
        ClipboardClient(args.host, args.port).connect()
