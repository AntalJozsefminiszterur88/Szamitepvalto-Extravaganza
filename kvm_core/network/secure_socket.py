import ssl
import socket
import os

CERT_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'cert.pem')
KEY_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'key.pem')

def create_server_context() -> ssl.SSLContext:
    """Létrehoz egy SSL kontextust a szerver számára, betöltve a tanúsítványt és a kulcsot."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    return context

def create_client_context() -> ssl.SSLContext:
    """Létrehoz egy SSL kontextust a kliens számára, ami megbízik a szerver tanúsítványában."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CERT_FILE)
    return context

def wrap_socket_server_side(sock: socket.socket, context: ssl.SSLContext) -> ssl.SSLSocket:
    """Becsomagol egy elfogadott kliens socketet szerver oldalon."""
    return context.wrap_socket(sock, server_side=True)

def wrap_socket_client_side(sock: socket.socket, context: ssl.SSLContext, server_hostname: str) -> ssl.SSLSocket:
    """Becsomagol egy csatlakozó socketet kliens oldalon, és ellenőrzi a hosztnevet."""
    return context.wrap_socket(sock, server_hostname=server_hostname)
