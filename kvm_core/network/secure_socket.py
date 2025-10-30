import os
import socket
import ssl
from typing import Optional

# Toggle for enabling or disabling TLS encryption between peers. When set to
# False the helper functions fall back to returning the raw socket objects so
# that communication proceeds without any encryption while keeping the original
# TLS implementation intact for later reactivation.
TLS_ENABLED = False

CERT_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'cert.pem')
KEY_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'key.pem')

def create_server_context() -> Optional[ssl.SSLContext]:
    """Létrehoz egy SSL kontextust a szerver számára, betöltve a tanúsítványt és a kulcsot."""
    if not TLS_ENABLED:
        return None
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    return context

def create_client_context(*, enforce_hostname: bool = True) -> Optional[ssl.SSLContext]:
    """Létrehoz egy SSL kontextust a kliens számára, ami megbízik a szerver tanúsítványában."""
    if not TLS_ENABLED:
        return None
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CERT_FILE)
    context.check_hostname = enforce_hostname
    return context

def wrap_socket_server_side(
    sock: socket.socket, context: Optional[ssl.SSLContext]
) -> socket.socket:
    """Becsomagol egy elfogadott kliens socketet szerver oldalon."""
    if not TLS_ENABLED or context is None:
        return sock
    return context.wrap_socket(sock, server_side=True)

def wrap_socket_client_side(
    sock: socket.socket,
    context: Optional[ssl.SSLContext],
    *,
    server_hostname: Optional[str] = None,
) -> socket.socket:
    """Becsomagol egy csatlakozó socketet kliens oldalon, és opcionálisan ellenőrzi a hosztnevet."""
    if not TLS_ENABLED or context is None:
        return sock
    if server_hostname:
        return context.wrap_socket(sock, server_hostname=server_hostname)
    return context.wrap_socket(sock)
