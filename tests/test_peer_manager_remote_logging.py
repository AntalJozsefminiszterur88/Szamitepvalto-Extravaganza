import types

import pathlib
import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

if "zeroconf" not in sys.modules:
    class _DummyServiceBrowser:
        def __init__(self, *args, **kwargs):
            pass

        def cancel(self):
            return None

    sys.modules["zeroconf"] = types.SimpleNamespace(ServiceBrowser=_DummyServiceBrowser)

if "monitorcontrol" not in sys.modules:
    monitor_stub = types.SimpleNamespace(get_monitors=lambda: [])
    monitor_submodule = types.SimpleNamespace(PowerMode=object())
    monitor_stub.monitorcontrol = monitor_submodule
    sys.modules["monitorcontrol"] = monitor_stub
    sys.modules["monitorcontrol.monitorcontrol"] = monitor_submodule

if "msgpack" not in sys.modules:
    import json

    def _packb(payload, use_bin_type=True):
        return json.dumps(payload).encode("utf-8")

    def _unpackb(payload, raw=False):
        return json.loads(payload.decode("utf-8"))

    sys.modules["msgpack"] = types.SimpleNamespace(packb=_packb, unpackb=_unpackb)

if "PySide6" not in sys.modules:
    class _DummyQSettings:
        _storage = {}

        def __init__(self, *args, **kwargs):
            self._values = self.__class__._storage

        def setValue(self, key, value):
            self._values[key] = value

        def value(self, key, default=None, type=None):
            return self._values.get(key, default)

    qtcore = types.SimpleNamespace(QSettings=_DummyQSettings)
    pyside6 = types.SimpleNamespace(QtCore=qtcore)
    sys.modules["PySide6"] = pyside6
    sys.modules["PySide6.QtCore"] = qtcore


def test_remote_logging_callback_rebound_on_reconnect():
    from kvm_core.network import peer_manager
    from kvm_core.state import KVMState

    original_discovery = peer_manager.ServiceDiscovery

    class DummyDiscovery:
        def __init__(self, *args, **kwargs):
            self.peers = []
            self.resolver_thread = None

        def start(self):
            return None

        def stop(self):
            return None

    class DummyRemoteHandler:
        def __init__(self):
            self.callback = None

        def has_callback(self):
            return self.callback is not None

        def set_send_callback(self, callback):
            self.callback = callback

    class DummyWorker:
        def __init__(self):
            self.settings = {"role": "input_provider"}
            self.remote_log_handler = DummyRemoteHandler()
            self._connected = 0

        def _on_server_connected(self):
            self._connected += 1

    class DummyConnection:
        def __init__(self, name):
            self.socket = object()
            self.addr = (name, 1234)
            self._sent = []

        def send(self, payload):
            self._sent.append(payload)
            return True

    try:
        peer_manager.ServiceDiscovery = DummyDiscovery
        worker = DummyWorker()
        state = KVMState()
        manager = peer_manager.PeerManager(
            worker,
            state,
            zeroconf=types.SimpleNamespace(),
            port=1234,
            device_name="desktop",
            message_callback=lambda *args: None,
        )

        first = DummyConnection("first")
        manager.register_connection(first, "controller", "ado")
        callback_one = worker.remote_log_handler.callback
        assert callback_one is not None

        second = DummyConnection("second")
        manager.register_connection(second, "controller", "ado")
        callback_two = worker.remote_log_handler.callback

        assert callback_two is not None
        assert callback_two is not callback_one
    finally:
        peer_manager.ServiceDiscovery = original_discovery
