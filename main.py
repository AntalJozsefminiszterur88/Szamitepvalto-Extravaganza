# main.py
# A program fő belépési pontja.

import sys
import os
import socket
import logging
from logging.handlers import RotatingFileHandler
import ctypes
import signal  # ÚJ IMPORT
import time    # ÚJ IMPORT
import threading
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QIcon
from PySide6.QtCore import QLockFile, QStandardPaths, QSettings
from ui.main_window import MainWindow
from config.constants import ICON_PATH, APP_NAME, ORG_NAME
from utils.stability_monitor import initialize_global_monitor
from utils.path_helpers import resolve_documents_directory
from utils.remote_logging import get_remote_log_handler


class _RemoteSourceFilter(logging.Filter):
    """Ensure the log record always exposes a `remote_source` attribute."""

    def filter(self, record: logging.LogRecord) -> bool:  # pragma: no cover - logging integration
        if not hasattr(record, "remote_source"):
            record.remote_source = ""
        return True

# Windows-specifikus importok
try:
    import win32api
    import win32con
    IS_WINDOWS = True
except ImportError:
    IS_WINDOWS = False

# Dinamikus alapútvonal meghatározása (működik scriptként és EXE-ként is)
if getattr(sys, 'frozen', False):
    # Ha a program EXE-ként fut (le van fagyasztva)
    application_path = os.path.dirname(sys.executable)
else:
    # Ha a program scriptként fut
    application_path = os.path.dirname(os.path.abspath(__file__))

def _log_thread_exception(args):
    """Globálisan naplózza a kezeletlen szálhibákat, hogy ne záródjon be csendben az alkalmazás."""
    logging.critical(
        "Unhandled exception in thread %s: %s",
        args.thread.name,
        args.exc_value,
        exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
    )


threading.excepthook = _log_thread_exception


def _log_unhandled_exception(exc_type, exc_value, exc_traceback):
    """Fő szál kivételeinek naplózása."""
    logging.critical(
        "Unhandled exception: %s", exc_value, exc_info=(exc_type, exc_value, exc_traceback)
    )


sys.excepthook = _log_unhandled_exception


def setup_exit_handler(app_instance):
    """Sets up handlers for graceful shutdown on signals."""

    def signal_handler(signum, frame):
        logging.critical(
            f"Leállítási jel ({signal.Signals(signum).name}) kapva. Program leáll."
        )
        app_instance.quit()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if IS_WINDOWS:
        def win_event_handler(event):
            if event in (
                win32con.CTRL_C_EVENT,
                win32con.CTRL_BREAK_EVENT,
                win32con.CTRL_LOGOFF_EVENT,
                win32con.CTRL_SHUTDOWN_EVENT,
                win32con.CTRL_CLOSE_EVENT,
            ):
                logging.critical(
                    f"Rendszer általi leállítási esemény ({event}) kapva. Alkalmazás leáll."
                )
                QApplication.instance().quit()
                time.sleep(5)
                return True
            return False

        try:
            win32api.SetConsoleCtrlHandler(win_event_handler, True)
            logging.info("Windows exit signal handler registered successfully.")
        except Exception as e:
            logging.error(f"Failed to register Windows exit handler: {e}")


def set_high_priority():
    """Attempt to run the process with high priority."""
    try:
        if os.name == "nt":
            HIGH_PRIORITY_CLASS = 0x0080
            ctypes.windll.kernel32.SetPriorityClass(
                ctypes.windll.kernel32.GetCurrentProcess(), HIGH_PRIORITY_CLASS
            )
    except Exception as e:
        logging.warning("Failed to set high process priority: %s", e)


if __name__ == "__main__":
    documents_dir = resolve_documents_directory()
    os.makedirs(documents_dir, exist_ok=True)

    settings = QSettings(ORG_NAME, APP_NAME)
    startup_role = settings.value("role/mode", "input_provider")
    device_name = settings.value("device/name", socket.gethostname())

    log_dir = os.path.join(str(documents_dir), "UMKGL Solutions", "Szamitepvalto-Extravaganza")
    log_file_path = os.path.join(log_dir, "kvm_app.log")

    stream_handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(remote_source)s%(levelname)s - %(threadName)s - %(message)s')
    stream_handler.setFormatter(formatter)
    stream_handler.addFilter(_RemoteSourceFilter())

    handlers = [stream_handler]
    if startup_role == "ado":
        os.makedirs(log_dir, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file_path,
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        file_handler.addFilter(_RemoteSourceFilter())
        handlers.append(file_handler)
    else:
        remote_handler = get_remote_log_handler()
        remote_handler.set_source(str(device_name))
        handlers.append(remote_handler)

    logging.basicConfig(level=logging.INFO, handlers=handlers, force=True)

    stability_monitor = initialize_global_monitor(
        check_interval=60.0,
        memory_warning_mb=600,
        memory_critical_mb=900,
        log_file_path=log_file_path if startup_role == "ado" else None,
        role=startup_role,
    )
    if startup_role == "ado":
        stability_monitor.add_directory_quota(log_dir, max_mb=200, min_free_mb=512)

    logging.info("Alkalmazás indítása...")
    set_high_priority()

    # Allow only a single running instance using a lock file
    data_dir = QStandardPaths.writableLocation(QStandardPaths.AppDataLocation)
    os.makedirs(data_dir, exist_ok=True)
    lock_path = os.path.join(data_dir, "kvm_switch.lock")
    lock_file = QLockFile(lock_path)
    if not lock_file.tryLock(100):
        logging.error("A program már fut. Csak egy példány indítható.")
        sys.exit(1)

    args = sys.argv[1:]
    start_hidden = "--tray" in args or "--minimized" in args
    auto_connect = "--tray" in args

    if getattr(sys, "frozen", False) and not start_hidden:
        settings = QSettings(ORG_NAME, APP_NAME)
        if settings.value("other/autostart", False, type=bool):
            start_hidden = True
            auto_connect = True
    app = QApplication(sys.argv)
    setup_exit_handler(app)
    # Prevent the application from quitting when the last window is closed.
    app.setQuitOnLastWindowClosed(False)
    app.setWindowIcon(QIcon(ICON_PATH))
    window = MainWindow()
    if start_hidden:
        window.hide()
        if auto_connect:
            window.start_kvm_service()
    else:
        window.show()
    sys.exit(app.exec())
