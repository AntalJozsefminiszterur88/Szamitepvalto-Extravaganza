# main.py
# A program fő belépési pontja.

import sys
import os
import logging
from logging.handlers import RotatingFileHandler
import ctypes
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QIcon
from PySide6.QtCore import QLockFile, QStandardPaths, QSettings
from gui import MainWindow
from config import ICON_PATH, APP_NAME, ORG_NAME

# Dinamikus alapútvonal meghatározása (működik scriptként és EXE-ként is)
if getattr(sys, 'frozen', False):
    # Ha a program EXE-ként fut (le van fagyasztva)
    application_path = os.path.dirname(sys.executable)
else:
    # Ha a program scriptként fut
    application_path = os.path.dirname(os.path.abspath(__file__))

# Log könyvtár létrehozása
log_dir = os.path.join(application_path, "logs")
os.makedirs(log_dir, exist_ok=True)
log_file_path = os.path.join(log_dir, "kvm_app.log")

# Naplózás beállítása fájlba, rotációval
# 5 MB-onként új fájlt kezd, és 3 régi fájlt tart meg.
file_handler = RotatingFileHandler(
    log_file_path, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8'
)
file_handler.setFormatter(
    logging.Formatter('%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')
)

# Konzolra író handler (fejlesztéshez hasznos marad)
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(
    logging.Formatter('%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')
)

# A gyökeres logger konfigurálása mindkét handlerrel
logging.basicConfig(
    level=logging.INFO,  # Állítsd DEBUG-ra a részletesebb hibakereséshez
    handlers=[file_handler, stream_handler]
)


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
