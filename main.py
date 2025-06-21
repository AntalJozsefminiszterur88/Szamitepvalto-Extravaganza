# main.py
# A program fő belépési pontja.

import sys
import os
import logging
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QIcon
from PySide6.QtCore import QLockFile, QStandardPaths, QSettings
from gui import MainWindow
from config import ICON_PATH, APP_NAME, ORG_NAME

# A naplózást itt, a legfelső szinten állítjuk be.
log_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
log_file = os.path.join(log_dir, "kvm_switch.log")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file, mode='w'),
        logging.StreamHandler(sys.stdout)
    ]
)

if __name__ == "__main__":
    logging.info("Alkalmazás indítása...")

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
