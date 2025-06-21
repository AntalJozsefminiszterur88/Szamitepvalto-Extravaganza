# main.py
# A program fő belépési pontja.

import sys
import logging
import os
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QIcon
from PySide6.QtCore import QLockFile, QStandardPaths
from gui import MainWindow
from config import ICON_PATH

# A naplózást itt, a legfelső szinten állítjuk be.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s',
    handlers=[
        logging.FileHandler("kvm_switch.log", mode='w'),
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

    app = QApplication(sys.argv)
    # Prevent the application from quitting when the last window is closed.
    app.setQuitOnLastWindowClosed(False)
    app.setWindowIcon(QIcon(ICON_PATH))
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
