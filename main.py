# main.py
# A program fő belépési pontja.

import sys
import logging
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QIcon
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
    app = QApplication(sys.argv)
    # Prevent the application from quitting when the last window is closed.
    app.setQuitOnLastWindowClosed(False)
    app.setWindowIcon(QIcon(ICON_PATH))
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
