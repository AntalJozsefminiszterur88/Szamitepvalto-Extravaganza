# config.py
# Központi konfigurációs értékek és konstansok

import os
import sys

# Alkalmazás adatai a QSettings-hez
APP_NAME = "KVMApp"
ORG_NAME = "MyKVM"

# Branding information
BRAND_NAME = "UMKGL Solutions"

# Hálózati beállítások
DEFAULT_PORT = 65432
SERVICE_TYPE = "_kvmswitch._tcp.local."
SERVICE_NAME_PREFIX = "KVM Switch Adó"

# Gyorsbillentyű virtuális kódjai
VK_CTRL = 162  # bal Ctrl
VK_CTRL_R = 163  # jobb Ctrl
VK_NUMPAD0 = 96
VK_NUMPAD1 = 97
VK_NUMPAD2 = 98
VK_F12 = 123
VK_LSHIFT = 160
VK_RSHIFT = 161


def resource_path(relative_path: str) -> str:
    """Return absolute path to resource, compatible with PyInstaller."""
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


# Program icon path
ICON_PATH = resource_path("keyboard_mouse_switch_icon.ico")
