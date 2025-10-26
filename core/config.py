# config.py
# Központi konfigurációs értékek és konstansok

from __future__ import annotations

import sys
from pathlib import Path

# Alkalmazás adatai a QSettings-hez
APP_NAME = "KVMApp"
ORG_NAME = "MyKVM"
# Branding
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
VK_DOWN = 40
VK_F12 = 123
VK_LSHIFT = 160
VK_RSHIFT = 161
VK_INSERT = 45
VK_END = 35
VK_F13 = 124
VK_F14 = 125
VK_F15 = 126
VK_F16 = 127


def resource_path(*relative_parts: str) -> str:
    """Return an absolute path to a bundled resource.

    When the application is frozen with PyInstaller the files are extracted
    beside the executable inside ``_MEIPASS``. During development we resolve
    the path relative to the repository root so the same helper can be used in
    both scenarios.
    """

    base_path = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return str(base_path.joinpath("resources", *relative_parts))


# Program icon path
ICON_PATH = resource_path("icons", "keyboard_mouse_switch_icon.ico")
# Soros port beállítása a Pico-hoz
# A Windows rendszer a Pico soros eszközét ezen a porton éri el.
PICO_SERIAL_PORT = "COM7"
