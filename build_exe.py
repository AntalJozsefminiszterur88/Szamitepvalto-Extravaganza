"""Builds a standalone Windows executable of the application.

This script uses PyInstaller to package ``main.py`` into a single ``.exe``
without showing a console window on startup.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
import importlib.util


def ensure_pyinstaller():
    """Ensure that PyInstaller is installed."""
    try:
        import PyInstaller  # type: ignore
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])


def build():
    """Run PyInstaller with parameters to hide the console."""
    hidden_imports = [
        "win32clipboard",
        "win32con",
        "win32api",
        "pywintypes",
        "pythoncom",
    ]

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--windowed",  # hide console window on Windows/macOS
        "--noconsole",  # explicit alias for clarity
        "--name",
        "Szamitepvalto-Extravaganza",
        "--icon",
        "keyboard_mouse_switch_icon.ico",
        "--add-data",
        "keyboard_mouse_switch_icon.ico;.",
        "main.py",
    ]

    for module in hidden_imports:
        cmd.extend(["--hidden-import", module])

    # Ensure PyInstaller bundles the helper DLLs from pywin32 that are required
    # for clipboard access when the application is packaged as an executable.
    cmd.extend([
        "--collect-binaries",
        "pywin32",
    ])

    cmd.extend(_collect_pywin32_system32_data())
    subprocess.check_call(cmd)


def _collect_pywin32_system32_data() -> list[str]:
    """Collect the ``pywin32_system32`` directory if pywin32 is available.

    When the project is frozen with PyInstaller in ``--onefile`` mode the
    ``pywintypes`` and ``pythoncom`` DLLs must be explicitly included.
    Otherwise importing :mod:`win32clipboard` succeeds, but clipboard
    operations that rely on these DLLs fail at runtime, which manifests as
    empty images on the clipboard when the packaged executable is used.
    """

    try:
        spec = importlib.util.find_spec("pywintypes")
    except ImportError:
        return []

    if not spec or not spec.origin:
        return []

    system32_dir = Path(spec.origin).resolve().parent
    if not system32_dir.exists():
        return []

    return [
        "--add-data",
        f"{system32_dir}{os.pathsep}pywin32_system32",
    ]


if __name__ == "__main__":
    ensure_pyinstaller()
    build()
