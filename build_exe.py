"""Builds a standalone Windows executable of the application.

This script uses PyInstaller to package ``main.py`` into a single ``.exe``
without showing a console window on startup.
"""
import subprocess
import sys


def ensure_pyinstaller():
    """Ensure that PyInstaller is installed."""
    try:
        import PyInstaller  # type: ignore
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])


def build():
    """Run PyInstaller with parameters to hide the console."""
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
    subprocess.check_call(cmd)


if __name__ == "__main__":
    ensure_pyinstaller()
    build()
