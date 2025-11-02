"""Path resolution helpers shared across the application."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from PySide6.QtCore import QStandardPaths


def _is_within_bundle(path: Path) -> bool:
    """Return ``True`` if *path* resolves inside the PyInstaller bundle."""

    bundle_root = getattr(sys, "_MEIPASS", None)
    if not bundle_root:
        return False

    try:
        return Path(path).resolve().is_relative_to(Path(bundle_root).resolve())
    except AttributeError:  # pragma: no cover - Python < 3.9 fallback
        try:
            Path(path).resolve().relative_to(Path(bundle_root).resolve())
        except ValueError:
            return False
        return True


def resolve_documents_directory() -> Path:
    """Return a persistent user Documents directory.

    When the application runs from a PyInstaller onefile bundle ``Qt`` may
    report a temporary extraction directory as the writable Documents location.
    Any data stored there is removed once the process exits, which prevented the
    packaged executable from persisting clipboard payloads and log files.

    This helper normalises the location and falls back to the user's home
    directory when Qt yields an empty path or the temporary bundle directory.
    """

    location = QStandardPaths.writableLocation(QStandardPaths.DocumentsLocation)
    if not location:
        location = os.path.join(Path.home(), "Documents")

    documents_path = Path(location)
    if not documents_path.is_absolute():
        documents_path = (Path.home() / documents_path).resolve()

    if _is_within_bundle(documents_path):
        documents_path = Path.home() / "Documents"

    return documents_path

