"""Network utility helpers."""

from __future__ import annotations

import locale
import os
import subprocess
from typing import Optional


def get_current_ssid() -> Optional[str]:
    """Return the SSID of the current Wi-Fi connection on Windows.

    Uses ``netsh wlan show interfaces`` to query the active Wi-Fi interface and
    parses the ``SSID`` field. Returns ``None`` when not connected to Wi-Fi or
    when the SSID cannot be determined.
    """

    if os.name != "nt":
        return None

    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            check=False,
            capture_output=True,
        )
    except Exception:
        return None

    encodings_to_try = [locale.getpreferredencoding(False) or "utf-8", "cp850", "utf-8"]
    decoded_output = None
    for encoding in encodings_to_try:
        try:
            decoded_output = result.stdout.decode(encoding, errors="replace")
            break
        except Exception:
            continue
    if decoded_output is None:
        return None

    for line in decoded_output.splitlines():
        stripped = line.strip()
        if not stripped.lower().startswith("ssid"):
            continue
        # Skip BSSID rows and ensure we only parse the SSID field.
        if stripped.lower().startswith("bssid"):
            continue
        parts = stripped.split(":", maxsplit=1)
        if len(parts) != 2:
            continue
        ssid = parts[1].strip()
        return ssid or None

    return None
