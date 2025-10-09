# clipboard_sync.py
#
# Egy robusztus vágólap-kezelő modul, ami megbízható szöveg- és képmásolást
# biztosít a rendszerek között. Windows alatt a natív Win32 API-t használjuk,
# más platformokon pedig a pyperclipet alkalmazzuk biztonságos visszaesésként.

from __future__ import annotations

import hashlib
import logging
import struct
import time
from typing import Any, Dict, Optional

import pyperclip

try:  # pragma: no cover - elérhető csak Windows alatt
    import win32clipboard  # type: ignore
    import win32con  # type: ignore
except ImportError:  # pragma: no cover - más platformok
    win32clipboard = None  # type: ignore
    win32con = None  # type: ignore


ClipboardItem = Dict[str, Any]

PyperclipException = getattr(pyperclip, "PyperclipException", Exception)

CF_PNG = None
if win32clipboard is not None:  # pragma: no cover - Windows specifikus
    try:
        CF_PNG = win32clipboard.RegisterClipboardFormat("PNG")
    except Exception:  # pragma: no cover - régebbi Windows verziók
        CF_PNG = None


def _compute_digest(fmt: str, encoding: Optional[str], raw: bytes) -> str:
    base = fmt.encode("utf-8") + b"\0"
    if encoding:
        base += encoding.encode("utf-8")
    base += b"\0" + raw
    return hashlib.sha256(base).hexdigest()


def _ensure_bytes(data: Any) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    if isinstance(data, memoryview):
        return bytes(data.tobytes())
    if isinstance(data, str):
        return data.encode("utf-8")
    raise TypeError(f"Unsupported clipboard payload type: {type(data)!r}")


def _extract_image_metadata(item: ClipboardItem, raw: bytes) -> None:
    encoding = item.get("encoding")
    if encoding == "dib":
        if len(raw) >= 40:
            header_size = struct.unpack_from("<I", raw, 0)[0]
            if header_size >= 16 and len(raw) >= header_size:
                width = struct.unpack_from("<i", raw, 4)[0]
                height = struct.unpack_from("<i", raw, 8)[0]
                bits_per_pixel = struct.unpack_from("<H", raw, 14)[0]
                item["width"] = abs(int(width))
                item["height"] = abs(int(height))
                item["bits_per_pixel"] = int(bits_per_pixel)
    elif encoding == "png" and len(raw) >= 24 and raw.startswith(b"\x89PNG\r\n\x1a\n"):
        try:
            width, height = struct.unpack_from(">II", raw, 16)
        except struct.error:
            return
        item["width"] = int(width)
        item["height"] = int(height)


def normalize_clipboard_item(item: Optional[ClipboardItem]) -> Optional[ClipboardItem]:
    """Közös reprezentációra hozza a vágólap elemeit."""

    if not item:
        return None

    fmt = item.get("format")
    if fmt not in {"text", "image"}:
        return None

    normalized: ClipboardItem = {"format": fmt}

    if fmt == "text":
        text = item.get("data")
        if text is None:
            return None
        if not isinstance(text, str):
            try:
                text = str(text)
            except Exception:
                return None
        raw = text.encode("utf-8")
        normalized.update(
            {
                "data": text,
                "encoding": "utf-8",
                "size": len(raw),
                "length": len(text),
                "digest": _compute_digest("text", "utf-8", raw),
            }
        )
        return normalized

    # image
    data = item.get("data")
    if data is None:
        return None
    try:
        raw_bytes = _ensure_bytes(data)
    except TypeError:
        return None

    encoding = item.get("encoding") or "dib"
    normalized.update(
        {
            "data": raw_bytes,
            "encoding": encoding,
            "size": len(raw_bytes),
            "digest": _compute_digest("image", encoding, raw_bytes),
        }
    )
    _extract_image_metadata(normalized, raw_bytes)
    return normalized


def clipboard_items_equal(a: Optional[ClipboardItem], b: Optional[ClipboardItem]) -> bool:
    if not a or not b:
        return False
    return a.get("format") == b.get("format") and a.get("digest") == b.get("digest")


def _win32_open_clipboard(retries: int = 5, delay: float = 0.05) -> bool:
    if win32clipboard is None:  # pragma: no cover - más platform
        return False
    for attempt in range(retries):
        try:
            win32clipboard.OpenClipboard()
            return True
        except Exception as exc:  # pragma: no cover - ritka hibák
            logging.debug("OpenClipboard failed (%s), retrying", exc)
            time.sleep(delay)
    raise RuntimeError("Unable to open clipboard after retries")


def _win32_close_clipboard() -> None:
    if win32clipboard is None:  # pragma: no cover
        return
    try:
        win32clipboard.CloseClipboard()
    except Exception:  # pragma: no cover - nem kritikus
        pass


def read_clipboard_content() -> Optional[ClipboardItem]:
    """Olvassa a rendszer vágólapját és normalizált elemet ad vissza."""

    if win32clipboard is not None:  # pragma: no cover - Windows-specifikus út
        try:
            if _win32_open_clipboard():
                try:
                    if win32clipboard.IsClipboardFormatAvailable(win32con.CF_DIB):
                        data = win32clipboard.GetClipboardData(win32con.CF_DIB)
                        item = normalize_clipboard_item(
                            {"format": "image", "encoding": "dib", "data": data}
                        )
                        if item:
                            return item
                    if CF_PNG and win32clipboard.IsClipboardFormatAvailable(CF_PNG):
                        data = win32clipboard.GetClipboardData(CF_PNG)
                        item = normalize_clipboard_item(
                            {"format": "image", "encoding": "png", "data": data}
                        )
                        if item:
                            return item
                    if win32clipboard.IsClipboardFormatAvailable(win32con.CF_UNICODETEXT):
                        text = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
                        item = normalize_clipboard_item({"format": "text", "data": text})
                        if item:
                            return item
                finally:
                    _win32_close_clipboard()
        except Exception as exc:
            logging.error("Failed to read clipboard through win32 API: %s", exc, exc_info=True)

    try:
        content = pyperclip.paste()
    except PyperclipException as e:
        if (
            "Error calling OpenClipboard" in str(e)
            and "Der Vorgang wurde erfolgreich beendet" in str(e)
        ):
            logging.debug("Ignoring benign pyperclip clipboard error: %s", e)
            return None
        logging.error("Failed to access clipboard via pyperclip: %s", e)
        return None
    if content:
        return normalize_clipboard_item({"format": "text", "data": str(content)})
    return None


def write_clipboard_content(item: ClipboardItem, retries: int = 5, delay: float = 0.05) -> None:
    """Vágólap beállítása normalizált elem alapján."""

    normalized = normalize_clipboard_item(item)
    if not normalized:
        return

    fmt = normalized["format"]

    if win32clipboard is not None:  # pragma: no cover - Windows
        for attempt in range(retries):
            try:
                if not _win32_open_clipboard():
                    break
                try:
                    win32clipboard.EmptyClipboard()
                    if fmt == "text":
                        win32clipboard.SetClipboardData(
                            win32con.CF_UNICODETEXT, normalized["data"]
                        )
                    elif fmt == "image":
                        encoding = normalized.get("encoding") or "dib"
                        if encoding == "dib":
                            win32clipboard.SetClipboardData(
                                win32con.CF_DIB, normalized["data"]
                            )
                        elif encoding == "png" and CF_PNG:
                            win32clipboard.SetClipboardData(CF_PNG, normalized["data"])
                        else:
                            raise ValueError(
                                f"Unsupported image encoding for clipboard: {encoding}"
                            )
                    else:  # pragma: no cover - nem érhető el
                        raise ValueError(f"Unsupported clipboard format: {fmt}")
                    return
                finally:
                    _win32_close_clipboard()
            except Exception as exc:
                logging.warning(
                    "Failed to write clipboard via win32 API (attempt %d/%d): %s",
                    attempt + 1,
                    retries,
                    exc,
                )
                time.sleep(delay)
        else:
            logging.error("Giving up on setting clipboard via win32 API.")
        return

    # Fallback – csak szöveg támogatott
    if fmt != "text":
        logging.debug("Non-text clipboard item ignored on non-Windows platform")
        return

    for attempt in range(retries):
        try:
            pyperclip.copy(normalized["data"])
            return
        except PyperclipException as exc:
            logging.warning(
                "pyperclip.copy failed (attempt %d/%d): %s", attempt + 1, retries, exc
            )
            time.sleep(delay)
    logging.error("Failed to write clipboard using pyperclip after retries")


def clear_clipboard() -> None:
    """Teljesen törli a rendszer vágólapját."""

    if win32clipboard is not None:  # pragma: no cover - Windows
        try:
            if _win32_open_clipboard():
                try:
                    win32clipboard.EmptyClipboard()
                finally:
                    _win32_close_clipboard()
        except Exception as exc:
            logging.error("Failed to clear clipboard via win32 API: %s", exc)
        return

    try:
        pyperclip.copy("")
    except PyperclipException as exc:
        logging.debug("Failed to clear clipboard via pyperclip: %s", exc)


def safe_copy(text: str, retries: int = 3, delay: float = 0.1) -> None:
    if not text:
        return
    write_clipboard_content({"format": "text", "data": text}, retries=retries, delay=delay)


def safe_paste() -> Optional[str]:
    item = read_clipboard_content()
    if item and item.get("format") == "text":
        return item.get("data")
    return None

