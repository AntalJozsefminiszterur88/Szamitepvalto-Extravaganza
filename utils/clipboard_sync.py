# clipboard_sync.py
#
# Egy robusztus vágólap-kezelő modul, ami megbízható szöveg- és képmásolást
# biztosít a rendszerek között. Windows alatt a natív Win32 API-t használjuk,
# más platformokon pedig a pyperclipet alkalmazzuk biztonságos visszaesésként.

from __future__ import annotations

import hashlib
import io
import logging
import os
import shutil
import struct
import tempfile
import time
import zipfile
from typing import Any, Dict, Iterable, Optional, Sequence

import pyperclip

try:  # pragma: no cover - elérhető csak Windows alatt
    import ctypes
    from ctypes import wintypes

    import win32clipboard  # type: ignore
    import win32con  # type: ignore
except ImportError:  # pragma: no cover - más platformok
    win32clipboard = None  # type: ignore
    win32con = None  # type: ignore
    ctypes = None  # type: ignore
    wintypes = None  # type: ignore


ClipboardItem = Dict[str, Any]

PyperclipException = getattr(pyperclip, "PyperclipException", Exception)

CF_PNG = None
CFSTR_PREFERREDDROPEFFECT = None
DROPEFFECT_COPY = 0x0001
DROPEFFECT_MOVE = 0x0002
MAX_FILE_PAYLOAD_BYTES = 50 * 1024 * 1024  # 50 MiB hard limit for shared files
MAX_IMAGE_PAYLOAD_BYTES = MAX_FILE_PAYLOAD_BYTES
_LAST_EXTRACTED_DIR: Optional[str] = None
if win32clipboard is not None:  # pragma: no cover - Windows specifikus
    try:
        CF_PNG = win32clipboard.RegisterClipboardFormat("PNG")
    except Exception:  # pragma: no cover - régebbi Windows verziók
        CF_PNG = None
    try:
        CFSTR_PREFERREDDROPEFFECT = win32clipboard.RegisterClipboardFormat(
            "Preferred DropEffect"
        )
    except Exception:  # pragma: no cover - régebbi Windows verziók
        CFSTR_PREFERREDDROPEFFECT = None

if win32clipboard is not None:  # pragma: no cover - Windows specifikus
    _KERNEL32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

    class DROPFILES(ctypes.Structure):  # type: ignore[misc]
        _fields_ = [
            ("pFiles", wintypes.DWORD),
            ("pt", wintypes.POINT),
            ("fNC", wintypes.BOOL),
            ("fWide", wintypes.BOOL),
        ]

    _KERNEL32.GlobalLock.argtypes = [wintypes.HGLOBAL]  # type: ignore[attr-defined]
    _KERNEL32.GlobalLock.restype = wintypes.LPVOID  # type: ignore[attr-defined]
    _KERNEL32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]  # type: ignore[attr-defined]
    _KERNEL32.GlobalUnlock.restype = wintypes.BOOL  # type: ignore[attr-defined]
    _KERNEL32.GlobalSize.argtypes = [wintypes.HGLOBAL]  # type: ignore[attr-defined]
    _KERNEL32.GlobalSize.restype = ctypes.c_size_t  # type: ignore[attr-defined]
    _KERNEL32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]  # type: ignore[attr-defined]
    _KERNEL32.GlobalAlloc.restype = wintypes.HGLOBAL  # type: ignore[attr-defined]
    _KERNEL32.GlobalFree.argtypes = [wintypes.HGLOBAL]  # type: ignore[attr-defined]
    _KERNEL32.GlobalFree.restype = wintypes.HGLOBAL  # type: ignore[attr-defined]

    GMEM_MOVEABLE = 0x0002


def _format_bytes(num: Optional[int]) -> str:
    if num is None:
        return "?"
    size = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def get_clipboard_sequence_number() -> Optional[int]:
    """Return the system clipboard change counter if available.

    Windows maintains a monotonically increasing sequence number that
    increments every time the clipboard contents change. Querying this
    number is significantly cheaper than reading the entire clipboard,
    especially when large file payloads are involved. If the platform
    does not expose such a counter we fall back to ``None`` so callers
    can revert to their previous polling behaviour.
    """

    if win32clipboard is None:  # pragma: no cover - non-Windows
        return None

    try:  # pragma: no branch - tiny helper
        return int(win32clipboard.GetClipboardSequenceNumber())  # type: ignore[attr-defined]
    except AttributeError:  # pragma: no cover - older pywin32 builds
        return None
    except Exception as exc:  # pragma: no cover - defensive logging
        logging.debug("Failed to query clipboard sequence number: %s", exc, exc_info=True)
        return None


def _describe_clipboard_item(item: ClipboardItem) -> str:
    """Build a human readable description for logging purposes."""

    fmt = item.get("format", "unknown")

    if fmt == "text":
        text = item.get("data", "")
        if isinstance(text, str):
            preview = text.replace("\n", "\\n")
            if len(preview) > 40:
                preview = f"{preview[:37]}..."
            return f"text(len={len(text)} preview='{preview}')"
        return f"text(type={type(text)!r})"

    if fmt == "image":
        encoding = item.get("encoding", "unknown")
        data = item.get("data", b"")
        if isinstance(data, (bytes, bytearray)):
            size = len(data)
            digest = hashlib.sha256(bytes(data)).hexdigest()[:12]
            return f"image(encoding={encoding}, size={size}, sha256={digest})"
        return f"image(encoding={encoding}, type={type(data)!r})"

    if fmt == "files":
        count = item.get("file_count") or len(item.get("entries") or [])
        total_size = _format_bytes(item.get("total_size"))
        payload_size = item.get("size")
        digest = item.get("digest", "")
        digest_preview = digest[:12] if isinstance(digest, str) else ""
        return (
            "files(count={count}, total={total}, payload={payload}, sha256={digest})".format(
                count=count,
                total=total_size,
                payload=_format_bytes(payload_size) if payload_size is not None else "?",
                digest=digest_preview,
            )
        )

    return f"format={fmt} keys={sorted(item.keys())}"
def _win32_clipboard_object_to_bytes(data: Any, fmt_hint: Optional[int] = None) -> Optional[bytes]:
    if win32clipboard is None:  # pragma: no cover - non-Windows
        return None

    handle: Optional[int] = None

    for attr in ("handle", "value"):
        if hasattr(data, attr):
            try:
                handle = int(getattr(data, attr))
                break
            except (TypeError, ValueError):
                continue

    if handle is None:
        try:
            handle = int(data)  # type: ignore[arg-type]
        except (TypeError, ValueError, OverflowError):
            handle = None

    if handle:
        try:
            size = int(_KERNEL32.GlobalSize(handle))  # type: ignore[arg-type]
            if size <= 0:
                return b""
            ptr = _KERNEL32.GlobalLock(handle)  # type: ignore[arg-type]
            if not ptr:
                raise ctypes.WinError()  # type: ignore[attr-defined]
            try:
                return ctypes.string_at(ptr, size)  # type: ignore[attr-defined]
            finally:
                _KERNEL32.GlobalUnlock(handle)  # type: ignore[arg-type]
        except Exception as exc:
            logging.debug("Failed to read clipboard handle %s: %s", handle, exc, exc_info=True)

    if fmt_hint is not None and win32clipboard is not None:
        try:
            handle_obj = win32clipboard.GetClipboardDataHandle(fmt_hint)  # type: ignore[attr-defined]
        except AttributeError:
            handle_obj = None
        except Exception as exc:
            logging.debug(
                "GetClipboardDataHandle(%s) failed: %s",
                fmt_hint,
                exc,
                exc_info=True,
            )
            handle_obj = None
        if handle_obj:
            try:
                size = int(_KERNEL32.GlobalSize(handle_obj))  # type: ignore[arg-type]
                if size <= 0:
                    return b""
                ptr = _KERNEL32.GlobalLock(handle_obj)  # type: ignore[arg-type]
                if not ptr:
                    raise ctypes.WinError()  # type: ignore[attr-defined]
                try:
                    return ctypes.string_at(ptr, size)  # type: ignore[attr-defined]
                finally:
                    _KERNEL32.GlobalUnlock(handle_obj)  # type: ignore[arg-type]
            except Exception as exc:
                logging.debug(
                    "Failed to read clipboard handle via fmt %s: %s",
                    fmt_hint,
                    exc,
                    exc_info=True,
                )

    return None


def _win32_clipboard_has_move_effect() -> bool:
    if win32clipboard is None or CFSTR_PREFERREDDROPEFFECT is None:
        return False
    try:
        raw = win32clipboard.GetClipboardData(CFSTR_PREFERREDDROPEFFECT)
    except Exception:
        return False
    raw_bytes = _win32_clipboard_object_to_bytes(raw, CFSTR_PREFERREDDROPEFFECT)
    if not raw_bytes or len(raw_bytes) < 4:
        return False
    try:
        effect = struct.unpack_from("<I", raw_bytes, 0)[0]
    except struct.error:
        return False
    return bool(effect & DROPEFFECT_MOVE)


def _win32_bytes_to_handle(data: bytes) -> int:
    if win32clipboard is None:  # pragma: no cover - non-Windows
        raise RuntimeError("Clipboard handle conversion only supported on Windows")

    size = len(data)
    if size == 0:
        size = 1  # allocate minimum block for empty payloads
    handle = _KERNEL32.GlobalAlloc(GMEM_MOVEABLE, size)  # type: ignore[arg-type]
    if not handle:
        raise ctypes.WinError()  # type: ignore[attr-defined]
    ptr = _KERNEL32.GlobalLock(handle)  # type: ignore[arg-type]
    if not ptr:
        _KERNEL32.GlobalFree(handle)  # type: ignore[arg-type]
        raise ctypes.WinError()  # type: ignore[attr-defined]
    try:
        if data:
            ctypes.memmove(ptr, data, len(data))  # type: ignore[attr-defined]
        else:  # pragma: no cover - empty payload
            ctypes.memset(ptr, 0, 1)  # type: ignore[attr-defined]
    finally:
        _KERNEL32.GlobalUnlock(handle)  # type: ignore[arg-type]
    return handle


def _win32_set_clipboard_bytes(fmt: int, data: bytes) -> None:
    if win32clipboard is None:  # pragma: no cover - non-Windows
        return
    handle = _win32_bytes_to_handle(data)
    try:
        win32clipboard.SetClipboardData(fmt, handle)
    except Exception:
        _KERNEL32.GlobalFree(handle)  # type: ignore[arg-type]
        raise


def _compute_digest(fmt: str, encoding: Optional[str], raw: bytes) -> str:
    base = fmt.encode("utf-8") + b"\0"
    if encoding:
        base += encoding.encode("utf-8")
    base += b"\0" + raw
    return hashlib.sha256(base).hexdigest()


def _compute_file_payload_digest(payload: bytes) -> str:
    """Build a stable digest for a ZIP payload representing shared files."""

    # The raw ZIP bytes can legitimately change between reads because certain
    # metadata (for example internal timestamps) may be regenerated.  To ensure
    # we only persist genuinely new clipboard payloads, derive the digest from
    # the logical file contents instead of the container bytes.
    hasher = hashlib.sha256()
    with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
        for info in sorted(archive.infolist(), key=lambda entry: entry.filename):
            # Normalise path separators so the hash is platform independent.
            name = info.filename.replace("\\", "/")
            if info.is_dir():
                hasher.update(b"D\0")
                hasher.update(name.encode("utf-8"))
                hasher.update(b"\0")
                continue

            hasher.update(b"F\0")
            hasher.update(name.encode("utf-8"))
            hasher.update(b"\0")
            with archive.open(info, "r") as source:
                for chunk in iter(lambda: source.read(65536), b""):
                    hasher.update(chunk)

    return hasher.hexdigest()


def _ensure_bytes(data: Any) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    if isinstance(data, memoryview):
        return bytes(data.tobytes())
    if isinstance(data, str):
        return data.encode("utf-8")
    if win32clipboard is not None:  # pragma: no cover - Windows specifikus
        raw = _win32_clipboard_object_to_bytes(data)
        if raw is not None:
            return raw
    raise TypeError(f"Unsupported clipboard payload type: {type(data)!r}")


def _cleanup_last_temp_dir() -> None:
    global _LAST_EXTRACTED_DIR
    if _LAST_EXTRACTED_DIR and os.path.isdir(_LAST_EXTRACTED_DIR):
        shutil.rmtree(_LAST_EXTRACTED_DIR, ignore_errors=True)
    _LAST_EXTRACTED_DIR = None


def _coerce_path_list(data: Any) -> Optional[list[str]]:
    if data is None:
        return None
    if isinstance(data, (str, os.PathLike)):
        return [os.fspath(data)]
    if isinstance(data, Iterable):
        paths: list[str] = []
        for entry in data:
            if entry is None:
                continue
            try:
                paths.append(os.fspath(entry))
            except TypeError:
                logging.debug("Ignoring non-path entry in clipboard file list: %r", entry)
                continue
        return paths
    logging.debug("Unable to coerce clipboard files from %r", data)
    return None


def _detect_windows_file_paths(text: str) -> Optional[list[str]]:
    """Detect Explorer style newline separated absolute paths in text data."""

    if win32clipboard is None:
        return None

    if not text:
        return None

    has_newline = "\n" in text or "\r" in text
    normalized_lines = (
        text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    )

    paths: list[str] = []

    for raw_line in normalized_lines:
        candidate = raw_line.strip()
        if not candidate:
            continue
        # Windows "Copy as path" surrounds the path with quotes – strip them.
        candidate = candidate.strip("\"")
        if not candidate:
            continue
        if not (
            candidate.startswith("\\\\")
            or (len(candidate) >= 3 and candidate[1] == ":" and candidate[2] in ("\\", "/"))
        ):
            return None
        normalized = os.path.abspath(candidate)
        if not os.path.exists(normalized):
            return None
        paths.append(normalized)

    if not paths:
        return None

    if not has_newline and len(paths) == 1:
        stripped = text.strip()
        if not (stripped.startswith('"') and stripped.endswith('"')):
            return None

    return paths


def _pack_clipboard_files(
    paths: Sequence[str],
) -> Optional[tuple[bytes, list[dict], int, int, str]]:
    if not paths:
        return None

    archive_buffer = io.BytesIO()
    entries: list[dict] = []
    file_count = 0
    total_size = 0
    used_root_names: set[str] = set()

    def _unique_root(name: str) -> str:
        base = name or "item"
        candidate = base
        counter = 2
        while candidate in used_root_names:
            candidate = f"{base} ({counter})"
            counter += 1
        used_root_names.add(candidate)
        return candidate

    def _stat_file_size(path: str) -> Optional[int]:
        try:
            return int(os.path.getsize(path))
        except Exception as exc:
            logging.debug("Failed to determine size of %s: %s", path, exc)
            return None

    def _would_exceed_limit(path: str, next_size: int) -> bool:
        if next_size > MAX_FILE_PAYLOAD_BYTES:
            logging.warning(
                "Clipboard file %s exceeds maximum payload size (%.2f MiB > %.2f MiB).",
                path,
                next_size / (1024 * 1024),
                MAX_FILE_PAYLOAD_BYTES / (1024 * 1024),
            )
            return True
        if total_size + next_size > MAX_FILE_PAYLOAD_BYTES:
            logging.warning(
                "Clipboard file selection exceeds maximum payload size when adding %s (%.2f MiB > %.2f MiB).",
                path,
                (total_size + next_size) / (1024 * 1024),
                MAX_FILE_PAYLOAD_BYTES / (1024 * 1024),
            )
            return True
        return False

    with zipfile.ZipFile(archive_buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for original in paths:
            if not original:
                continue
            try:
                normalized_path = os.path.abspath(original)
            except Exception:
                logging.debug("Failed to normalise clipboard path: %r", original)
                continue

            if not os.path.exists(normalized_path):
                logging.debug("Clipboard path does not exist anymore: %s", normalized_path)
                continue

            base_name = os.path.basename(normalized_path.rstrip("/\\")) or os.path.basename(normalized_path)
            root_name = _unique_root(base_name)

            if os.path.isdir(normalized_path):
                entries.append({"name": root_name, "is_dir": True})
                for root, _, files in os.walk(normalized_path):
                    rel_dir = os.path.relpath(root, normalized_path)
                    archive_root = root_name if rel_dir in (".", os.curdir) else os.path.join(root_name, rel_dir).replace("\\", "/")
                    for filename in files:
                        full_path = os.path.join(root, filename)
                        arcname = os.path.join(archive_root, filename).replace("\\", "/")
                        size = _stat_file_size(full_path)
                        if size is None:
                            continue
                        if _would_exceed_limit(full_path, size):
                            return None
                        try:
                            archive.write(full_path, arcname=arcname)
                        except Exception as exc:
                            logging.debug("Failed to add %s to clipboard archive: %s", full_path, exc)
                            continue
                        total_size += size
                        file_count += 1
            else:
                entries.append({"name": root_name, "is_dir": False})
                size = _stat_file_size(normalized_path)
                if size is None:
                    continue
                if _would_exceed_limit(normalized_path, size):
                    return None
                try:
                    archive.write(normalized_path, arcname=root_name)
                except Exception as exc:
                    logging.debug("Failed to add %s to clipboard archive: %s", normalized_path, exc)
                    continue
                total_size += size
                file_count += 1

    if file_count == 0:
        logging.debug("Clipboard file packaging yielded no files – skipping.")
        return None

    if total_size > MAX_FILE_PAYLOAD_BYTES:
        logging.warning(
            "Clipboard file payload too large (%.2f MiB > %.2f MiB). Ignoring.",
            total_size / (1024 * 1024),
            MAX_FILE_PAYLOAD_BYTES / (1024 * 1024),
        )
        return None

    payload = archive_buffer.getvalue()
    digest = _compute_file_payload_digest(payload)
    if len(payload) > MAX_FILE_PAYLOAD_BYTES:
        logging.warning(
            "Clipboard archive is too large to share (%.2f MiB > %.2f MiB).",
            len(payload) / (1024 * 1024),
            MAX_FILE_PAYLOAD_BYTES / (1024 * 1024),
        )
        return None
    return payload, entries, file_count, total_size, digest


def _win32_build_dropfiles_payload(paths: Sequence[str]) -> bytes:
    if win32clipboard is None:
        raise RuntimeError("File clipboard operations require Windows APIs")
    if not paths:
        raise ValueError("No paths supplied for file clipboard payload")

    normalised = [os.path.abspath(p) for p in paths]
    encoded = ("\0".join(normalised) + "\0\0").encode("utf-16-le")

    drop = DROPFILES()
    drop.pFiles = ctypes.sizeof(DROPFILES)
    drop.pt.x = 0  # type: ignore[attr-defined]
    drop.pt.y = 0  # type: ignore[attr-defined]
    drop.fNC = 0
    drop.fWide = 1
    header = ctypes.string_at(ctypes.byref(drop), ctypes.sizeof(DROPFILES))  # type: ignore[attr-defined]
    return header + encoded


def _win32_set_file_clipboard(data: bytes, entries: Sequence[Dict[str, Any]]) -> None:
    if win32clipboard is None:
        return
    if not data:
        logging.debug("Ignoring empty file clipboard payload")
        return

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            _cleanup_last_temp_dir()
            temp_dir = tempfile.mkdtemp(prefix="clipboard_files_")

            try:
                archive.extractall(temp_dir)
            except Exception as exc:
                logging.error("Failed to extract clipboard archive: %s", exc)
                shutil.rmtree(temp_dir, ignore_errors=True)
                return

            targets: list[str] = []
            if entries:
                for entry in entries:
                    name = entry.get("name") if isinstance(entry, dict) else None
                    if not name:
                        continue
                    candidate = os.path.join(temp_dir, name)
                    if os.path.exists(candidate):
                        targets.append(candidate)
            if not targets:
                # fall back to top-level archive members
                roots = {
                    item.split("/", 1)[0]
                    for item in archive.namelist()
                    if item
                }
                for name in roots:
                    candidate = os.path.join(temp_dir, name)
                    if os.path.exists(candidate):
                        targets.append(candidate)

            if not targets:
                logging.error("Could not determine extracted clipboard targets; aborting.")
                shutil.rmtree(temp_dir, ignore_errors=True)
                return

            try:
                payload = _win32_build_dropfiles_payload(targets)
            except Exception as exc:
                logging.error("Failed to build DROPFILES payload: %s", exc)
                shutil.rmtree(temp_dir, ignore_errors=True)
                return

            try:
                _win32_set_clipboard_bytes(win32con.CF_HDROP, payload)
                if CFSTR_PREFERREDDROPEFFECT is not None:
                    try:
                        effect_data = struct.pack("<I", DROPEFFECT_COPY)
                        _win32_set_clipboard_bytes(
                            CFSTR_PREFERREDDROPEFFECT, effect_data
                        )
                    except Exception as exc:
                        logging.debug(
                            "Failed to set preferred drop effect on clipboard: %s",
                            exc,
                        )
                logging.info(
                    "Set clipboard file list (%d item%s) from shared data.",
                    len(targets),
                    "s" if len(targets) != 1 else "",
                )
            except Exception as exc:
                logging.error("Failed to apply file clipboard payload: %s", exc)
                shutil.rmtree(temp_dir, ignore_errors=True)
                return

    except zipfile.BadZipFile:
        logging.error("Received invalid clipboard archive; refusing to apply.")
        return

    global _LAST_EXTRACTED_DIR
    _LAST_EXTRACTED_DIR = temp_dir


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

    logging.info(f"Normalizing clipboard item: {item}")

    if not item:
        return None

    fmt = item.get("format")
    if fmt not in {"text", "image", "files"}:
        return None

    logging.info(f"Processing format: {fmt}")

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
        file_paths = _detect_windows_file_paths(text)
        if file_paths:
            logging.debug(
                "Promoting text clipboard content to file list with %d entr%s.",
                len(file_paths),
                "ies" if len(file_paths) != 1 else "y",
            )
            return normalize_clipboard_item({"format": "files", "data": file_paths})
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

    if fmt == "image":
        data = item.get("data")
        if data is None:
            return None

        encoding = item.get("encoding") or "dib"

        try:
            raw_bytes = _ensure_bytes(data)
        except TypeError:
            if win32clipboard is not None:
                fmt_hint = None
                if encoding == "dib" and win32con is not None:
                    fmt_hint = getattr(win32con, "CF_DIB", None)
                elif encoding == "png":
                    fmt_hint = CF_PNG
                raw_bytes = _win32_clipboard_object_to_bytes(data, fmt_hint)
                if raw_bytes is None:
                    return None
            else:
                return None
        if len(raw_bytes) > MAX_IMAGE_PAYLOAD_BYTES:
            logging.warning(
                "Clipboard image is too large to share (%.2f MiB > %.2f MiB)",
                len(raw_bytes) / (1024 * 1024),
                MAX_IMAGE_PAYLOAD_BYTES / (1024 * 1024),
            )
            return None

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

    # files
    data = item.get("data")
    entries_data = item.get("entries")
    file_count = item.get("file_count")
    total_size = item.get("total_size")

    if isinstance(data, (bytes, bytearray, memoryview)):
        payload = _ensure_bytes(data)
        if len(payload) > MAX_FILE_PAYLOAD_BYTES:
            logging.warning(
                "Clipboard file archive is too large to share (%.2f MiB > %.2f MiB).",
                len(payload) / (1024 * 1024),
                MAX_FILE_PAYLOAD_BYTES / (1024 * 1024),
            )
            return None
        encoding = item.get("encoding") or "zip"
        try:
            digest = _compute_file_payload_digest(payload)
        except zipfile.BadZipFile:
            logging.debug("Invalid ZIP payload on clipboard; ignoring.")
            return None
    else:
        paths = _coerce_path_list(data)
        if not paths:
            return None
        packed = _pack_clipboard_files(paths)
        if not packed:
            return None
        payload, entries_data, file_count, total_size, digest = packed
        encoding = "zip"

    normalized.update(
        {
            "data": payload,
            "encoding": encoding,
            "size": len(payload),
            "digest": digest,
        }
    )

    entries_list: list[dict] = []
    if isinstance(entries_data, Iterable):
        for entry in entries_data:
            if isinstance(entry, dict) and entry.get("name"):
                entries_list.append(
                    {
                        "name": str(entry.get("name")),
                        "is_dir": bool(entry.get("is_dir", False)),
                    }
                )
    if entries_list:
        normalized["entries"] = entries_list

    if file_count is not None:
        try:
            normalized["file_count"] = int(file_count)
        except (TypeError, ValueError):
            pass
    elif entries_list:
        normalized["file_count"] = len(entries_list)

    if total_size is not None:
        try:
            normalized["total_size"] = int(total_size)
        except (TypeError, ValueError):
            pass

    return normalized


def clipboard_items_equal(a: Optional[ClipboardItem], b: Optional[ClipboardItem]) -> bool:
    if not a or not b:
        return False
    if a.get("format") != b.get("format"):
        return False
    digest_a = a.get("digest")
    digest_b = b.get("digest")
    if digest_a is None or digest_b is None:
        return False
    if digest_a != digest_b:
        return False
    timestamp_a = a.get("timestamp")
    timestamp_b = b.get("timestamp")
    if timestamp_a is None or timestamp_b is None:
        return True
    try:
        return float(timestamp_a) == float(timestamp_b)
    except (TypeError, ValueError):
        return True


def _win32_open_clipboard(
    retries: int = 5,
    delay: float = 0.05,
    *,
    backoff: float = 1.5,
    max_delay: float = 0.4,
) -> bool:
    if win32clipboard is None:  # pragma: no cover - más platform
        return False

    last_error: Optional[BaseException] = None
    current_delay = max(0.0, delay)

    max_attempts = max(1, retries)

    for attempt in range(1, max_attempts + 1):
        try:
            win32clipboard.OpenClipboard()
            return True
        except Exception as exc:  # pragma: no cover - ritka hibák
            last_error = exc
            logging.debug(
                "OpenClipboard failed (attempt %d/%d): %s",
                attempt,
                max_attempts,
                exc,
            )
            if attempt >= max_attempts:
                break
            if current_delay > 0:
                time.sleep(current_delay)
                current_delay = min(current_delay * max(1.0, backoff), max_delay)

    raise RuntimeError("Unable to open clipboard after retries") from last_error


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
            if _win32_open_clipboard(retries=8, delay=0.03, backoff=1.6):
                try:
                    if CF_PNG and win32clipboard.IsClipboardFormatAvailable(CF_PNG):
                        data = win32clipboard.GetClipboardData(CF_PNG)
                        item = normalize_clipboard_item(
                            {"format": "image", "encoding": "png", "data": data}
                        )
                        if item:
                            logging.debug(
                                "Read clipboard item via win32 API: %s",
                                _describe_clipboard_item(item),
                            )
                            return item
                    if win32clipboard.IsClipboardFormatAvailable(win32con.CF_DIB):
                        data = win32clipboard.GetClipboardData(win32con.CF_DIB)
                        item = normalize_clipboard_item(
                            {"format": "image", "encoding": "dib", "data": data}
                        )
                        if item:
                            logging.debug(
                                "Read clipboard item via win32 API: %s",
                                _describe_clipboard_item(item),
                            )
                            return item
                    if win32clipboard.IsClipboardFormatAvailable(win32con.CF_HDROP):
                        try:
                            paths = win32clipboard.GetClipboardData(win32con.CF_HDROP)
                        except Exception as exc:  # pragma: no cover - unexpected
                            logging.debug("Failed to read CF_HDROP payload: %s", exc)
                        else:
                            if _win32_clipboard_has_move_effect():
                                logging.debug("Ignoring clipboard file list with move effect (local cut).")
                            else:
                                file_list = list(paths) if paths else []
                                item = normalize_clipboard_item(
                                    {"format": "files", "data": file_list}
                                )
                                if item:
                                    logging.debug(
                                        "Read clipboard item via win32 API: %s",
                                        _describe_clipboard_item(item),
                                    )
                                    return item
                    if win32clipboard.IsClipboardFormatAvailable(win32con.CF_UNICODETEXT):
                        text = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
                        item = normalize_clipboard_item({"format": "text", "data": text})
                        if item:
                            logging.debug(
                                "Read clipboard item via win32 API: %s",
                                _describe_clipboard_item(item),
                            )
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
        item = normalize_clipboard_item({"format": "text", "data": str(content)})
        if item:
            logging.debug(
                "Read clipboard item via pyperclip: %s",
                _describe_clipboard_item(item),
            )
        return item
    return None


def write_clipboard_content(item: ClipboardItem, retries: int = 5, delay: float = 0.05) -> None:
    """Vágólap beállítása normalizált elem alapján."""

    normalized = normalize_clipboard_item(item)
    if not normalized:
        logging.debug("Ignoring clipboard write request with invalid payload: %s", item)
        return

    fmt = normalized["format"]

    logging.debug(
        "Requested clipboard write: %s", _describe_clipboard_item(normalized)
    )

    if win32clipboard is not None:  # pragma: no cover - Windows
        for attempt in range(retries):
            try:
                if not _win32_open_clipboard(
                    retries=max(3, retries), delay=delay, backoff=1.5
                ):
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
                            _win32_set_clipboard_bytes(
                                win32con.CF_DIB, normalized["data"]
                            )
                            logging.info(
                                "Set clipboard image (encoding=dib, attempt=%d)",
                                attempt + 1,
                            )
                        elif encoding == "png" and CF_PNG:
                            _win32_set_clipboard_bytes(CF_PNG, normalized["data"])
                            logging.info(
                                "Set clipboard image (encoding=png, attempt=%d)",
                                attempt + 1,
                            )
                        else:
                            raise ValueError(
                                f"Unsupported image encoding for clipboard: {encoding}"
                            )
                    elif fmt == "files":
                        entries = normalized.get("entries") or []
                        _win32_set_file_clipboard(normalized["data"], entries)
                        logging.info(
                            "Set clipboard files (count=%s, attempt=%d)",
                            normalized.get("file_count")
                            or len(entries)
                            or "?",
                            attempt + 1,
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
        logging.info(
            "Non-text clipboard item ignored on non-Windows platform: %s",
            _describe_clipboard_item(normalized),
        )
        return

    for attempt in range(retries):
        try:
            pyperclip.copy(normalized["data"])
            logging.debug(
                "Set clipboard text via pyperclip on attempt %d: %s",
                attempt + 1,
                _describe_clipboard_item(normalized),
            )
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
            if _win32_open_clipboard(retries=6, delay=0.05):
                try:
                    win32clipboard.EmptyClipboard()
                finally:
                    _win32_close_clipboard()
        except Exception as exc:
            logging.error("Failed to clear clipboard via win32 API: %s", exc)
        _cleanup_last_temp_dir()
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

