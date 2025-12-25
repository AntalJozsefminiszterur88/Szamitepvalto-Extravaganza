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
import re
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

    import pywintypes  # type: ignore
    import win32clipboard  # type: ignore
    import win32con  # type: ignore
except ImportError:  # pragma: no cover - más platformok
    win32clipboard = None  # type: ignore
    win32con = None  # type: ignore
    ctypes = None  # type: ignore
    wintypes = None  # type: ignore
    pywintypes = None  # type: ignore
    _KERNEL32 = None  # type: ignore


ClipboardItem = Dict[str, Any]

PyperclipException = getattr(pyperclip, "PyperclipException", Exception)


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

    if fmt == "html":
        html = item.get("data", "")
        if isinstance(html, str):
            preview = html.replace("\n", "\\n")
            if len(preview) > 40:
                preview = f"{preview[:37]}..."
            return f"html(len={len(html)} preview='{preview}')"
        if isinstance(html, (bytes, bytearray, memoryview)):
            raw = bytes(html)
            digest = hashlib.sha256(raw).hexdigest()[:12]
            return f"html(size={len(raw)}, sha256={digest})"
        return f"html(type={type(html)!r})"

    if fmt == "image":
        encoding = item.get("encoding", "unknown")
        data = item.get("data", b"")
        if isinstance(data, (bytes, bytearray, memoryview)):
            raw = bytes(data)
            size = len(raw)
            digest = hashlib.sha256(raw).hexdigest()[:12]
            return f"image(encoding={encoding}, size={size}, sha256={digest})"
        return f"image(encoding={encoding}, type={type(data)!r})"

    if fmt == "files":
        count: Any = item.get("file_count")
        if count is None:
            entries = item.get("entries")
            if hasattr(entries, "__len__"):
                try:
                    count = len(entries)  # type: ignore[arg-type]
                except Exception:
                    count = "?"
        total_size = _format_bytes(item.get("total_size"))
        payload_size = item.get("size")
        data = item.get("data")
        digest_preview: str
        if isinstance(data, (bytes, bytearray, memoryview)):
            raw = bytes(data)
            digest_preview = hashlib.sha256(raw).hexdigest()[:12]
            if payload_size is None:
                payload_size = len(raw)
        else:
            digest = item.get("digest")
            digest_preview = digest[:12] if isinstance(digest, str) else ""
        payload_display = (
            _format_bytes(int(payload_size))
            if isinstance(payload_size, (int, float))
            else "?"
        )
        return (
            "files(count={count}, total={total}, payload={payload}, sha256={digest})".format(
                count=count if count is not None else "?",
                total=total_size,
                payload=payload_display,
                digest=digest_preview,
            )
        )

    return f"format={fmt} keys={sorted(item.keys())}"


CF_PNG = None
CF_HTML = None
CF_TEXTHTML = None
CFSTR_PREFERREDDROPEFFECT = None
DROPEFFECT_COPY = 0x0001
DROPEFFECT_MOVE = 0x0002
MAX_FILE_PAYLOAD_BYTES = 8 * 1024 * 1024 * 1024  # 8 GiB hard limit for shared files
MAX_IMAGE_PAYLOAD_BYTES = MAX_FILE_PAYLOAD_BYTES
_LAST_EXTRACTED_DIR: Optional[str] = None
if win32clipboard is not None:  # pragma: no cover - Windows specifikus
    try:
        CF_PNG = win32clipboard.RegisterClipboardFormat("PNG")
    except Exception:  # pragma: no cover - régebbi Windows verziók
        CF_PNG = None
    try:
        CF_HTML = win32clipboard.RegisterClipboardFormat("HTML Format")
    except Exception:  # pragma: no cover - régebbi Windows verziók
        CF_HTML = None
    try:
        CF_TEXTHTML = win32clipboard.RegisterClipboardFormat("text/html")
    except Exception:  # pragma: no cover - régebbi Windows verziók
        CF_TEXTHTML = None
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

    if fmt == "html":
        html = item.get("data", "")
        if isinstance(html, str):
            preview = html.replace("\n", "\\n")
            if len(preview) > 40:
                preview = f"{preview[:37]}..."
            return f"html(len={len(html)} preview='{preview}')"
        if isinstance(html, (bytes, bytearray, memoryview)):
            raw = bytes(html)
            digest = hashlib.sha256(raw).hexdigest()[:12]
            return f"html(size={len(raw)}, sha256={digest})"
        return f"html(type={type(html)!r})"

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


def _win32_clipboard_object_size(data: Any) -> Optional[int]:
    if win32clipboard is None or _KERNEL32 is None:  # pragma: no cover - non-Windows
        return None

    if isinstance(data, (bytes, bytearray, memoryview)):
        return len(bytes(data))

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
            return None

    try:
        size = int(_KERNEL32.GlobalSize(handle))  # type: ignore[arg-type]
    except Exception as exc:
        logging.debug("Failed to read clipboard handle size: %s", exc, exc_info=True)
        return None

    return size if size > 0 else None


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


def _win32_get_html_clipboard_bytes() -> Optional[bytes]:
    if win32clipboard is None:
        return None
    if CF_HTML is None and CF_TEXTHTML is None:
        return None
    try:
        if _win32_open_clipboard(retries=8, delay=0.03, backoff=1.6):
            try:
                for fmt in (CF_HTML, CF_TEXTHTML):
                    if fmt and win32clipboard.IsClipboardFormatAvailable(fmt):
                        raw = win32clipboard.GetClipboardData(fmt)
                        raw_bytes = _win32_clipboard_object_to_bytes(raw, fmt)
                        if raw_bytes:
                            return raw_bytes
            finally:
                _win32_close_clipboard()
    except Exception as exc:  # pragma: no cover - defensive
        logging.debug("Failed to read HTML clipboard payload: %s", exc, exc_info=True)
    return None


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


def _build_file_payload_limit_bytes() -> Optional[int]:
    if MAX_FILE_PAYLOAD_BYTES <= 0:
        return None
    return MAX_FILE_PAYLOAD_BYTES


def _clip_limit_exceeded(current_total: int, next_size: int) -> bool:
    limit = _build_file_payload_limit_bytes()
    if limit is None:
        return False
    if next_size > limit:
        return True
    if current_total + next_size > limit:
        return True
    return False


def _prepare_clipboard_file_plan(paths: Sequence[str]) -> list[dict]:
    used_root_names: set[str] = set()
    plan: list[dict] = []

    def _unique_root(name: str) -> str:
        base = name or "item"
        candidate = base
        counter = 2
        while candidate in used_root_names:
            candidate = f"{base} ({counter})"
            counter += 1
        used_root_names.add(candidate)
        return candidate

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

        base_name = os.path.basename(normalized_path.rstrip("/\\")) or os.path.basename(
            normalized_path
        )
        root_name = _unique_root(base_name)
        plan.append(
            {
                "path": normalized_path,
                "root_name": root_name,
                "is_dir": os.path.isdir(normalized_path),
            }
        )

    return plan


def _stat_file_size(path: str) -> Optional[int]:
    try:
        return int(os.path.getsize(path))
    except Exception as exc:
        logging.debug("Failed to determine size of %s: %s", path, exc)
        return None


def _build_clipboard_file_metadata(paths: Sequence[str]) -> Optional[dict]:
    plan = _prepare_clipboard_file_plan(paths)
    if not plan:
        return None
    entries: list[dict] = []
    file_count = 0
    total_size = 0

    for item in plan:
        root_name = item["root_name"]
        is_dir = bool(item["is_dir"])
        entries.append({"name": root_name, "is_dir": is_dir})
        if is_dir:
            for root, _, files in os.walk(item["path"]):
                for filename in files:
                    full_path = os.path.join(root, filename)
                    size = _stat_file_size(full_path)
                    if size is None:
                        continue
                    if _clip_limit_exceeded(total_size, size):
                        logging.warning(
                            "Clipboard file selection exceeds maximum payload size when adding %s.",
                            full_path,
                        )
                        return None
                    total_size += size
                    file_count += 1
        else:
            size = _stat_file_size(item["path"])
            if size is None:
                continue
            if _clip_limit_exceeded(total_size, size):
                logging.warning(
                    "Clipboard file selection exceeds maximum payload size when adding %s.",
                    item["path"],
                )
                return None
            total_size += size
            file_count += 1

    return {
        "plan": plan,
        "entries": entries,
        "file_count": file_count,
        "total_size": total_size,
    }


def _compute_file_payload_digest_from_file(file_obj: Any) -> str:
    hasher = hashlib.sha256()
    with zipfile.ZipFile(file_obj, "r") as archive:
        for info in sorted(archive.infolist(), key=lambda entry: entry.filename):
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


def pack_files_to_zip(paths: Sequence[str]) -> Optional[dict[str, Any]]:
    info = _build_clipboard_file_metadata(paths)
    if not info:
        return None

    plan = info["plan"]
    entries = info["entries"]
    file_count = info["file_count"]
    total_size = info["total_size"]

    temp_dir = tempfile.mkdtemp(prefix="clipboard_files_")
    zip_path = os.path.join(temp_dir, "clipboard_content.zip")

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for item in plan:
            root_name = item["root_name"]
            base_path = item["path"]
            if item["is_dir"]:
                for root, _, files in os.walk(base_path):
                    rel_dir = os.path.relpath(root, base_path)
                    archive_root = (
                        root_name
                        if rel_dir in (".", os.curdir)
                        else os.path.join(root_name, rel_dir).replace("\\", "/")
                    )
                    for filename in files:
                        full_path = os.path.join(root, filename)
                        arcname = os.path.join(archive_root, filename).replace("\\", "/")
                        try:
                            archive.write(full_path, arcname=arcname)
                        except Exception as exc:
                            logging.debug(
                                "Failed to add %s to clipboard archive: %s",
                                full_path,
                                exc,
                            )
                            continue
            else:
                try:
                    archive.write(base_path, arcname=root_name)
                except Exception as exc:
                    logging.debug(
                        "Failed to add %s to clipboard archive: %s",
                        base_path,
                        exc,
                    )
                    continue

    if not os.path.exists(zip_path) or os.path.getsize(zip_path) == 0:
        return None

    with open(zip_path, "rb") as handle:
        digest = _compute_file_payload_digest_from_file(handle)

    return {
        "path": zip_path,
        "encoding": "zip",
        "entries": entries,
        "file_count": file_count,
        "total_size": total_size,
        "size": os.path.getsize(zip_path),
        "digest": digest,
    }


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
            _win32_set_file_clipboard_from_archive(archive, entries)

    except zipfile.BadZipFile:
        logging.error("Received invalid clipboard archive; refusing to apply.")
        return


def _win32_set_file_clipboard_from_archive(
    archive: zipfile.ZipFile, entries: Sequence[Dict[str, Any]]
) -> None:
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

    global _LAST_EXTRACTED_DIR
    _LAST_EXTRACTED_DIR = temp_dir


def _win32_set_file_clipboard_from_path(
    path: str, entries: Sequence[Dict[str, Any]]
) -> None:
    if win32clipboard is None:
        return
    if not path:
        logging.debug("Ignoring empty file clipboard payload")
        return
    try:
        with zipfile.ZipFile(path) as archive:
            _win32_set_file_clipboard_from_archive(archive, entries)
    except zipfile.BadZipFile:
        logging.error("Received invalid clipboard archive; refusing to apply.")


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


def _strip_html_clipboard_header(raw: bytes) -> bytes:
    if not raw:
        return raw
    try:
        header_text = raw.decode("ascii", errors="ignore")
    except Exception:
        return raw
    start_match = re.search(r"StartHTML:(\d+)", header_text)
    end_match = re.search(r"EndHTML:(\d+)", header_text)
    if not start_match or not end_match:
        return raw
    try:
        start = int(start_match.group(1))
        end = int(end_match.group(1))
    except ValueError:
        return raw
    if start < 0 or end <= start or end > len(raw):
        return raw
    return raw[start:end]


def _wrap_html_fragment(html: bytes) -> bytes:
    if b"<!--StartFragment-->" in html and b"<!--EndFragment-->" in html:
        return html
    return (
        b"<html><body><!--StartFragment-->"
        + html
        + b"<!--EndFragment--></body></html>"
    )


def _build_html_clipboard_payload(html: bytes) -> bytes:
    html_payload = _wrap_html_fragment(html)
    header_template = (
        "Version:0.9\r\n"
        "StartHTML:{start_html:010d}\r\n"
        "EndHTML:{end_html:010d}\r\n"
        "StartFragment:{start_fragment:010d}\r\n"
        "EndFragment:{end_fragment:010d}\r\n"
    )
    placeholder_header = header_template.format(
        start_html=0,
        end_html=0,
        start_fragment=0,
        end_fragment=0,
    ).encode("ascii")
    start_html = len(placeholder_header)
    start_fragment_marker = b"<!--StartFragment-->"
    end_fragment_marker = b"<!--EndFragment-->"
    fragment_start = html_payload.find(start_fragment_marker)
    fragment_end = html_payload.find(end_fragment_marker)
    if fragment_start == -1 or fragment_end == -1:
        fragment_start = 0
        fragment_end = len(html_payload)
    else:
        fragment_start += len(start_fragment_marker)
    start_fragment = start_html + fragment_start
    end_fragment = start_html + fragment_end
    end_html = start_html + len(html_payload)
    header = header_template.format(
        start_html=start_html,
        end_html=end_html,
        start_fragment=start_fragment,
        end_fragment=end_fragment,
    ).encode("ascii")
    return header + html_payload


def normalize_clipboard_item(item: Optional[ClipboardItem]) -> Optional[ClipboardItem]:
    """Közös reprezentációra hozza a vágólap elemeit."""

    if item is not None:
        logging.debug(
            "Normalizing clipboard item: %s", _describe_clipboard_item(item)
        )

    if not item:
        return None

    fmt = item.get("format")
    if fmt not in {"text", "html", "image", "files"}:
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

    if fmt == "html":
        html = item.get("data")
        if html is None:
            return None
        raw_bytes: bytes
        if isinstance(html, (bytes, bytearray, memoryview)):
            raw_bytes = _ensure_bytes(html)
        else:
            if not isinstance(html, str):
                try:
                    html = str(html)
                except Exception:
                    return None
            raw_bytes = html.encode("utf-8")
        normalized.update(
            {
                "data": html,
                "encoding": "utf-8",
                "size": len(raw_bytes),
                "digest": _compute_digest("html", "utf-8", raw_bytes),
            }
        )
        if isinstance(html, str):
            normalized["length"] = len(html)
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
        metadata = _build_clipboard_file_metadata(paths)
        if not metadata:
            return None
        normalized.update(
            {
                "encoding": "zip",
                "paths": paths,
                "entries": metadata.get("entries", []),
                "file_count": metadata.get("file_count"),
                "total_size": metadata.get("total_size"),
            }
        )
        return normalized

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
            win32clipboard.OpenClipboard(None)
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


def _is_clipboard_error_1418(exc: BaseException) -> bool:
    winerror = getattr(exc, "winerror", None)
    if winerror == 1418:
        return True
    args = getattr(exc, "args", ())
    if isinstance(args, tuple) and args:
        return 1418 in args
    return False


def _win32_close_clipboard() -> None:
    if win32clipboard is None:  # pragma: no cover
        return
    try:
        win32clipboard.CloseClipboard()
    except Exception:  # pragma: no cover - nem kritikus
        pass


def get_clipboard_metadata() -> Optional[ClipboardItem]:
    """Read clipboard metadata without loading large payloads."""

    def _build_files_metadata(paths: list[str]) -> ClipboardItem:
        return {
            "format": "files",
            "files": [os.path.basename(path) for path in paths],
        }

    if win32clipboard is not None:  # pragma: no cover - Windows-specifikus út
        try:
            if _win32_open_clipboard(retries=8, delay=0.03, backoff=1.6):
                try:
                    available_formats: list[str] = []
                    file_list: list[str] = []
                    image_info: Optional[dict[str, Any]] = None
                    text_data: Optional[str] = None
                    html_available = False

                    if win32clipboard.IsClipboardFormatAvailable(win32con.CF_HDROP):
                        try:
                            paths = win32clipboard.GetClipboardData(win32con.CF_HDROP)
                        except Exception as exc:  # pragma: no cover - unexpected
                            logging.debug("Failed to read CF_HDROP payload: %s", exc)
                        else:
                            if _win32_clipboard_has_move_effect():
                                logging.debug(
                                    "Ignoring clipboard file list with move effect (local cut)."
                                )
                            else:
                                file_list = list(paths) if paths else []
                                if file_list:
                                    available_formats.append("files")

                    if CF_PNG and win32clipboard.IsClipboardFormatAvailable(CF_PNG):
                        data = win32clipboard.GetClipboardData(CF_PNG)
                        image_info = {
                            "format": "image",
                            "encoding": "png",
                            "size": _win32_clipboard_object_size(data),
                        }
                        available_formats.append("image")
                    elif win32clipboard.IsClipboardFormatAvailable(win32con.CF_DIB):
                        data = win32clipboard.GetClipboardData(win32con.CF_DIB)
                        image_info = {
                            "format": "image",
                            "encoding": "dib",
                            "size": _win32_clipboard_object_size(data),
                        }
                        available_formats.append("image")

                    for fmt in (CF_HTML, CF_TEXTHTML):
                        if fmt and win32clipboard.IsClipboardFormatAvailable(fmt):
                            html_available = True
                            break
                    if html_available:
                        available_formats.append("html")

                    if win32clipboard.IsClipboardFormatAvailable(win32con.CF_UNICODETEXT):
                        text = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
                        if text:
                            text_data = str(text)
                            available_formats.append("text")

                    if available_formats:
                        priority = ("files", "image", "html", "text")
                        selected = next(
                            (fmt for fmt in priority if fmt in available_formats),
                            available_formats[0],
                        )
                        metadata: ClipboardItem = {
                            "format": selected,
                            "available_formats": available_formats,
                        }
                        if selected == "files" and file_list:
                            metadata.update(_build_files_metadata(file_list))
                        elif selected == "image" and image_info:
                            metadata.update(image_info)
                        elif selected == "text" and text_data:
                            metadata["data"] = text_data
                        return metadata
                finally:
                    _win32_close_clipboard()
        except Exception as exc:
            logging.error(
                "Failed to read clipboard metadata through win32 API: %s",
                exc,
                exc_info=True,
            )

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
        return {"format": "text", "data": str(content), "available_formats": ["text"]}
    return None


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


def set_clipboard_from_file(path: str, fmt: Optional[str] = None) -> None:
    if not path or not os.path.exists(path):
        logging.debug("Clipboard payload file does not exist: %s", path)
        return

    _, ext = os.path.splitext(path)
    extension = ext.lower()

    if fmt == "html" or extension == ".html":
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
        except Exception as exc:
            logging.error("Failed to read clipboard HTML payload %s: %s", path, exc)
            return
        write_clipboard_content({"format": "html", "data": raw})
        return

    if extension == ".txt":
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
        except Exception as exc:
            logging.error("Failed to read clipboard text payload %s: %s", path, exc)
            return
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
        write_clipboard_content({"format": "text", "data": text})
        return

    if extension in {".png", ".dib"}:
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
        except Exception as exc:
            logging.error("Failed to read clipboard image payload %s: %s", path, exc)
            return
        encoding = "png" if extension == ".png" else "dib"
        write_clipboard_content({"format": "image", "encoding": encoding, "data": raw})
        return

    if extension == ".zip":
        if win32clipboard is None:
            logging.info("File clipboard payload ignored on non-Windows platform.")
            return
        _win32_set_file_clipboard_from_path(path, [])
        return

    logging.debug("Unsupported clipboard payload extension: %s", extension)


def write_clipboard_content(item: ClipboardItem, retries: int = 5, delay: float = 0.05) -> None:
    """Vágólap beállítása normalizált elem alapján."""

    normalized = normalize_clipboard_item(item)
    if not normalized:
        logging.debug(
            "Ignoring clipboard write request with invalid payload: %s",
            _describe_clipboard_item(
                item if isinstance(item, dict) else {"format": "unknown", "data": item}
            ),
        )
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
                    retry_due_to_clipboard = False
                    try:
                        if fmt == "text":
                            win32clipboard.SetClipboardData(
                                win32con.CF_UNICODETEXT, normalized["data"]
                            )
                        elif fmt == "html":
                            html_data = normalized.get("data", "")
                            if isinstance(html_data, (bytes, bytearray, memoryview)):
                                html_bytes = _ensure_bytes(html_data)
                            else:
                                html_bytes = str(html_data).encode("utf-8")
                            payload = _build_html_clipboard_payload(html_bytes)
                            if CF_HTML is None and CF_TEXTHTML is None:
                                raise ValueError("HTML clipboard format is not available.")
                            target_fmt = CF_HTML or CF_TEXTHTML
                            if target_fmt is None:
                                raise ValueError("HTML clipboard format is not available.")
                            _win32_set_clipboard_bytes(target_fmt, payload)
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
                    except Exception as exc:
                        if _is_clipboard_error_1418(exc):
                            logging.warning(
                                "Clipboard write failed with 1418; retrying (attempt %d/%d).",
                                attempt + 1,
                                retries,
                            )
                            retry_due_to_clipboard = True
                        else:
                            raise
                    if retry_due_to_clipboard:
                        time.sleep(delay)
                        continue
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
    if fmt not in {"text", "html"}:
        logging.info(
            "Non-text clipboard item ignored on non-Windows platform: %s",
            _describe_clipboard_item(normalized),
        )
        return

    if fmt == "html":
        html_data = normalized.get("data", "")
        if isinstance(html_data, (bytes, bytearray, memoryview)):
            html_text = _ensure_bytes(html_data).decode("utf-8", errors="replace")
        else:
            html_text = str(html_data)
        normalized["data"] = html_text
        fmt = "text"

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
