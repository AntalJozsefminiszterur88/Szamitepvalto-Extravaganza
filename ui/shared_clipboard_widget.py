from __future__ import annotations

from datetime import datetime
from typing import Callable, Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QHideEvent, QShowEvent
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QVBoxLayout,
    QWidget,
)


def _format_bytes(value: Optional[float]) -> str:
    if value in (None, 0):
        return "0 B" if value == 0 else "ismeretlen"

    size = float(value)
    units = ("B", "KB", "MB", "GB", "TB")
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


class SharedClipboardWidget(QWidget):
    """View that surfaces the state of the shared clipboard."""

    def __init__(
        self,
        parent: QWidget,
        *,
        on_back: Callable[[], None],
        status_provider: Callable[[], Optional[dict]],
        stop_callback: Callable[[], bool],
        delete_callback: Callable[[], int],
    ) -> None:
        super().__init__(parent)
        self._on_back = on_back
        self._status_provider = status_provider
        self._stop_callback = stop_callback
        self._delete_callback = delete_callback

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        title = QLabel("Közös vágólap állapota")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        layout.addWidget(title)

        self.info_label = QLabel("Jelenleg nincs aktív fájlmásolás a közös vágólapon.")
        self.info_label.setWordWrap(True)
        layout.addWidget(self.info_label)

        self.file_list = QListWidget()
        self.file_list.setSelectionMode(QListWidget.NoSelection)
        self.file_list.setFocusPolicy(Qt.NoFocus)
        layout.addWidget(self.file_list)

        action_row = QHBoxLayout()
        self.refresh_button = QPushButton("Frissítés")
        self.refresh_button.clicked.connect(self.refresh_status)
        self.stop_button = QPushButton("Másolás leállítása")
        self.stop_button.clicked.connect(self.stop_transfer)
        self.delete_button = QPushButton("Folyamat törlése")
        self.delete_button.clicked.connect(self.delete_transfer)

        action_row.addWidget(self.refresh_button)
        action_row.addWidget(self.stop_button)
        action_row.addWidget(self.delete_button)
        layout.addLayout(action_row)

        bottom_row = QHBoxLayout()
        bottom_row.addItem(QSpacerItem(20, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))
        back_button = QPushButton("Vissza")
        back_button.clicked.connect(self._handle_back)
        bottom_row.addWidget(back_button)
        layout.addLayout(bottom_row)

        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(2000)
        self._refresh_timer.timeout.connect(self.refresh_status)

    def showEvent(self, event: QShowEvent) -> None:  # pragma: no cover - GUI behaviour
        super().showEvent(event)
        self.refresh_status()
        if not self._refresh_timer.isActive():
            self._refresh_timer.start()

    def hideEvent(self, event: QHideEvent) -> None:  # pragma: no cover - GUI behaviour
        if self._refresh_timer.isActive():
            self._refresh_timer.stop()
        super().hideEvent(event)

    def refresh_status(self) -> None:
        snapshot = self._status_provider() if self._status_provider else None
        self.file_list.clear()

        if not snapshot or snapshot.get('format') != 'files':
            self.info_label.setText(
                "Jelenleg nincs aktív fájlmásolás a közös vágólapon."
            )
            self.stop_button.setEnabled(False)
            self.delete_button.setEnabled(False)
            return

        entries = snapshot.get('entries') or []
        file_count = snapshot.get('file_count') or len(entries)
        total_size = snapshot.get('total_size') or snapshot.get('size')
        timestamp = snapshot.get('timestamp')
        timestamp_text = (
            datetime.fromtimestamp(float(timestamp)).strftime("%Y.%m.%d %H:%M:%S")
            if timestamp
            else "ismeretlen"
        )

        self.info_label.setText(
            "Aktív megosztás: {count} elem, összesen {size} (frissítve: {ts}).".format(
                count=file_count,
                size=_format_bytes(total_size),
                ts=timestamp_text,
            )
        )

        if entries:
            for entry in entries:
                name = entry.get('name') or "(névtelen)"
                suffix = "[mappa]" if entry.get('is_dir') else ""
                size_text = _format_bytes(entry.get('size'))
                text = f"{name} {suffix} — {size_text}" if suffix else f"{name} — {size_text}"
                self.file_list.addItem(QListWidgetItem(text))
        else:
            self.file_list.addItem(
                QListWidgetItem("A fájllista nem elérhető ehhez a megosztáshoz.")
            )

        self.stop_button.setEnabled(True)
        self.delete_button.setEnabled(True)

    def stop_transfer(self) -> None:
        if not self._stop_callback:
            return
        success = self._stop_callback()
        if success:
            QMessageBox.information(
                self,
                "Közös vágólap",
                "A fájlmegosztás megszakítva, a vágólap kiürítve.",
            )
        else:
            QMessageBox.information(
                self,
                "Közös vágólap",
                "Jelenleg nincs megszakítható fájlmegosztás.",
            )
        self.refresh_status()

    def delete_transfer(self) -> None:
        if not self._delete_callback:
            return
        removed = self._delete_callback()
        if removed:
            QMessageBox.information(
                self,
                "Közös vágólap",
                f"{removed} fájl törölve a helyi tárolóból.",
            )
        else:
            QMessageBox.information(
                self,
                "Közös vágólap",
                "Nem találtunk törölhető fájlokat a megosztáshoz.",
            )
        self.refresh_status()

    def _handle_back(self) -> None:
        if self._on_back:
            self._on_back()

