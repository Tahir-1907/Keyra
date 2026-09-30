"""Secure clipboard.

* Sensitive values are cleared from the clipboard after `CLEAR_AFTER_SECONDS`,
  when locking and when the application closes.
* The clipboard is cleared only if it *still* contains our value (whatever the
  user copied in the meantime is not destroyed). To check this, the value
  itself is not kept, only an HMAC-SHA256 fingerprint with a random key
  specific to this instance.
* The `x-kde-passwordManagerHint: secret` hint asks clipboard history managers
  (Klipper, GPaste, GNOME extensions…) not to remember the value. Not all of
  them honor it: this is a known limitation, documented in the README.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from PySide6.QtCore import QMimeData, QObject, QTimer, Signal
from PySide6.QtGui import QClipboard, QGuiApplication

from app.utils.logging import get_logger

CLEAR_AFTER_SECONDS = 30
PASSWORD_MANAGER_HINT = "x-kde-passwordManagerHint"  # noqa: S105 - MIME type name


class SecureClipboard(QObject):
    copied = Signal(str)   # message to display
    copied_item = Signal(str, bool, int)  # label, sensitive, seconds before clearing
    cleared = Signal()

    def __init__(self, clear_after_seconds: int = CLEAR_AFTER_SECONDS, parent=None) -> None:
        super().__init__(parent)
        self.clear_after_seconds = clear_after_seconds
        self._key = secrets.token_bytes(32)
        self._digest: bytes | None = None
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.clear_if_ours)

    def _fingerprint(self, text: str) -> bytes:
        return hmac.new(self._key, text.encode("utf-8"), hashlib.sha256).digest()

    def copy(self, text: str, label: str, sensitive: bool = True) -> None:
        if not text:
            return
        mime = QMimeData()
        mime.setText(text)
        if sensitive:
            mime.setData(PASSWORD_MANAGER_HINT, b"secret")
        QGuiApplication.clipboard().setMimeData(mime, QClipboard.Clipboard)
        if sensitive:
            self._digest = self._fingerprint(text)
            self._timer.start(self.clear_after_seconds * 1000)
            self.copied.emit(
                f"{label} copied — cleared from the clipboard in {self.clear_after_seconds} s."
            )
            self.copied_item.emit(label, True, self.clear_after_seconds)
        else:
            self.copied.emit(f"{label} copied.")
            self.copied_item.emit(label, False, 0)

    def clear_if_ours(self) -> None:
        """Clears the clipboard (and the X11 selection) if it contains our secret."""
        self._timer.stop()
        if self._digest is None:
            return
        clipboard = QGuiApplication.clipboard()
        modes = [QClipboard.Clipboard]
        if clipboard.supportsSelection():
            modes.append(QClipboard.Selection)
        cleared = False
        for mode in modes:
            current = clipboard.text(mode)
            if current and hmac.compare_digest(self._fingerprint(current), self._digest):
                clipboard.clear(mode)
                cleared = True
        self._digest = None
        if cleared:
            get_logger().info("Clipboard cleared")
            self.cleared.emit()
