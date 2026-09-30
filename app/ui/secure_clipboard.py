"""Presse-papiers sécurisé.

* Les valeurs sensibles sont effacées du presse-papiers après
  `CLEAR_AFTER_SECONDS`, au verrouillage et à la fermeture de l'application.
* On n'efface que si le presse-papiers contient *encore* notre valeur (on ne
  détruit pas ce que l'utilisateur a copié entre-temps). Pour le vérifier,
  on ne garde pas la valeur elle-même mais une empreinte HMAC-SHA256 avec
  une clé aléatoire propre à cette instance.
* L'indicateur `x-kde-passwordManagerHint: secret` demande aux gestionnaires
  d'historique du presse-papiers (Klipper, GPaste, extensions GNOME…) de ne
  pas mémoriser la valeur. Tous ne le respectent pas : c'est une limite
  connue, documentée dans le README.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from PySide6.QtCore import QMimeData, QObject, QTimer, Signal
from PySide6.QtGui import QClipboard, QGuiApplication

from app.utils.logging import get_logger

CLEAR_AFTER_SECONDS = 30
PASSWORD_MANAGER_HINT = "x-kde-passwordManagerHint"  # noqa: S105 - nom de type MIME


class SecureClipboard(QObject):
    copied = Signal(str)   # message à afficher
    copied_item = Signal(str, bool, int)  # libellé, sensible, secondes avant effacement
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
                f"{label} copié — effacé du presse-papiers dans {self.clear_after_seconds} s."
            )
            self.copied_item.emit(label, True, self.clear_after_seconds)
        else:
            self.copied.emit(f"{label} copié.")
            self.copied_item.emit(label, False, 0)

    def clear_if_ours(self) -> None:
        """Efface le presse-papiers (et la sélection X11) s'il contient notre secret."""
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
