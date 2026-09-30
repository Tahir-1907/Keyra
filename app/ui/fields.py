"""Specialized input fields."""

from __future__ import annotations

from PySide6.QtWidgets import QLineEdit, QWidget

from app.ui import lucide, theme


class PasswordField(QLineEdit):
    """Masked field (monospace font) with a built-in "show / hide" button."""

    def __init__(self, placeholder: str = "", parent: QWidget | None = None,
                 leading_icon: str | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Secret")
        self.setEchoMode(QLineEdit.Password)
        self.setPlaceholderText(placeholder)
        if leading_icon:
            self.addAction(lucide.icon(leading_icon, theme.TEXT_3, 16), QLineEdit.LeadingPosition)
        self._toggle = self.addAction(lucide.icon("eye", theme.TEXT_3, 16),
                                      QLineEdit.TrailingPosition)
        self._toggle.setToolTip("Afficher / masquer")
        self._toggle.triggered.connect(
            lambda: self.set_revealed(self.echoMode() == QLineEdit.Password)
        )

    def set_revealed(self, revealed: bool) -> None:
        self.setEchoMode(QLineEdit.Normal if revealed else QLineEdit.Password)
        self._toggle.setIcon(lucide.icon("eye-off" if revealed else "eye", theme.TEXT_3, 16))

    def real_text(self) -> str:
        return self.text()

    def reset(self) -> None:
        self.clear()
        self.set_revealed(False)
