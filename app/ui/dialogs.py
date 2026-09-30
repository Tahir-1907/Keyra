"""Application modals: shared base + confirmations, inputs, alerts.

Every dialog window inherits from `PremiumDialog`:
* the application behind it is dimmed and blurred (veil);
* opening: scale 0.97 → 1 + fade; closing: the reverse;
* rounded card, header (title, subtitle, close button), Esc closes;
* `close_now()` closes without animation (locking: nothing may linger).

Calls go through this module (`dialogs.confirm(...)`): a single entry point,
easy to replace in tests.
"""

from __future__ import annotations

from PySide6.QtCore import QEasingCurve, QPoint, QRectF, Qt, QVariantAnimation
from PySide6.QtGui import QColor, QPainter, QPixmap
from PySide6.QtWidgets import (
    QDialog,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from app.ui import components as ui
from app.ui import effects, theme

_SHADOW = 26  # transparent margin around the card (drawn shadow)


class _Backdrop(QWidget):
    """Blurred veil laid over the main window while a modal is open."""

    def __init__(self, window: QWidget) -> None:
        super().__init__(window)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.setGeometry(window.rect())
        self._blurred = effects._blurred(window.grab(), 10)
        self._alpha = 0.0
        self._animation = QVariantAnimation(self)
        self._animation.setDuration(theme.DURATION_BASE)
        self._animation.valueChanged.connect(self._set_alpha)

    def fade(self, visible: bool) -> None:
        if not effects.animations_enabled():
            self._set_alpha(1.0 if visible else 0.0)
            if not visible:
                self.deleteLater()
            return
        self._animation.stop()
        self._animation.setStartValue(self._alpha)
        self._animation.setEndValue(1.0 if visible else 0.0)
        if not visible:
            self._animation.finished.connect(self.deleteLater)
        self._animation.start()

    def _set_alpha(self, value) -> None:
        self._alpha = float(value)
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setOpacity(self._alpha)
        painter.drawPixmap(0, 0, self._blurred)
        painter.fillRect(self.rect(), theme.rgba(theme.BG, theme.BACKDROP_ALPHA))


class PremiumDialog(QDialog):
    def __init__(self, parent: QWidget | None, title: str = "", subtitle: str = "",
                 icon: str | None = None, width: int = 480, closable: bool = True,
                 icon_color: str = theme.ACCENT_2) -> None:
        super().__init__(parent, Qt.Dialog | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setWindowTitle(title or "Keyra")
        self.setModal(True)
        self._backdrop: _Backdrop | None = None
        self._progress = 1.0
        self._snapshot: QPixmap | None = None
        self._closing = False
        self._instant = False

        self.card = ui.card("ModalCard")
        self.card.setFixedWidth(width)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(_SHADOW, _SHADOW, _SHADOW, _SHADOW)
        outer.addWidget(self.card)

        self.card_layout = QVBoxLayout(self.card)
        self.card_layout.setContentsMargins(24, 22, 24, 22)
        self.card_layout.setSpacing(14)
        if title:
            header = QHBoxLayout()
            header.setSpacing(12)
            if icon:
                header.addWidget(ui.icon_label(icon, icon_color, 20), 0, Qt.AlignTop)
            texts = QVBoxLayout()
            texts.setSpacing(3)
            self.title_label = ui.label(title, "H2")
            texts.addWidget(self.title_label)
            if subtitle:
                texts.addWidget(ui.label(subtitle, "Muted", wrap=True))
            header.addLayout(texts, 1)
            if closable:
                close = ui.icon_button("x", "Close", "Esc", self.reject, 16)
                close.setFocusPolicy(Qt.NoFocus)  # Esc closes; no initial focus frame
                header.addWidget(close, 0, Qt.AlignTop)
            self.card_layout.addLayout(header)
        self.body = QVBoxLayout()
        self.body.setSpacing(12)
        self.card_layout.addLayout(self.body)

    # --- Standard buttons ----------------------------------------------------------------

    def add_buttons(self, cancel_text: str = "Cancel", confirm_text: str = "",
                    kind: str = "Primary", confirm_icon: str | None = None):
        row = QHBoxLayout()
        row.setSpacing(10)
        row.addStretch(1)
        cancel = ui.button(cancel_text, kind="Ghost", on_click=self.reject) if cancel_text else None
        if cancel:
            row.addWidget(cancel)
        confirm = None
        if confirm_text:
            confirm = ui.button(confirm_text, confirm_icon, kind)
            confirm.setDefault(True)
            row.addWidget(confirm)
        self.card_layout.addSpacing(4)
        self.card_layout.addLayout(row)
        return cancel, confirm

    # --- Open / close animation ----------------------------------------------------

    def showEvent(self, event) -> None:
        super().showEvent(event)
        window = self.parentWidget().window() if self.parentWidget() else None
        if window is not None and window.isVisible():
            self.adjustSize()
            center = window.mapToGlobal(window.rect().center())
            self.move(center - QPoint(self.width() // 2, self.height() // 2))
            if self._backdrop is None and window is not self:
                self._backdrop = _Backdrop(window)
                self._backdrop.show()
                self._backdrop.fade(True)
        self._animate(opening=True)

    def _animate(self, opening: bool, on_done=None) -> None:
        if not effects.animations_enabled() or self._instant:
            self._progress = 1.0
            if on_done:
                on_done()
            return
        self.layout().activate()
        self._snapshot = self.card.grab()
        effect = QGraphicsOpacityEffect(self.card)
        effect.setOpacity(0.0)
        self.card.setGraphicsEffect(effect)
        animation = QVariantAnimation(self)
        animation.setDuration(theme.DURATION_BASE if opening else theme.DURATION_FAST)
        animation.setStartValue(0.0 if opening else 1.0)
        animation.setEndValue(1.0 if opening else 0.0)
        animation.setEasingCurve(QEasingCurve.OutCubic if opening else QEasingCurve.InCubic)
        animation.valueChanged.connect(self._set_progress)

        def finished() -> None:
            self._snapshot = None
            if opening:
                self.card.setGraphicsEffect(None)
            self.update()
            if on_done:
                on_done()

        animation.finished.connect(finished)
        animation.start(QVariantAnimation.DeleteWhenStopped)

    def _set_progress(self, value) -> None:
        self._progress = float(value)
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        card_rect = QRectF(self.card.geometry())
        opacity = self._progress if self._snapshot is not None else 1.0
        # Soft drawn shadow (no graphics effect: it would block those of the children).
        painter.setPen(Qt.NoPen)
        for i in range(8):
            shadow = QColor(0, 0, 0, int(14 * opacity))
            painter.setBrush(shadow)
            grow = 3 + i * 2.6
            painter.drawRoundedRect(card_rect.adjusted(-grow, -grow + 6, grow, grow + 6),
                                    theme.RADIUS_XL + grow, theme.RADIUS_XL + grow)
        if self._snapshot is not None:
            scale = 0.97 + 0.03 * self._progress
            painter.setOpacity(self._progress)
            painter.translate(card_rect.center())
            painter.scale(scale, scale)
            painter.translate(-card_rect.center())
            painter.drawPixmap(card_rect.topLeft(), self._snapshot)

    def done(self, result: int) -> None:
        if self._closing:
            return
        self._closing = True
        if self._backdrop is not None:
            self._backdrop.fade(False)
            self._backdrop = None
        self._animate(opening=False, on_done=lambda: QDialog.done(self, result))

    def close_now(self, result: int = QDialog.Rejected) -> None:
        """Immediate close, without animation (vault locking)."""
        self._instant = True
        if self._backdrop is not None:
            self._backdrop.deleteLater()
            self._backdrop = None
        self._closing = True
        QDialog.done(self, result)


# --- Standard dialogs ---------------------------------------------------------------------------


class ConfirmDialog(PremiumDialog):
    def __init__(self, parent, title: str, text: str, confirm_text: str, danger: bool,
                 icon: str | None, acknowledge: str | None) -> None:
        super().__init__(parent, title, icon=icon or ("triangle-alert" if danger else "info"),
                         width=440, icon_color=theme.DANGER if danger else theme.ACCENT_2)
        message = ui.label(text, "Muted", wrap=True)
        self.body.addWidget(message)
        self.ack = None
        if acknowledge:
            self.ack = ui.ToggleSwitch(acknowledge)
            self.body.addWidget(self.ack)
        _, self.confirm = self.add_buttons("Cancel", confirm_text,
                                           "Danger" if danger else "Primary")
        self.confirm.clicked.connect(self.accept)
        if self.ack is not None:
            self.confirm.setEnabled(False)
            self.ack.toggled.connect(self.confirm.setEnabled)


def confirm(parent: QWidget, title: str, text: str, confirm_text: str = "Confirm",
            danger: bool = False, icon: str | None = None,
            acknowledge: str | None = None) -> bool:
    """Asks for confirmation. `acknowledge`: toggle to switch on (reinforced confirmation)."""
    return ConfirmDialog(parent, title, text, confirm_text, danger, icon,
                         acknowledge).exec() == QDialog.Accepted


class PromptDialog(PremiumDialog):
    def __init__(self, parent, title: str, field_label: str, text: str, placeholder: str,
                 icon: str | None) -> None:
        super().__init__(parent, title, icon=icon, width=420)
        self.body.addWidget(ui.label(field_label, "FieldLabel"))
        self.field = QLineEdit(text)
        self.field.setPlaceholderText(placeholder)
        self.field.selectAll()
        self.field.returnPressed.connect(self.accept)
        self.body.addWidget(self.field)
        _, ok = self.add_buttons("Cancel", "OK")
        ok.clicked.connect(self.accept)
        self.field.setFocus()


def prompt_text(parent: QWidget, title: str, field_label: str, text: str = "",
                placeholder: str = "", icon: str | None = None) -> str | None:
    dialog = PromptDialog(parent, title, field_label, text, placeholder, icon)
    return dialog.field.text() if dialog.exec() == QDialog.Accepted else None


def alert(parent: QWidget, title: str, text: str, kind: str = "error") -> None:
    icon = {"error": "circle-alert", "warning": "triangle-alert"}.get(kind, "circle-check")
    dialog = PremiumDialog(parent, title, icon=icon, width=420)
    dialog.body.addWidget(ui.label(text, "Muted", wrap=True))
    _, ok = dialog.add_buttons("", "Got it")
    ok.clicked.connect(dialog.accept)
    dialog.exec()


def open_dialogs() -> list[PremiumDialog]:
    from PySide6.QtWidgets import QApplication

    return [w for w in QApplication.topLevelWidgets()
            if isinstance(w, QDialog) and w.isVisible()]
