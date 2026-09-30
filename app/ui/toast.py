"""Notifications (« toasts ») en bas à droite de la fenêtre.

Courtes et non intrusives : entrée depuis la droite (+30 px, fondu), sortie
vers la droite, empilement. Icône dans une pastille colorée + texte (l'état
n'est jamais indiqué par la couleur seule). Une notification peut porter une
barre de compte à rebours : après une copie, le temps restant avant
l'effacement automatique du presse-papiers.
"""

from __future__ import annotations

import shiboken6
from PySide6.QtCore import (
    QEasingCurve,
    QElapsedTimer,
    QEvent,
    QObject,
    QPoint,
    QPropertyAnimation,
    Qt,
    QTimer,
)
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from app.ui import effects, lucide, theme

_MARGIN = 18
_SPACING = 10
_WIDTH = 340

KIND_COLORS = {
    "info": theme.INFO,
    "success": theme.ACCENT_2,
    "warning": theme.WARNING,
    "error": theme.DANGER,
}
KIND_ICONS = {"info": "info", "success": "circle-check", "warning": "triangle-alert",
              "error": "circle-alert"}


class _CountdownBar(QWidget):
    def __init__(self, seconds: float, color: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedHeight(3)
        self._total_ms = max(seconds * 1000, 1)
        self._color = QColor(color)
        self._clock = QElapsedTimer()
        self._clock.start()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.update)
        self._timer.start(50)

    def remaining_ratio(self) -> float:
        return max(0.0, 1 - self._clock.elapsed() / self._total_ms)

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(theme.BORDER))
        width = int(self.width() * self.remaining_ratio())
        painter.fillRect(0, 0, width, self.height(), self._color)


class Toast(QFrame):
    def __init__(self, parent: QWidget, title: str, message: str, kind: str,
                 icon: str | None, countdown: float | None) -> None:
        super().__init__(parent)
        self.setObjectName("Toast")
        self.setFixedWidth(_WIDTH)
        color = KIND_COLORS.get(kind, theme.ACCENT_2)
        self.setStyleSheet(
            f"QFrame#Toast {{ background: {theme.SURFACE_2};"
            f" border: 1px solid {theme.BORDER_ACTIVE}; border-radius: {theme.RADIUS_L}px; }}"
        )
        row = QHBoxLayout()
        row.setContentsMargins(12, 11, 16, 11)
        row.setSpacing(12)
        glyph = QLabel()
        glyph.setFixedSize(30, 30)
        glyph.setAlignment(Qt.AlignCenter)
        tint = QColor(color)
        glyph.setStyleSheet(
            f"background: rgba({tint.red()}, {tint.green()}, {tint.blue()}, 0.14);"
            f" border-radius: 15px;")
        glyph.setPixmap(lucide.pixmap(icon or KIND_ICONS.get(kind, "info"), color, 16))
        row.addWidget(glyph, 0, Qt.AlignVCenter)
        texts = QVBoxLayout()
        texts.setSpacing(2)
        head = QLabel(title)
        head.setObjectName("ToastTitle")
        texts.addWidget(head)
        if message:
            body = QLabel(message)
            body.setObjectName("Muted")
            body.setWordWrap(True)
            texts.addWidget(body)
        row.addLayout(texts, 1)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addLayout(row)
        self.countdown = _CountdownBar(countdown, color, self) if countdown else None
        if self.countdown:
            layout.addWidget(self.countdown)
        self.adjustSize()

    def clear_effect(self) -> None:
        self.setGraphicsEffect(None)


class ToastManager(QObject):
    """Empile les notifications dans le coin inférieur droit de `host`."""

    def __init__(self, host: QWidget) -> None:
        super().__init__(host)
        self._host = host
        self._toasts: list[Toast] = []
        host.installEventFilter(self)

    def show(self, title: str, message: str = "", kind: str = "info",
             icon: str | None = None, duration: float = 3.5,
             countdown: float | None = None) -> Toast:
        toast = Toast(self._host, title, message, kind, icon, countdown)
        self._toasts.insert(0, toast)
        toast.show()
        toast.raise_()
        self._layout(animate_new=toast)
        # Minuteur rattaché à la notification : il disparaît avec elle.
        timer = QTimer(toast)
        timer.setSingleShot(True)
        timer.timeout.connect(lambda: self.dismiss(toast))
        timer.start(int((countdown or duration) * 1000))
        return toast

    def clear(self) -> None:
        for toast in list(self._toasts):
            self._remove(toast)

    def dismiss(self, toast: Toast) -> None:
        if toast not in self._toasts or not shiboken6.isValid(toast):
            return
        if not effects.animations_enabled():
            self._remove(toast)
            return
        # Sortie vers la droite en fondu.
        effect = QGraphicsOpacityEffect(toast)
        toast.setGraphicsEffect(effect)
        fade = QPropertyAnimation(effect, b"opacity", toast)
        fade.setDuration(theme.DURATION_BASE)
        fade.setStartValue(1.0)
        fade.setEndValue(0.0)
        fade.finished.connect(lambda: self._remove(toast))
        fade.start(QPropertyAnimation.DeleteWhenStopped)
        slide = QPropertyAnimation(toast, b"pos", toast)
        slide.setDuration(theme.DURATION_BASE)
        slide.setEndValue(toast.pos() + QPoint(30, 0))
        slide.setEasingCurve(QEasingCurve.InCubic)
        slide.start(QPropertyAnimation.DeleteWhenStopped)

    def active_titles(self) -> list[str]:
        return [t.findChild(QLabel, "ToastTitle").text() for t in self._toasts]

    def _remove(self, toast: Toast) -> None:
        if toast in self._toasts:
            self._toasts.remove(toast)
            toast.hide()
            toast.deleteLater()
            self._layout()

    def _target_positions(self) -> list[QPoint]:
        positions = []
        y = self._host.height() - _MARGIN
        status = getattr(self._host, "statusBar", None)
        if callable(status) and status().isVisible():
            y -= status().height()
        for toast in self._toasts:
            y -= toast.height()
            positions.append(QPoint(self._host.width() - _WIDTH - _MARGIN, y))
            y -= _SPACING
        return positions

    def _layout(self, animate_new: Toast | None = None) -> None:
        # Chaque animation appartient à SA notification (parent = toast) : si la
        # notification est supprimée en cours d'animation (ex. verrouillage),
        # l'animation disparaît avec elle au lieu de viser un objet détruit.
        for toast, target in zip(self._toasts, self._target_positions(), strict=True):
            if not effects.animations_enabled():
                toast.move(target)
                toast.raise_()
                continue
            if toast is animate_new:
                toast.move(target + QPoint(30, 0))
                effect = QGraphicsOpacityEffect(toast)
                toast.setGraphicsEffect(effect)
                fade = QPropertyAnimation(effect, b"opacity", toast)
                fade.setDuration(theme.DURATION_BASE)
                fade.setStartValue(0.0)
                fade.setEndValue(1.0)
                fade.finished.connect(toast.clear_effect)
                fade.start(QPropertyAnimation.DeleteWhenStopped)
            slide = QPropertyAnimation(toast, b"pos", toast)
            slide.setDuration(theme.DURATION_BASE)
            slide.setEndValue(target)
            slide.setEasingCurve(QEasingCurve.OutCubic)
            slide.start(QPropertyAnimation.DeleteWhenStopped)
            toast.raise_()

    def eventFilter(self, obj, event) -> bool:
        if obj is self._host and event.type() == QEvent.Resize:
            for toast, target in zip(self._toasts, self._target_positions(), strict=True):
                toast.move(target)
        return False
