"""Reusable visual components (the design system applied).

No domain logic: these widgets display the values they are given. Every
color and dimension comes from `theme`, and every animation honors the global
switch of `effects`.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Callable

from PySide6.QtCore import (
    Property,
    QEasingCurve,
    QElapsedTimer,
    QPointF,
    QPropertyAnimation,
    QRectF,
    QSize,
    Qt,
    QTimer,
    QVariantAnimation,
    Signal,
)
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QRadialGradient,
)
from PySide6.QtWidgets import (
    QAbstractButton,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from app.ui import effects, icons, lucide, theme

# --- Basic building blocks ------------------------------------------------------------------------


def card(kind: str = "Card", parent: QWidget | None = None) -> QFrame:
    frame = QFrame(parent)
    frame.setObjectName(kind)
    return frame


def divider() -> QFrame:
    line = QFrame()
    line.setObjectName("Divider")
    return line


def label(text: str = "", kind: str | None = None, wrap: bool = False) -> QLabel:
    widget = QLabel(text)
    if kind:
        widget.setObjectName(kind)
    widget.setWordWrap(wrap)
    return widget


_ZWSP = "\u200b"  # zero-width space: invisible break point


def breakable(text: str) -> str:
    """Text that may wrap anywhere (long password, URL, email).

    Display only: never copy this text (use the original value).
    """
    return _ZWSP.join(text)


def button(text: str, icon: str | None = None, kind: str | None = None,
           tooltip: str = "", on_click: Callable[[], None] | None = None) -> QPushButton:
    """Standard button. kind ∈ {None, "Primary", "Danger", "Ghost", "Chip"}."""
    widget = QPushButton(text)
    if kind:
        widget.setObjectName(kind)
    if icon:
        color = {"Primary": "#03130C", "Danger": theme.DANGER}.get(kind or "", theme.TEXT_2)
        widget.setIcon(lucide.icon(icon, color, 16))
        widget.setIconSize(QSize(16, 16))
    if tooltip:
        widget.setToolTip(tooltip)
    widget.setCursor(Qt.PointingHandCursor)
    if on_click:
        widget.clicked.connect(lambda _checked=False: on_click())
    return widget


def icon_button(icon: str, tooltip: str, shortcut: str = "",
                on_click: Callable[[], None] | None = None, size: int = 18,
                color: str = theme.TEXT_2) -> QToolButton:
    """Icon button with a tooltip (and the shortcut shown)."""
    widget = QToolButton()
    widget.setIcon(lucide.icon(icon, color, size))
    widget.setIconSize(QSize(size, size))
    widget.setToolTip(f"{tooltip}  ·  {shortcut}" if shortcut else tooltip)
    widget.setAccessibleName(tooltip)
    widget.setCursor(Qt.PointingHandCursor)
    if on_click:
        widget.clicked.connect(lambda _checked=False: on_click())
    return widget


def icon_label(icon: str, color: str = theme.TEXT_2, size: int = 18) -> QLabel:
    widget = QLabel()
    widget.setPixmap(lucide.pixmap(icon, color, size))
    widget.setFixedSize(size, size)
    return widget


def brand_label(size: int = 22) -> QLabel:
    """Brand symbol (logo), distinct from the functional Lucide icons."""
    widget = QLabel()
    widget.setPixmap(icons.brand_pixmap(size))
    widget.setFixedSize(size, size)
    widget.setAccessibleName("Keyra")
    return widget


# --- Avatar (monogram) -------------------------------------------------------------------------


def avatar_color(name: str) -> str:
    # Stable color choice from the name: no security role.
    digest = hashlib.sha1(name.strip().lower().encode("utf-8"), usedforsecurity=False).digest()
    return theme.AVATAR_COLORS[digest[0] % len(theme.AVATAR_COLORS)]


def paint_avatar(painter: QPainter, rect: QRectF, name: str, font_size: int = 14) -> None:
    """Tinted rounded square + initial (used by the painted lists and Avatar)."""
    color = QColor(avatar_color(name))
    background = QColor(color)
    background.setAlpha(38)
    border = QColor(color)
    border.setAlpha(90)
    painter.save()
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setPen(QPen(border, 1))
    painter.setBrush(background)
    painter.drawRoundedRect(rect.adjusted(0.5, 0.5, -0.5, -0.5), rect.width() * 0.28,
                            rect.width() * 0.28)
    painter.setPen(color.lighter(135))
    painter.setFont(theme.font(font_size, QFont.DemiBold))
    initial = (name.strip()[:1] or "?").upper()
    painter.drawText(rect, Qt.AlignCenter, initial)
    painter.restore()


class Avatar(QWidget):
    def __init__(self, name: str = "", size: int = 40, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._name = name
        self.setFixedSize(size, size)

    def set_name(self, name: str) -> None:
        self._name = name
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        paint_avatar(painter, QRectF(self.rect()), self._name, int(self.height() * 0.4))


# --- Statistic ---------------------------------------------------------------------------------


class StatCard(QFrame):
    """Statistics card: icon, large counting number, label, detail."""

    clicked = Signal()

    def __init__(self, title: str, icon: str, color: str = theme.TEXT_2,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(118)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(6)
        top = QHBoxLayout()
        caption = label(title.upper(), "Overline")
        top.addWidget(caption)
        top.addStretch(1)
        top.addWidget(icon_label(icon, color, 18))
        layout.addLayout(top)
        self.value = QLabel("0")
        self.value.setFont(theme.font(theme.SIZE_DISPLAY + 2, QFont.DemiBold, display=True))
        layout.addWidget(self.value)
        self.hint = label("", "Faint", wrap=True)
        layout.addWidget(self.hint)
        layout.addStretch(1)

    def set_value(self, value: int, hint: str = "") -> None:
        self.hint.setText(hint)
        effects.count_up(self.value, value)

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mouseReleaseEvent(event)


# --- Score ring -----------------------------------------------------------------------------


class ScoreRing(QWidget):
    """Animated circular gauge 0 → score (out of 100)."""

    def __init__(self, size: int = 188, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(size, size)
        self._shown = 0.0
        self._score = 0
        self._animation = QVariantAnimation(self)
        self._animation.setDuration(900)
        self._animation.setEasingCurve(QEasingCurve.OutCubic)
        self._animation.valueChanged.connect(self._on_value)

    def set_score(self, score: int) -> None:
        self._score = max(0, min(100, score))
        if not effects.animations_enabled():
            self._shown = float(self._score)
            self.update()
            return
        self._animation.stop()
        self._animation.setStartValue(0.0)
        self._animation.setEndValue(float(self._score))
        self._animation.start()

    def color(self) -> QColor:
        if self._score >= 80:
            return QColor(theme.ACCENT)
        if self._score >= 50:
            return QColor(theme.WARNING)
        return QColor(theme.DANGER)

    def _on_value(self, value) -> None:
        self._shown = float(value)
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        stroke = 12
        rect = QRectF(self.rect()).adjusted(stroke, stroke, -stroke, -stroke)
        glow = QRadialGradient(rect.center(), rect.width() * 0.62)
        halo = self.color()
        halo.setAlpha(28)
        glow.setColorAt(0.55, halo)
        glow.setColorAt(1.0, QColor(0, 0, 0, 0))
        painter.setPen(Qt.NoPen)
        painter.setBrush(glow)
        painter.drawEllipse(rect.adjusted(-stroke, -stroke, stroke, stroke))
        painter.setBrush(Qt.NoBrush)
        painter.setPen(QPen(QColor(theme.BORDER), stroke, Qt.SolidLine, Qt.RoundCap))
        painter.drawArc(rect, 0, 360 * 16)
        pen = QPen(self.color(), stroke, Qt.SolidLine, Qt.RoundCap)
        painter.setPen(pen)
        painter.drawArc(rect, 90 * 16, int(-360 * 16 * self._shown / 100))
        painter.setPen(QColor(theme.TEXT))
        painter.setFont(theme.font(46, QFont.DemiBold, display=True))
        painter.drawText(rect.adjusted(0, -14, 0, -14), Qt.AlignCenter, f"{round(self._shown)}")
        painter.setPen(QColor(theme.TEXT_3))
        painter.setFont(theme.font(theme.SIZE_SMALL, QFont.Medium))
        painter.drawText(rect.adjusted(0, 44, 0, 44), Qt.AlignCenter, "/ 100")


# --- Empty states, skeletons ----------------------------------------------------------------------


class EmptyState(QWidget):
    """Never an empty page: icon in a halo, title, explanation, action."""

    def __init__(self, icon: str, title: str, text: str, action_text: str = "",
                 on_action: Callable[[], None] | None = None, action_icon: str = "plus",
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(10)
        layout.addStretch(1)
        self.halo = HaloIcon(icon, 72, animated=False)
        layout.addWidget(self.halo, 0, Qt.AlignHCenter)
        layout.addSpacing(6)
        self.title = label(title, "H2")
        self.title.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.title)
        self.text = label(text, "Muted", wrap=True)
        self.text.setAlignment(Qt.AlignCenter)
        # Width AND height enforced (adjusted to the available space): a word-wrapping
        # QLabel does not report its height to parent layouts on its own.
        self._fit_text(self._TEXT_MAX)
        layout.addWidget(self.text, 0, Qt.AlignHCenter)
        self.action = None
        if action_text and on_action:
            layout.addSpacing(8)
            self.action = button(action_text, action_icon, "Primary", on_click=on_action)
            layout.addWidget(self.action, 0, Qt.AlignHCenter)
        layout.addStretch(2)

    _TEXT_MIN, _TEXT_MAX = 180, 340

    def minimumSizeHint(self) -> QSize:
        # The text narrows: never enforce its current width (half the screen).
        hint = super().minimumSizeHint()
        return QSize(min(hint.width(), self._TEXT_MIN + 48), hint.height())

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._fit_text(event.size().width() - 48)

    def _fit_text(self, available: int) -> None:
        width = max(self._TEXT_MIN, min(self._TEXT_MAX, available))
        height = self.text.heightForWidth(width)
        if (width, height) != (self.text.width(), self.text.height()):
            self.text.setFixedSize(width, height)

    def set_text(self, title: str, text: str) -> None:
        self.title.setText(title)
        self.text.setText(text)
        self._fit_text(self.width() - 48 if self.isVisible() else self._TEXT_MAX)


class Skeleton(QWidget):
    """Grey lines with an animated sheen, while something is computed (audit…)."""

    def __init__(self, widths: tuple[float, ...] = (0.9, 0.6, 0.75), line_height: int = 12,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._widths = widths
        self._line = line_height
        self.setMinimumHeight(len(widths) * (line_height + 12))
        self._clock = QElapsedTimer()
        self._clock.start()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.update)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if effects.animations_enabled():
            self._timer.start(30)

    def hideEvent(self, event) -> None:
        super().hideEvent(event)
        self._timer.stop()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        phase = (self._clock.elapsed() % 1400) / 1400
        shine = QLinearGradient(0, 0, self.width(), 0)
        base = QColor(theme.SURFACE_3)
        light = QColor(theme.BORDER_ACTIVE)
        shine.setColorAt(max(0.0, phase - 0.2), base)
        shine.setColorAt(phase, light)
        shine.setColorAt(min(1.0, phase + 0.2), base)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(shine))
        y = 6
        for width in self._widths:
            painter.drawRoundedRect(QRectF(0, y, self.width() * width, self._line), 5, 5)
            y += self._line + 12


# --- Toggle switch --------------------------------------------------------------------------------


class ToggleSwitch(QAbstractButton):
    """Animated slider toggle (replaces check boxes in the settings)."""

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setCheckable(True)
        self.setText(text)
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.StrongFocus)
        self._offset = 0.0
        self._animation = QPropertyAnimation(self, b"offset", self)
        self._animation.setDuration(theme.DURATION_FAST)
        self._animation.setEasingCurve(QEasingCurve.OutCubic)
        self.toggled.connect(self._animate)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)

    def _get_offset(self) -> float:
        return self._offset

    def _set_offset(self, value: float) -> None:
        self._offset = value
        self.update()

    offset = Property(float, _get_offset, _set_offset)

    def setChecked(self, checked: bool) -> None:  # initial state: no animation
        super().setChecked(checked)
        self._animation.stop()
        self._offset = 1.0 if checked else 0.0
        self.update()

    def _animate(self, checked: bool) -> None:
        target = 1.0 if checked else 0.0
        if not effects.animations_enabled():
            self._set_offset(target)
            return
        self._animation.stop()
        self._animation.setStartValue(self._offset)
        self._animation.setEndValue(target)
        self._animation.start()

    def sizeHint(self) -> QSize:
        width = 40 + (self.fontMetrics().horizontalAdvance(self.text()) + 12 if self.text() else 0)
        return QSize(width, 26)

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        track = QRectF(0, 4, 36, 20)
        off, on = QColor(theme.BORDER_ACTIVE), QColor(theme.ACCENT)
        mix = QColor(
            int(off.red() + (on.red() - off.red()) * self._offset),
            int(off.green() + (on.green() - off.green()) * self._offset),
            int(off.blue() + (on.blue() - off.blue()) * self._offset),
        )
        painter.setPen(Qt.NoPen)
        painter.setBrush(mix if self.isEnabled() else QColor(theme.BORDER))
        painter.drawRoundedRect(track, 10, 10)
        knob_x = track.left() + 3 + self._offset * 16
        painter.setBrush(QColor(theme.TEXT))
        painter.drawEllipse(QRectF(knob_x, track.top() + 3, 14, 14))
        if self.hasFocus():
            painter.setPen(QPen(QColor(theme.ACCENT_2), 1))
            painter.setBrush(Qt.NoBrush)
            painter.drawRoundedRect(track.adjusted(-2, -2, 2, 2), 12, 12)
        if self.text():
            painter.setPen(QColor(theme.TEXT if self.isEnabled() else theme.TEXT_3))
            painter.setFont(self.font())
            painter.drawText(QRectF(48, 0, self.width() - 48, 28), Qt.AlignVCenter, self.text())


# --- Strength -----------------------------------------------------------------------------------

_STRENGTH_COLORS = (theme.DANGER, "#F97316", theme.WARNING, theme.ACCENT, theme.ACCENT_2)


class StrengthBar(QWidget):
    """Animated strength bar + text label (never color alone)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._ratio = 0.0
        self._score = -1
        self.setFixedHeight(6)
        self._animation = QVariantAnimation(self)
        self._animation.setDuration(theme.DURATION_SLOW)
        self._animation.setEasingCurve(QEasingCurve.OutCubic)
        self._animation.valueChanged.connect(self._on_value)

    def set_score(self, score: int, bits: float) -> None:
        """score 0-4; the length follows the entropy (capped at 128 bits)."""
        self._score = score
        target = 0.0 if score < 0 else max(0.06, min(1.0, bits / 128))
        if not effects.animations_enabled():
            self._on_value(target)
            return
        self._animation.stop()
        self._animation.setStartValue(self._ratio)
        self._animation.setEndValue(target)
        self._animation.start()

    def _on_value(self, value) -> None:
        self._ratio = float(value)
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(theme.BORDER))
        painter.drawRoundedRect(QRectF(self.rect()), 3, 3)
        if self._score >= 0 and self._ratio > 0:
            painter.setBrush(QColor(_STRENGTH_COLORS[self._score]))
            painter.drawRoundedRect(QRectF(0, 0, self.width() * self._ratio, self.height()), 3, 3)


# --- Copy button (copy icon → ✓) -----------------------------------------------------------


class CopyButton(QToolButton):
    """Copy button: after a click, the icon briefly becomes ✓ (and "Copied").

    `labeled=True` shows the text "Copy" next to the icon (secret fields).
    """

    def __init__(self, tooltip: str = "Copy", parent: QWidget | None = None,
                 labeled: bool = False) -> None:
        super().__init__(parent)
        self._labeled = labeled
        self.setIconSize(QSize(16, 16))
        self.setToolTip(tooltip)
        self.setAccessibleName(tooltip)
        self.setCursor(Qt.PointingHandCursor)
        if labeled:
            self.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self._restore = QTimer(self)
        self._restore.setSingleShot(True)
        self._restore.timeout.connect(self._reset)
        self._reset()

    def _reset(self) -> None:
        self.setIcon(lucide.icon("copy", theme.TEXT_2, 16))
        if self._labeled:
            self.setText("Copy")

    def confirm(self) -> None:
        self.setIcon(lucide.icon("check", theme.ACCENT_2, 16))
        if self._labeled:
            self.setText("Copied")
        self._restore.start(1400)


# --- Halo icon (lock screen, empty states) --------------------------------------------


BRAND = "brand"  # reserved name: HaloIcon(BRAND) shows the logo instead of a Lucide icon


class HaloIcon(QWidget):
    """Lucide icon (or the logo, with BRAND) in the middle of a halo, optionally "breathing"."""

    def __init__(self, icon: str, size: int = 120, color: str = theme.ACCENT_2,
                 animated: bool = True, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._icon = icon
        self._color = color
        self.setFixedSize(size, size)
        self._phase = 0.0
        self._clock = QElapsedTimer()
        self._clock.start()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._animated = animated

    def set_icon(self, icon: str, color: str | None = None) -> None:
        self._icon = icon
        self._color = color or self._color
        self.update()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if self._animated and effects.animations_enabled():
            self._timer.start(33)

    def hideEvent(self, event) -> None:
        super().hideEvent(event)
        self._timer.stop()

    def _tick(self) -> None:
        # Slow breathing (3.2 s) — the only continuous animation on screen.
        self._phase = (self._clock.elapsed() % 3200) / 3200
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        center = QPointF(self.width() / 2, self.height() / 2)
        radius = self.width() / 2
        breath = 0.5 + 0.5 * math.sin(self._phase * 2 * math.pi) if self._animated else 0.5
        glow = QRadialGradient(center, radius)
        tint = QColor(self._color)
        tint.setAlpha(int(34 + 30 * breath))
        glow.setColorAt(0.0, tint)
        glow.setColorAt(1.0, QColor(0, 0, 0, 0))
        painter.setPen(Qt.NoPen)
        painter.setBrush(glow)
        painter.drawEllipse(center, radius, radius)
        inner = radius * 0.52
        disc = QColor(theme.SURFACE_2)
        painter.setBrush(disc)
        ring = QColor(self._color)
        ring.setAlpha(int(70 + 50 * breath))
        painter.setPen(QPen(ring, 1.2))
        painter.drawEllipse(center, inner, inner)
        if self._icon == BRAND:
            icon_size = int(inner * 1.2)
            pixmap = icons.brand_pixmap(icon_size)
        else:
            icon_size = int(inner * 0.95)
            pixmap = lucide.pixmap(self._icon, self._color, icon_size, 1.6)
        painter.drawPixmap(int(center.x() - icon_size / 2), int(center.y() - icon_size / 2),
                           pixmap)


# --- Section title -----------------------------------------------------------------------------


def section(title: str, subtitle: str = "", trailing: QWidget | None = None) -> QWidget:
    host = QWidget()
    row = QHBoxLayout(host)
    row.setContentsMargins(0, 0, 0, 0)
    texts = QVBoxLayout()
    texts.setSpacing(2)
    texts.addWidget(label(title, "H2"))
    if subtitle:
        texts.addWidget(label(subtitle, "Faint", wrap=True))
    row.addLayout(texts, 1)
    if trailing is not None:
        row.addWidget(trailing, 0, Qt.AlignBottom)
    return host


def rounded_path(rect: QRectF, radius: float) -> QPainterPath:
    path = QPainterPath()
    path.addRoundedRect(rect, radius, radius)
    return path
