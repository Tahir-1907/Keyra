"""Interface animations — fast, directional, subtle.

Principles (design system, see theme.DURATION_*):
* 150-320 ms, "OutCubic" curves: nothing slow, nothing bouncy;
* meaningful motion: a next view comes in from the right, a previous view
  from the left; a deleted entry leaves towards the left;
* an animation NEVER delays the real state of the interface (the new view is
  shown immediately; a capture of the old one fades out on top of it);
* everything can be turned off (Settings → Interface → Animations): the final
  state is then applied instantly.
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import (
    QAbstractAnimation,
    QEasingCurve,
    QElapsedTimer,
    QObject,
    QPoint,
    QPropertyAnimation,
    QRectF,
    QSequentialAnimationGroup,
    Qt,
    QTimer,
    QVariantAnimation,
)
from PySide6.QtGui import QColor, QPainter, QPen, QPixmap
from PySide6.QtWidgets import (
    QGraphicsBlurEffect,
    QGraphicsOpacityEffect,
    QGraphicsPixmapItem,
    QGraphicsScene,
    QLabel,
    QStackedWidget,
    QWidget,
)

from app.ui import theme

_enabled = True


def set_animations_enabled(enabled: bool) -> None:
    global _enabled
    _enabled = enabled


def animations_enabled() -> bool:
    return _enabled


def _running(widget: QWidget, target, prop: bytes) -> list[QPropertyAnimation]:
    """Animations of `widget` still running on property `prop` of `target`."""
    return [a for a in widget.findChildren(QPropertyAnimation)
            if a.targetObject() is target and a.propertyName() == prop
            and a.state() == QAbstractAnimation.Running]


def _opacity(widget: QWidget, start: float, end: float, duration: int,
             on_done: Callable[[], None] | None = None,
             curve: QEasingCurve.Type = QEasingCurve.OutCubic) -> QPropertyAnimation:
    # A new fade-in replaces the previous one: without this stop, the end of the
    # old animation would remove the effect of the new one mid-fade.
    previous = widget.graphicsEffect()
    if previous is not None:
        for running in _running(widget, previous, b"opacity"):
            running.stop()
    effect = QGraphicsOpacityEffect(widget)
    effect.setOpacity(start)
    widget.setGraphicsEffect(effect)
    animation = QPropertyAnimation(effect, b"opacity", widget)
    animation.setDuration(duration)
    animation.setStartValue(start)
    animation.setEndValue(end)
    animation.setEasingCurve(curve)

    def finished() -> None:
        # An effect left in place slows rendering and blocks child effects.
        if end >= 1.0:
            widget.setGraphicsEffect(None)
        if on_done:
            on_done()

    animation.finished.connect(finished)
    animation.start(QAbstractAnimation.DeleteWhenStopped)
    return animation


# --- Appearances -------------------------------------------------------------------------------


def fade_in(widget: QWidget, duration: int = theme.DURATION_BASE) -> None:
    if _enabled and widget.isVisible():
        _opacity(widget, 0.0, 1.0, duration)


def slide_in(widget: QWidget, dx: int = theme.SLIDE_DISTANCE, dy: int = 0,
             duration: int = theme.DURATION_BASE) -> None:
    """Entrance: offset (dx, dy) + transparency → final position and opacity."""
    if not _enabled or not widget.isVisible():
        return
    end = widget.pos()
    # Restarted while still sliding (slider moved quickly…): start again from the
    # FINAL position of the previous one, otherwise the widget drifts out of place.
    for running in _running(widget, widget, b"pos"):
        end = running.endValue()
        running.stop()
    slide = QPropertyAnimation(widget, b"pos", widget)
    slide.setDuration(duration)
    slide.setStartValue(end + QPoint(dx, dy))
    slide.setEndValue(end)
    slide.setEasingCurve(QEasingCurve.OutCubic)
    slide.start(QAbstractAnimation.DeleteWhenStopped)
    _opacity(widget, 0.0, 1.0, duration)


def switch_page(stack: QStackedWidget, page: QWidget, direction: int = 1,
                duration: int = theme.DURATION_BASE) -> None:
    """Switches view: the new one comes in from the right (direction=1) or the left (-1)."""
    current = stack.currentWidget()
    if not _enabled or current is None or current is page or not stack.isVisible():
        stack.setCurrentWidget(page)
        return
    snapshot = QLabel(stack)
    snapshot.setPixmap(current.grab())
    snapshot.setGeometry(stack.rect())
    stack.setCurrentWidget(page)
    snapshot.show()
    snapshot.raise_()
    # The old view fades out quickly while moving back slightly; the new one slides in.
    retreat = QPropertyAnimation(snapshot, b"pos", snapshot)
    retreat.setDuration(theme.DURATION_FAST)
    retreat.setEndValue(QPoint(-direction * theme.SLIDE_DISTANCE // 2, 0))
    retreat.start(QAbstractAnimation.DeleteWhenStopped)
    _opacity(snapshot, 1.0, 0.0, theme.DURATION_FAST, snapshot.deleteLater, QEasingCurve.InQuad)
    slide_in(page, direction * theme.SLIDE_DISTANCE, 0, duration)
    page.raise_()
    snapshot.raise_()


def _blurred(pixmap: QPixmap, radius: int = 18) -> QPixmap:
    """Blurred version of a capture (computed only once, off-screen)."""
    scene = QGraphicsScene()
    item = QGraphicsPixmapItem(pixmap)
    blur = QGraphicsBlurEffect()
    blur.setBlurRadius(radius)
    blur.setBlurHints(QGraphicsBlurEffect.PerformanceHint)
    item.setGraphicsEffect(blur)
    scene.addItem(item)
    result = QPixmap(pixmap.size())
    result.fill(QColor(theme.BG))
    painter = QPainter(result)
    scene.render(painter, QRectF(result.rect()), QRectF(pixmap.rect()))
    painter.end()
    result.setDevicePixelRatio(pixmap.devicePixelRatio())
    return result


class _ProtectOverlay(QWidget):
    """Capture of the interface: sharp → blurred → transparent."""

    def __init__(self, host: QWidget) -> None:
        super().__init__(host)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self._sharp = host.grab()
        self._blurred = _blurred(self._sharp)
        self._t = 0.0
        self.setGeometry(host.rect())
        animation = QVariantAnimation(self)
        animation.setDuration(theme.DURATION_SLOW + 80)
        animation.setStartValue(0.0)
        animation.setEndValue(1.0)
        animation.setEasingCurve(QEasingCurve.InOutQuad)
        animation.valueChanged.connect(self._set_t)
        animation.finished.connect(self.deleteLater)
        self._animation = animation

    def start(self) -> None:
        self.show()
        self.raise_()
        self._animation.start()

    def _set_t(self, value: float) -> None:
        self._t = value
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        t = self._t
        if t < 0.45:  # sharpness fades
            painter.drawPixmap(0, 0, self._blurred)
            painter.setOpacity(1 - t / 0.45)
            painter.drawPixmap(0, 0, self._sharp)
        else:         # then the blurred interface fades out over the lock screen
            painter.setOpacity(max(0.0, 1 - (t - 0.45) / 0.55))
            painter.drawPixmap(0, 0, self._blurred)


def protect_transition(host: QWidget, change: Callable[[], None]) -> None:
    """Locking: the interface blurs, then fades out above the lock screen."""
    if not _enabled or not host.isVisible():
        change()
        return
    overlay = _ProtectOverlay(host)
    change()
    overlay.start()


def shake(widget: QWidget, amplitude: int = 8) -> None:
    if not _enabled:
        return
    origin = widget.pos()
    group = QSequentialAnimationGroup(widget)
    for dx in (amplitude, -amplitude, amplitude * 0.5, -amplitude * 0.5, 0):
        step = QPropertyAnimation(widget, b"pos")
        step.setDuration(45)
        step.setEndValue(origin + QPoint(int(dx), 0))
        group.addAnimation(step)
    group.finished.connect(lambda: widget.move(origin))
    group.start(QAbstractAnimation.DeleteWhenStopped)


def count_up(label: QLabel, target: int, duration: int = theme.DURATION_SLOW + 200,
             fmt: Callable[[int], str] = str) -> None:
    """Number that counts up from 0 to `target` (overview statistics)."""
    if not _enabled or target <= 0:
        label.setText(fmt(target))
        return
    animation = QVariantAnimation(label)
    animation.setDuration(duration)
    animation.setStartValue(0)
    animation.setEndValue(target)
    animation.setEasingCurve(QEasingCurve.OutCubic)
    animation.valueChanged.connect(lambda v: label.setText(fmt(int(v))))
    animation.finished.connect(lambda: label.setText(fmt(target)))
    animation.start(QAbstractAnimation.DeleteWhenStopped)


def stagger(widgets: list[QWidget], dy: int = 8, step: int = theme.STAGGER_STEP) -> None:
    """Staggered appearance of a series of widgets (0, 30, 60, 90 ms…)."""
    for index, widget in enumerate(widgets):
        if not _enabled:
            return
        QTimer.singleShot(index * step, lambda w=widget: slide_in(w, 0, dy, theme.DURATION_BASE))


class Stagger(QObject):
    """Staggered appearance clock for a list painted by a delegate.

    `progress(row)` goes from 0 → 1 for each row, with `STAGGER_STEP` ms between
    rows; the delegate uses it for opacity and offset.
    """

    def __init__(self, viewport: QWidget) -> None:
        super().__init__(viewport)
        self._viewport = viewport
        self._clock = QElapsedTimer()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._rows = 0

    def start(self, rows: int) -> None:
        self._rows = min(rows, 14)  # beyond the visible screen: no waiting
        if not _enabled or rows == 0:
            self._timer.stop()
            return
        self._clock.start()
        self._timer.start(16)

    def progress(self, row: int) -> float:
        if not self._timer.isActive():
            return 1.0
        local = self._clock.elapsed() - min(row, self._rows) * theme.STAGGER_STEP
        return max(0.0, min(1.0, local / theme.DURATION_BASE))

    def _tick(self) -> None:
        if self._clock.elapsed() > self._rows * theme.STAGGER_STEP + theme.DURATION_BASE:
            self._timer.stop()
        self._viewport.update()


# --- Indicators ---------------------------------------------------------------------------


class Spinner(QWidget):
    """Rotating arc (activity in progress, e.g. Argon2id derivation)."""

    def __init__(self, size: int = 18, color: str = theme.ACCENT_2,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(size, size)
        self._color = color
        self._angle = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._advance)

    def start(self) -> None:
        self.show()
        self._timer.start(16)

    def stop(self) -> None:
        self._timer.stop()
        self.hide()

    def _advance(self) -> None:
        self._angle = (self._angle + 7) % 360
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(2, 2, -2, -2)
        painter.setPen(QPen(QColor(theme.BORDER_ACTIVE), 2))
        painter.drawEllipse(rect)
        pen = QPen(QColor(self._color), 2)
        pen.setCapStyle(Qt.RoundCap)
        painter.setPen(pen)
        painter.drawArc(rect, -self._angle * 16, 110 * 16)
