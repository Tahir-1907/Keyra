"""Command palette (Ctrl+K): every action and entry, from the keyboard.

Borderless floating window, animated (fade + slide), with instant search that
ignores case and accents. ↑/↓ to choose, Enter to run, Esc to close. Shows no
secret: only action and entry names.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from PySide6.QtCore import QEasingCurve, QEvent, QPoint, QPropertyAnimation, QSize, Qt, QTimer
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QGraphicsOpacityEffect,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.core.entries import normalize_for_search
from app.i18n import tr
from app.ui import effects, lucide, theme

_MAX_VISIBLE = 9


@dataclass
class Command:
    label: str
    callback: Callable[[], None]
    hint: str = ""        # shortcut or category shown on the right
    icon: str | None = None
    keywords: str = ""
    group: str = ""  # translated group title; empty = "Actions"
    _search: str = field(default="", init=False, repr=False)

    def __post_init__(self) -> None:
        self.group = self.group or tr("action_group.actions")
        self._search = normalize_for_search(" ".join((self.label, self.keywords, self.group)))


class CommandPalette(QDialog):
    def __init__(self, parent: QWidget, commands: list[Command]) -> None:
        super().__init__(parent, Qt.FramelessWindowHint | Qt.Popup)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self._commands = commands
        self.executed: Command | None = None

        frame = QFrame(self)
        frame.setObjectName("Palette")
        self.input = QLineEdit()
        self.input.setObjectName("PaletteInput")
        self.input.setPlaceholderText(tr("palette.placeholder"))
        self.input.addAction(lucide.icon("command", theme.TEXT_3), QLineEdit.LeadingPosition)
        self.input.textChanged.connect(self._refresh)
        self.input.installEventFilter(self)
        self.results = QListWidget()
        self.results.setObjectName("PaletteList")
        self.results.setIconSize(QSize(18, 18))
        self.results.itemActivated.connect(lambda item: self._run(item))
        self.results.itemClicked.connect(lambda item: self._run(item))
        self.footer = QLabel(tr("palette.footer"))
        self.footer.setObjectName("PaletteFooter")

        inner = QVBoxLayout(frame)
        inner.setContentsMargins(10, 10, 10, 8)
        inner.setSpacing(8)
        inner.addWidget(self.input)
        inner.addWidget(self.results)
        inner.addWidget(self.footer)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(frame)
        self.setFixedWidth(min(640, max(420, parent.width() - 120)))
        self._refresh("")

    # --- Animated display ----------------------------------------------------------------

    def popup(self) -> None:
        parent = self.parentWidget()
        top_left = parent.mapToGlobal(QPoint((parent.width() - self.width()) // 2, 70))
        self.move(top_left)
        self.show()
        self.input.setFocus()
        if effects.animations_enabled():
            effect = QGraphicsOpacityEffect(self)
            self.setGraphicsEffect(effect)
            fade = QPropertyAnimation(effect, b"opacity", self)
            fade.setDuration(170)
            fade.setStartValue(0.0)
            fade.setEndValue(1.0)
            fade.finished.connect(lambda: self.setGraphicsEffect(None))
            fade.start(QPropertyAnimation.DeleteWhenStopped)
            slide = QPropertyAnimation(self, b"pos", self)
            slide.setDuration(200)
            slide.setStartValue(top_left - QPoint(0, 14))
            slide.setEndValue(top_left)
            slide.setEasingCurve(QEasingCurve.OutCubic)
            slide.start(QPropertyAnimation.DeleteWhenStopped)

    # --- Filtering -------------------------------------------------------------------------

    def matching(self, text: str) -> list[Command]:
        terms = normalize_for_search(text).split()
        return [c for c in self._commands if all(t in c._search for t in terms)]

    def _refresh(self, text: str) -> None:
        self.results.clear()
        last_group = None
        for command in self.matching(text):
            if command.group != last_group:
                header = QListWidgetItem(command.group.upper())
                header.setFlags(Qt.NoItemFlags)
                self.results.addItem(header)
                last_group = command.group
            label = f"{command.label}"
            icon = lucide.icon(command.icon, theme.TEXT_2) if command.icon else QIcon()
            item = QListWidgetItem(icon, label)
            item.setData(Qt.UserRole, command)
            item.setToolTip(command.hint)
            if command.hint:
                item.setText(f"{label}\t{command.hint}")
            self.results.addItem(item)
        if self.results.count() == 0:
            empty = QListWidgetItem(tr("palette.no_results"))
            empty.setFlags(Qt.NoItemFlags)
            self.results.addItem(empty)
        self._select_first()
        rows = min(self.results.count(), _MAX_VISIBLE)
        self.results.setFixedHeight(max(rows, 1) * 34 + 6)
        self.adjustSize()

    def _select_first(self) -> None:
        for i in range(self.results.count()):
            if self.results.item(i).flags() & Qt.ItemIsEnabled:
                self.results.setCurrentRow(i)
                return

    def _move_selection(self, step: int) -> None:
        row = self.results.currentRow()
        for _ in range(self.results.count()):
            row = (row + step) % self.results.count()
            if self.results.item(row).flags() & Qt.ItemIsEnabled:
                self.results.setCurrentRow(row)
                return

    def eventFilter(self, obj, event) -> bool:
        if obj is self.input and event.type() == QEvent.KeyPress:
            if event.key() == Qt.Key_Down:
                self._move_selection(1)
                return True
            if event.key() == Qt.Key_Up:
                self._move_selection(-1)
                return True
            if event.key() in (Qt.Key_Return, Qt.Key_Enter):
                self._run(self.results.currentItem())
                return True
        return super().eventFilter(obj, event)

    def _run(self, item: QListWidgetItem | None) -> None:
        command = item.data(Qt.UserRole) if item is not None else None
        if not isinstance(command, Command):
            return
        self.executed = command
        self.accept()
        # Run after closing (the command may open a dialog).
        QTimer.singleShot(0, command.callback)
