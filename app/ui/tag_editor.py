"""Tags: chip editor (entry window) and badges (details panel).

No rule is defined here: all validation goes through
app.core.metadata.normalize_tags, the source of truth (case, accents, logical
duplicates, length, number, forbidden characters). The service validates again
when saving anyway.
"""

from __future__ import annotations

from PySide6.QtCore import QPoint, QRect, QSize, QStringListModel, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QCompleter,
    QLayout,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
    QWidgetItem,
)

from app.core.exceptions import EntryValidationError
from app.core.metadata import normalize_tags
from app.i18n import tr
from app.ui import components as ui
from app.ui import lucide, theme


class FlowLayout(QLayout):
    """Left-aligned items, wrapping when width runs out."""

    def __init__(self, parent: QWidget | None = None, spacing: int = 6) -> None:
        super().__init__(parent)
        self._items: list[QWidgetItem] = []
        self.setContentsMargins(0, 0, 0, 0)
        self.setSpacing(spacing)

    def addItem(self, item) -> None:
        self._items.append(item)

    def count(self) -> int:
        return len(self._items)

    def itemAt(self, index: int):
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index: int):
        return self._items.pop(index) if 0 <= index < len(self._items) else None

    def expandingDirections(self):
        return Qt.Orientations(0)

    def hasHeightForWidth(self) -> bool:
        return True

    def heightForWidth(self, width: int) -> int:
        return self._arrange(QRect(0, 0, width, 0), apply=False)

    def setGeometry(self, rect: QRect) -> None:
        super().setGeometry(rect)
        self._arrange(rect, apply=True)

    def sizeHint(self) -> QSize:
        return self.minimumSize()

    def minimumSize(self) -> QSize:
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        return size

    def _arrange(self, rect: QRect, apply: bool) -> int:
        x, y, line_height = rect.x(), rect.y(), 0
        gap = self.spacing()
        for item in self._items:
            hint = item.sizeHint()
            width = min(hint.width(), rect.width()) if rect.width() > 0 else hint.width()
            if x > rect.x() and x + width > rect.right() + 1:
                x, y = rect.x(), y + line_height + gap
                line_height = 0
            if apply:
                item.setGeometry(QRect(QPoint(x, y), QSize(width, hint.height())))
            x += width + gap
            line_height = max(line_height, hint.height())
        return y + line_height - rect.y()


_CHIP_STYLE = (
    f"QPushButton#TagChip {{ background: {theme.ACCENT_SOFT}; color: {theme.TEXT};"
    f" border: 1px solid {theme.ACCENT_LINE}; border-radius: 11px; padding: 2px 10px;"
    f" font-size: {theme.SIZE_SMALL}px; }}"
    f"QPushButton#TagChip:hover {{ border-color: {theme.ACCENT}; }}"
)


def tag_chip(tag: str, tooltip: str, removable: bool = False) -> QPushButton:
    """Clickable tag chip (removal in the editor, search in the details)."""
    chip = QPushButton(tag)
    chip.setObjectName("TagChip")
    chip.setStyleSheet(_CHIP_STYLE)
    chip.setCursor(Qt.PointingHandCursor)
    chip.setToolTip(tooltip)
    chip.setFocusPolicy(Qt.TabFocus)
    if removable:
        chip.setIcon(lucide.icon("x", theme.TEXT_2, 12))
        chip.setIconSize(QSize(12, 12))
        chip.setLayoutDirection(Qt.RightToLeft)  # cross after the text
    return chip


class _TagInput(QLineEdit):
    """Enter: accepts the typed tag. Empty field: Enter keeps its role (save)."""

    commit = Signal()

    def keyPressEvent(self, event) -> None:
        if event.key() in (Qt.Key_Return, Qt.Key_Enter) and self.text().strip():
            popup = self.completer().popup() if self.completer() else None
            if popup is None or not popup.isVisible():
                self.commit.emit()
                event.accept()
                return
        super().keyPressEvent(event)


class TagEditor(QWidget):
    """List of tag chips + input field (Enter or comma to add)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._tags: list[str] = []
        self._completion_text = ""
        self._completion_timer = QTimer(self)
        self._completion_timer.setSingleShot(True)
        self._completion_timer.setInterval(0)
        self._completion_timer.timeout.connect(self._apply_completion)
        self._chips = QWidget()
        self._flow = FlowLayout(self._chips)
        self.input = _TagInput()
        self.input.setPlaceholderText(tr("tags.placeholder"))
        self.input.commit.connect(self._commit_input)
        self.input.textChanged.connect(self._on_text_changed)
        self._model = QStringListModel(self)
        completer = QCompleter(self._model, self)
        completer.setCaseSensitivity(Qt.CaseInsensitive)
        completer.setFilterMode(Qt.MatchContains)
        completer.activated.connect(self._on_completion)
        self.input.setCompleter(completer)
        self.error = ui.label("", "Error", wrap=True)
        self.error.hide()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        layout.addWidget(self._chips)
        layout.addWidget(self.input)
        layout.addWidget(self.error)
        self._rebuild()

    # --- API ------------------------------------------------------------------------

    def tags(self) -> tuple[str, ...]:
        return tuple(self._tags)

    def set_tags(self, tags) -> None:
        self._tags = list(tags)
        self._set_error("")
        self._rebuild()

    def pending_tags(self) -> list[str]:
        """Tags + typed text not yet accepted (the service will accept or reject it)."""
        pending = self.input.text().strip()
        return [*self._tags, pending] if pending else list(self._tags)

    def add_text(self, value: str) -> bool:
        """Adds a tag; False (message shown) if normalize_tags rejects it."""
        try:
            self._tags = list(normalize_tags([*self._tags, value]))
        except EntryValidationError as exc:
            self._set_error(str(exc))
            return False
        self._set_error("")
        self._rebuild()
        return True

    def remove_tag(self, tag: str) -> None:
        if tag in self._tags:
            self._tags.remove(tag)
            self._set_error("")
            self._rebuild()

    def set_suggestions(self, tags) -> None:
        self._model.setStringList(list(tags))

    def completer_model_strings(self) -> list[str]:
        return self._model.stringList()

    def chip_buttons(self) -> list[QPushButton]:
        return [self._flow.itemAt(i).widget() for i in range(self._flow.count())]

    def error_text(self) -> str:
        return self.error.text() if not self.error.isHidden() else ""

    # --- Internal --------------------------------------------------------------------

    def _set_error(self, message: str) -> None:
        self.error.setText(message)
        self.error.setVisible(bool(message))

    def _rebuild(self) -> None:
        while self._flow.count():
            item = self._flow.takeAt(0)
            item.widget().deleteLater()
        for tag in self._tags:
            chip = tag_chip(tag, tr("tags.remove", tag=tag), removable=True)
            chip.clicked.connect(lambda _checked=False, t=tag: self.remove_tag(t))
            self._flow.addWidget(chip)
        self._chips.setVisible(bool(self._tags))
        self._flow.invalidate()

    def _commit_input(self) -> None:
        if self.add_text(self.input.text()):
            self.input.clear()

    def _on_text_changed(self, text: str) -> None:
        if "," not in text:
            return
        *complete, rest = text.split(",")
        for index, part in enumerate(complete):
            if part.strip() and not self.add_text(part):
                # Rejected: the unprocessed text stays in the field, to be corrected.
                remaining = ",".join([part, *complete[index + 1:], rest])
                self._replace_text(remaining.lstrip())
                return
        self._replace_text(rest.lstrip())

    def _replace_text(self, text: str) -> None:
        self.input.blockSignals(True)
        self.input.setText(text)
        self.input.blockSignals(False)

    def _on_completion(self, text: str) -> None:
        # The completer rewrites the field after this signal: validate on the next turn.
        # Timer owned by the editor: destroyed with it, never called afterwards.
        self._completion_text = text
        self._completion_timer.start()

    def _apply_completion(self) -> None:
        if self.add_text(self._completion_text):
            self.input.clear()
