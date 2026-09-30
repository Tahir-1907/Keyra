"""Details panel of an entry (Vault, Trash, history versions).

Slides in from the right on every selection. Secrets are hidden by default;
"show" reveals them with a simple fade (150 ms) — never an animation that
would expose the secret longer than necessary. Copying goes through the
`copy_requested` signal (secure clipboard handled by the caller) and the
button icon turns into ✓.
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QScrollArea,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from app.core.entries import ENTRY_TYPES, Entry, tag_search_query
from app.core.strength import estimate_strength
from app.i18n import tr, tr_n
from app.ui import components as ui
from app.ui import effects, theme
from app.ui.entry_list import domain_of
from app.ui.tag_editor import FlowLayout, tag_chip

_MASK = "•" * 14


def _format_date(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError):
        return iso


class _FieldBox(QFrame):
    """Value in a rounded box, followed by its action buttons."""

    def __init__(self, value: str, secret: bool, mono: bool = False) -> None:
        super().__init__()
        self.setObjectName("FieldBox")
        self.setStyleSheet(
            f"QFrame#FieldBox {{ background: {theme.BG_2}; border: 1px solid {theme.BORDER};"
            f" border-radius: {theme.RADIUS_M}px; }}")
        self.real_value = value
        self.secret = secret
        self.revealed = False
        row = QHBoxLayout(self)
        row.setContentsMargins(12, 4, 4, 4)
        row.setSpacing(2)
        # Long value: wraps anywhere, never widens the panel (the Show / Copy
        # buttons always stay visible). No mouse selection: it would copy the
        # invisible break points; copying goes through the button, which copies
        # the exact value.
        self.value = QLabel(_MASK if secret else ui.breakable(value))
        self.value.setMinimumHeight(30)
        self.value.setMinimumWidth(40)
        self.value.setWordWrap(True)
        self.value.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        if mono or secret:
            self.value.setFont(theme.mono_font(theme.SIZE_BODY))
        row.addWidget(self.value, 1)
        self.actions = row

    def add(self, widget: QWidget) -> None:
        self.actions.addWidget(widget)

    def set_revealed(self, revealed: bool) -> None:
        self.revealed = revealed
        self.value.setText(ui.breakable(self.real_value) if revealed else _MASK)
        effects.fade_in(self.value, theme.DURATION_FAST)


class DetailPanel(QFrame):
    MODE_NORMAL, MODE_TRASH, MODE_READONLY = "normal", "trash", "readonly"

    edit_requested = Signal(int)
    delete_requested = Signal(int)
    history_requested = Signal(int)
    duplicate_requested = Signal(int)
    restore_requested = Signal(int)
    purge_requested = Signal(int)
    favorite_toggled = Signal(int, bool)
    copy_requested = Signal(str, str, bool)  # value, label, sensitive
    tag_clicked = Signal(str)  # tag of a badge ("Vault" view only)

    def __init__(self, parent: QWidget | None = None, mode: str = MODE_NORMAL) -> None:
        super().__init__(parent)
        self.setObjectName("Surface")
        self._mode = mode
        self._entry: Entry | None = None
        self._secret_boxes: list[_FieldBox] = []
        self._tag_widgets: list[QWidget] = []

        self.placeholder = ui.EmptyState(
            "key-round", tr("detail.placeholder"),
            tr("detail.placeholder.text"))
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.content = QWidget()
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(22, 22, 22, 22)
        self.content_layout.setSpacing(14)
        self.scroll.setWidget(self.content)

        self.footer = QHBoxLayout()
        self.footer.setContentsMargins(22, 0, 22, 18)
        self.footer.setSpacing(8)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.placeholder, 1)
        layout.addWidget(self.scroll, 1)
        layout.addLayout(self.footer)
        self.clear()

    # --- API --------------------------------------------------------------------------------

    def set_mode(self, mode: str) -> None:
        self._mode = mode

    def current_entry_id(self) -> int | None:
        return self._entry.id if self._entry else None

    def tag_widgets(self) -> list[QWidget]:
        """Displayed tag badges (buttons in the "Vault" view, labels elsewhere)."""
        return list(self._tag_widgets)

    def clear(self) -> None:
        """Clears every displayed value (empty selection, locking)."""
        self._entry = None
        self._secret_boxes = []
        self._tag_widgets = []
        self._clear_layout(self.content_layout)
        self._clear_layout(self.footer)
        self.scroll.hide()
        self.placeholder.set_text(tr("detail.placeholder"), tr("detail.placeholder.text"))
        self.placeholder.show()

    def show_error(self, message: str) -> None:
        self.clear()
        self.placeholder.set_text(tr("detail.unreadable"), message)

    def set_favorite_state(self, is_favorite: bool) -> None:
        if self._entry is not None:
            self._entry.is_favorite = is_favorite
            self._favorite.setIcon(self._star_icon(is_favorite))

    def show_entry(self, entry: Entry, category_name: str, history_count: int = 0) -> None:
        self.clear()
        self._entry = entry
        spec = ENTRY_TYPES[entry.entry_type]
        layout = self.content_layout

        # Header: avatar, name, domain, favorite, edit.
        header = QHBoxLayout()
        header.setSpacing(14)
        header.addWidget(ui.Avatar(entry.service_name, 48), 0, Qt.AlignTop)
        titles = QVBoxLayout()
        titles.setSpacing(2)
        name = ui.label(entry.service_name, "H2", wrap=True)
        name.setFont(theme.font(19, name.font().weight()))
        name.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        titles.addWidget(name)
        subtitle = ui.label(ui.breakable(domain_of(entry.url) or spec.label), "Muted", wrap=True)
        subtitle.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        titles.addWidget(subtitle)
        header.addLayout(titles, 1)
        if self._mode == self.MODE_NORMAL:
            self._favorite = ui.icon_button(
                "star",
                tr("detail.favorite.remove") if entry.is_favorite else tr("detail.favorite.add"),
                on_click=lambda: self.favorite_toggled.emit(entry.id, not entry.is_favorite))
            self._favorite.setIcon(self._star_icon(entry.is_favorite))
            header.addWidget(self._favorite, 0, Qt.AlignTop)
            header.addWidget(ui.icon_button("square-pen", tr("detail.edit"), "Ctrl+E",
                                            lambda: self.edit_requested.emit(entry.id)),
                             0, Qt.AlignTop)
        layout.addLayout(header)

        badges = QHBoxLayout()
        badges.setSpacing(6)
        badges.addWidget(ui.label(spec.label, "Badge"))
        badges.addWidget(ui.label(category_name or tr("pdf.uncategorized"), "Badge"))
        if entry.deleted_at:
            badges.addWidget(ui.label(tr("detail.in_trash"), "BadgeDanger"))
        badges.addStretch(1)
        layout.addLayout(badges)
        if entry.tags:
            layout.addWidget(self._tags_row(entry.tags))
        layout.addWidget(ui.divider())

        if spec.uses_username:
            self._field(tr("field.username"), entry.username, copy_label=tr("field.username"),
                        sensitive=False)
        if spec.uses_email:
            self._field(tr("field.email"), entry.email, copy_label=tr("field.email"))
        if spec.uses_password:
            box = self._field(spec.password_label, entry.password, secret=True,
                              copy_label=spec.password_label)
            if box is not None:
                self._strength(entry.password)
        for field_spec in spec.extra_fields:
            self._field(field_spec.label, entry.extra.get(field_spec.key, ""),
                        secret=field_spec.secret, copy_label=field_spec.label,
                        sensitive=field_spec.secret)
        if spec.uses_url and entry.url:
            box = self._field(tr("field.url"), entry.url, copy_label=tr("field.url"),
                              sensitive=False)
            if box is not None:
                box.add(ui.icon_button(
                    "external-link", tr("detail.open_browser"), size=16,
                    on_click=lambda: QDesktopServices.openUrl(QUrl(
                        entry.url if "://" in entry.url else f"https://{entry.url}"))))
        if entry.notes:
            layout.addWidget(ui.label(tr("field.notes"), "FieldLabel"))
            notes = QPlainTextEdit(entry.notes)
            notes.setReadOnly(True)
            notes.setMinimumHeight(70)
            notes.setMaximumHeight(170)
            layout.addWidget(notes)

        meta = []
        if entry.created_at:
            meta.append(tr("detail.meta.created", date=_format_date(entry.created_at)))
        if entry.updated_at:
            meta.append(tr("detail.meta.modified", date=_format_date(entry.updated_at)))
        if spec.uses_password and entry.password and entry.password_changed_at:
            meta.append(tr("detail.meta.password_changed",
                           date=_format_date(entry.password_changed_at)))
        if entry.deleted_at:
            meta.append(tr("detail.meta.deleted", date=_format_date(entry.deleted_at)))
        layout.addWidget(ui.label(" · ".join(meta), "Faint", wrap=True))
        layout.addStretch(1)

        self._build_footer(entry, history_count)
        self.placeholder.hide()
        self.scroll.show()
        effects.slide_in(self.content, theme.SLIDE_DISTANCE, 0, theme.DURATION_BASE)

    def hide_secrets(self) -> None:
        for box in self._secret_boxes:
            if box.revealed:
                box.set_revealed(False)

    def secret_buttons(self, index: int = 0):
        """(Show button, Copy button) of the n-th secret field (tests, accessibility)."""
        box = self._secret_boxes[index]
        widgets = [box.actions.itemAt(i).widget() for i in range(box.actions.count())]
        buttons = [w for w in widgets if isinstance(w, QToolButton)]
        return buttons[0], buttons[1]

    # --- Construction -------------------------------------------------------------------------

    def _tags_row(self, tags: tuple[str, ...]) -> QWidget:
        host = QWidget()
        flow = FlowLayout(host)
        for tag in tags:
            if self._mode == self.MODE_NORMAL:  # click: search for this tag
                widget = tag_chip(tag, tr("detail.search_tag", query=tag_search_query(tag)))
                widget.clicked.connect(lambda _checked=False, t=tag: self.tag_clicked.emit(t))
            else:  # Trash, history: plain label
                widget = ui.label(tag, "Badge")
            flow.addWidget(widget)
            self._tag_widgets.append(widget)
        return host

    def _field(self, title: str, value: str, secret: bool = False, copy_label: str = "",
               sensitive: bool = True) -> _FieldBox | None:
        if not value:
            return None
        self.content_layout.addWidget(ui.label(title, "FieldLabel"))
        box = _FieldBox(value, secret)
        if secret:
            # Secret field: clearly visible "Show" / "Copy" labeled buttons.
            eye = ui.icon_button("eye", tr("detail.show_field", field=title), size=16)
            eye.setText(tr("common.show"))
            eye.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)

            def toggle(_checked=False, b=box, e=eye) -> None:
                b.set_revealed(not b.revealed)
                e.setIcon(ui.lucide.icon("eye-off" if b.revealed else "eye", theme.TEXT_2, 16))
                e.setText(tr("common.hide") if b.revealed else tr("common.show"))

            eye.clicked.connect(toggle)
            box.add(eye)
            self._secret_boxes.append(box)
        copy = ui.CopyButton(tr("detail.copy_field", field=copy_label or title), labeled=secret)

        def do_copy(_checked=False, b=box, c=copy) -> None:
            self.copy_requested.emit(b.real_value, copy_label or title, sensitive)
            c.confirm()

        copy.clicked.connect(do_copy)
        box.add(copy)
        self.content_layout.addWidget(box)
        return box

    def _strength(self, password: str) -> None:
        result = estimate_strength(password)
        row = QHBoxLayout()
        row.addWidget(ui.label(tr("detail.strength"), "FieldLabel"))
        row.addStretch(1)
        row.addWidget(ui.label(tr("strength.summary", label=result.label,
                                  bits=f"{result.entropy_bits:.0f}"), "Faint"))
        self.content_layout.addLayout(row)
        bar = ui.StrengthBar()
        self.content_layout.addWidget(bar)
        bar.set_score(result.score, result.entropy_bits)

    def _build_footer(self, entry: Entry, history_count: int) -> None:
        if self._mode == self.MODE_NORMAL:
            history = ui.icon_button("history", tr_n("detail.history.count", history_count)
                                     if history_count else tr("detail.history.none"),
                                     on_click=lambda: self.history_requested.emit(entry.id))
            if history_count:
                history.setText(str(history_count))
                history.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
            history.setEnabled(history_count > 0)
            self.footer.addWidget(history)
            self.footer.addWidget(ui.icon_button("copy-plus", tr("detail.duplicate"), "Ctrl+D",
                                                 lambda: self.duplicate_requested.emit(entry.id)))
            self.footer.addStretch(1)
            self.footer.addWidget(ui.button(tr("common.delete"), "trash-2", "Danger", tooltip="Del",
                                            on_click=lambda: self.delete_requested.emit(entry.id)))
        elif self._mode == self.MODE_TRASH:
            self.footer.addWidget(ui.button(tr("backups.restore"), "archive-restore", "Primary",
                                            on_click=lambda: self.restore_requested.emit(entry.id)))
            self.footer.addStretch(1)
            self.footer.addWidget(ui.button(tr("delete_vault.submit"), "trash-2", "Danger",
                                            on_click=lambda: self.purge_requested.emit(entry.id)))

    @staticmethod
    def _star_icon(active: bool):
        return ui.lucide.icon("star", theme.WARNING if active else theme.TEXT_2, 18)

    @staticmethod
    def _clear_layout(layout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            if item.widget() is not None:
                item.widget().deleteLater()
            elif item.layout() is not None:
                DetailPanel._clear_layout(item.layout())
