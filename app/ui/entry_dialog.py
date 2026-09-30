"""Form to create / edit an entry (premium modal).

The form is derived from `app.core.entries.ENTRY_TYPES` (no hard-coded type
or field); validation and saving are delegated to `EntryService`.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QGridLayout,
    QHBoxLayout,
    QLineEdit,
    QPlainTextEdit,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from app.core.categories import Category
from app.core.entries import DEFAULT_ENTRY_TYPE, ENTRY_TYPES, Entry, EntryService
from app.core.exceptions import EntryError
from app.core.strength import estimate_strength
from app.i18n import tr
from app.services.settings import Settings
from app.ui import components as ui
from app.ui.dialogs import PremiumDialog
from app.ui.fields import PasswordField
from app.ui.generator_dialog import GeneratorDialog
from app.ui.secure_clipboard import SecureClipboard
from app.ui.tag_editor import TagEditor


def _field(title: str, widget: QWidget) -> QWidget:
    host = QWidget()
    layout = QVBoxLayout(host)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(6)
    host.caption = ui.label(title, "FieldLabel")
    layout.addWidget(host.caption)
    layout.addWidget(widget)
    return host


class EntryDialog(PremiumDialog):
    def __init__(self, service: EntryService, categories: list[Category],
                 clipboard: SecureClipboard, entry: Entry | None = None,
                 settings: Settings | None = None, default_category_id: int | None = None,
                 parent: QWidget | None = None) -> None:
        editing = entry is not None
        super().__init__(parent, tr("action.edit_entry") if editing else tr("action.new_entry"),
                         tr("entry_dialog.subtitle"),
                         icon="square-pen" if editing else "plus", width=560)
        self._service = service
        self._clipboard = clipboard
        self._settings = settings
        self._entry = entry
        self.saved_entry_id: int | None = None

        form = QWidget()
        grid = QGridLayout(form)
        grid.setContentsMargins(0, 0, 8, 0)
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(14)

        self.type_combo = QComboBox()
        for spec in ENTRY_TYPES.values():
            self.type_combo.addItem(spec.label, spec.key)
        self.type_combo.setEnabled(not editing)  # the type is fixed after creation
        self.category = QComboBox()
        self.category.addItem(tr("entry_dialog.no_category"), None)
        for cat in categories:
            self.category.addItem(cat.name, cat.id)
        grid.addWidget(_field(tr("field.type"), self.type_combo), 0, 0)
        grid.addWidget(_field(tr("field.category"), self.category), 0, 1)

        self.name = QLineEdit()
        self.name.setPlaceholderText(tr("entry_dialog.name_placeholder"))
        grid.addWidget(_field(tr("entry_dialog.name_required"), self.name), 1, 0, 1, 2)
        self.favorite = ui.ToggleSwitch(tr("entry_dialog.favorite"))
        grid.addWidget(self.favorite, 2, 0, 1, 2)

        self.url = QLineEdit()
        self.url.setPlaceholderText("https://…")
        self.username = QLineEdit()
        self.email = QLineEdit()
        self._url_row = _field(tr("field.url"), self.url)
        self._username_row = _field(tr("field.username"), self.username)
        self._email_row = _field(tr("field.email"), self.email)
        grid.addWidget(self._url_row, 3, 0, 1, 2)
        grid.addWidget(self._username_row, 4, 0)
        grid.addWidget(self._email_row, 4, 1)

        self.password = PasswordField()
        generate = ui.icon_button("wand-sparkles", tr("dashboard.generate"), "",
                                  self._open_generator)
        line = QHBoxLayout()
        line.setSpacing(6)
        line.addWidget(self.password, 1)
        line.addWidget(generate)
        password_host = QWidget()
        password_layout = QVBoxLayout(password_host)
        password_layout.setContentsMargins(0, 0, 0, 0)
        password_layout.setSpacing(6)
        password_layout.addLayout(line)
        self.strength = ui.StrengthBar()
        self.strength_label = ui.label("", "Faint")
        password_layout.addWidget(self.strength)
        password_layout.addWidget(self.strength_label)
        self._password_row = _field(tr("field.password"), password_host)
        self.password.textChanged.connect(self._update_strength)
        grid.addWidget(self._password_row, 5, 0, 1, 2)

        # Type-specific fields of every type; only those of the current type are visible.
        self._extra_widgets: dict[tuple[str, str], QLineEdit] = {}
        self._extra_rows: dict[tuple[str, str], QWidget] = {}
        row = 6
        for spec in ENTRY_TYPES.values():
            for index, field_spec in enumerate(spec.extra_fields):
                widget = PasswordField() if field_spec.secret else QLineEdit()
                host = _field(field_spec.label, widget)
                self._extra_widgets[(spec.key, field_spec.key)] = widget
                self._extra_rows[(spec.key, field_spec.key)] = host
                grid.addWidget(host, row + index // 2, index % 2)
            row += (len(spec.extra_fields) + 1) // 2

        self.notes = QPlainTextEdit()
        self.notes.setPlaceholderText(tr("entry_dialog.notes_placeholder"))
        self.notes.setFixedHeight(90)
        grid.addWidget(_field(tr("field.notes"), self.notes), row, 0, 1, 2)

        self.tags = TagEditor()
        self.tags.set_suggestions(service.all_tags())
        grid.addWidget(_field(tr("field.tags"), self.tags), row + 1, 0, 1, 2)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(form)
        scroll.setMinimumHeight(430)
        self.body.addWidget(scroll)
        self.error = ui.label("", "Error", wrap=True)
        self.error.hide()
        self.body.addWidget(self.error)
        _, save = self.add_buttons(tr("common.cancel"), tr("common.save"), confirm_icon="check")
        save.clicked.connect(self._save)

        self.type_combo.currentIndexChanged.connect(self._apply_type_visibility)
        if entry is not None:
            self._load(entry)
        else:
            self.category.setCurrentIndex(max(self.category.findData(default_category_id), 0))
        self._apply_type_visibility()
        self.name.setFocus()

    # --- Helpers ------------------------------------------------------------------------------

    def _current_type(self) -> str:
        return self.type_combo.currentData() or DEFAULT_ENTRY_TYPE

    def _apply_type_visibility(self) -> None:
        spec = ENTRY_TYPES[self._current_type()]
        self._url_row.setVisible(spec.uses_url)
        self._username_row.setVisible(spec.uses_username)
        self._email_row.setVisible(spec.uses_email)
        self._password_row.setVisible(spec.uses_password)
        self._password_row.caption.setText(spec.password_label)
        for (type_key, _field_key), host in self._extra_rows.items():
            host.setVisible(type_key == spec.key)

    def _update_strength(self, text: str) -> None:
        if not text:
            self.strength.set_score(-1, 0)
            self.strength_label.setText("")
            return
        result = estimate_strength(text)
        self.strength.set_score(result.score, result.entropy_bits)
        advice = f" — {result.warnings[0]}" if result.warnings else ""
        self.strength_label.setText(tr("strength.summary", label=result.label,
                                       bits=f"{result.entropy_bits:.0f}") + advice)

    def _open_generator(self) -> None:
        dialog = GeneratorDialog(self._clipboard, use_mode=True, parent=self,
                                 settings=self._settings)
        if dialog.exec() and dialog.chosen_value:
            self.password.setText(dialog.chosen_value)
            self.password.set_revealed(True)

    def _load(self, entry: Entry) -> None:
        self.type_combo.setCurrentIndex(max(self.type_combo.findData(entry.entry_type), 0))
        self.name.setText(entry.service_name)
        self.category.setCurrentIndex(max(self.category.findData(entry.category_id), 0))
        self.favorite.setChecked(entry.is_favorite)
        self.url.setText(entry.url)
        self.username.setText(entry.username)
        self.email.setText(entry.email)
        self.password.setText(entry.password)
        self.notes.setPlainText(entry.notes)
        self.tags.set_tags(entry.tags)
        for (type_key, field_key), widget in self._extra_widgets.items():
            if type_key == entry.entry_type:
                widget.setText(entry.extra.get(field_key, ""))

    def _collect(self) -> Entry:
        entry_type = self._current_type()
        extra = {field_key: widget.text()
                 for (type_key, field_key), widget in self._extra_widgets.items()
                 if type_key == entry_type and widget.text()}
        return Entry(
            id=self._entry.id if self._entry else None, entry_type=entry_type,
            service_name=self.name.text(), url=self.url.text(), username=self.username.text(),
            email=self.email.text(), password=self.password.text(),
            notes=self.notes.toPlainText(), extra=extra,
            category_id=self.category.currentData(), is_favorite=self.favorite.isChecked(),
            # Text typed without pressing Enter is included: the service validates or rejects it.
            tags=tuple(self.tags.pending_tags()),
        )

    def _save(self) -> None:
        entry = self._collect()
        try:
            if entry.id is None:
                self.saved_entry_id = self._service.create_entry(entry)
            else:
                self._service.update_entry(entry)
                self.saved_entry_id = entry.id
        except EntryError as exc:
            self.error.setText(str(exc))
            self.error.show()
            return
        self.accept()

    def done(self, result: int) -> None:
        # Leave no secrets in the widgets after closing.
        self.password.clear()
        self.notes.clear()
        for widget in self._extra_widgets.values():
            widget.clear()
        super().done(result)
