"""Previous versions of an entry: view, copy, restore (modal)."""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QListWidget, QListWidgetItem, QVBoxLayout, QWidget

from app.core.entries import EntryService, HistoryVersion
from app.core.exceptions import EntryError
from app.i18n import tr
from app.ui import components as ui
from app.ui import dialogs
from app.ui.detail_panel import DetailPanel
from app.ui.dialogs import PremiumDialog
from app.ui.secure_clipboard import SecureClipboard

_VERSION_ROLE = Qt.UserRole + 1


def _when(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return iso


class HistoryDialog(PremiumDialog):
    def __init__(self, service: EntryService, entry_id: int, clipboard: SecureClipboard,
                 category_names: dict[int, str], parent: QWidget | None = None) -> None:
        super().__init__(parent, tr("history_dialog.title"),
                         tr("history_dialog.subtitle"),
                         icon="history", width=900)
        self._service = service
        self._entry_id = entry_id
        self._category_names = category_names
        self.changed = False
        self._versions: dict[int, HistoryVersion] = {}

        self.versions = QListWidget()
        self.versions.setFixedWidth(270)
        self.versions.currentItemChanged.connect(self._on_version_changed)
        self.detail = DetailPanel(mode=DetailPanel.MODE_READONLY)
        self.detail.setMinimumHeight(430)
        self.detail.copy_requested.connect(
            lambda value, lbl, sensitive: clipboard.copy(value, lbl, sensitive))
        row = QHBoxLayout()
        row.setSpacing(16)
        left = QVBoxLayout()
        left.addWidget(ui.label(tr("history_dialog.versions"), "Overline"))
        left.addWidget(self.versions, 1)
        row.addLayout(left)
        row.addWidget(self.detail, 1)
        self.body.addLayout(row)

        buttons = QHBoxLayout()
        buttons.addWidget(ui.button(tr("history_dialog.clear"), "trash-2", "Danger",
                                    tr("history_dialog.clear.tooltip"),
                                    self._clear))
        buttons.addStretch(1)
        buttons.addWidget(ui.button(tr("common.close"), kind="Ghost", on_click=self.accept))
        self.restore_button = ui.button(tr("history_dialog.restore"), "rotate-ccw", "Primary",
                                        on_click=self._restore)
        buttons.addWidget(self.restore_button)
        self.card_layout.addLayout(buttons)
        self._load()

    def _load(self) -> None:
        self.versions.clear()
        self._versions.clear()
        try:
            versions = self._service.list_history(self._entry_id)
        except EntryError as exc:
            self.detail.show_error(str(exc))
            self.restore_button.setEnabled(False)
            return
        for version in versions:
            changed = (", ".join(version.changed) if version.changed
                       else tr("history_dialog.no_change"))
            item = QListWidgetItem(f"{_when(version.replaced_at)}\n{changed}")
            item.setData(_VERSION_ROLE, version.id)
            self.versions.addItem(item)
            self._versions[version.id] = version
        if versions:
            self.versions.setCurrentRow(0)
        else:
            self.detail.show_error(tr("history_dialog.none"))
        self.restore_button.setEnabled(bool(versions))

    def _current(self) -> HistoryVersion | None:
        item = self.versions.currentItem()
        return self._versions.get(item.data(_VERSION_ROLE)) if item else None

    def _on_version_changed(self, *_args) -> None:
        version = self._current()
        if version is None:
            self.detail.clear()
            return
        category = self._category_names.get(version.entry.category_id, "")
        self.detail.show_entry(version.entry, category)

    def _restore(self) -> None:
        version = self._current()
        if version is None or not dialogs.confirm(
                self, tr("history_dialog.restore.title"),
                tr("history_dialog.restore.text",
                   date=_when(version.replaced_at)), tr("backups.restore"),
                icon="rotate-ccw"):
            return
        try:
            self._service.restore_version(version.id)
        except EntryError as exc:
            dialogs.alert(self, tr("restore.impossible"), str(exc))
            return
        self.changed = True
        self.accept()

    def _clear(self) -> None:
        if dialogs.confirm(self, tr("history_dialog.clear.title"),
                           tr("history_dialog.clear.text"),
                           tr("history_dialog.clear"), danger=True, icon="trash-2"):
            self._service.clear_history(self._entry_id)
            self.changed = True
            self._load()

    def done(self, result: int) -> None:
        self.detail.clear()
        self._versions.clear()
        super().done(result)
