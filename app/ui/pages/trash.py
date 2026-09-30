"""The "Trash" view: deleted entries, restore, permanent deletion."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QStackedWidget, QVBoxLayout

from app.core.entries import EntryFilter
from app.core.exceptions import EntryError
from app.ui import components as ui
from app.ui import dialogs, theme
from app.ui.detail_panel import DetailPanel
from app.ui.entry_list import EntryListView
from app.ui.pages.base import AppContext, Page

_IRREVERSIBLE = "I understand that this action cannot be undone"


class TrashPage(Page):
    key = "trash"
    title = "Trash"
    subtitle = "Deleted entries, restorable"
    icon = "trash-2"

    def __init__(self, ctx: AppContext) -> None:
        super().__init__(ctx)
        banner = ui.card("CardDanger")
        banner_row = QHBoxLayout(banner)
        banner_row.setContentsMargins(16, 12, 16, 12)
        banner_row.setSpacing(12)
        banner_row.addWidget(ui.icon_label("trash-2", theme.DANGER, 20))
        texts = QVBoxLayout()
        texts.setSpacing(2)
        self.summary = ui.label("", "H2")
        self.retention = ui.label("", "Faint", wrap=True)
        texts.addWidget(self.summary)
        texts.addWidget(self.retention)
        banner_row.addLayout(texts, 1)
        self.empty_button = ui.button("Empty Trash", "trash-2", "Danger",
                                      on_click=self.empty_trash)
        banner_row.addWidget(self.empty_button, 0, Qt.AlignVCenter)

        self.list = EntryListView(trash_mode=True)
        self.list.entry_selected.connect(self._on_selected)
        self.empty = ui.EmptyState("trash-2", "The Trash is empty",
                                   "Deleted entries stay here before being permanently "
                                   "erased.")
        self.stack = QStackedWidget()
        self.stack.addWidget(self.list)
        self.stack.addWidget(self.empty)

        left = QVBoxLayout()
        left.setSpacing(14)
        left.addWidget(banner)
        left.addWidget(self.stack, 1)

        self.detail = DetailPanel(mode=DetailPanel.MODE_TRASH)
        self.detail.setMinimumWidth(theme.DETAIL_MIN_WIDTH)
        self.detail.setMaximumWidth(theme.DETAIL_MAX_WIDTH)
        self.detail.restore_requested.connect(self.restore)
        self.detail.purge_requested.connect(self.purge)
        self.detail.copy_requested.connect(
            lambda value, lbl, sensitive: self.ctx.clipboard.copy(value, lbl, sensitive))

        body = QHBoxLayout(self)
        body.setContentsMargins(28, 22, 24, 24)
        body.setSpacing(20)
        body.addLayout(left, 3)
        body.addWidget(self.detail, 2)

    def refresh(self) -> None:
        if self.ctx.vault.is_locked:
            return
        rows = self.ctx.entries.list_entries(EntryFilter(in_trash=True))
        self.list.set_entries(rows)
        count = len(rows)
        self.summary.setText(f"{count} item{'s' if count > 1 else ''}")
        days = self.ctx.settings().trash_retention_days
        self.retention.setText(
            f"Permanently deleted after {days} days." if days else
            "Kept until the Trash is emptied manually.")
        self.empty_button.setEnabled(count > 0)
        self.stack.setCurrentWidget(self.list if rows else self.empty)
        self.detail.clear()

    def _on_selected(self, entry_id) -> None:
        if entry_id is None:
            self.detail.clear()
            return
        try:
            entry = self.ctx.entries.get_entry(entry_id, include_deleted=True)
        except EntryError as exc:
            self.detail.show_error(str(exc))
            return
        summary = self.list.selected_summary()
        self.detail.show_entry(entry, summary.category_name if summary else "")

    def restore(self, entry_id: int) -> None:
        try:
            self.ctx.entries.restore_entry(entry_id)
        except EntryError as exc:
            dialogs.alert(self, "Restore impossible", str(exc))
            return
        self.list.animate_removal(entry_id, self._after_change)
        self.ctx.notify("Entry restored", "It is back in the vault.",
                        icon="archive-restore")

    def purge(self, entry_id: int) -> None:
        summary = self.list.selected_summary()
        name = summary.service_name if summary else "this entry"
        if not dialogs.confirm(self, f"Permanently delete {name}?",
                               "The entry and its whole history (old passwords "
                               "included) will be erased. It can no longer be restored, "
                               "except from a backup.",
                               "Delete permanently", danger=True, icon="trash-2",
                               acknowledge=_IRREVERSIBLE):
            return

        def remove() -> None:
            try:
                self.ctx.entries.delete_permanently(entry_id)
            except EntryError as exc:
                dialogs.alert(self, "Deletion impossible", str(exc))
                return
            self._after_change()
            self.ctx.notify("Permanently deleted", name, icon="trash-2")

        self.list.animate_removal(entry_id, remove)

    def empty_trash(self) -> None:
        count = self.ctx.entries.trash_count()
        if not count or not dialogs.confirm(
                self, "Empty the Trash?",
                f"The {count} entry(ies) in the Trash and their history will be permanently "
                "erased.", "Empty Trash", danger=True, icon="trash-2",
                acknowledge=_IRREVERSIBLE):
            return
        removed = self.ctx.entries.empty_trash()
        self._after_change()
        self.ctx.notify("Trash emptied", f"{removed} entry(ies) erased.", icon="trash-2")

    def _after_change(self) -> None:
        self.refresh()
        self.ctx.changed()

    def wipe(self) -> None:
        self.detail.clear()
        self.list.set_entries([], animate=False)
