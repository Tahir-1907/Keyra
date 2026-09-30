"""The "Vault" view: filters, list of entry cards, details panel."""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QButtonGroup,
    QHBoxLayout,
    QMenu,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
)

from app.core.entries import ENTRY_TYPES, UNCATEGORIZED, EntryFilter
from app.core.exceptions import CategoryError, EntryError
from app.i18n import tr, tr_n
from app.ui import components as ui
from app.ui import dialogs, lucide, theme
from app.ui.detail_panel import DetailPanel
from app.ui.entry_dialog import EntryDialog
from app.ui.entry_list import EntryListView
from app.ui.history_dialog import HistoryDialog
from app.ui.pages.base import AppContext, Page

# Idle typing delay before the search is applied (one read instead of one per key).
SEARCH_DEBOUNCE_MS = 150


class VaultPage(Page):
    key = "vault"
    title_key = "page.vault.title"
    subtitle_key = "page.vault.subtitle"
    icon = "key-round"

    def __init__(self, ctx: AppContext) -> None:
        super().__init__(ctx)
        self._text = ""
        self._favorites_only = False
        self._category_id: int | None = None
        self._pending_text: str | None = None  # pending search (debounce)
        self._search_timer = QTimer(self)  # child of the page: destroyed with it
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(SEARCH_DEBOUNCE_MS)
        self._search_timer.timeout.connect(self._on_search_timeout)

        # --- Filter bar ---------------------------------------------------------
        self.all_chip = ui.button(tr("vault.filter.all"), kind="Chip")
        self.fav_chip = ui.button(tr("vault.filter.favorites"), "star", "Chip")
        for chip in (self.all_chip, self.fav_chip):
            chip.setCheckable(True)
        group = QButtonGroup(self)
        group.addButton(self.all_chip)
        group.addButton(self.fav_chip)
        self.all_chip.setChecked(True)
        self.all_chip.clicked.connect(lambda: self._set_favorites(False))
        self.fav_chip.clicked.connect(lambda: self._set_favorites(True))
        self.category_button = ui.button(tr("vault.filter.category_all"), "folder", "Chip")
        self.category_menu = QMenu(self.category_button)
        self.category_menu.aboutToShow.connect(self._fill_category_menu)
        self.category_button.setMenu(self.category_menu)
        self.count_label = ui.label("", "Faint")
        # The counter gives way when the window is narrow (half of the screen).
        self.count_label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.count_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        filters = QHBoxLayout()
        filters.setSpacing(8)
        filters.addWidget(self.all_chip)
        filters.addWidget(self.fav_chip)
        filters.addWidget(self.category_button)
        filters.addStretch(1)
        filters.addWidget(self.count_label)

        # --- List + empty states ------------------------------------------------------------
        self.list = EntryListView()
        self.list.entry_selected.connect(self._on_selected)
        self.list.favorite_clicked.connect(self._toggle_favorite_from_list)
        self.list.activated_entry.connect(self.edit_entry)
        self.empty = ui.EmptyState("key-round", tr("vault.empty.title"),
                                   tr("vault.empty.text"), tr("vault.empty.action"),
                                   self.new_entry)
        self.list_stack = QStackedWidget()
        self.list_stack.addWidget(self.list)
        self.list_stack.addWidget(self.empty)

        left = QVBoxLayout()
        left.setSpacing(14)
        left.addLayout(filters)
        left.addWidget(self.list_stack, 1)

        # --- Details ---------------------------------------------------------------------------
        self.detail = DetailPanel()
        self.detail.setMinimumWidth(theme.DETAIL_MIN_WIDTH)
        self.detail.setMaximumWidth(theme.DETAIL_MAX_WIDTH)
        self.detail.edit_requested.connect(self.edit_entry)
        self.detail.delete_requested.connect(self.delete_entry)
        self.detail.duplicate_requested.connect(self.duplicate_entry)
        self.detail.history_requested.connect(self.show_history)
        self.detail.favorite_toggled.connect(self.set_favorite)
        self.detail.copy_requested.connect(
            lambda value, lbl, sensitive: self.ctx.clipboard.copy(value, lbl, sensitive))

        body = QHBoxLayout(self)
        body.setContentsMargins(28, 22, 24, 24)
        body.setSpacing(20)
        body.addLayout(left, 3)
        body.addWidget(self.detail, 2)

    # --- Filters ----------------------------------------------------------------------------------

    def set_search(self, text: str) -> None:
        """Typing in the search: applied after SEARCH_DEBOUNCE_MS without a new
        keystroke (a single read of the list). Clearing the search is immediate."""
        if not text.strip():
            self._cancel_pending_search()
            self._apply_search(text)
            return
        self._pending_text = text
        self._search_timer.start()

    def apply_search_now(self) -> None:
        """Enter, click on a tag: applies the pending search right away."""
        if self._pending_text is not None:
            text = self._pending_text
            self._cancel_pending_search()
            self._apply_search(text)

    def has_pending_search(self) -> bool:
        return self._pending_text is not None

    def _cancel_pending_search(self) -> None:
        self._search_timer.stop()
        self._pending_text = None

    def _on_search_timeout(self) -> None:
        text = self._pending_text
        self._pending_text = None
        if text is not None:
            self._apply_search(text)

    def _apply_search(self, text: str) -> None:
        # Safeguard: never any access to the locked vault, whatever the order of the
        # events (delay expired during or after locking).
        if self.ctx.vault.is_locked:
            return
        if text != self._text:
            self._text = text
            self.refresh(animate=False)

    def _set_favorites(self, value: bool) -> None:
        self._favorites_only = value
        self.refresh()

    def _fill_category_menu(self) -> None:
        menu = self.category_menu
        menu.clear()
        overview = self.ctx.categories.overview()
        menu.addAction(lucide.icon("folder-open"),
                       tr("vault.category.all_count", count=overview.total),
                       lambda: self._set_category(None))
        menu.addSeparator()
        for cat in overview.categories:
            action = menu.addAction(lucide.icon("folder"), f"{cat.name}   ·  {cat.entry_count}",
                                    lambda c=cat.id: self._set_category(c))
            action.setCheckable(True)
            action.setChecked(cat.id == self._category_id)
        menu.addAction(lucide.icon("folder"),
                       tr("vault.category.none_count", count=overview.uncategorized),
                       lambda: self._set_category(UNCATEGORIZED))
        menu.addSeparator()
        menu.addAction(lucide.icon("plus"), tr("vault.category.new_menu"), self._create_category)
        current = next((c for c in overview.categories if c.id == self._category_id), None)
        if current is not None and not current.is_builtin:
            menu.addAction(lucide.icon("square-pen"),
                           tr("vault.category.rename_named", name=current.name),
                           lambda: self._rename_category(current.id, current.name))
            menu.addAction(lucide.icon("trash-2", theme.DANGER),
                           tr("vault.category.delete_named", name=current.name),
                           lambda: self._delete_category(current.id, current.name,
                                                         current.entry_count))

    def _set_category(self, category_id: int | None) -> None:
        self._category_id = category_id
        names = {c.id: c.name for c in self.ctx.categories.list_categories()}
        if category_id is None:
            self.category_button.setText(tr("vault.filter.category_all"))
        elif category_id == UNCATEGORIZED:
            self.category_button.setText(tr("vault.filter.category_none"))
        else:
            self.category_button.setText(tr("vault.filter.category_named",
                                            name=names.get(category_id, "")))
        self.category_button.setChecked(category_id is not None)
        self.refresh()

    def _filter(self) -> EntryFilter:
        return EntryFilter(text=self._text, favorites_only=self._favorites_only,
                           category_id=self._category_id)

    # --- Refresh ------------------------------------------------------------------------

    def refresh(self, animate: bool = True, select_id: int | None = None) -> None:
        keep = select_id if select_id is not None else self.detail.current_entry_id()
        rows = self.ctx.entries.list_entries(self._filter())
        self.list.set_entries(rows, animate=animate)
        self.count_label.setText(tr_n("vault.count", len(rows)))
        if rows:
            self.list_stack.setCurrentWidget(self.list)
        else:
            self._show_empty()
        if keep is not None and self.list.model().row_of(keep) >= 0:
            self.list.select_entry(keep, emit=False)
            self._show_detail(keep)
        else:
            self.detail.clear()

    def _show_empty(self) -> None:
        if self._text.strip():
            self.empty.set_text(tr("palette.no_results"),
                                tr("vault.empty.search", text=self._text.strip()))
            self.empty.halo.set_icon("search")
        elif self._favorites_only:
            self.empty.set_text(tr("vault.empty.favorites"),
                                tr("vault.empty.favorites.text"))
            self.empty.halo.set_icon("star")
        elif self._category_id is not None:
            self.empty.set_text(tr("vault.empty.category"), tr("vault.empty.category.text"))
            self.empty.halo.set_icon("folder")
        else:
            self.empty.set_text(tr("vault.empty.title"), tr("vault.empty.text"))
            self.empty.halo.set_icon("key-round")
        if self.empty.action is not None:
            self.empty.action.setVisible(not self._text.strip() and not self._favorites_only)
        self.list_stack.setCurrentWidget(self.empty)

    def _on_selected(self, entry_id) -> None:
        if entry_id is None:
            self.detail.clear()
        elif entry_id != self.detail.current_entry_id():
            self._show_detail(entry_id)

    def _show_detail(self, entry_id: int) -> None:
        summary = self.list.model().summary(self.list.model().row_of(entry_id))
        try:
            entry = self.ctx.entries.get_entry(entry_id)
            count = self.ctx.entries.history_count(entry_id)
        except EntryError as exc:
            self.detail.show_error(str(exc))
            return
        self.detail.show_entry(entry, summary.category_name if summary else "", count)

    def open_entry(self, entry_id: int) -> None:
        """Shows a given entry (from the overview, the security view, the palette…)."""
        self._cancel_pending_search()
        self._text = ""
        self._favorites_only = False
        self._category_id = None
        self.all_chip.setChecked(True)
        self.category_button.setText(tr("vault.filter.category_all"))
        self.refresh(select_id=entry_id)
        self.list.select_entry(entry_id, emit=False)
        self.list.setFocus()

    def selected_id(self) -> int | None:
        return self.list.selected_id()

    # --- Actions ----------------------------------------------------------------------------------

    def new_entry(self) -> None:
        default_category = self._category_id if self._category_id not in (None,
                                                                          UNCATEGORIZED) else None
        dialog = EntryDialog(self.ctx.entries, self.ctx.categories.list_categories(),
                             self.ctx.clipboard, default_category_id=default_category,
                             parent=self, settings=self.ctx.settings())
        if self._favorites_only:
            dialog.favorite.setChecked(True)
        if dialog.exec() and dialog.saved_entry_id is not None:
            self.ctx.changed()
            self.open_entry(dialog.saved_entry_id)
            self.ctx.notify(tr("vault.entry_added"), dialog.name.text().strip(), icon="plus")

    def edit_entry(self, entry_id: int | None = None) -> None:
        entry_id = entry_id if entry_id is not None else self.selected_id()
        if entry_id is None:
            return
        try:
            entry = self.ctx.entries.get_entry(entry_id)
        except EntryError as exc:
            dialogs.alert(self, tr("vault.edit_impossible"), str(exc))
            return
        dialog = EntryDialog(self.ctx.entries, self.ctx.categories.list_categories(),
                             self.ctx.clipboard, entry=entry, parent=self,
                             settings=self.ctx.settings())
        if dialog.exec():
            self.detail.clear()
            self.ctx.changed()
            self.refresh(animate=False, select_id=entry_id)
            self.ctx.notify(tr("vault.changes_saved"), entry.service_name, icon="check")

    def delete_entry(self, entry_id: int | None = None) -> None:
        entry_id = entry_id if entry_id is not None else self.selected_id()
        if entry_id is None:
            return
        summary = self.list.model().summary(self.list.model().row_of(entry_id))
        name = summary.service_name if summary else tr("vault.this_entry")
        if not dialogs.confirm(self, tr("vault.delete.title", name=name),
                               tr("vault.delete.text"),
                               tr("action.delete_entry"), danger=True, icon="trash-2"):
            return

        def remove() -> None:
            try:
                self.ctx.entries.delete_entry(entry_id)
            except EntryError as exc:
                dialogs.alert(self, tr("delete_vault.impossible"), str(exc))
                return
            self.detail.clear()
            self.ctx.changed()
            self.refresh(animate=False)
            self.ctx.notify(tr("vault.moved_to_trash"), name, icon="trash-2")

        self.list.animate_removal(entry_id, remove)

    def duplicate_entry(self, entry_id: int | None = None) -> None:
        entry_id = entry_id if entry_id is not None else self.selected_id()
        if entry_id is None:
            return
        try:
            new_id = self.ctx.entries.duplicate_entry(entry_id)
        except EntryError as exc:
            dialogs.alert(self, tr("vault.duplicate_impossible"), str(exc))
            return
        self.ctx.changed()
        self.refresh(animate=False, select_id=new_id)
        self.ctx.notify(tr("vault.duplicated"), icon="copy-plus")

    def set_favorite(self, entry_id: int, value: bool) -> None:
        try:
            self.ctx.entries.set_favorite(entry_id, value)
        except EntryError as exc:
            dialogs.alert(self, tr("vault.filter.favorites"), str(exc))
            return
        self.detail.set_favorite_state(value)
        self.refresh(animate=False)
        self.ctx.changed()

    def _toggle_favorite_from_list(self, entry_id: int) -> None:
        summary = self.list.model().summary(self.list.model().row_of(entry_id))
        if summary is not None:
            self.set_favorite(entry_id, not summary.is_favorite)

    def show_history(self, entry_id: int) -> None:
        names = {c.id: c.name for c in self.ctx.categories.list_categories()}
        dialog = HistoryDialog(self.ctx.entries, entry_id, self.ctx.clipboard, names, parent=self)
        dialog.exec()
        if dialog.changed:
            self.detail.clear()
            self.ctx.changed()
            self.refresh(animate=False, select_id=entry_id)
            self.ctx.notify(tr("vault.history_updated"), icon="history")

    def copy_selected_password(self) -> None:
        entry_id = self.selected_id()
        if entry_id is None:
            return
        try:
            entry = self.ctx.entries.get_entry(entry_id)
        except EntryError as exc:
            dialogs.alert(self, tr("vault.copy_impossible"), str(exc))
            return
        spec = ENTRY_TYPES[entry.entry_type]
        if not spec.uses_password or not entry.password:
            self.ctx.notify(tr("vault.no_password"), tr("vault.no_password.text"),
                            kind="warning")
            return
        self.ctx.clipboard.copy(entry.password, spec.password_label)

    def copy_selected_username(self) -> None:
        summary = self.list.selected_summary()
        if summary is None or not summary.username:
            self.ctx.notify(tr("vault.no_username"), kind="warning")
            return
        self.ctx.clipboard.copy(summary.username, tr("field.username"), sensitive=False)

    # --- Categories -------------------------------------------------------------------------------

    def _create_category(self) -> None:
        name = dialogs.prompt_text(self, tr("vault.category.new"), tr("vault.category.name"),
                                   placeholder=tr("vault.category.placeholder"), icon="folder")
        if name is None:
            return
        try:
            category_id = self.ctx.categories.create_category(name)
        except CategoryError as exc:
            dialogs.alert(self, tr("field.category"), str(exc))
            return
        self._set_category(category_id)
        self.ctx.notify(tr("vault.category.created"), name.strip(), icon="folder")

    def _rename_category(self, category_id: int, current: str) -> None:
        name = dialogs.prompt_text(self, tr("vault.category.rename"),
                                   tr("settings.vault.new_name"), current,
                                   icon="folder")
        if name is None:
            return
        try:
            self.ctx.categories.rename_category(category_id, name)
        except CategoryError as exc:
            dialogs.alert(self, tr("field.category"), str(exc))
            return
        self._set_category(category_id)

    def _delete_category(self, category_id: int, name: str, count: int) -> None:
        if not dialogs.confirm(self, tr("vault.category.delete.title", name=name),
                               tr_n("vault.category.delete.text", count),
                               tr("vault.category.delete"), danger=True):
            return
        try:
            self.ctx.categories.delete_category(category_id)
        except CategoryError as exc:
            dialogs.alert(self, tr("field.category"), str(exc))
            return
        self._set_category(None)
        self.ctx.changed()

    def wipe(self) -> None:
        self._cancel_pending_search()  # locking: no deferred search survives
        self._text = ""
        self.detail.clear()
        self.list.set_entries([], animate=False)
