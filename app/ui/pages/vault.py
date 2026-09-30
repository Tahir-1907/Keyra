"""Vue « Coffre » : filtres, liste de comptes en cartes, panneau de détail."""

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
from app.ui import components as ui
from app.ui import dialogs, lucide, theme
from app.ui.detail_panel import DetailPanel
from app.ui.entry_dialog import EntryDialog
from app.ui.entry_list import EntryListView
from app.ui.history_dialog import HistoryDialog
from app.ui.pages.base import AppContext, Page

# Délai sans frappe avant d'appliquer la recherche (une relecture au lieu d'une par touche).
SEARCH_DEBOUNCE_MS = 150


class VaultPage(Page):
    key = "vault"
    title = "Coffre"
    subtitle = "Vos comptes et identifiants"
    icon = "key-round"

    def __init__(self, ctx: AppContext) -> None:
        super().__init__(ctx)
        self._text = ""
        self._favorites_only = False
        self._category_id: int | None = None
        self._pending_text: str | None = None  # recherche en attente (debounce)
        self._search_timer = QTimer(self)  # enfant de la page : détruit avec elle
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(SEARCH_DEBOUNCE_MS)
        self._search_timer.timeout.connect(self._on_search_timeout)

        # --- Barre de filtres ---------------------------------------------------------
        self.all_chip = ui.button("Tous", kind="Chip")
        self.fav_chip = ui.button("Favoris", "star", "Chip")
        for chip in (self.all_chip, self.fav_chip):
            chip.setCheckable(True)
        group = QButtonGroup(self)
        group.addButton(self.all_chip)
        group.addButton(self.fav_chip)
        self.all_chip.setChecked(True)
        self.all_chip.clicked.connect(lambda: self._set_favorites(False))
        self.fav_chip.clicked.connect(lambda: self._set_favorites(True))
        self.category_button = ui.button("Catégorie : toutes", "folder", "Chip")
        self.category_menu = QMenu(self.category_button)
        self.category_menu.aboutToShow.connect(self._fill_category_menu)
        self.category_button.setMenu(self.category_menu)
        self.count_label = ui.label("", "Faint")
        # Le compteur cède sa place quand la fenêtre est étroite (moitié d'écran).
        self.count_label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.count_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        filters = QHBoxLayout()
        filters.setSpacing(8)
        filters.addWidget(self.all_chip)
        filters.addWidget(self.fav_chip)
        filters.addWidget(self.category_button)
        filters.addStretch(1)
        filters.addWidget(self.count_label)

        # --- Liste + états vides ------------------------------------------------------------
        self.list = EntryListView()
        self.list.entry_selected.connect(self._on_selected)
        self.list.favorite_clicked.connect(self._toggle_favorite_from_list)
        self.list.activated_entry.connect(self.edit_entry)
        self.empty = ui.EmptyState("key-round", "Votre coffre est vide",
                                   "Ajoutez votre premier compte pour commencer à protéger "
                                   "vos identifiants.", "Ajouter un compte", self.new_entry)
        self.list_stack = QStackedWidget()
        self.list_stack.addWidget(self.list)
        self.list_stack.addWidget(self.empty)

        left = QVBoxLayout()
        left.setSpacing(14)
        left.addLayout(filters)
        left.addWidget(self.list_stack, 1)

        # --- Détail ---------------------------------------------------------------------------
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

    # --- Filtres ----------------------------------------------------------------------------------

    def set_search(self, text: str) -> None:
        """Frappe dans la recherche : appliquée après SEARCH_DEBOUNCE_MS sans nouvelle
        frappe (une seule relecture de la liste). Effacer la recherche est immédiat."""
        if not text.strip():
            self._cancel_pending_search()
            self._apply_search(text)
            return
        self._pending_text = text
        self._search_timer.start()

    def apply_search_now(self) -> None:
        """Entrée, clic sur un tag : applique tout de suite la recherche en attente."""
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
        # Garde-fou : jamais d'accès au coffre verrouillé, quel que soit l'ordre des
        # événements (délai échu pendant ou après le verrouillage).
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
        menu.addAction(lucide.icon("folder-open"), f"Toutes   ·  {overview.total}",
                       lambda: self._set_category(None))
        menu.addSeparator()
        for cat in overview.categories:
            action = menu.addAction(lucide.icon("folder"), f"{cat.name}   ·  {cat.entry_count}",
                                    lambda c=cat.id: self._set_category(c))
            action.setCheckable(True)
            action.setChecked(cat.id == self._category_id)
        menu.addAction(lucide.icon("folder"), f"Sans catégorie   ·  {overview.uncategorized}",
                       lambda: self._set_category(UNCATEGORIZED))
        menu.addSeparator()
        menu.addAction(lucide.icon("plus"), "Nouvelle catégorie…", self._create_category)
        current = next((c for c in overview.categories if c.id == self._category_id), None)
        if current is not None and not current.is_builtin:
            menu.addAction(lucide.icon("square-pen"), f"Renommer « {current.name} »…",
                           lambda: self._rename_category(current.id, current.name))
            menu.addAction(lucide.icon("trash-2", theme.DANGER), f"Supprimer « {current.name} »…",
                           lambda: self._delete_category(current.id, current.name,
                                                         current.entry_count))

    def _set_category(self, category_id: int | None) -> None:
        self._category_id = category_id
        names = {c.id: c.name for c in self.ctx.categories.list_categories()}
        label = ("toutes" if category_id is None else
                 "sans catégorie" if category_id == UNCATEGORIZED else names.get(category_id, ""))
        self.category_button.setText(f"Catégorie : {label}")
        self.category_button.setChecked(category_id is not None)
        self.refresh()

    def _filter(self) -> EntryFilter:
        return EntryFilter(text=self._text, favorites_only=self._favorites_only,
                           category_id=self._category_id)

    # --- Rafraîchissement ------------------------------------------------------------------------

    def refresh(self, animate: bool = True, select_id: int | None = None) -> None:
        keep = select_id if select_id is not None else self.detail.current_entry_id()
        rows = self.ctx.entries.list_entries(self._filter())
        self.list.set_entries(rows, animate=animate)
        self.count_label.setText(f"{len(rows)} compte{'s' if len(rows) > 1 else ''}")
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
            self.empty.set_text("Aucun résultat",
                                f"Aucun compte ne correspond à « {self._text.strip()} ».")
            self.empty.halo.set_icon("search")
        elif self._favorites_only:
            self.empty.set_text("Aucun favori",
                                "Cliquez sur l'étoile d'un compte pour le retrouver ici.")
            self.empty.halo.set_icon("star")
        elif self._category_id is not None:
            self.empty.set_text("Catégorie vide", "Aucun compte dans cette catégorie.")
            self.empty.halo.set_icon("folder")
        else:
            self.empty.set_text("Votre coffre est vide",
                                "Ajoutez votre premier compte pour commencer à protéger "
                                "vos identifiants.")
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
        """Affiche un compte précis (depuis le tableau de bord, la sécurité, la palette…)."""
        self._cancel_pending_search()
        self._text = ""
        self._favorites_only = False
        self._category_id = None
        self.all_chip.setChecked(True)
        self.category_button.setText("Catégorie : toutes")
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
            self.ctx.notify("Compte ajouté", dialog.name.text().strip(), icon="plus")

    def edit_entry(self, entry_id: int | None = None) -> None:
        entry_id = entry_id if entry_id is not None else self.selected_id()
        if entry_id is None:
            return
        try:
            entry = self.ctx.entries.get_entry(entry_id)
        except EntryError as exc:
            dialogs.alert(self, "Modification impossible", str(exc))
            return
        dialog = EntryDialog(self.ctx.entries, self.ctx.categories.list_categories(),
                             self.ctx.clipboard, entry=entry, parent=self,
                             settings=self.ctx.settings())
        if dialog.exec():
            self.detail.clear()
            self.ctx.changed()
            self.refresh(animate=False, select_id=entry_id)
            self.ctx.notify("Modifications enregistrées", entry.service_name, icon="check")

    def delete_entry(self, entry_id: int | None = None) -> None:
        entry_id = entry_id if entry_id is not None else self.selected_id()
        if entry_id is None:
            return
        summary = self.list.model().summary(self.list.model().row_of(entry_id))
        name = summary.service_name if summary else "ce compte"
        if not dialogs.confirm(self, f"Supprimer {name} ?",
                               "Cette entrée sera déplacée vers la corbeille. Vous pourrez la "
                               "restaurer pendant la durée de conservation de la corbeille.",
                               "Déplacer vers la corbeille", danger=True, icon="trash-2"):
            return

        def remove() -> None:
            try:
                self.ctx.entries.delete_entry(entry_id)
            except EntryError as exc:
                dialogs.alert(self, "Suppression impossible", str(exc))
                return
            self.detail.clear()
            self.ctx.changed()
            self.refresh(animate=False)
            self.ctx.notify("Déplacé vers la corbeille", name, icon="trash-2")

        self.list.animate_removal(entry_id, remove)

    def duplicate_entry(self, entry_id: int | None = None) -> None:
        entry_id = entry_id if entry_id is not None else self.selected_id()
        if entry_id is None:
            return
        try:
            new_id = self.ctx.entries.duplicate_entry(entry_id)
        except EntryError as exc:
            dialogs.alert(self, "Duplication impossible", str(exc))
            return
        self.ctx.changed()
        self.refresh(animate=False, select_id=new_id)
        self.ctx.notify("Compte dupliqué", icon="copy-plus")

    def set_favorite(self, entry_id: int, value: bool) -> None:
        try:
            self.ctx.entries.set_favorite(entry_id, value)
        except EntryError as exc:
            dialogs.alert(self, "Favoris", str(exc))
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
            self.ctx.notify("Historique mis à jour", icon="history")

    def copy_selected_password(self) -> None:
        entry_id = self.selected_id()
        if entry_id is None:
            return
        try:
            entry = self.ctx.entries.get_entry(entry_id)
        except EntryError as exc:
            dialogs.alert(self, "Copie impossible", str(exc))
            return
        spec = ENTRY_TYPES[entry.entry_type]
        if not spec.uses_password or not entry.password:
            self.ctx.notify("Aucun mot de passe", "Ce compte n'a pas de mot de passe.",
                            kind="warning")
            return
        self.ctx.clipboard.copy(entry.password, spec.password_label)

    def copy_selected_username(self) -> None:
        summary = self.list.selected_summary()
        if summary is None or not summary.username:
            self.ctx.notify("Aucun identifiant", kind="warning")
            return
        self.ctx.clipboard.copy(summary.username, "Identifiant", sensitive=False)

    # --- Catégories -------------------------------------------------------------------------------

    def _create_category(self) -> None:
        name = dialogs.prompt_text(self, "Nouvelle catégorie", "Nom de la catégorie",
                                   placeholder="Ex. : Jeux vidéo", icon="folder")
        if name is None:
            return
        try:
            category_id = self.ctx.categories.create_category(name)
        except CategoryError as exc:
            dialogs.alert(self, "Catégorie", str(exc))
            return
        self._set_category(category_id)
        self.ctx.notify("Catégorie créée", name.strip(), icon="folder")

    def _rename_category(self, category_id: int, current: str) -> None:
        name = dialogs.prompt_text(self, "Renommer la catégorie", "Nouveau nom", current,
                                   icon="folder")
        if name is None:
            return
        try:
            self.ctx.categories.rename_category(category_id, name)
        except CategoryError as exc:
            dialogs.alert(self, "Catégorie", str(exc))
            return
        self._set_category(category_id)

    def _delete_category(self, category_id: int, name: str, count: int) -> None:
        if not dialogs.confirm(self, f"Supprimer la catégorie « {name} » ?",
                               f"Ses {count} compte(s) ne seront pas supprimés : ils passeront "
                               "« Sans catégorie ».", "Supprimer la catégorie", danger=True):
            return
        try:
            self.ctx.categories.delete_category(category_id)
        except CategoryError as exc:
            dialogs.alert(self, "Catégorie", str(exc))
            return
        self._set_category(None)
        self.ctx.changed()

    def wipe(self) -> None:
        self._cancel_pending_search()  # verrouillage : aucune recherche différée ne survit
        self._text = ""
        self.detail.clear()
        self.list.set_entries([], animate=False)
