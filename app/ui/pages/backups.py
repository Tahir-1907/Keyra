"""Vue « Sauvegardes » : état, création, restauration ; import et export."""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QMenu, QPushButton, QVBoxLayout

from app.core.exceptions import VaultError
from app.services import backup
from app.services.settings import backup_directory
from app.ui import components as ui
from app.ui import dialogs, effects, theme
from app.ui.entry_list import relative_date
from app.ui.pages.base import AppContext, Page, scrolling
from app.ui.transfer_dialogs import (
    ExportDialog,
    describe_backup_location,
    open_backup_folder,
    restore_file,
    run_import,
    run_restore,
)


def _size(n: int) -> str:
    return f"{n / 1024:.0f} Ko" if n < 1024 * 1024 else f"{n / 1024 / 1024:.1f} Mo"


class BackupsPage(Page):
    key = "backups"
    title = "Sauvegardes"
    subtitle = "Copies chiffrées, import et export"
    icon = "database-backup"

    def __init__(self, ctx: AppContext) -> None:
        super().__init__(ctx)
        self._infos: list[backup.BackupInfo] = []
        layout = scrolling(self)

        # --- État --------------------------------------------------------------------------
        status = ui.card("Surface")
        row = QHBoxLayout(status)
        row.setContentsMargins(22, 20, 22, 20)
        row.setSpacing(18)
        self.halo = ui.HaloIcon("database-backup", 84, animated=False)
        row.addWidget(self.halo)
        texts = QVBoxLayout()
        texts.setSpacing(4)
        texts.addWidget(ui.label("DERNIÈRE SAUVEGARDE", "Overline"))
        self.last = ui.label("", "H1")
        texts.addWidget(self.last)
        badges = QHBoxLayout()
        badges.setSpacing(6)
        self.badge = ui.label("✓ Chiffrée · AES-256-GCM", "BadgeAccent")
        badges.addWidget(self.badge)
        self.auto_badge = ui.label("", "Badge")
        badges.addWidget(self.auto_badge)
        badges.addStretch(1)
        texts.addLayout(badges)
        self.location = ui.label("", "Faint", wrap=True)
        texts.addWidget(self.location)
        row.addLayout(texts, 1)
        buttons = QVBoxLayout()
        buttons.setSpacing(8)
        buttons.addWidget(ui.button("Créer une sauvegarde", "database-backup", "Primary",
                                    on_click=self.create_backup))
        buttons.addWidget(ui.button("Restaurer un fichier…", "rotate-ccw",
                                    on_click=self.restore_other))
        buttons.addWidget(ui.button("Ouvrir le dossier", "folder-open", "Ghost",
                                    on_click=lambda: open_backup_folder(
                                        backup_directory(self.ctx.settings()))))
        row.addLayout(buttons)
        layout.addWidget(status)

        # --- Liste -----------------------------------------------------------------------------
        history_head = QHBoxLayout()
        history_head.setSpacing(12)
        history_head.addWidget(ui.section("Historique des sauvegardes",
                                          "Chaque fichier s'ouvre avec le mot de passe maître en "
                                          "vigueur au moment de la sauvegarde. Restaurer crée un "
                                          "nouveau coffre : rien n'est écrasé."), 1)
        self.delete_button = ui.button("Supprimer…", "trash-2", "Ghost")
        self.delete_menu = QMenu(self.delete_button)
        self.delete_auto_action = self.delete_menu.addAction(
            ui.lucide.icon("trash-2", theme.TEXT_2), "Les sauvegardes automatiques…",
            lambda: self.delete_all(backup.KIND_AUTO))
        self.delete_menu.addAction(ui.lucide.icon("trash-2", theme.DANGER),
                                   "Toutes les sauvegardes de ce coffre…",
                                   lambda: self.delete_all(None))
        self.delete_button.setMenu(self.delete_menu)
        history_head.addWidget(self.delete_button, 0, Qt.AlignBottom)
        layout.addLayout(history_head)
        self.rows_host = ui.card()
        self.rows = QVBoxLayout(self.rows_host)
        self.rows.setContentsMargins(10, 8, 10, 8)
        self.rows.setSpacing(2)
        layout.addWidget(self.rows_host)

        # --- Transferts --------------------------------------------------------------------------
        layout.addWidget(ui.section("Import et export",
                                    "Migrer depuis ou vers un autre logiciel, ou garder une copie "
                                    "papier."))
        grid = QGridLayout()
        grid.setSpacing(12)
        for column, (icon, title, text, label, action) in enumerate((
            ("file-down", "Importer",
             "Bitwarden, KeePassXC, Chrome, Firefox (CSV) ou export chiffré Mon Coffre-Fort.",
             "Importer…", self.import_entries),
            ("file-up", "Exporter",
             "Export chiffré (recommandé) ou CSV en clair. Mot de passe maître requis.",
             "Exporter…", self.export_entries),
            ("file-text", "Copie papier (PDF)",
             "Tous les comptes et mots de passe, pour les imprimer. PDF protégé par mot de "
             "passe (recommandé) ou en clair.", "Créer le PDF…", self.export_pdf),
        )):
            card = ui.card()
            inner = QVBoxLayout(card)
            inner.setContentsMargins(18, 16, 18, 16)
            inner.setSpacing(8)
            head = QHBoxLayout()
            head.addWidget(ui.icon_label(icon, theme.TEXT_2, 20))
            head.addWidget(ui.label(title, "H2"), 1)
            inner.addLayout(head)
            inner.addWidget(ui.label(text, "Faint", wrap=True))
            inner.addWidget(ui.button(label, on_click=action), 0, Qt.AlignLeft)
            grid.addWidget(card, 0, column)
        layout.addLayout(grid)
        layout.addStretch(1)

    def refresh(self) -> None:
        if self.ctx.vault.is_locked:
            return
        settings = self.ctx.settings()
        directory = backup_directory(settings)
        try:
            infos = backup.list_backups(directory, self.ctx.vault.vault_id)
        except OSError:
            infos = []
        self.last.setText(relative_date(infos[0].created_at).capitalize() if infos
                          else "Aucune sauvegarde")
        self.badge.setVisible(bool(infos))
        self.auto_badge.setText(
            f"Auto : activée · {settings.auto_backups_kept} conservées" if settings.auto_backup
            else "Auto : désactivée")
        self.location.setText(f"Dossier : {describe_backup_location(directory / 'x')}")
        while self.rows.count():
            item = self.rows.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._infos = infos
        self.delete_button.setVisible(bool(infos))
        self.delete_auto_action.setEnabled(any(i.kind == backup.KIND_AUTO for i in infos))
        if not infos:
            self.rows.addWidget(ui.EmptyState(
                "database-backup", "Aucune sauvegarde",
                "Créez une sauvegarde chiffrée pour pouvoir restaurer ce coffre en cas de "
                "problème.", "Créer une sauvegarde", self.create_backup, "database-backup"))
            return
        rows = []
        for info in infos:
            row = QPushButton()
            row.setObjectName("Ghost")
            row.setMinimumHeight(54)
            inner = QHBoxLayout(row)
            inner.setContentsMargins(10, 4, 10, 4)
            inner.setSpacing(12)
            inner.addWidget(ui.icon_label("shield-check", theme.ACCENT_2, 18))
            texts = QVBoxLayout()
            texts.setSpacing(0)
            try:
                when = datetime.fromisoformat(info.created_at).astimezone()
                title = f"{when:%d/%m/%Y à %H:%M}"
            except ValueError:
                title = info.path.name
            texts.addWidget(ui.label(title))
            texts.addWidget(ui.label(f"{info.path.name} · {_size(info.size)}", "Faint"))
            inner.addLayout(texts, 1)
            inner.addWidget(ui.label("automatique" if info.kind == backup.KIND_AUTO
                                     else "manuelle", "Badge"))
            restore = ui.button("Restaurer", "rotate-ccw",
                                on_click=lambda p=info.path: self.restore_path(p))
            inner.addWidget(restore)
            inner.addWidget(ui.icon_button("trash-2", "Supprimer cette sauvegarde",
                                           on_click=lambda i=info: self.delete_one(i)))
            self.rows.addWidget(row)
            rows.append(row)
        effects.stagger(rows[:10])

    # --- Actions ------------------------------------------------------------------------------

    def create_backup(self) -> None:
        try:
            path = backup.create_backup(self.ctx.vault,
                                        directory=backup_directory(self.ctx.settings()))
        except (VaultError, OSError) as exc:
            dialogs.alert(self, "Sauvegarde impossible", str(exc))
            return
        self.refresh()
        self.ctx.notify("Sauvegarde créée", path.name, icon="database-backup")

    def delete_one(self, info: backup.BackupInfo) -> None:
        try:
            when = f"du {datetime.fromisoformat(info.created_at).astimezone():%d/%m/%Y à %H:%M}"
        except ValueError:
            when = info.path.name
        remaining = len(self._infos) - 1
        if not dialogs.confirm(
                self, f"Supprimer la sauvegarde {when} ?",
                f"Le fichier {info.path.name} sera effacé du disque ; il ne pourra plus servir "
                "à restaurer ce coffre."
                + ("" if remaining else " C'est la DERNIÈRE sauvegarde de ce coffre."),
                "Supprimer", danger=True, icon="trash-2"):
            return
        try:
            backup.delete_backup(info.path, self.ctx.vault.vault_id)
        except (VaultError, OSError) as exc:
            dialogs.alert(self, "Suppression impossible", str(exc))
            self.refresh()
            return
        self.refresh()
        self.ctx.notify("Sauvegarde supprimée", info.path.name, icon="trash-2")

    def delete_all(self, kind: str | None) -> None:
        targets = [i for i in self._infos if kind is None or i.kind == kind]
        if not targets:
            return
        count = len(targets)
        automatic = kind == backup.KIND_AUTO
        what = (f"{count} sauvegarde(s) automatique(s)" if automatic
                else f"les {count} sauvegarde(s) de ce coffre")
        if not dialogs.confirm(
                self, "Supprimer " + ("les sauvegardes automatiques ?" if automatic
                                      else "toutes les sauvegardes ?"),
                f"{what[0].upper() + what[1:]} seront effacées du disque. "
                + ("Les sauvegardes manuelles sont conservées." if automatic else
                   "Il ne restera AUCUNE copie de secours de ce coffre (hors copies faites "
                   "ailleurs par vous-même)."),
                "Supprimer", danger=True, icon="trash-2",
                acknowledge=None if automatic else
                "Je comprends qu'aucune restauration ne sera plus possible"):
            return
        removed = backup.delete_backups(self.ctx.vault.vault_id,
                                        backup_directory(self.ctx.settings()), kind)
        self.refresh()
        self.ctx.notify("Sauvegardes supprimées", f"{removed} fichier(s) effacé(s).",
                        icon="trash-2")

    def restore_path(self, path) -> None:
        restored = restore_file(self, path)
        if restored is not None:
            self.ctx.notify("Sauvegarde restaurée", f"Nouveau coffre « {restored.vault_name} ».",
                            icon="archive-restore")

    def restore_other(self) -> None:
        restored = run_restore(self, backup_directory(self.ctx.settings()))
        if restored is not None:
            self.ctx.notify("Sauvegarde restaurée", f"Nouveau coffre « {restored.vault_name} ».",
                            icon="archive-restore")

    def import_entries(self) -> None:
        if run_import(self, self.ctx.entries, self.ctx.categories):
            self.ctx.changed()
            self.ctx.notify("Import terminé", icon="file-down")

    def export_entries(self, initial: str = "encrypted") -> None:
        dialog = ExportDialog(self.ctx.entries, self.ctx.vault, parent=self, initial=initial)
        if dialog.exec() and dialog.exported_path is not None:
            path = dialog.exported_path
            if path.suffix == ".pdf":
                self.ctx.notify(
                    "PDF protégé créé" if dialog.exported_protected else "PDF créé (non protégé)",
                    f"{dialog.exported_count} compte(s) → {path.name}. "
                    + ("Son mot de passe sera demandé à l'ouverture." if dialog.exported_protected
                       else "Imprimez-le puis supprimez le fichier."),
                    icon="file-text", duration=8)
            else:
                self.ctx.notify("Export terminé",
                                f"{dialog.exported_count} compte(s) → {path.name}",
                                icon="file-up")

    def export_pdf(self) -> None:
        self.export_entries("pdf")

    def wipe(self) -> None:
        self._infos = []
        while self.rows.count():
            item = self.rows.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
