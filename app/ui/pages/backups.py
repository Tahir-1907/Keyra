"""The "Backups" view: state, creation, restore; import and export."""

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
    return f"{n / 1024:.0f} KB" if n < 1024 * 1024 else f"{n / 1024 / 1024:.1f} MB"


class BackupsPage(Page):
    key = "backups"
    title = "Backups"
    subtitle = "Encrypted copies, import and export"
    icon = "database-backup"

    def __init__(self, ctx: AppContext) -> None:
        super().__init__(ctx)
        self._infos: list[backup.BackupInfo] = []
        layout = scrolling(self)

        # --- State --------------------------------------------------------------------------
        status = ui.card("Surface")
        row = QHBoxLayout(status)
        row.setContentsMargins(22, 20, 22, 20)
        row.setSpacing(18)
        self.halo = ui.HaloIcon("database-backup", 84, animated=False)
        row.addWidget(self.halo)
        texts = QVBoxLayout()
        texts.setSpacing(4)
        texts.addWidget(ui.label("LAST BACKUP", "Overline"))
        self.last = ui.label("", "H1")
        texts.addWidget(self.last)
        badges = QHBoxLayout()
        badges.setSpacing(6)
        self.badge = ui.label("✓ Encrypted · AES-256-GCM", "BadgeAccent")
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
        buttons.addWidget(ui.button("Create a backup", "database-backup", "Primary",
                                    on_click=self.create_backup))
        buttons.addWidget(ui.button("Restore a file…", "rotate-ccw",
                                    on_click=self.restore_other))
        buttons.addWidget(ui.button("Open the folder", "folder-open", "Ghost",
                                    on_click=lambda: open_backup_folder(
                                        backup_directory(self.ctx.settings()))))
        row.addLayout(buttons)
        layout.addWidget(status)

        # --- List -----------------------------------------------------------------------------
        history_head = QHBoxLayout()
        history_head.setSpacing(12)
        history_head.addWidget(ui.section("Backup history",
                                          "Each file opens with the master password in effect "
                                          "when the backup was made. Restoring creates a "
                                          "new vault: nothing is overwritten."), 1)
        self.delete_button = ui.button("Delete…", "trash-2", "Ghost")
        self.delete_menu = QMenu(self.delete_button)
        self.delete_auto_action = self.delete_menu.addAction(
            ui.lucide.icon("trash-2", theme.TEXT_2), "Automatic backups…",
            lambda: self.delete_all(backup.KIND_AUTO))
        self.delete_menu.addAction(ui.lucide.icon("trash-2", theme.DANGER),
                                   "All backups of this vault…",
                                   lambda: self.delete_all(None))
        self.delete_button.setMenu(self.delete_menu)
        history_head.addWidget(self.delete_button, 0, Qt.AlignBottom)
        layout.addLayout(history_head)
        self.rows_host = ui.card()
        self.rows = QVBoxLayout(self.rows_host)
        self.rows.setContentsMargins(10, 8, 10, 8)
        self.rows.setSpacing(2)
        layout.addWidget(self.rows_host)

        # --- Transfers --------------------------------------------------------------------------
        layout.addWidget(ui.section("Import and export",
                                    "Move from or to other software, or keep a paper "
                                    "copy."))
        grid = QGridLayout()
        grid.setSpacing(12)
        for column, (icon, title, text, label, action) in enumerate((
            ("file-down", "Import",
             "Bitwarden, KeePassXC, Chrome, Firefox (CSV) or a Keyra encrypted export.",
             "Import…", self.import_entries),
            ("file-up", "Export",
             "Encrypted export (recommended) or plaintext CSV. Master password required.",
             "Export…", self.export_entries),
            ("file-text", "Paper copy (PDF)",
             "Every entry and password, to print them. Password-protected PDF "
             "(recommended) or plaintext.", "Create the PDF…", self.export_pdf),
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
                          else "No backup")
        self.badge.setVisible(bool(infos))
        self.auto_badge.setText(
            f"Auto: on · {settings.auto_backups_kept} kept" if settings.auto_backup
            else "Auto: off")
        self.location.setText(f"Folder: {describe_backup_location(directory / 'x')}")
        while self.rows.count():
            item = self.rows.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._infos = infos
        self.delete_button.setVisible(bool(infos))
        self.delete_auto_action.setEnabled(any(i.kind == backup.KIND_AUTO for i in infos))
        if not infos:
            self.rows.addWidget(ui.EmptyState(
                "database-backup", "No backup",
                "Create an encrypted backup to be able to restore this vault if something "
                "goes wrong.", "Create a backup", self.create_backup, "database-backup"))
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
                title = f"{when:%Y-%m-%d %H:%M}"
            except ValueError:
                title = info.path.name
            texts.addWidget(ui.label(title))
            texts.addWidget(ui.label(f"{info.path.name} · {_size(info.size)}", "Faint"))
            inner.addLayout(texts, 1)
            inner.addWidget(ui.label(backup.kind_label(info.kind), "Badge"))
            restore = ui.button("Restore", "rotate-ccw",
                                on_click=lambda p=info.path: self.restore_path(p))
            inner.addWidget(restore)
            inner.addWidget(ui.icon_button("trash-2", "Delete this backup",
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
            dialogs.alert(self, "Backup impossible", str(exc))
            return
        self.refresh()
        self.ctx.notify("Backup created", path.name, icon="database-backup")

    def delete_one(self, info: backup.BackupInfo) -> None:
        try:
            when = f"from {datetime.fromisoformat(info.created_at).astimezone():%Y-%m-%d %H:%M}"
        except ValueError:
            when = info.path.name
        remaining = len(self._infos) - 1
        if not dialogs.confirm(
                self, f"Delete the backup {when}?",
                f"The file {info.path.name} will be erased from the disk; it can no longer be "
                "used to restore this vault."
                + ("" if remaining else " It is the LAST backup of this vault."),
                "Delete", danger=True, icon="trash-2"):
            return
        try:
            backup.delete_backup(info.path, self.ctx.vault.vault_id)
        except (VaultError, OSError) as exc:
            dialogs.alert(self, "Deletion impossible", str(exc))
            self.refresh()
            return
        self.refresh()
        self.ctx.notify("Backup deleted", info.path.name, icon="trash-2")

    def delete_all(self, kind: str | None) -> None:
        targets = [i for i in self._infos if kind is None or i.kind == kind]
        if not targets:
            return
        count = len(targets)
        automatic = kind == backup.KIND_AUTO
        what = (f"{count} automatic backup(s)" if automatic
                else f"the {count} backup(s) of this vault")
        if not dialogs.confirm(
                self, "Delete " + ("the automatic backups?" if automatic
                                   else "all backups?"),
                f"{what[0].upper() + what[1:]} will be erased from the disk. "
                + ("Manual backups are kept." if automatic else
                   "NO safety copy of this vault will remain (apart from copies you made "
                   "elsewhere yourself)."),
                "Delete", danger=True, icon="trash-2",
                acknowledge=None if automatic else
                "I understand that no restore will be possible anymore"):
            return
        removed = backup.delete_backups(self.ctx.vault.vault_id,
                                        backup_directory(self.ctx.settings()), kind)
        self.refresh()
        self.ctx.notify("Backups deleted", f"{removed} file(s) erased.",
                        icon="trash-2")

    def restore_path(self, path) -> None:
        restored = restore_file(self, path)
        if restored is not None:
            self.ctx.notify("Backup restored", f"New vault \"{restored.vault_name}\".",
                            icon="archive-restore")

    def restore_other(self) -> None:
        restored = run_restore(self, backup_directory(self.ctx.settings()))
        if restored is not None:
            self.ctx.notify("Backup restored", f"New vault \"{restored.vault_name}\".",
                            icon="archive-restore")

    def import_entries(self) -> None:
        if run_import(self, self.ctx.entries, self.ctx.categories):
            self.ctx.changed()
            self.ctx.notify("Import complete", icon="file-down")

    def export_entries(self, initial: str = "encrypted") -> None:
        dialog = ExportDialog(self.ctx.entries, self.ctx.vault, parent=self, initial=initial)
        if dialog.exec() and dialog.exported_path is not None:
            path = dialog.exported_path
            if path.suffix == ".pdf":
                self.ctx.notify(
                    "PDF created (protected)" if dialog.exported_protected else "PDF created",
                    f"{dialog.exported_count} entry(ies) → {path.name}. "
                    + ("Its password will be asked when it is opened." if dialog.exported_protected
                       else "Print it, then delete the file."),
                    icon="file-text", duration=8)
            else:
                self.ctx.notify("Export complete",
                                f"{dialog.exported_count} entry(ies) → {path.name}",
                                icon="file-up")

    def export_pdf(self) -> None:
        self.export_entries("pdf")

    def wipe(self) -> None:
        self._infos = []
        while self.rows.count():
            item = self.rows.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
