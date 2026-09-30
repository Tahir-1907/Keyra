"""Import, export and backup restore (modals and flows).

All the logic lives in app.services.import_export and app.services.backup;
this module only asks for files, passwords and confirmations.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QFileDialog,
    QHeaderView,
    QRadioButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.core.categories import CategoryService
from app.core.entries import ENTRY_TYPES, EntryService
from app.core.exceptions import VaultError, WrongMasterPasswordError
from app.core.vault import Vault, VaultInfo
from app.services import backup, import_export, pdf_export
from app.ui import components as ui
from app.ui import dialogs, theme
from app.ui.dialogs import PremiumDialog
from app.ui.fields import PasswordField
from app.utils.paths import default_backup_dir

_PREVIEW_ROWS = 200


class _BusyCursor:
    def __enter__(self):
        QGuiApplication.setOverrideCursor(Qt.WaitCursor)
        QGuiApplication.processEvents()

    def __exit__(self, *exc):
        QGuiApplication.restoreOverrideCursor()
        return False


def _when(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return iso


class PasswordPrompt(PremiumDialog):
    """Asks for a password (masked field), cleared on close."""

    def __init__(self, title: str, message: str, parent: QWidget | None = None,
                 icon: str = "key-round") -> None:
        super().__init__(parent, title, icon=icon, width=460)
        self.body.addWidget(ui.label(message, "Muted", wrap=True))
        self.password = PasswordField("Password", leading_icon="lock")
        self.password.returnPressed.connect(self.accept)
        self.body.addWidget(self.password)
        self.error = ui.label("", "Error", wrap=True)
        self.error.hide()
        self.body.addWidget(self.error)
        _, ok = self.add_buttons("Cancel", "OK")
        ok.clicked.connect(self.accept)

    def ask(self, error: str = "") -> str | None:
        self.password.reset()
        self.error.setText(error)
        self.error.setVisible(bool(error))
        self._closing = False
        self._instant = False
        self.password.setFocus()
        if self.exec() != PremiumDialog.Accepted:
            return None
        value = self.password.text()
        self.password.reset()
        return value


# --- Import --------------------------------------------------------------------------------


class ImportPreviewDialog(PremiumDialog):
    def __init__(self, preview: import_export.ImportPreview, parent: QWidget | None = None) -> None:
        count = len(preview.items)
        super().__init__(parent, "Import entries",
                         f"{count} entry(ies) found — format: {preview.format_label}."
                         + (f" {preview.skipped_rows} empty row(s) ignored."
                            if preview.skipped_rows else "")
                         + (f" {preview.dropped_tags} invalid or duplicate tag(s) "
                            "will be ignored." if preview.dropped_tags else ""),
                         icon="file-down", width=760)
        self.body.addWidget(ui.label("Passwords are not shown in this preview.",
                                     "Faint"))
        table = QTableWidget(min(count, _PREVIEW_ROWS), 5)
        table.setHorizontalHeaderLabels(["Name", "Username", "URL", "Category", "Type"])
        table.verticalHeader().hide()
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionMode(QAbstractItemView.NoSelection)
        table.setShowGrid(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setStyleSheet(
            f"QTableWidget {{ background: {theme.BG_2}; border: 1px solid {theme.BORDER};"
            f" border-radius: {theme.RADIUS_M}px; }}"
            f"QHeaderView::section {{ background: {theme.SURFACE}; color: {theme.TEXT_3};"
            f" border: none; padding: 6px; font-weight: 600; }}")
        for row, item in enumerate(preview.items[:_PREVIEW_ROWS]):
            e = item.entry
            spec = ENTRY_TYPES.get(e.entry_type)
            for col, value in enumerate((e.service_name, e.username, e.url, item.category_name,
                                         spec.label if spec else e.entry_type)):
                table.setItem(row, col, QTableWidgetItem(value))
        table.setMinimumHeight(280)
        self.body.addWidget(table)
        if count > _PREVIEW_ROWS:
            self.body.addWidget(ui.label(f"… and {count - _PREVIEW_ROWS} more.", "Faint"))
        self.create_categories = ui.ToggleSwitch(
            "Create the missing categories (folders / groups of the file)")
        self.create_categories.setChecked(True)
        self.skip_duplicates = ui.ToggleSwitch(
            "Skip duplicates (same name, username, URL and password)")
        self.skip_duplicates.setChecked(True)
        self.body.addWidget(self.create_categories)
        self.body.addWidget(self.skip_duplicates)
        _, confirm = self.add_buttons("Cancel", f"Import {count} entry(ies)",
                                      confirm_icon="file-down")
        confirm.setEnabled(count > 0)
        confirm.clicked.connect(self.accept)


def run_import(parent: QWidget, entries: EntryService, categories: CategoryService) -> bool:
    """Complete flow; returns True if entries were imported."""
    path_str, _ = QFileDialog.getOpenFileName(
        parent, "Import entries", str(Path.home()),
        "Supported files (*.csv *.mcfexport);;CSV (*.csv);;"
        "Keyra encrypted export (*.mcfexport);;All files (*)")
    if not path_str:
        return False
    path = Path(path_str)
    try:
        if import_export.is_encrypted_export(path):
            prompt = PasswordPrompt("Encrypted export",
                                    f"Export password of the file \"{path.name}\".", parent)
            error = ""
            while True:
                password = prompt.ask(error)
                if password is None:
                    return False
                try:
                    with _BusyCursor():
                        preview = import_export.parse_encrypted_export(path, password)
                    break
                except WrongMasterPasswordError as exc:
                    error = str(exc)
        else:
            with _BusyCursor():
                preview = import_export.parse_csv(path)
    except VaultError as exc:
        dialogs.alert(parent, "Import impossible", str(exc))
        return False

    dialog = ImportPreviewDialog(preview, parent)
    if dialog.exec() != PremiumDialog.Accepted:
        return False
    try:
        with _BusyCursor():
            result = import_export.apply_import(
                entries, categories, preview,
                create_categories=dialog.create_categories.isChecked(),
                skip_duplicates=dialog.skip_duplicates.isChecked())
    except VaultError as exc:
        dialogs.alert(parent, "Import impossible", f"{exc}\n\nNo entry was imported.")
        return False

    lines = [f"{result.imported} entry(ies) imported."]
    if result.duplicates:
        lines.append(f"{result.duplicates} duplicate(s) skipped.")
    if result.invalid:
        lines.append(f"{result.invalid} invalid entry(ies) ignored.")
    if preview.dropped_tags:
        lines.append(f"{preview.dropped_tags} invalid or duplicate tag(s) ignored.")
    if result.categories_created:
        lines.append("Categories created: " + ", ".join(result.categories_created) + ".")
    if preview.format_key != "moncoffre_encrypted":
        if dialogs.confirm(parent, "Import complete — delete the CSV file?",
                           " ".join(lines) + "\n\nThis file contains your passwords IN "
                           "PLAINTEXT. Deleting it now is recommended.",
                           "Delete the file", danger=True, icon="file-down"):
            try:
                path.unlink()
            except OSError as exc:
                dialogs.alert(parent, "Deletion impossible",
                              f"The file could not be deleted: {exc.strerror}.")
    else:
        dialogs.alert(parent, "Import complete", " ".join(lines), kind="info")
    return result.imported > 0


# --- Export --------------------------------------------------------------------------------


class ExportDialog(PremiumDialog):
    FORMATS = ("encrypted", "csv", "pdf")

    def __init__(self, entries: EntryService, vault: Vault, parent: QWidget | None = None,
                 initial: str = "encrypted") -> None:
        super().__init__(parent, "Export entries",
                         "The Trash and the history are not exported.",
                         icon="file-up", width=540)
        self._entries = entries
        self._vault = vault
        self.exported_path: Path | None = None
        self.exported_count = 0
        self.exported_protected = False

        self.encrypted = QRadioButton("Encrypted export (.mcfexport) — recommended")
        self.plain_csv = QRadioButton("Unencrypted CSV — to move to other software")
        self.pdf = QRadioButton("PDF — to print a paper copy")
        group = QButtonGroup(self)
        for button in (self.encrypted, self.plain_csv, self.pdf):
            group.addButton(button)
            self.body.addWidget(button)
        {"csv": self.plain_csv, "pdf": self.pdf}.get(initial, self.encrypted).setChecked(True)

        self.master = PasswordField("Vault master password", leading_icon="lock")
        self.body.addWidget(ui.label("Master password (required)", "FieldLabel"))
        self.body.addWidget(self.master)
        self.protect_pdf = ui.ToggleSwitch("Protect the PDF with a password (recommended)")
        if pdf_export.protection_available():
            self.protect_pdf.setChecked(True)
        else:  # missing dependency: reported, never bypassed
            self.protect_pdf.setEnabled(False)
            self.protect_pdf.setToolTip(pdf_export.MISSING_DEPENDENCY)
        self.protection_missing = ui.label(pdf_export.MISSING_DEPENDENCY, "Faint", wrap=True)
        self.body.addWidget(self.protect_pdf)
        self.body.addWidget(self.protection_missing)
        self._export_fields = QWidget()
        fields = QVBoxLayout(self._export_fields)
        fields.setContentsMargins(0, 0, 0, 0)
        fields.setSpacing(8)
        self.export_password = PasswordField("8 characters minimum")
        self.export_confirm = PasswordField("Confirmation")
        self.export_password_label = ui.label("Export password", "FieldLabel")
        fields.addWidget(self.export_password_label)
        fields.addWidget(self.export_password)
        fields.addWidget(self.export_confirm)
        self.pdf_note = ui.label(
            "Different from the master password. The PDF is encrypted with AES-256: this "
            "password will be asked when it is opened. The printed copy stays readable.",
            "Faint", wrap=True)
        fields.addWidget(self.pdf_note)
        self.body.addWidget(self._export_fields)

        self.warning = ui.label("", wrap=True)
        self.warning.setStyleSheet(f"color: {theme.DANGER};")
        self.acknowledge = ui.ToggleSwitch("I understand that this file will not be protected")
        self.body.addWidget(self.warning)
        self.body.addWidget(self.acknowledge)
        self.error = ui.label("", "Error", wrap=True)
        self.error.hide()
        self.body.addWidget(self.error)
        _, self.go = self.add_buttons("Cancel", "Choose location…",
                                      confirm_icon="file-up")
        self.go.clicked.connect(self._export)
        for button in (self.encrypted, self.plain_csv, self.pdf):
            button.toggled.connect(self._update_mode)
        self.acknowledge.toggled.connect(self._update_mode)
        self.protect_pdf.toggled.connect(self._update_mode)
        self._update_mode()

    @property
    def _pdf_protected(self) -> bool:
        return self.pdf.isChecked() and self.protect_pdf.isChecked()

    def _update_mode(self, *_args) -> None:
        pdf = self.pdf.isChecked()
        self.protect_pdf.setVisible(pdf)
        self.protection_missing.setVisible(pdf and not pdf_export.protection_available())
        self.pdf_note.setVisible(self._pdf_protected)
        self.export_password_label.setText(
            "PDF password" if pdf else "Export password")
        # Encrypted = .mcfexport export, or protected PDF: no warning and no confirmation.
        encrypted = self.encrypted.isChecked() or self._pdf_protected
        if pdf:
            self.warning.setText(
                "The PDF will contain ALL your passwords IN PLAINTEXT, without any protection. "
                "Print it, keep the paper copy locked away, then delete the file.")
        else:
            self.warning.setText(
                "The CSV file will contain ALL your passwords IN PLAINTEXT: any person or "
                "program with access to it will be able to read them. Delete it as soon as the "
                "move is complete.")
        self._export_fields.setVisible(encrypted)
        self.warning.setVisible(not encrypted)
        self.acknowledge.setVisible(not encrypted)
        self.go.setEnabled(encrypted or self.acknowledge.isChecked())
        self.adjustSize()

    def _fail(self, message: str) -> None:
        self.error.setText(message)
        self.error.show()

    def _export(self) -> None:
        encrypted = self.encrypted.isChecked()
        pdf = self.pdf.isChecked()
        if (encrypted or self._pdf_protected) and \
                self.export_password.text() != self.export_confirm.text():
            self._fail("The two " + ("PDF" if pdf else "export")
                       + " passwords do not match.")
            return
        if pdf:
            suffix, name, file_filter = (pdf_export.PDF_SUFFIX, "keyra-passwords",
                                         "PDF (*.pdf)")
        elif encrypted:
            suffix, name, file_filter = (import_export.EXPORT_SUFFIX, "keyra-export",
                                         "Encrypted export (*.mcfexport)")
        else:
            suffix, name, file_filter = ".csv", "keyra-export", "CSV (*.csv)"
        default = Path.home() / f"{name}-{datetime.now().astimezone():%Y%m%d}{suffix}"
        path_str, _ = QFileDialog.getSaveFileName(self, "Save the export", str(default),
                                                  file_filter)
        if not path_str:
            return
        path = Path(path_str)
        if path.suffix.lower() != suffix:
            path = path.with_name(path.name + suffix)
        try:
            with _BusyCursor():
                if pdf:
                    count = pdf_export.export_pdf(
                        self._entries, self._vault, self.master.text(), path,
                        self.export_password.text() if self._pdf_protected else None)
                elif encrypted:
                    count = import_export.export_encrypted(
                        self._entries, self._vault, self.master.text(),
                        self.export_password.text(), path)
                else:
                    count = import_export.export_csv(self._entries, self._vault,
                                                     self.master.text(), path)
        except VaultError as exc:
            self._fail(str(exc))
            return
        except OSError as exc:
            self._fail(f"Write impossible: {exc.strerror}.")
            return
        self.exported_path = path
        self.exported_count = count
        self.exported_protected = self._pdf_protected
        self.accept()

    def done(self, result: int) -> None:
        for field in (self.master, self.export_password, self.export_confirm):
            field.reset()
        super().done(result)


# --- Backups ------------------------------------------------------------------------------


def open_backup_folder(directory: Path | None = None) -> None:
    QDesktopServices.openUrl(QUrl.fromLocalFile(str(directory or default_backup_dir())))


def describe_backup_location(path: Path) -> str:
    home = str(Path.home())
    shown = str(path.parent)
    return shown.replace(home, "~", 1) if shown.startswith(home) else shown


def restore_file(parent: QWidget, path: Path) -> VaultInfo | None:
    """Restores a given .mcfbak file as a NEW vault."""
    try:
        info = backup.read_backup_info(path)
    except VaultError as exc:
        dialogs.alert(parent, "Unreadable backup", str(exc))
        return None
    prompt = PasswordPrompt(
        "Restore a backup",
        f"Backup of the vault \"{info.vault_name}\" from {_when(info.created_at)} "
        f"({backup.kind_label(info.kind)}). It will be restored as a NEW vault: the current "
        "vault is not modified. Master password in effect when the backup was made:",
        parent, icon="rotate-ccw")
    error = ""
    while True:
        password = prompt.ask(error)
        if password is None:
            return None
        try:
            with _BusyCursor():
                return backup.restore_backup(path, password)
        except WrongMasterPasswordError:
            error = "Wrong master password for this backup."
        except VaultError as exc:
            dialogs.alert(parent, "Restore impossible", str(exc))
            return None


def run_restore(parent: QWidget, start_dir: Path | None = None) -> VaultInfo | None:
    """Choice of a .mcfbak file, then restore as a new vault."""
    path_str, _ = QFileDialog.getOpenFileName(
        parent, "Restore a backup", str(start_dir or default_backup_dir()),
        "Keyra backups (*.mcfbak);;All files (*)")
    if not path_str:
        return None
    return restore_file(parent, Path(path_str))
