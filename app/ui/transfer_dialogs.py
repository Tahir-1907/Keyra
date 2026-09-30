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
from app.core.vault import MIN_MASTER_PASSWORD_LENGTH, Vault, VaultInfo
from app.i18n import tr, tr_n
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
        self.password = PasswordField(tr("field.password"), leading_icon="lock")
        self.password.returnPressed.connect(self.accept)
        self.body.addWidget(self.password)
        self.error = ui.label("", "Error", wrap=True)
        self.error.hide()
        self.body.addWidget(self.error)
        _, ok = self.add_buttons(tr("common.cancel"), tr("common.ok"))
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
        summary = tr_n("import.preview.found", count, format=preview.format_label)
        if preview.skipped_rows:
            summary += " " + tr_n("import.preview.empty_rows", preview.skipped_rows)
        if preview.dropped_tags:
            summary += " " + tr_n("import.preview.dropped_tags", preview.dropped_tags)
        super().__init__(parent, tr("import.title"), summary, icon="file-down", width=760)
        self.body.addWidget(ui.label(tr("import.preview.no_passwords"),
                                     "Faint"))
        table = QTableWidget(min(count, _PREVIEW_ROWS), 5)
        table.setHorizontalHeaderLabels([tr("field.name"), tr("field.username"), tr("field.url"),
                                         tr("field.category"), tr("field.type")])
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
            self.body.addWidget(ui.label(tr("import.preview.more", count=count - _PREVIEW_ROWS),
                                         "Faint"))
        self.create_categories = ui.ToggleSwitch(
            tr("import.preview.create_categories"))
        self.create_categories.setChecked(True)
        self.skip_duplicates = ui.ToggleSwitch(
            tr("import.preview.skip_duplicates"))
        self.skip_duplicates.setChecked(True)
        self.body.addWidget(self.create_categories)
        self.body.addWidget(self.skip_duplicates)
        _, confirm = self.add_buttons(tr("common.cancel"), tr_n("import.submit", count),
                                      confirm_icon="file-down")
        confirm.setEnabled(count > 0)
        confirm.clicked.connect(self.accept)


def run_import(parent: QWidget, entries: EntryService, categories: CategoryService) -> bool:
    """Complete flow; returns True if entries were imported."""
    path_str, _ = QFileDialog.getOpenFileName(
        parent, tr("import.title"), str(Path.home()),
        f"{tr('import.filter.supported')} (*.csv *.mcfexport);;CSV (*.csv);;"
        f"{tr('import.filter.encrypted')} (*.mcfexport);;{tr('filter.all_files')} (*)")
    if not path_str:
        return False
    path = Path(path_str)
    try:
        if import_export.is_encrypted_export(path):
            prompt = PasswordPrompt(tr("import.encrypted_title"),
                                    tr("import.export_password_of", name=path.name), parent)
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
        dialogs.alert(parent, tr("import.impossible"), str(exc))
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
        dialogs.alert(parent, tr("import.impossible"),
                      f"{exc}\n\n{tr('import.nothing_imported')}")
        return False

    lines = [tr_n("import.result.imported", result.imported)]
    if result.duplicates:
        lines.append(tr_n("import.result.duplicates", result.duplicates))
    if result.invalid:
        lines.append(tr_n("import.result.invalid", result.invalid))
    if preview.dropped_tags:
        lines.append(tr_n("import.result.dropped_tags", preview.dropped_tags))
    if result.categories_created:
        lines.append(tr("import.result.categories",
                        names=", ".join(result.categories_created)))
    if preview.format_key != "moncoffre_encrypted":
        if dialogs.confirm(parent, tr("import.delete_csv.title"),
                           " ".join(lines) + "\n\n" + tr("import.delete_csv.body"),
                           tr("import.delete_file"), danger=True, icon="file-down"):
            try:
                path.unlink()
            except OSError as exc:
                dialogs.alert(parent, tr("delete_vault.impossible"),
                              tr("import.delete_failed", reason=exc.strerror))
    else:
        dialogs.alert(parent, tr("import.complete"), " ".join(lines), kind="info")
    return result.imported > 0


# --- Export --------------------------------------------------------------------------------


class ExportDialog(PremiumDialog):
    FORMATS = ("encrypted", "csv", "pdf")

    def __init__(self, entries: EntryService, vault: Vault, parent: QWidget | None = None,
                 initial: str = "encrypted") -> None:
        super().__init__(parent, tr("export.title"),
                         tr("export.subtitle"),
                         icon="file-up", width=540)
        self._entries = entries
        self._vault = vault
        self.exported_path: Path | None = None
        self.exported_count = 0
        self.exported_protected = False

        self.encrypted = QRadioButton(tr("export.format.encrypted"))
        self.plain_csv = QRadioButton(tr("export.format.csv"))
        self.pdf = QRadioButton(tr("export.format.pdf"))
        group = QButtonGroup(self)
        for button in (self.encrypted, self.plain_csv, self.pdf):
            group.addButton(button)
            self.body.addWidget(button)
        {"csv": self.plain_csv, "pdf": self.pdf}.get(initial, self.encrypted).setChecked(True)

        self.master = PasswordField(tr("export.master_placeholder"), leading_icon="lock")
        self.body.addWidget(ui.label(tr("export.master_label"), "FieldLabel"))
        self.body.addWidget(self.master)
        self.protect_pdf = ui.ToggleSwitch(tr("export.protect_pdf"))
        if pdf_export.protection_available():
            self.protect_pdf.setChecked(True)
        else:  # missing dependency: reported, never bypassed
            self.protect_pdf.setEnabled(False)
            self.protect_pdf.setToolTip(tr(pdf_export.MISSING_DEPENDENCY))
        self.protection_missing = ui.label(tr(pdf_export.MISSING_DEPENDENCY), "Faint", wrap=True)
        self.body.addWidget(self.protect_pdf)
        self.body.addWidget(self.protection_missing)
        self._export_fields = QWidget()
        fields = QVBoxLayout(self._export_fields)
        fields.setContentsMargins(0, 0, 0, 0)
        fields.setSpacing(8)
        self.export_password = PasswordField(tr("password_change.new_placeholder",
                                                     min=MIN_MASTER_PASSWORD_LENGTH))
        self.export_confirm = PasswordField(tr("password_change.confirmation"))
        self.export_password_label = ui.label(tr("export.password"), "FieldLabel")
        fields.addWidget(self.export_password_label)
        fields.addWidget(self.export_password)
        fields.addWidget(self.export_confirm)
        self.pdf_note = ui.label(tr("export.pdf_note"), "Faint", wrap=True)
        fields.addWidget(self.pdf_note)
        self.body.addWidget(self._export_fields)

        self.warning = ui.label("", wrap=True)
        self.warning.setStyleSheet(f"color: {theme.DANGER};")
        self.acknowledge = ui.ToggleSwitch(tr("export.acknowledge"))
        self.body.addWidget(self.warning)
        self.body.addWidget(self.acknowledge)
        self.error = ui.label("", "Error", wrap=True)
        self.error.hide()
        self.body.addWidget(self.error)
        _, self.go = self.add_buttons(tr("common.cancel"), tr("recovery.pdf.choose_location"),
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
            tr("recovery.pdf.password") if pdf else tr("export.password"))
        # Encrypted = .mcfexport export, or protected PDF: no warning and no confirmation.
        encrypted = self.encrypted.isChecked() or self._pdf_protected
        if pdf:
            self.warning.setText(tr("export.warning.pdf"))
        else:
            self.warning.setText(tr("export.warning.csv"))
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
            self._fail(tr("export.error.pdf_mismatch") if pdf
                       else tr("export.error.mismatch"))
            return
        if pdf:
            suffix, name, file_filter = (pdf_export.PDF_SUFFIX, tr("export.filename.pdf"),
                                         "PDF (*.pdf)")
        elif encrypted:
            suffix, name, file_filter = (import_export.EXPORT_SUFFIX, tr("export.filename"),
                                         f"{tr('export.filter.encrypted')} (*.mcfexport)")
        else:
            suffix, name, file_filter = ".csv", tr("export.filename"), "CSV (*.csv)"
        default = Path.home() / f"{name}-{datetime.now().astimezone():%Y%m%d}{suffix}"
        path_str, _ = QFileDialog.getSaveFileName(self, tr("export.save_title"), str(default),
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
            self._fail(tr("common.error.write", reason=exc.strerror))
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
        dialogs.alert(parent, tr("restore.unreadable"), str(exc))
        return None
    prompt = PasswordPrompt(
        tr("lock.restore_backup"),
        tr("restore.prompt", name=info.vault_name, date=_when(info.created_at),
           kind=backup.kind_label(info.kind)),
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
            error = tr("restore.wrong_password")
        except VaultError as exc:
            dialogs.alert(parent, tr("restore.impossible"), str(exc))
            return None


def run_restore(parent: QWidget, start_dir: Path | None = None) -> VaultInfo | None:
    """Choice of a .mcfbak file, then restore as a new vault."""
    path_str, _ = QFileDialog.getOpenFileName(
        parent, tr("lock.restore_backup"), str(start_dir or default_backup_dir()),
        f"{tr('restore.filter')} (*.mcfbak);;{tr('filter.all_files')} (*)")
    if not path_str:
        return None
    return restore_file(parent, Path(path_str))
