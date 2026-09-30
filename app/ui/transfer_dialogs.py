"""Import, export et restauration de sauvegarde (modales et enchaînements).

Toute la logique est dans app.services.import_export et app.services.backup ;
ce module ne fait que demander fichiers, mots de passe et confirmations.
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
        return datetime.fromisoformat(iso).astimezone().strftime("%d/%m/%Y à %H:%M")
    except ValueError:
        return iso


class PasswordPrompt(PremiumDialog):
    """Demande d'un mot de passe (champ masqué), vidé à la fermeture."""

    def __init__(self, title: str, message: str, parent: QWidget | None = None,
                 icon: str = "key-round") -> None:
        super().__init__(parent, title, icon=icon, width=460)
        self.body.addWidget(ui.label(message, "Muted", wrap=True))
        self.password = PasswordField("Mot de passe", leading_icon="lock")
        self.password.returnPressed.connect(self.accept)
        self.body.addWidget(self.password)
        self.error = ui.label("", "Error", wrap=True)
        self.error.hide()
        self.body.addWidget(self.error)
        _, ok = self.add_buttons("Annuler", "Valider")
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
        super().__init__(parent, "Importer des comptes",
                         f"{count} compte(s) détecté(s) — format : {preview.format_label}."
                         + (f" {preview.skipped_rows} ligne(s) vide(s) ignorée(s)."
                            if preview.skipped_rows else "")
                         + (f" {preview.dropped_tags} tag(s) invalide(s) ou en double "
                            "seront ignorés." if preview.dropped_tags else ""),
                         icon="file-down", width=760)
        self.body.addWidget(ui.label("Les mots de passe ne sont pas affichés dans cet aperçu.",
                                     "Faint"))
        table = QTableWidget(min(count, _PREVIEW_ROWS), 5)
        table.setHorizontalHeaderLabels(["Nom", "Identifiant", "URL", "Catégorie", "Type"])
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
            self.body.addWidget(ui.label(f"… et {count - _PREVIEW_ROWS} autre(s).", "Faint"))
        self.create_categories = ui.ToggleSwitch(
            "Créer les catégories manquantes (dossiers / groupes du fichier)")
        self.create_categories.setChecked(True)
        self.skip_duplicates = ui.ToggleSwitch(
            "Ignorer les doublons (même nom, identifiant, URL et mot de passe)")
        self.skip_duplicates.setChecked(True)
        self.body.addWidget(self.create_categories)
        self.body.addWidget(self.skip_duplicates)
        _, confirm = self.add_buttons("Annuler", f"Importer {count} compte(s)",
                                      confirm_icon="file-down")
        confirm.setEnabled(count > 0)
        confirm.clicked.connect(self.accept)


def run_import(parent: QWidget, entries: EntryService, categories: CategoryService) -> bool:
    """Enchaînement complet ; retourne True si des comptes ont été importés."""
    path_str, _ = QFileDialog.getOpenFileName(
        parent, "Importer des comptes", str(Path.home()),
        "Fichiers pris en charge (*.csv *.mcfexport);;CSV (*.csv);;"
        "Export chiffré Mon Coffre-Fort (*.mcfexport);;Tous les fichiers (*)")
    if not path_str:
        return False
    path = Path(path_str)
    try:
        if import_export.is_encrypted_export(path):
            prompt = PasswordPrompt("Export chiffré",
                                    f"Mot de passe d'export du fichier « {path.name} ».", parent)
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
        dialogs.alert(parent, "Import impossible", f"{exc}\n\nAucun compte n'a été importé.")
        return False

    lines = [f"{result.imported} compte(s) importé(s)."]
    if result.duplicates:
        lines.append(f"{result.duplicates} doublon(s) ignoré(s).")
    if result.invalid:
        lines.append(f"{result.invalid} entrée(s) invalide(s) ignorée(s).")
    if preview.dropped_tags:
        lines.append(f"{preview.dropped_tags} tag(s) invalide(s) ou en double ignoré(s).")
    if result.categories_created:
        lines.append("Catégories créées : " + ", ".join(result.categories_created) + ".")
    if preview.format_key != "moncoffre_encrypted":
        if dialogs.confirm(parent, "Import terminé — supprimer le fichier CSV ?",
                           " ".join(lines) + "\n\nCe fichier contient vos mots de passe EN "
                           "CLAIR. Il est recommandé de le supprimer maintenant.",
                           "Supprimer le fichier", danger=True, icon="file-down"):
            try:
                path.unlink()
            except OSError as exc:
                dialogs.alert(parent, "Suppression impossible",
                              f"Le fichier n'a pas pu être supprimé : {exc.strerror}.")
    else:
        dialogs.alert(parent, "Import terminé", " ".join(lines), kind="info")
    return result.imported > 0


# --- Export --------------------------------------------------------------------------------


class ExportDialog(PremiumDialog):
    FORMATS = ("encrypted", "csv", "pdf")

    def __init__(self, entries: EntryService, vault: Vault, parent: QWidget | None = None,
                 initial: str = "encrypted") -> None:
        super().__init__(parent, "Exporter les comptes",
                         "La corbeille et l'historique ne sont pas exportés.",
                         icon="file-up", width=540)
        self._entries = entries
        self._vault = vault
        self.exported_path: Path | None = None
        self.exported_count = 0
        self.exported_protected = False

        self.encrypted = QRadioButton("Export chiffré (.mcfexport) — recommandé")
        self.plain_csv = QRadioButton("CSV non chiffré — pour migrer vers un autre logiciel")
        self.pdf = QRadioButton("PDF — pour imprimer une copie papier")
        group = QButtonGroup(self)
        for button in (self.encrypted, self.plain_csv, self.pdf):
            group.addButton(button)
            self.body.addWidget(button)
        {"csv": self.plain_csv, "pdf": self.pdf}.get(initial, self.encrypted).setChecked(True)

        self.master = PasswordField("Mot de passe maître du coffre", leading_icon="lock")
        self.body.addWidget(ui.label("Mot de passe maître (requis)", "FieldLabel"))
        self.body.addWidget(self.master)
        self.protect_pdf = ui.ToggleSwitch("Protéger le PDF par un mot de passe (recommandé)")
        if pdf_export.protection_available():
            self.protect_pdf.setChecked(True)
        else:  # dépendance manquante : signalée, jamais contournée
            self.protect_pdf.setEnabled(False)
            self.protect_pdf.setToolTip(pdf_export.MISSING_DEPENDENCY)
        self.protection_missing = ui.label(pdf_export.MISSING_DEPENDENCY, "Faint", wrap=True)
        self.body.addWidget(self.protect_pdf)
        self.body.addWidget(self.protection_missing)
        self._export_fields = QWidget()
        fields = QVBoxLayout(self._export_fields)
        fields.setContentsMargins(0, 0, 0, 0)
        fields.setSpacing(8)
        self.export_password = PasswordField("8 caractères minimum")
        self.export_confirm = PasswordField("Confirmation")
        self.export_password_label = ui.label("Mot de passe de l'export", "FieldLabel")
        fields.addWidget(self.export_password_label)
        fields.addWidget(self.export_password)
        fields.addWidget(self.export_confirm)
        self.pdf_note = ui.label(
            "Différent du mot de passe maître. Le PDF est chiffré en AES-256 : ce mot de passe "
            "sera demandé à l'ouverture. La copie imprimée, elle, reste lisible.",
            "Faint", wrap=True)
        fields.addWidget(self.pdf_note)
        self.body.addWidget(self._export_fields)

        self.warning = ui.label("", wrap=True)
        self.warning.setStyleSheet(f"color: {theme.DANGER};")
        self.acknowledge = ui.ToggleSwitch("Je comprends que ce fichier ne sera pas protégé")
        self.body.addWidget(self.warning)
        self.body.addWidget(self.acknowledge)
        self.error = ui.label("", "Error", wrap=True)
        self.error.hide()
        self.body.addWidget(self.error)
        _, self.go = self.add_buttons("Annuler", "Choisir l'emplacement…",
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
            "Mot de passe du PDF" if pdf else "Mot de passe de l'export")
        # Chiffré = export .mcfexport, ou PDF protégé : ni avertissement ni confirmation.
        encrypted = self.encrypted.isChecked() or self._pdf_protected
        if pdf:
            self.warning.setText(
                "Le PDF contiendra TOUS vos mots de passe EN CLAIR, sans aucune protection. "
                "Imprimez-le, rangez la copie papier sous clé, puis supprimez le fichier.")
        else:
            self.warning.setText(
                "Le fichier CSV contiendra TOUS vos mots de passe EN CLAIR : toute personne ou "
                "tout programme y ayant accès pourra les lire. Supprimez-le dès la migration "
                "terminée.")
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
            self._fail("Les deux mots de passe " + ("du PDF" if pdf else "d'export")
                       + " ne correspondent pas.")
            return
        if pdf:
            suffix, name, file_filter = (pdf_export.PDF_SUFFIX, "mon-coffre-mots-de-passe",
                                         "PDF (*.pdf)")
        elif encrypted:
            suffix, name, file_filter = (import_export.EXPORT_SUFFIX, "mon-coffre-export",
                                         "Export chiffré (*.mcfexport)")
        else:
            suffix, name, file_filter = ".csv", "mon-coffre-export", "CSV (*.csv)"
        default = Path.home() / f"{name}-{datetime.now().astimezone():%Y%m%d}{suffix}"
        path_str, _ = QFileDialog.getSaveFileName(self, "Enregistrer l'export", str(default),
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
            self._fail(f"Écriture impossible : {exc.strerror}.")
            return
        self.exported_path = path
        self.exported_count = count
        self.exported_protected = self._pdf_protected
        self.accept()

    def done(self, result: int) -> None:
        for field in (self.master, self.export_password, self.export_confirm):
            field.reset()
        super().done(result)


# --- Sauvegardes ------------------------------------------------------------------------------


def open_backup_folder(directory: Path | None = None) -> None:
    QDesktopServices.openUrl(QUrl.fromLocalFile(str(directory or default_backup_dir())))


def describe_backup_location(path: Path) -> str:
    home = str(Path.home())
    shown = str(path.parent)
    return shown.replace(home, "~", 1) if shown.startswith(home) else shown


def restore_file(parent: QWidget, path: Path) -> VaultInfo | None:
    """Restaure un fichier .mcfbak précis en tant que NOUVEAU coffre."""
    try:
        info = backup.read_backup_info(path)
    except VaultError as exc:
        dialogs.alert(parent, "Sauvegarde illisible", str(exc))
        return None
    prompt = PasswordPrompt(
        "Restaurer une sauvegarde",
        f"Sauvegarde du coffre « {info.vault_name} » du {_when(info.created_at)} "
        f"({info.kind}). Elle sera restaurée comme un NOUVEAU coffre : le coffre actuel "
        "n'est pas modifié. Mot de passe maître en vigueur au moment de la sauvegarde :",
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
            error = "Mot de passe maître incorrect pour cette sauvegarde."
        except VaultError as exc:
            dialogs.alert(parent, "Restauration impossible", str(exc))
            return None


def run_restore(parent: QWidget, start_dir: Path | None = None) -> VaultInfo | None:
    """Choix d'un fichier .mcfbak puis restauration en tant que nouveau coffre."""
    path_str, _ = QFileDialog.getOpenFileName(
        parent, "Restaurer une sauvegarde", str(start_dir or default_backup_dir()),
        "Sauvegardes Mon Coffre-Fort (*.mcfbak);;Tous les fichiers (*)")
    if not path_str:
        return None
    return restore_file(parent, Path(path_str))
