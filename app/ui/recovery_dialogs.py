"""Clé de récupération : affichage unique, utilisation (mot de passe oublié), gestion.

* `RecoveryKeyDialog` montre la clé UNE seule fois. Si elle est fermée sans
  que l'utilisateur confirme l'avoir notée (y compris par un verrouillage),
  la clé est aussitôt supprimée du coffre : une clé que personne n'a notée ne
  doit pas rester capable d'ouvrir le coffre.
* `RecoverVaultDialog` : clé + nouveau mot de passe maître (Argon2id en
  arrière-plan). La clé utilisée est remplacée par une nouvelle.
* `create_or_replace` / `remove` : gestion depuis les paramètres, mot de passe
  maître exigé (une session ouverte ne suffit pas).
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLineEdit,
    QWidget,
)

from app.core import recovery
from app.core.exceptions import (
    NoRecoveryKeyError,
    RecoveryKeyError,
    RecoveryKeyFormatError,
    VaultError,
    WrongMasterPasswordError,
)
from app.core.strength import estimate_strength
from app.core.vault import MIN_MASTER_PASSWORD_LENGTH, Vault
from app.services import pdf_export, vault_upgrade
from app.ui import components as ui
from app.ui import dialogs, effects, tasks, theme
from app.ui.dialogs import PremiumDialog
from app.ui.fields import PasswordField
from app.ui.secure_clipboard import SecureClipboard
from app.ui.vault_dialogs import _Busy, _labeled


def describe(created_at: str | None) -> str:
    """État lisible de la clé, pour les paramètres."""
    if not created_at:
        return "Aucune clé : un mot de passe maître oublié rendrait le coffre irrécupérable."
    from datetime import datetime

    try:
        day = datetime.fromisoformat(created_at).astimezone().strftime("%d/%m/%Y")
    except ValueError:
        return "Active."
    return f"Active, créée le {day}. Elle ouvre le coffre à elle seule."


class RecoveryKeyDialog(PremiumDialog):
    def __init__(self, key: str, clipboard: SecureClipboard,
                 on_abandoned: Callable[[], None], parent: QWidget | None = None,
                 renewed: bool = False, vault: Vault | None = None,
                 kept_if_abandoned: bool = False) -> None:
        """`kept_if_abandoned` : la clé est déjà enregistrée et `on_abandoned` ne la
        supprime pas (récupération faite, mise à niveau échouée) ; seul le texte de la
        confirmation de fermeture en dépend, jamais le comportement."""
        super().__init__(
            parent,
            "Votre nouvelle clé de récupération" if renewed else "Votre clé de récupération",
            ("L'ancienne clé ne fonctionne plus. " if renewed else "")
            + "Elle permet de retrouver l'accès au coffre si vous oubliez le mot de passe "
              "maître.", icon="key-round", width=560)
        self._key = key
        self._clipboard = clipboard
        self._on_abandoned = on_abandoned
        self._renewed = renewed
        self._kept_if_abandoned = kept_if_abandoned
        self._vault = vault
        self.confirmed = False
        self.saved_pdf: Path | None = None

        frame = QFrame()
        frame.setObjectName("Generated")
        row = QHBoxLayout(frame)
        row.setContentsMargins(20, 16, 12, 16)
        row.setSpacing(10)
        groups = key.split("-")
        self.key_label = ui.label("-".join(groups[:4]) + "\n" + "-".join(groups[4:]))
        self.key_label.setFont(theme.mono_font(20))
        self.key_label.setAccessibleName("Clé de récupération")
        row.addWidget(self.key_label, 1)
        self.copy_button = ui.CopyButton("Copier la clé", labeled=True)
        self.copy_button.clicked.connect(self._copy)
        row.addWidget(self.copy_button, 0, Qt.AlignVCenter)
        self.body.addWidget(frame)

        pdf_row = QHBoxLayout()
        pdf_row.setSpacing(10)
        self.pdf_button = ui.button("Enregistrer en PDF protégé…", "file-text",
                                    on_click=self._save_pdf)
        pdf_row.addWidget(self.pdf_button)
        self.pdf_status = ui.label("", "Faint", wrap=True)
        pdf_row.addWidget(self.pdf_status, 1)
        if not pdf_export.protection_available():  # dépendance manquante : signalée
            self.pdf_button.setEnabled(False)
            self.pdf_status.setText(pdf_export.MISSING_DEPENDENCY)
        self.body.addLayout(pdf_row)

        for icon, color, text in (
                ("square-pen", theme.ACCENT_2,
                 "Recopiez-la sur papier, ou enregistrez-la en PDF protégé par mot de passe, "
                 "et rangez-la en lieu sûr, loin de l'ordinateur (clé USB, tiroir fermé)."),
                ("shield-alert", theme.WARNING,
                 "Elle ouvre votre coffre SANS le mot de passe maître : protégez-la comme lui. "
                 "Ne la stockez pas en clair sur cet ordinateur ni dans un courriel."),
                ("eye-off", theme.TEXT_2,
                 "Elle ne sera plus jamais affichée. En cas de perte, créez-en une nouvelle "
                 "depuis Paramètres → Ce coffre.")):
            line = QHBoxLayout()
            line.setSpacing(10)
            line.addWidget(ui.icon_label(icon, color, 16), 0, Qt.AlignTop)
            line.addWidget(ui.label(text, "Muted", wrap=True), 1)
            self.body.addLayout(line)

        self.ack = ui.ToggleSwitch("J'ai noté ma clé (ou enregistré son PDF) en lieu sûr")
        self.body.addSpacing(4)
        self.body.addWidget(self.ack)
        _, self.done_button = self.add_buttons("", "Terminé", confirm_icon="check")
        self.done_button.setEnabled(False)
        self.ack.toggled.connect(self.done_button.setEnabled)
        self.done_button.clicked.connect(self._confirm)
        # Déclenché aussi par une fermeture forcée (verrouillage du coffre).
        self.finished.connect(self._on_finished)

    def _copy(self) -> None:
        self._clipboard.copy(self._key, "Clé de récupération")
        self.copy_button.confirm()

    def _save_pdf(self) -> None:
        vault_name = self._vault.info.vault_name if self._vault is not None and \
            not self._vault.is_locked else "Mon coffre"
        dialog = RecoveryPdfDialog(self._key, vault_name, self._vault, self)
        if dialog.exec() == RecoveryPdfDialog.Accepted and dialog.saved_path is not None:
            self.saved_pdf = dialog.saved_path
            self.pdf_status.setText(f"✓ PDF protégé enregistré : {dialog.saved_path.name}. "
                                    "Déplacez-le hors de cet ordinateur.")
            self.pdf_status.setStyleSheet(f"color: {theme.ACCENT_2};")

    def _confirm(self) -> None:
        self.confirmed = True
        self.accept()

    def reject(self) -> None:
        if not self.confirmed and not self._confirm_abandon():
            return
        super().reject()

    def _confirm_abandon(self) -> bool:
        old_key = " L'ancienne clé ne fonctionne déjà plus." if self._renewed else ""
        if self._kept_if_abandoned:
            return dialogs.confirm(
                self, "Fermer sans avoir noté la clé ?",
                "Cette clé de récupération reste valide : elle est déjà enregistrée dans le "
                "coffre et ne sera pas supprimée." + old_key + " Si vous ne l'avez pas "
                "notée, remplacez-la une fois le coffre ouvert (Paramètres → Ce coffre).",
                "Fermer quand même", danger=True, icon="key-round")
        return dialogs.confirm(
            self, "Ne pas garder de clé de récupération ?",
            "Vous n'avez pas confirmé l'avoir notée : elle sera supprimée du coffre." + old_key
            + " Vous pourrez en créer une depuis Paramètres → Ce coffre.",
            "Supprimer la clé", danger=True, icon="key-round")

    def _on_finished(self, _result: int) -> None:
        self.key_label.clear()
        self._key = ""
        if not self.confirmed:
            self._on_abandoned()


def _file_slug(name: str) -> str:
    ascii_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]+", "-", ascii_name.lower()).strip("-")[:40] or "coffre"


class RecoveryPdfDialog(PremiumDialog):
    """Mot de passe du PDF de la clé (toujours chiffré), puis emplacement."""

    def __init__(self, key: str, vault_name: str, vault: Vault | None,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent, "Clé de récupération en PDF",
                         "Le PDF est chiffré (AES-256) : ce mot de passe sera demandé pour "
                         "l'ouvrir.", icon="file-text", width=500)
        self._key = key
        self._vault_name = vault_name
        self._vault = vault
        self.saved_path: Path | None = None
        self.password = PasswordField("Mot de passe du PDF")
        self.confirm = PasswordField("Confirmation")
        self.confirm.returnPressed.connect(self._submit)
        self.meter = ui.StrengthBar()
        self.meter_label = ui.label("", "Faint")
        self.password.textChanged.connect(self._update_meter)
        self.body.addWidget(_labeled("Mot de passe du PDF", self.password))
        self.body.addWidget(self.meter)
        self.body.addWidget(self.meter_label)
        self.body.addWidget(_labeled("Confirmation", self.confirm))
        self.body.addWidget(ui.label(
            "Exigé « fort » et différent du mot de passe maître : la clé ouvre votre coffre à "
            "elle seule, et un PDF volé peut être attaqué hors ligne. Retenez-le ou notez-le "
            "ailleurs que sur cet ordinateur.", "Faint", wrap=True))
        self.error = ui.label("", "Error", wrap=True)
        self.error.hide()
        self.body.addWidget(self.error)
        _, ok = self.add_buttons("Annuler", "Choisir l'emplacement…", confirm_icon="file-text")
        ok.clicked.connect(self._submit)
        self.password.setFocus()

    def _update_meter(self, text: str) -> None:
        if not text:
            self.meter.set_score(-1, 0)
            self.meter_label.setText("")
            return
        result = estimate_strength(text)
        self.meter.set_score(result.score, result.entropy_bits)
        self.meter_label.setText(f"{result.label} · ~{result.entropy_bits:.0f} bits")

    def _fail(self, message: str) -> None:
        self.error.setText(message)
        self.error.show()
        effects.shake(self.card)

    def _submit(self) -> None:
        password = self.password.text()
        if password != self.confirm.text():
            self._fail("Les deux mots de passe ne correspondent pas.")
            return
        try:
            with _Busy():
                pdf_export.check_recovery_pdf_password(password, self._key, self._vault)
        except VaultError as exc:
            self._fail(str(exc))
            return
        default = Path.home() / f"cle-de-recuperation-{_file_slug(self._vault_name)}.pdf"
        path_str, _ = QFileDialog.getSaveFileName(self, "Enregistrer la clé de récupération",
                                                  str(default), "PDF (*.pdf)")
        if not path_str:
            return
        path = Path(path_str)
        if path.suffix.lower() != ".pdf":
            path = path.with_name(path.name + ".pdf")
        try:
            with _Busy():
                pdf_export.export_recovery_pdf(self._key, self._vault_name, path, password,
                                               self._vault)
        except VaultError as exc:
            self._fail(str(exc))
            return
        except OSError as exc:
            self._fail(f"Écriture impossible : {exc.strerror}.")
            return
        self.saved_path = path
        self.accept()

    def done(self, result: int) -> None:
        for field in (self.password, self.confirm):
            field.reset()
        self._key = ""
        super().done(result)


class RecoverVaultDialog(PremiumDialog):
    """Mot de passe oublié : clé de récupération → nouveau mot de passe maître."""

    def __init__(self, vault_id: str, vault_name: str, parent: QWidget | None = None,
                 upgrade_backup_dir: Path | None = None) -> None:
        super().__init__(parent, "Mot de passe maître oublié",
                         f"Coffre « {vault_name} ». Saisissez la clé de récupération notée à "
                         "sa création, puis choisissez un nouveau mot de passe maître.",
                         icon="key-round", width=520)
        self._vault_id = vault_id
        self._busy = False
        # Coffre d'une version précédente (mise à niveau déjà confirmée) : récupération,
        # puis mise à niveau et vérification, dans la même tâche d'arrière-plan.
        self._upgrade_dir = upgrade_backup_dir
        self.vault: Vault | None = None
        self.new_key = ""
        self.upgrade_result = None  # vault_upgrade.UpgradeResult
        # Récupération faite mais mise à niveau échouée : nouvelle clé à montrer.
        self.orphan_key = ""
        self.upgrade_error = ""

        self.key = QLineEdit()
        self.key.setObjectName("Secret")
        self.key.setFont(theme.mono_font(15))
        self.key.setPlaceholderText("XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX")
        self.key.setMinimumHeight(42)
        self.key.textEdited.connect(self._format_key)
        self.new = PasswordField(f"{MIN_MASTER_PASSWORD_LENGTH} caractères minimum")
        self.confirm = PasswordField("Confirmez le nouveau mot de passe")
        self.confirm.returnPressed.connect(self._submit)
        self.meter = ui.StrengthBar()
        self.meter_label = ui.label("", "Faint")
        self.new.textChanged.connect(self._update_meter)
        self.body.addWidget(_labeled("Clé de récupération", self.key))
        self.body.addWidget(_labeled("Nouveau mot de passe maître", self.new))
        self.body.addWidget(self.meter)
        self.body.addWidget(self.meter_label)
        self.body.addWidget(_labeled("Confirmation", self.confirm))
        self.body.addWidget(ui.label(
            ("Le coffre sera ensuite mis à niveau (sauvegarde chiffrée préalable). "
             if upgrade_backup_dir is not None else "Vos données ne sont pas réécrites. ")
            + "Une nouvelle clé de récupération vous sera donnée : celle-ci ne fonctionnera "
              "plus.", "Faint", wrap=True))
        self.error = ui.label("", "Error", wrap=True)
        self.error.hide()
        self.body.addWidget(self.error)
        busy = QWidget()
        busy_row = QHBoxLayout(busy)
        busy_row.setContentsMargins(0, 0, 0, 0)
        self.spinner = effects.Spinner(16)
        busy_row.addStretch(1)
        busy_row.addWidget(self.spinner)
        busy_row.addWidget(ui.label(
            "Récupération et mise à niveau en cours…" if upgrade_backup_dir is not None
            else "Vérification de la clé (Argon2id)…", "Muted"))
        busy_row.addStretch(1)
        busy.hide()
        self.busy_row = busy
        self.body.addWidget(busy)
        self.cancel, self.ok = self.add_buttons(
            "Annuler", "Réinitialiser, mettre à niveau et ouvrir"
            if upgrade_backup_dir is not None else "Réinitialiser et ouvrir",
            confirm_icon="lock-open")
        self.ok.clicked.connect(self._submit)
        self.key.setFocus()

    def _format_key(self, text: str) -> None:
        """Groupes de 4 affichés automatiquement pendant la saisie."""
        compact = "".join(ch for ch in text.upper() if ch.isalnum())[:32]
        formatted = recovery.format_key(compact)
        if formatted != text:
            self.key.setText(formatted)

    def _update_meter(self, text: str) -> None:
        if not text:
            self.meter.set_score(-1, 0)
            self.meter_label.setText("")
            return
        result = estimate_strength(text)
        self.meter.set_score(result.score, result.entropy_bits)
        self.meter_label.setText(f"{result.label} · ~{result.entropy_bits:.0f} bits")

    def _fail(self, message: str) -> None:
        self.error.setText(message)
        self.error.show()
        effects.shake(self.card)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        for widget in (self.key, self.new, self.confirm, self.ok, self.cancel):
            widget.setEnabled(not busy)
        self.busy_row.setVisible(busy)
        if busy:
            self.error.hide()
            self.spinner.start()
        else:
            self.spinner.stop()

    def _submit(self) -> None:
        if self._busy:
            return
        key, password = self.key.text(), self.new.text()
        try:
            recovery.normalize(key)  # faute de frappe signalée tout de suite
        except RecoveryKeyFormatError as exc:
            self._fail(str(exc))
            self.key.setFocus()
            return
        if password != self.confirm.text():
            self._fail("Les deux mots de passe ne correspondent pas.")
            return
        if len(password) >= MIN_MASTER_PASSWORD_LENGTH and estimate_strength(password).score < 2:
            self._fail("Ce mot de passe maître est trop facile à deviner. "
                       "Une phrase de passe de 5 à 6 mots est recommandée.")
            return
        self._set_busy(True)
        if self._upgrade_dir is not None:
            directory = self._upgrade_dir
            tasks.run_task(lambda: vault_upgrade.recover_and_upgrade(
                self._vault_id, key, password, directory), self._on_recovered,
                self._on_failed, self)
            return
        tasks.run_task(lambda: Vault.recover(self._vault_id, key, password),
                       self._on_recovered, self._on_failed, self)

    def is_busy(self) -> bool:
        return self._busy

    def _on_recovered(self, result) -> None:
        if self._upgrade_dir is not None:
            self.upgrade_result, self.new_key = result
            self.vault = self.upgrade_result.vault
        else:
            self.vault, self.new_key = result
        self._set_busy(False)
        self.accept()

    def _on_failed(self, exc: Exception) -> None:
        self._set_busy(False)
        orphan = getattr(exc, "new_recovery_key", "")
        if orphan:
            # Nouveau mot de passe et nouvelle clé déjà enregistrés : l'ancienne clé ne
            # marche plus. On ferme pour que la nouvelle clé soit montrée sans délai.
            self.orphan_key, self.upgrade_error = orphan, str(exc)
            self.done(PremiumDialog.Rejected)
            return
        if isinstance(exc, (RecoveryKeyFormatError, NoRecoveryKeyError)):
            message = str(exc)
        elif isinstance(exc, RecoveryKeyError):
            message = "Clé de récupération incorrecte pour ce coffre."
        elif isinstance(exc, VaultError):
            message = str(exc)
        else:
            message = "La récupération a échoué."
        self._fail(message)

    def reject(self) -> None:
        if not self._busy:  # jamais pendant la dérivation : le résultat serait perdu
            super().reject()

    def done(self, result: int) -> None:
        self.key.clear()
        for field in (self.new, self.confirm):
            field.reset()
        super().done(result)


class _MasterPasswordPrompt(PremiumDialog):
    def __init__(self, parent: QWidget | None, title: str, text: str, confirm_text: str,
                 danger: bool) -> None:
        super().__init__(parent, title, icon="key-round", width=460,
                         icon_color=theme.DANGER if danger else theme.ACCENT_2)
        self.body.addWidget(ui.label(text, "Muted", wrap=True))
        self.password = PasswordField("Mot de passe maître", leading_icon="lock")
        self.password.returnPressed.connect(self.accept)
        self.body.addWidget(self.password)
        _, ok = self.add_buttons("Annuler", confirm_text, "Danger" if danger else "Primary")
        ok.clicked.connect(self.accept)
        self.password.setFocus()


def _ask_master_password(parent: QWidget, title: str, text: str, confirm_text: str,
                         danger: bool = False) -> str | None:
    dialog = _MasterPasswordPrompt(parent, title, text, confirm_text, danger)
    accepted = dialog.exec() == PremiumDialog.Accepted
    password = dialog.password.text()
    dialog.password.reset()
    return password if accepted and password else None


def show_key(parent: QWidget, vault: Vault, key: str, clipboard: SecureClipboard,
             on_changed: Callable[[], None] = lambda: None,
             renewed: bool = False) -> RecoveryKeyDialog:
    """Affiche la clé (fenêtre non bloquante) ; supprimée si l'affichage est abandonné."""

    def abandoned() -> None:
        if not vault.is_locked:
            vault.discard_recovery_key()
        on_changed()

    dialog = RecoveryKeyDialog(key, clipboard, abandoned, parent, renewed, vault)
    dialog.setAttribute(Qt.WA_DeleteOnClose)
    dialog.open()
    return dialog


def create_or_replace(parent: QWidget, vault: Vault, clipboard: SecureClipboard,
                      on_changed: Callable[[], None]) -> RecoveryKeyDialog | None:
    replacing = vault.has_recovery_key
    password = _ask_master_password(
        parent, "Remplacer la clé de récupération" if replacing else
        "Créer une clé de récupération",
        ("L'ancienne clé cessera immédiatement de fonctionner. " if replacing else "")
        + "Confirmez avec votre mot de passe maître.",
        "Remplacer la clé" if replacing else "Créer la clé")
    if password is None:
        return None
    try:
        with _Busy():
            key = vault.create_recovery_key(password)
    except WrongMasterPasswordError:
        dialogs.alert(parent, "Clé non créée", "Mot de passe maître incorrect.")
        return None
    except VaultError as exc:
        dialogs.alert(parent, "Clé non créée", str(exc))
        return None
    on_changed()
    return show_key(parent, vault, key, clipboard, on_changed, renewed=replacing)


def remove(parent: QWidget, vault: Vault, on_changed: Callable[[], None]) -> bool:
    password = _ask_master_password(
        parent, "Supprimer la clé de récupération ?",
        "Sans clé, un mot de passe maître oublié rend le coffre définitivement "
        "irrécupérable. Confirmez avec votre mot de passe maître.",
        "Supprimer la clé", danger=True)
    if password is None:
        return False
    try:
        with _Busy():
            vault.remove_recovery_key(password)
    except WrongMasterPasswordError:
        dialogs.alert(parent, "Clé conservée", "Mot de passe maître incorrect.")
        return False
    on_changed()
    return True
