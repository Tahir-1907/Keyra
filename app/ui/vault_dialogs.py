"""Gestion du coffre (mot de passe maître, suppression), raccourcis, « À propos »."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QGridLayout, QLineEdit, QVBoxLayout, QWidget

from app import __version__
from app.core.exceptions import VaultError, WrongMasterPasswordError
from app.core.strength import estimate_strength
from app.core.vault import MIN_MASTER_PASSWORD_LENGTH, Vault, delete_vault
from app.ui import components as ui
from app.ui import theme
from app.ui.dialogs import PremiumDialog
from app.ui.fields import PasswordField


class _Busy:
    def __enter__(self):
        QGuiApplication.setOverrideCursor(Qt.WaitCursor)
        QGuiApplication.processEvents()

    def __exit__(self, *exc):
        QGuiApplication.restoreOverrideCursor()
        return False


def _labeled(title: str, widget: QWidget) -> QWidget:
    host = QWidget()
    layout = QVBoxLayout(host)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(6)
    layout.addWidget(ui.label(title, "FieldLabel"))
    layout.addWidget(widget)
    return host


class ChangeMasterPasswordDialog(PremiumDialog):
    def __init__(self, vault: Vault, parent: QWidget | None = None) -> None:
        super().__init__(parent, "Changer le mot de passe maître",
                         "Seule la clé enveloppée est rechiffrée : vos données ne sont pas "
                         "réécrites.", icon="key-round", width=500)
        self._vault = vault
        note = ui.label("Les sauvegardes déjà créées restent protégées par l'ANCIEN mot de "
                        "passe. Une nouvelle sauvegarde est créée juste après le changement.",
                        "Faint", wrap=True)
        self.body.addWidget(note)
        self.current = PasswordField("Mot de passe maître actuel")
        self.new = PasswordField(f"{MIN_MASTER_PASSWORD_LENGTH} caractères minimum")
        self.confirm = PasswordField("Confirmez le nouveau mot de passe")
        self.meter = ui.StrengthBar()
        self.meter_label = ui.label("", "Faint")
        self.new.textChanged.connect(self._update_meter)
        self.body.addWidget(_labeled("Mot de passe actuel", self.current))
        self.body.addWidget(_labeled("Nouveau mot de passe", self.new))
        self.body.addWidget(self.meter)
        self.body.addWidget(self.meter_label)
        self.body.addWidget(_labeled("Confirmation", self.confirm))
        self.error = ui.label("", "Error", wrap=True)
        self.error.hide()
        self.body.addWidget(self.error)
        _, ok = self.add_buttons("Annuler", "Changer le mot de passe", confirm_icon="key-round")
        ok.clicked.connect(self._submit)

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

    def _submit(self) -> None:
        if self.new.text() != self.confirm.text():
            self._fail("Les deux nouveaux mots de passe ne correspondent pas.")
            return
        if self.new.text() == self.current.text():
            self._fail("Le nouveau mot de passe doit être différent de l'actuel.")
            return
        if len(self.new.text()) >= MIN_MASTER_PASSWORD_LENGTH and \
                estimate_strength(self.new.text()).score < 2:
            self._fail("Ce mot de passe maître est trop facile à deviner. "
                       "Une phrase de passe de 5 à 6 mots est recommandée.")
            return
        try:
            with _Busy():
                self._vault.change_master_password(self.current.text(), self.new.text())
        except WrongMasterPasswordError:
            self._fail("Le mot de passe maître actuel est incorrect.")
            return
        except VaultError as exc:
            self._fail(str(exc))
            return
        self.accept()

    def done(self, result: int) -> None:
        for field in (self.current, self.new, self.confirm):
            field.reset()
        super().done(result)


class DeleteVaultDialog(PremiumDialog):
    """Confirmation forte : saisie du nom du coffre + mot de passe maître.

    La suppression est faite par l'appelant (coffre fermé d'abord) via
    `delete_vault`, qui revérifie le mot de passe.
    """

    def __init__(self, vault_id: str, vault_name: str, parent: QWidget | None = None) -> None:
        super().__init__(parent, f"Supprimer le coffre « {vault_name} » ?",
                         icon="triangle-alert", width=500)
        self._vault_name = vault_name
        self.entered_password = ""
        warning = ui.label(
            "Le coffre et TOUT son contenu (comptes, historique, corbeille) seront supprimés "
            "définitivement de cet ordinateur. Les fichiers de sauvegarde (.mcfbak) sont "
            "conservés et permettront de le restaurer.", wrap=True)
        warning.setStyleSheet(f"color: {theme.DANGER};")
        self.body.addWidget(warning)
        self.name = QLineEdit()
        self.name.setPlaceholderText(vault_name)
        self.password = PasswordField("Mot de passe maître de ce coffre")
        self.body.addWidget(_labeled("Tapez le nom du coffre pour confirmer", self.name))
        self.body.addWidget(_labeled("Mot de passe maître", self.password))
        self.error = ui.label("", "Error", wrap=True)
        self.error.hide()
        self.body.addWidget(self.error)
        _, self.ok = self.add_buttons("Annuler", "Supprimer définitivement", "Danger", "trash-2")
        self.ok.setEnabled(False)
        self.ok.clicked.connect(self._submit)
        self.name.textChanged.connect(
            lambda text: self.ok.setEnabled(" ".join(text.split()) == self._vault_name))

    def _submit(self) -> None:
        if not self.password.text():
            self.error.setText("Saisissez le mot de passe maître.")
            self.error.show()
            return
        self.entered_password = self.password.text()
        self.accept()

    def done(self, result: int) -> None:
        self.password.reset()
        super().done(result)


def delete_closed_vault(vault_id: str, password: str) -> None:
    """Suppression effective (le coffre doit être fermé). Lève VaultError."""
    with _Busy():
        delete_vault(vault_id, password)


SHORTCUTS = (
    ("Ctrl+K", "Palette de commandes"),
    ("Ctrl+N", "Nouveau compte"),
    ("Ctrl+F", "Rechercher"),
    ("Ctrl+G", "Générateur de mots de passe"),
    ("Entrée / Ctrl+E", "Modifier le compte sélectionné"),
    ("Ctrl+D", "Dupliquer le compte sélectionné"),
    ("Suppr", "Déplacer vers la corbeille"),
    ("Ctrl+C", "Copier le mot de passe (liste)"),
    ("Ctrl+B", "Copier l'identifiant (liste)"),
    ("Alt+1 … Alt+6", "Changer de vue"),
    ("Ctrl+,", "Paramètres"),
    ("Ctrl+L", "Verrouiller le coffre"),
    ("Échap", "Fermer / effacer la recherche"),
    ("F11", "Plein écran"),
    ("F1", "Cette aide"),
)


class ShortcutsDialog(PremiumDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent, "Raccourcis clavier", icon="keyboard", width=480)
        grid = QGridLayout()
        grid.setHorizontalSpacing(20)
        grid.setVerticalSpacing(9)
        for row, (keys, action) in enumerate(SHORTCUTS):
            grid.addWidget(ui.label(keys, "Badge"), row, 0, Qt.AlignLeft)
            grid.addWidget(ui.label(action, "Muted"), row, 1)
        grid.setColumnStretch(1, 1)
        self.body.addLayout(grid)
        _, ok = self.add_buttons("", "Fermer")
        ok.clicked.connect(self.accept)


class AboutDialog(PremiumDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent, width=420)
        halo = ui.HaloIcon("shield-check", 104)
        self.body.addWidget(halo, 0, Qt.AlignHCenter)
        title = ui.label("Mon Coffre-Fort", "H1")
        title.setAlignment(Qt.AlignCenter)
        self.body.addWidget(title)
        version = ui.label(f"Version {__version__}", "BadgeAccent")
        self.body.addWidget(version, 0, Qt.AlignHCenter)
        text = ui.label("Gestionnaire de mots de passe local, hors ligne et chiffré.\n"
                        "Argon2id + AES-256-GCM (chiffrement en enveloppe).\n"
                        "Aucune donnée n'est envoyée sur Internet.", "Muted", wrap=True)
        text.setAlignment(Qt.AlignCenter)
        self.body.addWidget(text)
        credits_ = ui.label("Police Inter (OFL) · Icônes Lucide (ISC)", "Faint")
        credits_.setAlignment(Qt.AlignCenter)
        self.body.addWidget(credits_)
        _, ok = self.add_buttons("", "Fermer")
        ok.clicked.connect(self.accept)
