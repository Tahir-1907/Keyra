"""Vue « Paramètres » : réglages enregistrés automatiquement, gestion du coffre, aide."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from app import __version__
from app.core.exceptions import VaultError
from app.core.generator import (
    MAX_PASSPHRASE_WORDS,
    MAX_PASSWORD_LENGTH,
    MIN_PASSPHRASE_WORDS,
    MIN_PASSWORD_LENGTH,
)
from app.services.settings import (
    AUTO_LOCK_CHOICES,
    CLIPBOARD_CHOICES,
    MAX_AUTO_BACKUPS,
    MIN_AUTO_BACKUPS,
    TRASH_RETENTION_CHOICES,
    Settings,
)
from app.ui import components as ui
from app.ui import dialogs, recovery_dialogs, theme
from app.ui.pages.base import AppContext, Page, scrolling
from app.utils.paths import documents_dir

_SEPARATORS = {"-": "Tiret  -", " ": "Espace", ".": "Point  .", "_": "Souligné  _", "": "Aucun"}


def _combo(choices: dict, current) -> QComboBox:
    combo = QComboBox()
    for text, value in choices.items():
        combo.addItem(text, value)
    combo.setCurrentIndex(max(combo.findData(current), 0))
    combo.setMinimumWidth(220)
    return combo


class _Section(QWidget):
    """Carte de réglages : titre, description, lignes « libellé — contrôle »."""

    def __init__(self, icon: str, title: str, subtitle: str, danger: bool = False) -> None:
        super().__init__()
        frame = ui.card("CardDanger" if danger else "Card")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(frame)
        self.layout_ = QVBoxLayout(frame)
        self.layout_.setContentsMargins(22, 18, 22, 18)
        self.layout_.setSpacing(14)
        head = QHBoxLayout()
        head.setSpacing(12)
        head.addWidget(ui.icon_label(icon, theme.DANGER if danger else theme.ACCENT_2, 20),
                       0, Qt.AlignTop)
        texts = QVBoxLayout()
        texts.setSpacing(2)
        texts.addWidget(ui.label(title, "H2"))
        texts.addWidget(ui.label(subtitle, "Faint", wrap=True))
        head.addLayout(texts, 1)
        self.layout_.addLayout(head)
        self.grid = QGridLayout()
        self.grid.setHorizontalSpacing(24)
        self.grid.setVerticalSpacing(12)
        self.grid.setColumnStretch(0, 1)
        self.layout_.addLayout(self.grid)

    def row(self, text: str, control: QWidget, hint: str = "") -> QLabel | None:
        """Ajoute une ligne ; retourne le libellé d'aide (modifiable ensuite) s'il y en a un."""
        row = self.grid.rowCount()
        texts = QVBoxLayout()
        texts.setSpacing(1)
        texts.addWidget(ui.label(text, wrap=True))  # passe à la ligne si la fenêtre est étroite
        hint_label = ui.label(hint, "Faint", wrap=True) if hint else None
        if hint_label is not None:
            texts.addWidget(hint_label)
        self.grid.addLayout(texts, row, 0)
        self.grid.addWidget(control, row, 1, Qt.AlignRight | Qt.AlignVCenter)
        return hint_label


class SettingsPage(Page):
    key = "settings"
    title = "Paramètres"
    subtitle = "Enregistrés automatiquement"
    icon = "settings"

    def __init__(self, ctx: AppContext) -> None:
        super().__init__(ctx)
        self._loading = False
        self._saved_toast = QTimer(self)
        self._saved_toast.setSingleShot(True)
        self._saved_toast.timeout.connect(
            lambda: self.ctx.notify("Paramètres enregistrés", icon="check"))
        layout = scrolling(self, spacing=16)
        s = ctx.settings()

        # --- Sécurité ---------------------------------------------------------------------
        security = _Section("lock-keyhole", "Sécurité", "Verrouillage et presse-papiers.")
        self.auto_lock = _combo(AUTO_LOCK_CHOICES, s.auto_lock_seconds)
        security.row("Verrouillage après inactivité", self.auto_lock,
                     "« Jamais » n'est pas recommandé.")
        self.lock_on_session = ui.ToggleSwitch()
        security.row("Verrouiller avec la session", self.lock_on_session,
                     "Écran de veille, verrouillage de session, mise en veille.")
        self.clipboard = _combo(CLIPBOARD_CHOICES, s.clipboard_clear_seconds)
        security.row("Effacer le presse-papiers après", self.clipboard)
        layout.addWidget(security)

        # --- Corbeille et sauvegardes ---------------------------------------------------------
        data = _Section("database-backup", "Corbeille et sauvegardes",
                        "Conservation et sauvegardes chiffrées automatiques.")
        self.retention = _combo(TRASH_RETENTION_CHOICES, s.trash_retention_days)
        data.row("Vider la corbeille des éléments de plus de", self.retention)
        self.auto_backup = ui.ToggleSwitch()
        data.row("Sauvegarde automatique", self.auto_backup,
                 "Au verrouillage, si le coffre a été modifié.")
        self.backups_kept = QSpinBox()
        self.backups_kept.setRange(MIN_AUTO_BACKUPS, MAX_AUTO_BACKUPS)
        self.backups_kept.setMinimumWidth(90)
        data.row("Sauvegardes automatiques conservées", self.backups_kept)
        folder = QWidget()
        folder_row = QHBoxLayout(folder)
        folder_row.setContentsMargins(0, 0, 0, 0)
        folder_row.setSpacing(6)
        self.backup_dir = QLineEdit()
        self.backup_dir.setReadOnly(True)
        self.backup_dir.setMinimumWidth(180)
        self.backup_dir.setPlaceholderText(str(documents_dir() / "MonCoffre" / "backup"))
        folder_row.addWidget(self.backup_dir)
        folder_row.addWidget(ui.icon_button("folder-open", "Choisir un dossier",
                                            on_click=self._choose_dir))
        folder_row.addWidget(ui.icon_button("rotate-ccw", "Dossier par défaut",
                                            on_click=lambda: self._set_dir("")))
        data.row("Dossier des sauvegardes", folder, "Un dossier synchronisé convient : le "
                 "contenu des sauvegardes est chiffré (seuls le nom du coffre et des "
                 "informations techniques restent lisibles).")
        layout.addWidget(data)

        # --- Générateur -----------------------------------------------------------------------
        gen = _Section("wand-sparkles", "Générateur", "Valeurs proposées par défaut.")
        self.gen_mode = _combo({"Mot de passe": "password", "Phrase de passe": "passphrase"},
                               s.generator_mode)
        gen.row("Type proposé", self.gen_mode)
        self.gen_length = QSpinBox()
        self.gen_length.setRange(MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH)
        self.gen_length.setMinimumWidth(90)
        gen.row("Longueur des mots de passe", self.gen_length)
        self.gen_toggles = {}
        for key, text in (("generator_uppercase", "Majuscules"),
                          ("generator_lowercase", "Minuscules"),
                          ("generator_digits", "Chiffres"), ("generator_symbols", "Symboles"),
                          ("generator_exclude_ambiguous", "Exclure les caractères ambigus")):
            toggle = ui.ToggleSwitch()
            gen.row(text, toggle)
            self.gen_toggles[key] = toggle
        self.pp_words = QSpinBox()
        self.pp_words.setRange(MIN_PASSPHRASE_WORDS, MAX_PASSPHRASE_WORDS)
        self.pp_words.setMinimumWidth(90)
        gen.row("Mots par phrase de passe", self.pp_words)
        self.pp_separator = _combo({v: k for k, v in _SEPARATORS.items()},
                                   s.passphrase_separator)
        gen.row("Séparateur", self.pp_separator)
        self.pp_capitalize = ui.ToggleSwitch()
        gen.row("Majuscule à chaque mot", self.pp_capitalize)
        self.pp_number = ui.ToggleSwitch()
        gen.row("Ajouter un chiffre", self.pp_number)
        layout.addWidget(gen)

        # --- Interface ------------------------------------------------------------------------
        interface = _Section("sparkles", "Interface", "Apparence et confort.")
        self.animations = ui.ToggleSwitch()
        interface.row("Animations", self.animations,
                      "Transitions, apparitions, notifications. À désactiver sur une machine "
                      "lente ou si les mouvements vous gênent.")
        layout.addWidget(interface)

        # --- Coffre -------------------------------------------------------------------------------
        vault = _Section("lock-keyhole", "Ce coffre",
                         "Nom, mot de passe maître et clé de récupération.")
        self.vault_name = ui.label("", "Muted")
        vault.row("Nom", self._with_button(self.vault_name, "Renommer…", self._rename))
        vault.row("Mot de passe maître",
                  ui.button("Changer…", "key-round",
                            on_click=lambda: self.ctx.vault_action("password")),
                  "Les sauvegardes existantes gardent l'ancien mot de passe. "
                  "La clé de récupération reste valable.")
        recovery_buttons = QWidget()
        buttons_row = QHBoxLayout(recovery_buttons)
        buttons_row.setContentsMargins(0, 0, 0, 0)
        buttons_row.setSpacing(8)
        self.recovery_create = ui.button("Créer…", "key-round",
                                         on_click=lambda: self.ctx.vault_action("recovery"))
        self.recovery_remove = ui.button("Supprimer…", "trash-2", "Ghost",
                                         on_click=lambda: self.ctx.vault_action("recovery_remove"))
        buttons_row.addWidget(self.recovery_create)
        buttons_row.addWidget(self.recovery_remove)
        self.recovery_state = vault.row("Clé de récupération", recovery_buttons, " ")
        layout.addWidget(vault)

        danger = _Section("triangle-alert", "Zone sensible",
                          "Actions définitives sur ce coffre.", danger=True)
        danger.row("Supprimer ce coffre",
                   ui.button("Supprimer…", "trash-2", "Danger",
                             on_click=lambda: self.ctx.vault_action("delete")),
                   "Nom du coffre et mot de passe maître exigés. Les sauvegardes sont "
                   "conservées.")
        layout.addWidget(danger)

        about = _Section("info", "Aide", f"Mon Coffre-Fort {__version__} · 100 % hors ligne · "
                                         "Argon2id + AES-256-GCM")
        about.row("Raccourcis clavier", ui.button("Afficher", "keyboard",
                                                  on_click=lambda: self.ctx.navigate("shortcuts")))
        about.row("À propos", ui.button("Afficher", "info",
                                        on_click=lambda: self.ctx.navigate("about")))
        layout.addWidget(about)
        layout.addStretch(1)

        for widget in (self.auto_lock, self.clipboard, self.retention, self.gen_mode,
                       self.pp_separator):
            widget.currentIndexChanged.connect(self._save)
        for widget in (self.backups_kept, self.gen_length, self.pp_words):
            widget.valueChanged.connect(self._save)
        for toggle in (self.lock_on_session, self.auto_backup, self.animations,
                       self.pp_capitalize, self.pp_number, *self.gen_toggles.values()):
            toggle.toggled.connect(self._save)
        self.refresh()

    @staticmethod
    def _with_button(widget: QWidget, text: str, action) -> QWidget:
        host = QWidget()
        row = QHBoxLayout(host)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(12)
        row.addWidget(widget)
        row.addWidget(ui.button(text, "square-pen", on_click=action))
        return host

    # --- Chargement / enregistrement -----------------------------------------------------------

    def refresh(self) -> None:
        s = self.ctx.settings()
        self._loading = True
        for combo, value in ((self.auto_lock, s.auto_lock_seconds),
                             (self.clipboard, s.clipboard_clear_seconds),
                             (self.retention, s.trash_retention_days),
                             (self.gen_mode, s.generator_mode),
                             (self.pp_separator, s.passphrase_separator)):
            combo.setCurrentIndex(max(combo.findData(value), 0))
        self.lock_on_session.setChecked(s.lock_on_session_lock)
        self.auto_backup.setChecked(s.auto_backup)
        self.backups_kept.setValue(s.auto_backups_kept)
        self.backup_dir.setText(s.backup_dir)
        self.gen_length.setValue(s.generator_length)
        for key, toggle in self.gen_toggles.items():
            toggle.setChecked(getattr(s, key))
        self.pp_words.setValue(s.passphrase_words)
        self.pp_capitalize.setChecked(s.passphrase_capitalize)
        self.pp_number.setChecked(s.passphrase_add_number)
        self.animations.setChecked(s.animations)
        if not self.ctx.vault.is_locked:
            self.vault_name.setText(self.ctx.vault.info.vault_name)
            self.refresh_recovery()
        self._loading = False

    def refresh_recovery(self) -> None:
        created = self.ctx.vault.recovery_created_at
        self.recovery_state.setText(recovery_dialogs.describe(created))
        self.recovery_state.setStyleSheet("" if created else f"color: {theme.WARNING};")
        self.recovery_create.setText("Remplacer…" if created else "Créer…")
        self.recovery_remove.setVisible(created is not None)

    def current(self) -> Settings:
        return replace(
            self.ctx.settings(),
            auto_lock_seconds=self.auto_lock.currentData(),
            lock_on_session_lock=self.lock_on_session.isChecked(),
            clipboard_clear_seconds=self.clipboard.currentData(),
            trash_retention_days=self.retention.currentData(),
            auto_backup=self.auto_backup.isChecked(),
            auto_backups_kept=self.backups_kept.value(),
            backup_dir=self.backup_dir.text(),
            generator_mode=self.gen_mode.currentData(),
            generator_length=self.gen_length.value(),
            passphrase_words=self.pp_words.value(),
            passphrase_separator=self.pp_separator.currentData(),
            passphrase_capitalize=self.pp_capitalize.isChecked(),
            passphrase_add_number=self.pp_number.isChecked(),
            animations=self.animations.isChecked(),
            **{key: toggle.isChecked() for key, toggle in self.gen_toggles.items()},
        ).validated()

    def _save(self, *_args) -> None:
        if self._loading:
            return
        classes = ("generator_uppercase", "generator_lowercase", "generator_digits",
                   "generator_symbols")
        if not any(self.gen_toggles[k].isChecked() for k in classes):
            self.ctx.notify("Au moins un type de caractères", "Le générateur en a besoin.",
                            kind="warning")
            self.refresh()
            return
        self.ctx.update_settings(self.current())
        self._saved_toast.start(600)  # une seule notification pour une rafale de changements

    def _choose_dir(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Dossier des sauvegardes",
                                                  self.backup_dir.text() or str(Path.home()))
        if chosen:
            self._set_dir(chosen)

    def _set_dir(self, value: str) -> None:
        self.backup_dir.setText(value)
        self._save()

    def _rename(self) -> None:
        current = self.ctx.vault.info.vault_name
        name = dialogs.prompt_text(self, "Renommer le coffre", "Nouveau nom", current,
                                   icon="lock-keyhole")
        if name is None:
            return
        try:
            self.ctx.vault.rename(name)
        except VaultError as exc:
            dialogs.alert(self, "Renommage impossible", str(exc))
            return
        self.refresh()
        self.ctx.changed()
        self.ctx.notify("Coffre renommé", self.ctx.vault.info.vault_name, icon="lock-keyhole")
