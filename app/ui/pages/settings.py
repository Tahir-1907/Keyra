"""The "Settings" view: automatically saved preferences, vault management, help."""

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

from app import __version__, i18n
from app.core.exceptions import VaultError
from app.core.generator import (
    MAX_PASSPHRASE_WORDS,
    MAX_PASSWORD_LENGTH,
    MIN_PASSPHRASE_WORDS,
    MIN_PASSWORD_LENGTH,
)
from app.i18n import LOCALES, tr
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

# Separator -> translation key of its label.
_SEPARATORS = {"-": "separator.dash", " ": "separator.space", ".": "separator.dot",
               "_": "separator.underscore", "": "separator.none"}


def _combo(choices: dict, current) -> QComboBox:
    """Choices: translation key of the label -> stored value."""
    combo = QComboBox()
    for key, value in choices.items():
        combo.addItem(tr(key), value)
    combo.setCurrentIndex(max(combo.findData(current), 0))
    combo.setMinimumWidth(220)
    return combo


class _Section(QWidget):
    """Settings card: title, description, "label — control" rows."""

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
        """Adds a row; returns the help label (editable later) if there is one."""
        row = self.grid.rowCount()
        texts = QVBoxLayout()
        texts.setSpacing(1)
        texts.addWidget(ui.label(text, wrap=True))  # wraps if the window is narrow
        hint_label = ui.label(hint, "Faint", wrap=True) if hint else None
        if hint_label is not None:
            texts.addWidget(hint_label)
        self.grid.addLayout(texts, row, 0)
        self.grid.addWidget(control, row, 1, Qt.AlignRight | Qt.AlignVCenter)
        return hint_label


class SettingsPage(Page):
    key = "settings"
    title_key = "page.settings.title"
    subtitle_key = "page.settings.subtitle"
    icon = "settings"

    def __init__(self, ctx: AppContext) -> None:
        super().__init__(ctx)
        self._loading = False
        self._saved_toast = QTimer(self)
        self._saved_toast.setSingleShot(True)
        self._saved_toast.timeout.connect(
            lambda: self.ctx.notify(tr("settings.saved"), icon="check"))
        layout = scrolling(self, spacing=16)
        s = ctx.settings()

        # --- Language ---------------------------------------------------------------------
        language = _Section("globe", tr("settings.language.title"),
                            tr("settings.language.subtitle"))
        self.language = QComboBox()
        # "System default" names the language it currently resolves to.
        self.language.addItem(tr("settings.language.system",
                                 language=LOCALES[i18n.detector.detect()]), i18n.SYSTEM)
        for locale, name in LOCALES.items():  # native names, never translated
            self.language.addItem(name, locale)
        self.language.setMinimumWidth(220)
        language.row(tr("settings.language.label"), self.language,
                     tr("settings.language.hint"))
        layout.addWidget(language)

        # --- Security ---------------------------------------------------------------------
        security = _Section("lock-keyhole", tr("settings.security.title"),
                            tr("settings.security.subtitle"))
        self.auto_lock = _combo(AUTO_LOCK_CHOICES, s.auto_lock_seconds)
        security.row(tr("settings.auto_lock"), self.auto_lock,
                     tr("settings.auto_lock.hint", never=tr("choice.never")))
        self.lock_on_session = ui.ToggleSwitch()
        security.row(tr("settings.lock_on_session"), self.lock_on_session,
                     tr("settings.lock_on_session.hint"))
        self.clipboard = _combo(CLIPBOARD_CHOICES, s.clipboard_clear_seconds)
        security.row(tr("settings.clipboard"), self.clipboard)
        layout.addWidget(security)

        # --- Trash and backups ---------------------------------------------------------
        data = _Section("database-backup", tr("settings.data.title"),
                        tr("settings.data.subtitle"))
        self.retention = _combo(TRASH_RETENTION_CHOICES, s.trash_retention_days)
        data.row(tr("settings.trash_retention"), self.retention)
        self.auto_backup = ui.ToggleSwitch()
        data.row(tr("settings.auto_backup"), self.auto_backup,
                 tr("settings.auto_backup.hint"))
        self.backups_kept = QSpinBox()
        self.backups_kept.setRange(MIN_AUTO_BACKUPS, MAX_AUTO_BACKUPS)
        self.backups_kept.setMinimumWidth(90)
        data.row(tr("settings.backups_kept"), self.backups_kept)
        folder = QWidget()
        folder_row = QHBoxLayout(folder)
        folder_row.setContentsMargins(0, 0, 0, 0)
        folder_row.setSpacing(6)
        self.backup_dir = QLineEdit()
        self.backup_dir.setReadOnly(True)
        self.backup_dir.setMinimumWidth(180)
        self.backup_dir.setPlaceholderText(str(documents_dir() / "MonCoffre" / "backup"))
        folder_row.addWidget(self.backup_dir)
        folder_row.addWidget(ui.icon_button("folder-open", tr("settings.backup_dir.choose"),
                                            on_click=self._choose_dir))
        folder_row.addWidget(ui.icon_button("rotate-ccw", tr("settings.backup_dir.default"),
                                            on_click=lambda: self._set_dir("")))
        data.row(tr("settings.backup_dir"), folder, tr("settings.backup_dir.hint"))
        layout.addWidget(data)

        # --- Generator -----------------------------------------------------------------------
        gen = _Section("wand-sparkles", tr("settings.generator.title"),
                       tr("settings.generator.subtitle"))
        self.gen_mode = _combo({"generator.mode.password": "password",
                                "generator.mode.passphrase": "passphrase"}, s.generator_mode)
        gen.row(tr("settings.generator.mode"), self.gen_mode)
        self.gen_length = QSpinBox()
        self.gen_length.setRange(MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH)
        self.gen_length.setMinimumWidth(90)
        gen.row(tr("settings.generator.length"), self.gen_length)
        self.gen_toggles = {}
        for key, text in (("generator_uppercase", tr("generator.uppercase")),
                          ("generator_lowercase", tr("generator.lowercase")),
                          ("generator_digits", tr("generator.digits")),
                          ("generator_symbols", tr("generator.symbols")),
                          ("generator_exclude_ambiguous", tr("generator.exclude_ambiguous"))):
            toggle = ui.ToggleSwitch()
            gen.row(text, toggle)
            self.gen_toggles[key] = toggle
        self.pp_words = QSpinBox()
        self.pp_words.setRange(MIN_PASSPHRASE_WORDS, MAX_PASSPHRASE_WORDS)
        self.pp_words.setMinimumWidth(90)
        gen.row(tr("settings.generator.words"), self.pp_words)
        self.pp_separator = _combo({v: k for k, v in _SEPARATORS.items()},
                                   s.passphrase_separator)
        gen.row(tr("generator.separator"), self.pp_separator)
        self.pp_capitalize = ui.ToggleSwitch()
        gen.row(tr("generator.capitalize"), self.pp_capitalize)
        self.pp_number = ui.ToggleSwitch()
        gen.row(tr("generator.add_number"), self.pp_number)
        layout.addWidget(gen)

        # --- Interface ------------------------------------------------------------------------
        interface = _Section("sparkles", tr("settings.interface.title"),
                             tr("settings.interface.subtitle"))
        self.animations = ui.ToggleSwitch()
        interface.row(tr("action.animations"), self.animations,
                      tr("settings.animations.hint"))
        layout.addWidget(interface)

        # --- Vault -------------------------------------------------------------------------------
        vault = _Section("lock-keyhole", tr("settings.vault.title"),
                         tr("settings.vault.subtitle"))
        self.vault_name = ui.label("", "Muted")
        vault.row(tr("field.name"), self._with_button(self.vault_name, tr("settings.vault.rename"),
                                                      self._rename))
        vault.row(tr("common.master_password"),
                  ui.button(tr("settings.vault.change"), "key-round",
                            on_click=lambda: self.ctx.vault_action("password")),
                  tr("settings.vault.change.hint"))
        recovery_buttons = QWidget()
        buttons_row = QHBoxLayout(recovery_buttons)
        buttons_row.setContentsMargins(0, 0, 0, 0)
        buttons_row.setSpacing(8)
        self.recovery_create = ui.button(tr("settings.vault.recovery_create"), "key-round",
                                         on_click=lambda: self.ctx.vault_action("recovery"))
        self.recovery_remove = ui.button(tr("settings.vault.recovery_remove"), "trash-2", "Ghost",
                                         on_click=lambda: self.ctx.vault_action("recovery_remove"))
        buttons_row.addWidget(self.recovery_create)
        buttons_row.addWidget(self.recovery_remove)
        self.recovery_state = vault.row(tr("common.recovery_key"), recovery_buttons, " ")
        layout.addWidget(vault)

        danger = _Section("triangle-alert", tr("settings.danger.title"),
                          tr("settings.danger.subtitle"), danger=True)
        danger.row(tr("settings.danger.delete"),
                   ui.button(tr("settings.danger.delete_button"), "trash-2", "Danger",
                             on_click=lambda: self.ctx.vault_action("delete")),
                   tr("settings.danger.delete.hint"))
        layout.addWidget(danger)

        about = _Section("info", tr("settings.help.title"),
                         tr("settings.help.subtitle", version=__version__))
        about.row(tr("action.shortcuts"), ui.button(tr("common.show"), "keyboard",
                                                  on_click=lambda: self.ctx.navigate("shortcuts")))
        about.row(tr("settings.help.about"), ui.button(tr("common.show"), "info",
                                        on_click=lambda: self.ctx.navigate("about")))
        layout.addWidget(about)
        layout.addStretch(1)

        for widget in (self.language, self.auto_lock, self.clipboard, self.retention,
                       self.gen_mode, self.pp_separator):
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

    # --- Loading / saving -----------------------------------------------------------

    def refresh(self) -> None:
        s = self.ctx.settings()
        self._loading = True
        for combo, value in ((self.language, s.language),
                             (self.auto_lock, s.auto_lock_seconds),
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
        self.recovery_create.setText(tr("settings.vault.recovery_replace") if created
                                     else tr("settings.vault.recovery_create"))
        self.recovery_remove.setVisible(created is not None)

    def current(self) -> Settings:
        return replace(
            self.ctx.settings(),
            language=self.language.currentData(),
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
            self.ctx.notify(tr("settings.generator.need_class"),
                            tr("settings.generator.need_class.body"),
                            kind="warning")
            self.refresh()
            return
        self.ctx.update_settings(self.current())
        self._saved_toast.start(600)  # a single notification for a burst of changes

    def _choose_dir(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, tr("settings.backup_dir"),
                                                  self.backup_dir.text() or str(Path.home()))
        if chosen:
            self._set_dir(chosen)

    def _set_dir(self, value: str) -> None:
        self.backup_dir.setText(value)
        self._save()

    def _rename(self) -> None:
        current = self.ctx.vault.info.vault_name
        name = dialogs.prompt_text(self, tr("settings.vault.rename_title"),
                                   tr("settings.vault.new_name"), current,
                                   icon="lock-keyhole")
        if name is None:
            return
        try:
            self.ctx.vault.rename(name)
        except VaultError as exc:
            dialogs.alert(self, tr("settings.vault.rename_impossible"), str(exc))
            return
        self.refresh()
        self.ctx.changed()
        self.ctx.notify(tr("settings.vault.renamed"), self.ctx.vault.info.vault_name,
                        icon="lock-keyhole")
