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

_SEPARATORS = {"-": "Dash  -", " ": "Space", ".": "Dot  .", "_": "Underscore  _", "": "None"}


def _combo(choices: dict, current) -> QComboBox:
    combo = QComboBox()
    for text, value in choices.items():
        combo.addItem(text, value)
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
    title = "Settings"
    subtitle = "Saved automatically"
    icon = "settings"

    def __init__(self, ctx: AppContext) -> None:
        super().__init__(ctx)
        self._loading = False
        self._saved_toast = QTimer(self)
        self._saved_toast.setSingleShot(True)
        self._saved_toast.timeout.connect(
            lambda: self.ctx.notify("Settings saved", icon="check"))
        layout = scrolling(self, spacing=16)
        s = ctx.settings()

        # --- Security ---------------------------------------------------------------------
        security = _Section("lock-keyhole", "Security", "Locking and clipboard.")
        self.auto_lock = _combo(AUTO_LOCK_CHOICES, s.auto_lock_seconds)
        security.row("Lock after inactivity", self.auto_lock,
                     "\"Never\" is not recommended.")
        self.lock_on_session = ui.ToggleSwitch()
        security.row("Lock with the session", self.lock_on_session,
                     "Screen saver, session lock, sleep.")
        self.clipboard = _combo(CLIPBOARD_CHOICES, s.clipboard_clear_seconds)
        security.row("Clear the clipboard after", self.clipboard)
        layout.addWidget(security)

        # --- Trash and backups ---------------------------------------------------------
        data = _Section("database-backup", "Trash and backups",
                        "Retention and automatic encrypted backups.")
        self.retention = _combo(TRASH_RETENTION_CHOICES, s.trash_retention_days)
        data.row("Empty Trash items older than", self.retention)
        self.auto_backup = ui.ToggleSwitch()
        data.row("Automatic backup", self.auto_backup,
                 "On locking, if the vault was modified.")
        self.backups_kept = QSpinBox()
        self.backups_kept.setRange(MIN_AUTO_BACKUPS, MAX_AUTO_BACKUPS)
        self.backups_kept.setMinimumWidth(90)
        data.row("Automatic backups kept", self.backups_kept)
        folder = QWidget()
        folder_row = QHBoxLayout(folder)
        folder_row.setContentsMargins(0, 0, 0, 0)
        folder_row.setSpacing(6)
        self.backup_dir = QLineEdit()
        self.backup_dir.setReadOnly(True)
        self.backup_dir.setMinimumWidth(180)
        self.backup_dir.setPlaceholderText(str(documents_dir() / "MonCoffre" / "backup"))
        folder_row.addWidget(self.backup_dir)
        folder_row.addWidget(ui.icon_button("folder-open", "Choose a folder",
                                            on_click=self._choose_dir))
        folder_row.addWidget(ui.icon_button("rotate-ccw", "Default folder",
                                            on_click=lambda: self._set_dir("")))
        data.row("Backup folder", folder, "A synchronized folder is fine: the "
                 "backup content is encrypted (only the vault name and some "
                 "technical information stay readable).")
        layout.addWidget(data)

        # --- Generator -----------------------------------------------------------------------
        gen = _Section("wand-sparkles", "Generator", "Values suggested by default.")
        self.gen_mode = _combo({"Password": "password", "Passphrase": "passphrase"},
                               s.generator_mode)
        gen.row("Suggested type", self.gen_mode)
        self.gen_length = QSpinBox()
        self.gen_length.setRange(MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH)
        self.gen_length.setMinimumWidth(90)
        gen.row("Password length", self.gen_length)
        self.gen_toggles = {}
        for key, text in (("generator_uppercase", "Uppercase"),
                          ("generator_lowercase", "Lowercase"),
                          ("generator_digits", "Digits"), ("generator_symbols", "Symbols"),
                          ("generator_exclude_ambiguous", "Exclude ambiguous characters")):
            toggle = ui.ToggleSwitch()
            gen.row(text, toggle)
            self.gen_toggles[key] = toggle
        self.pp_words = QSpinBox()
        self.pp_words.setRange(MIN_PASSPHRASE_WORDS, MAX_PASSPHRASE_WORDS)
        self.pp_words.setMinimumWidth(90)
        gen.row("Words per passphrase", self.pp_words)
        self.pp_separator = _combo({v: k for k, v in _SEPARATORS.items()},
                                   s.passphrase_separator)
        gen.row("Separator", self.pp_separator)
        self.pp_capitalize = ui.ToggleSwitch()
        gen.row("Capitalize each word", self.pp_capitalize)
        self.pp_number = ui.ToggleSwitch()
        gen.row("Add a digit", self.pp_number)
        layout.addWidget(gen)

        # --- Interface ------------------------------------------------------------------------
        interface = _Section("sparkles", "Interface", "Appearance and comfort.")
        self.animations = ui.ToggleSwitch()
        interface.row("Animations", self.animations,
                      "Transitions, appearances, notifications. Turn off on a slow machine "
                      "or if motion bothers you.")
        layout.addWidget(interface)

        # --- Vault -------------------------------------------------------------------------------
        vault = _Section("lock-keyhole", "This vault",
                         "Name, master password and recovery key.")
        self.vault_name = ui.label("", "Muted")
        vault.row("Name", self._with_button(self.vault_name, "Rename…", self._rename))
        vault.row("Master password",
                  ui.button("Change…", "key-round",
                            on_click=lambda: self.ctx.vault_action("password")),
                  "Existing backups keep the old password. "
                  "The recovery key stays valid.")
        recovery_buttons = QWidget()
        buttons_row = QHBoxLayout(recovery_buttons)
        buttons_row.setContentsMargins(0, 0, 0, 0)
        buttons_row.setSpacing(8)
        self.recovery_create = ui.button("Create…", "key-round",
                                         on_click=lambda: self.ctx.vault_action("recovery"))
        self.recovery_remove = ui.button("Remove…", "trash-2", "Ghost",
                                         on_click=lambda: self.ctx.vault_action("recovery_remove"))
        buttons_row.addWidget(self.recovery_create)
        buttons_row.addWidget(self.recovery_remove)
        self.recovery_state = vault.row("Recovery key", recovery_buttons, " ")
        layout.addWidget(vault)

        danger = _Section("triangle-alert", "Danger zone",
                          "Irreversible actions on this vault.", danger=True)
        danger.row("Delete this vault",
                   ui.button("Delete…", "trash-2", "Danger",
                             on_click=lambda: self.ctx.vault_action("delete")),
                   "Vault name and master password required. Backups are "
                   "kept.")
        layout.addWidget(danger)

        about = _Section("info", "Help", f"Keyra {__version__} · 100% offline · "
                                         "Argon2id + AES-256-GCM")
        about.row("Keyboard shortcuts", ui.button("Show", "keyboard",
                                                  on_click=lambda: self.ctx.navigate("shortcuts")))
        about.row("About", ui.button("Show", "info",
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

    # --- Loading / saving -----------------------------------------------------------

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
        self.recovery_create.setText("Replace…" if created else "Create…")
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
            self.ctx.notify("At least one character type", "The generator needs one.",
                            kind="warning")
            self.refresh()
            return
        self.ctx.update_settings(self.current())
        self._saved_toast.start(600)  # a single notification for a burst of changes

    def _choose_dir(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Backup folder",
                                                  self.backup_dir.text() or str(Path.home()))
        if chosen:
            self._set_dir(chosen)

    def _set_dir(self, value: str) -> None:
        self.backup_dir.setText(value)
        self._save()

    def _rename(self) -> None:
        current = self.ctx.vault.info.vault_name
        name = dialogs.prompt_text(self, "Rename the vault", "New name", current,
                                   icon="lock-keyhole")
        if name is None:
            return
        try:
            self.ctx.vault.rename(name)
        except VaultError as exc:
            dialogs.alert(self, "Rename impossible", str(exc))
            return
        self.refresh()
        self.ctx.changed()
        self.ctx.notify("Vault renamed", self.ctx.vault.info.vault_name, icon="lock-keyhole")
