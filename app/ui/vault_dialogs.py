"""Vault management (master password, deletion), shortcuts, "About"."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QGridLayout, QLineEdit, QVBoxLayout, QWidget

from app import __version__
from app.core.exceptions import VaultError, WrongMasterPasswordError
from app.core.strength import estimate_strength
from app.core.vault import MIN_MASTER_PASSWORD_LENGTH, Vault, delete_vault
from app.i18n import tr
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
        super().__init__(parent, tr("password_change.title"),
                         tr("password_change.subtitle"), icon="key-round", width=500)
        self._vault = vault
        note = ui.label(tr("password_change.note"), "Faint", wrap=True)
        self.body.addWidget(note)
        self.current = PasswordField(tr("password_change.current_placeholder"))
        self.new = PasswordField(tr("password_change.new_placeholder",
                                                min=MIN_MASTER_PASSWORD_LENGTH))
        self.confirm = PasswordField(tr("password_change.confirm_placeholder"))
        self.meter = ui.StrengthBar()
        self.meter_label = ui.label("", "Faint")
        self.new.textChanged.connect(self._update_meter)
        self.body.addWidget(_labeled(tr("password_change.current"), self.current))
        self.body.addWidget(_labeled(tr("password_change.new"), self.new))
        self.body.addWidget(self.meter)
        self.body.addWidget(self.meter_label)
        self.body.addWidget(_labeled(tr("password_change.confirmation"), self.confirm))
        self.error = ui.label("", "Error", wrap=True)
        self.error.hide()
        self.body.addWidget(self.error)
        _, ok = self.add_buttons(tr("common.cancel"), tr("password_change.submit"),
                                 confirm_icon="key-round")
        ok.clicked.connect(self._submit)

    def _update_meter(self, text: str) -> None:
        if not text:
            self.meter.set_score(-1, 0)
            self.meter_label.setText("")
            return
        result = estimate_strength(text)
        self.meter.set_score(result.score, result.entropy_bits)
        self.meter_label.setText(tr("strength.summary", label=result.label,
                                    bits=f"{result.entropy_bits:.0f}"))

    def _fail(self, message: str) -> None:
        self.error.setText(message)
        self.error.show()

    def _submit(self) -> None:
        if self.new.text() != self.confirm.text():
            self._fail(tr("password_change.error.mismatch"))
            return
        if self.new.text() == self.current.text():
            self._fail(tr("password_change.error.same"))
            return
        if len(self.new.text()) >= MIN_MASTER_PASSWORD_LENGTH and \
                estimate_strength(self.new.text()).score < 2:
            self._fail(tr("password_change.error.weak"))
            return
        try:
            with _Busy():
                self._vault.change_master_password(self.current.text(), self.new.text())
        except WrongMasterPasswordError:
            self._fail(tr("vault.error.wrong_current_password"))
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
    """Strong confirmation: typing the vault name + the master password.

    The deletion is done by the caller (vault closed first) through
    `delete_vault`, which checks the password again.
    """

    def __init__(self, vault_id: str, vault_name: str, parent: QWidget | None = None) -> None:
        super().__init__(parent, tr("delete_vault.title", name=vault_name),
                         icon="triangle-alert", width=500)
        self._vault_name = vault_name
        self.entered_password = ""
        warning = ui.label(
            tr("delete_vault.warning"), wrap=True)
        warning.setStyleSheet(f"color: {theme.DANGER};")
        self.body.addWidget(warning)
        self.name = QLineEdit()
        self.name.setPlaceholderText(vault_name)
        self.password = PasswordField(tr("delete_vault.password_placeholder"))
        self.body.addWidget(_labeled(tr("delete_vault.type_name"), self.name))
        self.body.addWidget(_labeled(tr("common.master_password"), self.password))
        self.error = ui.label("", "Error", wrap=True)
        self.error.hide()
        self.body.addWidget(self.error)
        _, self.ok = self.add_buttons(tr("common.cancel"), tr("delete_vault.submit"), "Danger",
                                      "trash-2")
        self.ok.setEnabled(False)
        self.ok.clicked.connect(self._submit)
        self.name.textChanged.connect(
            lambda text: self.ok.setEnabled(" ".join(text.split()) == self._vault_name))

    def _submit(self) -> None:
        if not self.password.text():
            self.error.setText(tr("delete_vault.error.password"))
            self.error.show()
            return
        self.entered_password = self.password.text()
        self.accept()

    def done(self, result: int) -> None:
        self.password.reset()
        super().done(result)


def delete_closed_vault(vault_id: str, password: str) -> None:
    """Actual deletion (the vault must be closed). Raises VaultError."""
    with _Busy():
        delete_vault(vault_id, password)


# (keys, translation key of the description)
SHORTCUTS = (
    ("Ctrl+K", "action.palette"),
    ("Ctrl+N", "action.new_entry"),
    ("Ctrl+F", "action.search"),
    ("Ctrl+G", "action.generator"),
    ("Enter / Ctrl+E", "shortcuts.edit"),
    ("Ctrl+D", "shortcuts.duplicate"),
    ("Del", "action.delete_entry"),
    ("Ctrl+C", "shortcuts.copy_password"),
    ("Ctrl+B", "shortcuts.copy_username"),
    ("Alt+1 … Alt+6", "shortcuts.switch_view"),
    ("Ctrl+,", "action.settings"),
    ("Ctrl+L", "shortcuts.lock"),
    ("Esc", "shortcuts.escape"),
    ("F11", "action.fullscreen"),
    ("F1", "shortcuts.help"),
)


class ShortcutsDialog(PremiumDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent, tr("action.shortcuts"), icon="keyboard", width=480)
        grid = QGridLayout()
        grid.setHorizontalSpacing(20)
        grid.setVerticalSpacing(9)
        for row, (keys, action) in enumerate(SHORTCUTS):
            grid.addWidget(ui.label(keys, "Badge"), row, 0, Qt.AlignLeft)
            grid.addWidget(ui.label(tr(action), "Muted"), row, 1)
        grid.setColumnStretch(1, 1)
        self.body.addLayout(grid)
        _, ok = self.add_buttons("", tr("common.close"))
        ok.clicked.connect(self.accept)


class AboutDialog(PremiumDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent, width=420)
        halo = ui.HaloIcon(ui.BRAND, 104)
        self.body.addWidget(halo, 0, Qt.AlignHCenter)
        title = ui.label("Keyra", "H1")
        title.setAlignment(Qt.AlignCenter)
        self.body.addWidget(title)
        version = ui.label(tr("about.version", version=__version__), "BadgeAccent")
        self.body.addWidget(version, 0, Qt.AlignHCenter)
        text = ui.label(tr("about.description"), "Muted", wrap=True)
        text.setAlignment(Qt.AlignCenter)
        self.body.addWidget(text)
        credits_ = ui.label(tr("about.credits"), "Faint")
        credits_.setAlignment(Qt.AlignCenter)
        self.body.addWidget(credits_)
        _, ok = self.add_buttons("", tr("common.close"))
        ok.clicked.connect(self.accept)
