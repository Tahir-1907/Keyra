"""Recovery key: single display, use (forgotten password), management.

* `RecoveryKeyDialog` shows the key ONCE only. If it is closed without the
  user confirming they wrote it down (including through a lock), the key is
  immediately removed from the vault: a key that nobody wrote down must not
  remain able to open the vault.
* `RecoverVaultDialog`: key + new master password (Argon2id in the
  background). The key used is replaced by a new one.
* `create_or_replace` / `remove`: management from the settings, master
  password required (an open session is not enough).
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
from app.i18n import tr
from app.services import pdf_export, vault_upgrade
from app.ui import components as ui
from app.ui import dialogs, effects, tasks, theme
from app.ui.dialogs import PremiumDialog
from app.ui.fields import PasswordField
from app.ui.secure_clipboard import SecureClipboard
from app.ui.vault_dialogs import _Busy, _labeled


def describe(created_at: str | None) -> str:
    """Readable state of the key, for the settings."""
    if not created_at:
        return tr("recovery.state.none")
    from datetime import datetime

    try:
        day = datetime.fromisoformat(created_at).astimezone().strftime("%Y-%m-%d")
    except ValueError:
        return tr("recovery.state.active")
    return tr("recovery.state.active_since", date=day)


class RecoveryKeyDialog(PremiumDialog):
    def __init__(self, key: str, clipboard: SecureClipboard,
                 on_abandoned: Callable[[], None], parent: QWidget | None = None,
                 renewed: bool = False, vault: Vault | None = None,
                 kept_if_abandoned: bool = False) -> None:
        """`kept_if_abandoned`: the key is already saved and `on_abandoned` does not
        remove it (recovery done, upgrade failed); only the text of the close
        confirmation depends on it, never the behavior."""
        super().__init__(
            parent,
            tr("recovery.show.title_renewed") if renewed else tr("recovery.show.title"),
            tr("recovery.show.subtitle_renewed") if renewed else tr("recovery.show.subtitle"),
            icon="key-round", width=560)
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
        self.key_label.setAccessibleName(tr("common.recovery_key"))
        row.addWidget(self.key_label, 1)
        self.copy_button = ui.CopyButton(tr("recovery.copy"), labeled=True)
        self.copy_button.clicked.connect(self._copy)
        row.addWidget(self.copy_button, 0, Qt.AlignVCenter)
        self.body.addWidget(frame)

        pdf_row = QHBoxLayout()
        pdf_row.setSpacing(10)
        self.pdf_button = ui.button(tr("recovery.save_pdf"), "file-text",
                                    on_click=self._save_pdf)
        pdf_row.addWidget(self.pdf_button)
        self.pdf_status = ui.label("", "Faint", wrap=True)
        pdf_row.addWidget(self.pdf_status, 1)
        if not pdf_export.protection_available():  # missing dependency: reported
            self.pdf_button.setEnabled(False)
            self.pdf_status.setText(tr(pdf_export.MISSING_DEPENDENCY))
        self.body.addLayout(pdf_row)

        for icon, color, text in (
                ("square-pen", theme.ACCENT_2, tr("recovery.show.tip_store")),
                ("shield-alert", theme.WARNING, tr("recovery.show.tip_protect")),
                ("eye-off", theme.TEXT_2, tr("recovery.show.tip_once"))):
            line = QHBoxLayout()
            line.setSpacing(10)
            line.addWidget(ui.icon_label(icon, color, 16), 0, Qt.AlignTop)
            line.addWidget(ui.label(text, "Muted", wrap=True), 1)
            self.body.addLayout(line)

        self.ack = ui.ToggleSwitch(tr("recovery.ack"))
        self.body.addSpacing(4)
        self.body.addWidget(self.ack)
        _, self.done_button = self.add_buttons("", tr("common.done"), confirm_icon="check")
        self.done_button.setEnabled(False)
        self.ack.toggled.connect(self.done_button.setEnabled)
        self.done_button.clicked.connect(self._confirm)
        # Also triggered by a forced close (vault lock).
        self.finished.connect(self._on_finished)

    def _copy(self) -> None:
        self._clipboard.copy(self._key, tr("common.recovery_key"))
        self.copy_button.confirm()

    def _save_pdf(self) -> None:
        vault_name = self._vault.info.vault_name if self._vault is not None and \
            not self._vault.is_locked else tr("recovery.default_vault_name")
        dialog = RecoveryPdfDialog(self._key, vault_name, self._vault, self)
        if dialog.exec() == RecoveryPdfDialog.Accepted and dialog.saved_path is not None:
            self.saved_pdf = dialog.saved_path
            self.pdf_status.setText(tr("recovery.pdf.saved", name=dialog.saved_path.name))
            self.pdf_status.setStyleSheet(f"color: {theme.ACCENT_2};")

    def _confirm(self) -> None:
        self.confirmed = True
        self.accept()

    def reject(self) -> None:
        if not self.confirmed and not self._confirm_abandon():
            return
        super().reject()

    def _confirm_abandon(self) -> bool:
        old_key = (" " + tr("recovery.abandon.old_key")) if self._renewed else ""
        if self._kept_if_abandoned:
            return dialogs.confirm(
                self, tr("recovery.abandon_kept.title"),
                tr("recovery.abandon_kept.body", old_key=old_key),
                tr("recovery.abandon_kept.confirm"), danger=True, icon="key-round")
        return dialogs.confirm(
            self, tr("recovery.abandon.title"),
            tr("recovery.abandon.body", old_key=old_key),
            tr("recovery.remove_key"), danger=True, icon="key-round")

    def _on_finished(self, _result: int) -> None:
        self.key_label.clear()
        self._key = ""
        if not self.confirmed:
            self._on_abandoned()


def _file_slug(name: str) -> str:
    ascii_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]+", "-", ascii_name.lower()).strip("-")[:40] or "vault"


class RecoveryPdfDialog(PremiumDialog):
    """Password of the key PDF (always encrypted), then location."""

    def __init__(self, key: str, vault_name: str, vault: Vault | None,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent, tr("recovery.pdf.title"),
                         tr("recovery.pdf.subtitle"), icon="file-text", width=500)
        self._key = key
        self._vault_name = vault_name
        self._vault = vault
        self.saved_path: Path | None = None
        self.password = PasswordField(tr("recovery.pdf.password"))
        self.confirm = PasswordField(tr("password_change.confirmation"))
        self.confirm.returnPressed.connect(self._submit)
        self.meter = ui.StrengthBar()
        self.meter_label = ui.label("", "Faint")
        self.password.textChanged.connect(self._update_meter)
        self.body.addWidget(_labeled(tr("recovery.pdf.password"), self.password))
        self.body.addWidget(self.meter)
        self.body.addWidget(self.meter_label)
        self.body.addWidget(_labeled(tr("password_change.confirmation"), self.confirm))
        self.body.addWidget(ui.label(
            tr("recovery.pdf.hint", strong=tr("strength.strong")), "Faint", wrap=True))
        self.error = ui.label("", "Error", wrap=True)
        self.error.hide()
        self.body.addWidget(self.error)
        _, ok = self.add_buttons(tr("common.cancel"), tr("recovery.pdf.choose_location"),
                                 confirm_icon="file-text")
        ok.clicked.connect(self._submit)
        self.password.setFocus()

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
        effects.shake(self.card)

    def _submit(self) -> None:
        password = self.password.text()
        if password != self.confirm.text():
            self._fail(tr("create.error.mismatch"))
            return
        try:
            with _Busy():
                pdf_export.check_recovery_pdf_password(password, self._key, self._vault)
        except VaultError as exc:
            self._fail(str(exc))
            return
        default = Path.home() / tr("recovery.pdf.filename", name=_file_slug(self._vault_name))
        path_str, _ = QFileDialog.getSaveFileName(self, tr("recovery.pdf.save_title"),
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
            self._fail(tr("common.error.write", reason=exc.strerror))
            return
        self.saved_path = path
        self.accept()

    def done(self, result: int) -> None:
        for field in (self.password, self.confirm):
            field.reset()
        self._key = ""
        super().done(result)


class RecoverVaultDialog(PremiumDialog):
    """Forgotten password: recovery key → new master password."""

    def __init__(self, vault_id: str, vault_name: str, parent: QWidget | None = None,
                 upgrade_backup_dir: Path | None = None) -> None:
        super().__init__(parent, tr("recover.title"),
                         tr("recover.subtitle", name=vault_name),
                         icon="key-round", width=520)
        self._vault_id = vault_id
        self._busy = False
        # Vault from an earlier version (upgrade already confirmed): recovery,
        # then upgrade and verification, in the same background task.
        self._upgrade_dir = upgrade_backup_dir
        self.vault: Vault | None = None
        self.new_key = ""
        self.upgrade_result = None  # vault_upgrade.UpgradeResult
        # Recovery done but upgrade failed: new key to be shown.
        self.orphan_key = ""
        self.upgrade_error = ""

        self.key = QLineEdit()
        self.key.setObjectName("Secret")
        self.key.setFont(theme.mono_font(15))
        self.key.setPlaceholderText("XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX")
        self.key.setMinimumHeight(42)
        self.key.textEdited.connect(self._format_key)
        self.new = PasswordField(tr("password_change.new_placeholder",
                                                min=MIN_MASTER_PASSWORD_LENGTH))
        self.confirm = PasswordField(tr("password_change.confirm_placeholder"))
        self.confirm.returnPressed.connect(self._submit)
        self.meter = ui.StrengthBar()
        self.meter_label = ui.label("", "Faint")
        self.new.textChanged.connect(self._update_meter)
        self.body.addWidget(_labeled(tr("common.recovery_key"), self.key))
        self.body.addWidget(_labeled(tr("recover.new_password"), self.new))
        self.body.addWidget(self.meter)
        self.body.addWidget(self.meter_label)
        self.body.addWidget(_labeled(tr("password_change.confirmation"), self.confirm))
        self.body.addWidget(ui.label(
            tr("recover.hint_upgrade") if upgrade_backup_dir is not None
            else tr("recover.hint"), "Faint", wrap=True))
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
            tr("recover.busy_upgrade") if upgrade_backup_dir is not None
            else tr("recover.busy"), "Muted"))
        busy_row.addStretch(1)
        busy.hide()
        self.busy_row = busy
        self.body.addWidget(busy)
        self.cancel, self.ok = self.add_buttons(
            tr("common.cancel"), tr("recover.submit_upgrade")
            if upgrade_backup_dir is not None else tr("recover.submit"),
            confirm_icon="lock-open")
        self.ok.clicked.connect(self._submit)
        self.key.setFocus()

    def _format_key(self, text: str) -> None:
        """Groups of 4 shown automatically while typing."""
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
        self.meter_label.setText(tr("strength.summary", label=result.label,
                                    bits=f"{result.entropy_bits:.0f}"))

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
            recovery.normalize(key)  # typo reported immediately
        except RecoveryKeyFormatError as exc:
            self._fail(str(exc))
            self.key.setFocus()
            return
        if password != self.confirm.text():
            self._fail(tr("create.error.mismatch"))
            return
        if len(password) >= MIN_MASTER_PASSWORD_LENGTH and estimate_strength(password).score < 2:
            self._fail(tr("password_change.error.weak"))
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
            # New password and new key already saved: the old key no longer works.
            # Close so that the new key is shown without delay.
            self.orphan_key, self.upgrade_error = orphan, str(exc)
            self.done(PremiumDialog.Rejected)
            return
        if isinstance(exc, (RecoveryKeyFormatError, NoRecoveryKeyError)):
            message = str(exc)
        elif isinstance(exc, RecoveryKeyError):
            message = tr("vault.error.wrong_recovery_key")
        elif isinstance(exc, VaultError):
            message = str(exc)
        else:
            message = tr("recover.error.failed")
        self._fail(message)

    def reject(self) -> None:
        if not self._busy:  # never during the derivation: the result would be lost
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
        self.password = PasswordField(tr("common.master_password"), leading_icon="lock")
        self.password.returnPressed.connect(self.accept)
        self.body.addWidget(self.password)
        _, ok = self.add_buttons(tr("common.cancel"), confirm_text,
                                 "Danger" if danger else "Primary")
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
    """Shows the key (non-blocking window); removed if the display is abandoned."""

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
        parent, tr("recovery.replace.title") if replacing else tr("recovery.create.title"),
        tr("recovery.replace.body") if replacing else tr("recovery.create.body"),
        tr("recovery.replace.confirm") if replacing else tr("recovery.create.confirm"))
    if password is None:
        return None
    try:
        with _Busy():
            key = vault.create_recovery_key(password)
    except WrongMasterPasswordError:
        dialogs.alert(parent, tr("recovery.not_created"), tr("vault.error.wrong_password"))
        return None
    except VaultError as exc:
        dialogs.alert(parent, tr("recovery.not_created"), str(exc))
        return None
    on_changed()
    return show_key(parent, vault, key, clipboard, on_changed, renewed=replacing)


def remove(parent: QWidget, vault: Vault, on_changed: Callable[[], None]) -> bool:
    password = _ask_master_password(
        parent, tr("recovery.remove.title"),
        tr("recovery.remove.body"),
        tr("recovery.remove_key"), danger=True)
    if password is None:
        return False
    try:
        with _Busy():
            vault.remove_recovery_key(password)
    except WrongMasterPasswordError:
        dialogs.alert(parent, tr("recovery.kept"), tr("vault.error.wrong_password"))
        return False
    on_changed()
    return True
