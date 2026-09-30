"""Main window: locked screens ↔ application (shell + views).

This is the only place in the UI that calls `Vault.create` / `Vault.unlock`
and owns the `SessionManager`. When locking, the interface blurs and fades
out over the lock screen; it is emptied and then destroyed, the DEK is erased
(`SessionManager.lock_now`) and the connection closed: nothing from the vault
remains displayed or accessible.
"""

from __future__ import annotations

from PySide6.QtCore import QByteArray, QEvent, QObject, QTimer
from PySide6.QtWidgets import QApplication, QMainWindow, QStackedWidget

from app.core.categories import CategoryService
from app.core.entries import EntryService
from app.core.exceptions import (
    UnsupportedVaultVersionError,
    VaultCorruptedError,
    VaultError,
    VaultMigrationRequiredError,
    VaultNotFoundError,
    WrongMasterPasswordError,
)
from app.core.session import SessionManager
from app.core.vault import Vault, generate_vault_id, list_vaults, vault_has_recovery_key
from app.services import backup, vault_upgrade
from app.services.settings import Settings, backup_directory, load_settings, save_settings
from app.ui import dialogs, effects, recovery_dialogs, tasks, theme
from app.ui.app_menus import AppMenus
from app.ui.command_palette import Command, CommandPalette
from app.ui.icons import app_icon
from app.ui.lock_screen import CreateVaultScreen, UnlockScreen
from app.ui.migration_dialog import MigrationDialog
from app.ui.secure_clipboard import SecureClipboard
from app.ui.shell import AppShell
from app.ui.system_lock import SystemLockMonitor
from app.ui.toast import ToastManager
from app.ui.transfer_dialogs import open_backup_folder, run_restore
from app.ui.vault_dialogs import (
    AboutDialog,
    ChangeMasterPasswordDialog,
    DeleteVaultDialog,
    ShortcutsDialog,
    delete_closed_vault,
)
from app.utils.logging import get_logger

APP_DISPLAY_NAME = "Keyra"
IDLE_CHECK_INTERVAL_MS = 1000
UNLOCK_FEEDBACK_MS = 260  # the padlock opens before the transition to the application

# Events counted as user activity (automatic locking).
_ACTIVITY_EVENTS = frozenset({
    QEvent.KeyPress, QEvent.MouseButtonPress, QEvent.MouseMove, QEvent.Wheel,
    QEvent.TouchBegin,
})


class _ActivityFilter(QObject):
    """Global filter: every interaction resets the inactivity delay."""

    def __init__(self, on_activity, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._on_activity = on_activity

    def eventFilter(self, obj, event) -> bool:
        if event.type() in _ACTIVITY_EVENTS:
            self._on_activity()
        return False


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self._logger = get_logger()
        self._session: SessionManager | None = None
        self._shell: AppShell | None = None
        self._settings: Settings = load_settings()
        self._last_vault_id: str | None = self._settings.last_vault_id or None
        self._lock_message = ""
        self._changes_at_open = 0
        self._busy = False
        # Upgrade / recovery window open (closing refused while it works).
        self._blocking_dialog = None
        effects.set_animations_enabled(self._settings.animations)

        self.setWindowTitle(APP_DISPLAY_NAME)
        self.setWindowIcon(app_icon())
        self.resize(1320, 820)
        # Small enough to snap to half of the screen (GNOME: Super+←/→),
        # including on a 1,680 px wide screen.
        self.setMinimumSize(theme.WINDOW_MIN_WIDTH, theme.WINDOW_MIN_HEIGHT)
        if self._settings.window_geometry:
            self.restoreGeometry(QByteArray.fromBase64(self._settings.window_geometry.encode()))
        self.statusBar().hide()

        self._toasts = ToastManager(self)
        self._clipboard = SecureClipboard(parent=self)
        self._clipboard.copied_item.connect(self._on_copied)
        self._clipboard.cleared.connect(
            lambda: self._toasts.show("Clipboard cleared", kind="info", icon="shield-check",
                                      duration=2.5))
        self._activity_filter = _ActivityFilter(self._on_activity, self)
        self._idle_timer = QTimer(self)
        self._idle_timer.setInterval(IDLE_CHECK_INTERVAL_MS)
        self._idle_timer.timeout.connect(self._check_idle)
        self._system_lock = SystemLockMonitor(self)
        self._system_lock.lock_requested.connect(self._on_system_lock)

        self._stack = QStackedWidget()
        self.setCentralWidget(self._stack)
        self._create_screen = CreateVaultScreen()
        self._create_screen.create_requested.connect(self._create_vault)
        self._create_screen.restore_requested.connect(self._restore_from_locked_state)
        self._create_screen.back_requested.connect(self._show_locked_state)
        self._unlock_screen = UnlockScreen()
        self._unlock_screen.unlock_requested.connect(self._unlock_vault)
        self._unlock_screen.recovery_requested.connect(self._recover_vault)
        self._unlock_screen.restore_requested.connect(self._restore_from_locked_state)
        self._unlock_screen.new_vault_requested.connect(lambda: self._show_create_screen(False))
        self._stack.addWidget(self._create_screen)
        self._stack.addWidget(self._unlock_screen)

        self._menus = AppMenus(self, self._menu_handlers())
        self._menus.actions["animations"].setChecked(self._settings.animations)
        self._apply_settings()
        self._set_vault_open(False)
        self._show_locked_state()

    # --- States ---------------------------------------------------------------------------

    def _show_create_screen(self, first: bool = False) -> None:
        self._create_screen.set_first_vault(first)
        self._create_screen.prepare()
        effects.switch_page(self._stack, self._create_screen, 1)
        if not first:
            self._create_screen.name.setFocus()

    def _show_locked_state(self) -> None:
        vaults = list_vaults()
        if not vaults:
            self._show_create_screen(first=True)
        else:
            self._unlock_screen.set_vaults(vaults, self._last_vault_id)
            effects.switch_page(self._stack, self._unlock_screen, -1)
            self._unlock_screen.prepare(self._lock_message)
            self._lock_message = ""
        self.setWindowTitle(APP_DISPLAY_NAME)
        self._set_vault_open(False)

    def _open_session(self, vault: Vault) -> None:
        self._session = SessionManager(vault, self._settings.auto_lock_seconds)
        self._last_vault_id = vault.vault_id
        self._settings.last_vault_id = vault.vault_id
        self._save_settings()
        CategoryService(vault).ensure_builtin_categories()
        if self._settings.trash_retention_days is not None:
            EntryService(vault).purge_trash(self._settings.trash_retention_days)
        # Reference for the automatic backup: changes made *during* the session.
        self._changes_at_open = vault.connection.total_changes
        shell = AppShell(self._session, self._clipboard, lambda: self._settings, self._notify,
                         self._on_vault_action, self.update_settings)
        shell.lock_requested.connect(lambda: self.lock())
        self._shell = shell
        self._stack.addWidget(shell)
        # Lock screen → application: slide to the left + fade.
        effects.switch_page(self._stack, shell, 1, effects.theme.DURATION_SLOW)
        self.setWindowTitle(f"{vault.info.vault_name} — {APP_DISPLAY_NAME}")
        self._set_vault_open(True)
        QApplication.instance().installEventFilter(self._activity_filter)
        self._idle_timer.start()
        self._update_lock_countdown()

    # --- Creation / unlocking (Argon2id in the background) -------------------------------------

    def _create_vault(self, name: str, password: str, with_recovery: bool = False) -> None:
        if self._busy:
            return
        self._busy = True
        self._create_screen.set_busy(True)
        vault_id = generate_vault_id(name)

        def create() -> tuple[Vault, str | None]:
            if with_recovery:
                return Vault.create_with_recovery(vault_id, name, password)
            return Vault.create(vault_id, name, password), None

        tasks.run_task(create, self._on_created, self._on_create_failed, self)

    def _on_created(self, result) -> None:
        vault, recovery_key = result
        self._busy = False
        self._open_session(vault)
        self._notify("Vault created", f"\"{vault.info.vault_name}\" is ready.", icon="shield-check")
        if recovery_key:
            self._show_recovery_key(vault, recovery_key)

    def _show_recovery_key(self, vault: Vault, key: str, renewed: bool = False) -> None:
        """Shows the key once (the key is removed if the user does not confirm)."""
        shell = self._shell
        recovery_dialogs.show_key(
            self, vault, key, self._clipboard,
            lambda: shell.recovery_changed() if shell is self._shell and shell else None,
            renewed=renewed)

    # --- Forgotten master password ---------------------------------------------------------------

    def _recover_vault(self, vault_id: str) -> None:
        if self._busy:
            return
        name = next((v.vault_name for v in list_vaults() if v.vault_id == vault_id), vault_id)
        if not vault_has_recovery_key(vault_id):
            dialogs.alert(
                self, "No recovery key",
                f"The vault \"{name}\" has no recovery key: without the master "
                "password, nobody can open it. If you remember an OLD password, a "
                "backup made back then opens with it (\"Restore a "
                "backup\").", kind="warning")
            return
        try:
            check = vault_upgrade.inspect(vault_id)
        except VaultError as exc:
            dialogs.alert(self, "Recovery impossible", str(exc))
            return
        upgrade_dir = None
        if check.needs_upgrade:
            # Vault from an earlier version: recovery goes through the upgrade,
            # confirmed BEFORE any modification.
            if not check.can_upgrade:
                self._refuse_upgrade(vault_id, check)
                return
            upgrade_dir = backup_directory(self._settings)
            confirm = MigrationDialog(check, name, upgrade_dir, None, self)
            confirmed = confirm.exec() == MigrationDialog.Accepted
            confirm.deleteLater()  # confirmation only: no sensitive data, never kept
            if not confirmed:
                return
        dialog = recovery_dialogs.RecoverVaultDialog(vault_id, name, self,
                                                     upgrade_backup_dir=upgrade_dir)
        self._blocking_dialog = dialog
        try:
            accepted = dialog.exec() == recovery_dialogs.RecoverVaultDialog.Accepted
        finally:
            self._blocking_dialog = None
        if dialog.orphan_key:
            self._show_orphan_recovery_key(dialog.orphan_key, dialog.upgrade_error)
            dialog.orphan_key = ""
            return
        if not accepted or dialog.vault is None:
            return
        vault, new_key, upgraded = dialog.vault, dialog.new_key, dialog.upgrade_result
        dialog.vault, dialog.new_key, dialog.upgrade_result = None, "", None
        self._logger.warning("Vault opened with its recovery key: %s", vault_id)
        self._open_session(vault)
        if upgraded is not None:
            self._report_upgrade(upgraded)
        self._notify("New master password saved",
                     "Write down the new recovery key.", icon="key-round", duration=6)
        self._show_recovery_key(vault, new_key, renewed=True)

    def _show_orphan_recovery_key(self, key: str, message: str) -> None:
        """Recovery done (new password, NEW key) but the vault was not upgraded: the key
        is shown unconditionally (the old one no longer works) and cannot be
        "abandoned" (it is already saved in the vault)."""
        dialog = recovery_dialogs.RecoveryKeyDialog(key, self._clipboard, lambda: None, self,
                                                    renewed=True, kept_if_abandoned=True)
        dialog.exec()
        dialogs.alert(self, "Upgrade not performed", message, kind="warning")
        self._unlock_screen.show_error(
            "Unlock with the new master password to retry the "
            "upgrade.")

    def _on_create_failed(self, exc: Exception) -> None:
        self._busy = False
        self._create_screen.set_busy(False)
        if isinstance(exc, VaultError):  # password policy, invalid name, duplicate…
            self._create_screen.show_error(str(exc))
        else:
            self._logger.error("Vault creation failed: %s", type(exc).__name__)
            self._create_screen.show_error("Vault creation failed.")

    def _unlock_vault(self, vault_id: str, password: str) -> None:
        if self._busy:
            return
        self._busy = True
        self._unlock_screen.set_busy(True)
        tasks.run_task(lambda: Vault.unlock(vault_id, password), self._on_unlocked,
                       lambda exc: self._on_unlock_failed(vault_id, exc, password), self)

    def _on_unlocked(self, vault: Vault) -> None:
        self._busy = False
        if effects.animations_enabled() and tasks.BACKGROUND_TASKS:
            # Micro-interaction: the padlock opens, then the application slides into place.
            self._unlock_screen.show_success()
            QTimer.singleShot(UNLOCK_FEEDBACK_MS, lambda: self._open_session(vault))
        else:
            self._open_session(vault)

    def _on_unlock_failed(self, vault_id: str, exc: Exception, password: str = "") -> None:
        self._busy = False
        if isinstance(exc, VaultMigrationRequiredError) and password:
            # Correct password (checked before the version check): older format.
            self._unlock_screen.set_busy(False)
            self._offer_upgrade(vault_id, password)
            return
        if isinstance(exc, WrongMasterPasswordError):
            self._logger.warning("Failed unlock attempt: vault=%s", vault_id)
            message = "Wrong master password."
        elif isinstance(exc, (VaultCorruptedError, UnsupportedVaultVersionError,
                              VaultNotFoundError, VaultMigrationRequiredError)):
            self._logger.error("Unlock failed: vault=%s (%s)", vault_id, type(exc).__name__)
            message = str(exc)
        else:
            self._logger.error("Unlock failed: vault=%s (%s)", vault_id, type(exc).__name__)
            message = "Unlocking failed."
        self._unlock_screen.set_busy(False)
        self._unlock_screen.show_error(message)

    # --- Upgrade of a vault from an earlier version (v1 to v3 -> v4) ---------------------

    def _refuse_upgrade(self, vault_id: str, check) -> None:
        self._logger.error("Upgrade impossible: vault=%s (%d structure problems)", vault_id,
                           len(check.problems))
        self._unlock_screen.show_error(
            "This vault cannot be upgraded: its file contains items that the "
            "application did not create (details: " + "; ".join(check.problems[:3])
            + "). It has not been modified. A version 1.6, if still installed, "
            "can still open it.")

    def _offer_upgrade(self, vault_id: str, password: str) -> None:
        """Explicit confirmation, upgrade in the background, verification, session."""
        try:
            check = vault_upgrade.inspect(vault_id)
        except VaultError as exc:
            self._unlock_screen.show_error(str(exc))
            return
        if not check.can_upgrade:
            self._refuse_upgrade(vault_id, check)
            return
        name = next((v.vault_name for v in list_vaults() if v.vault_id == vault_id), vault_id)
        directory = backup_directory(self._settings)
        dialog = MigrationDialog(
            check, name, directory,
            lambda: vault_upgrade.upgrade(vault_id, password, directory), self)
        self._blocking_dialog = dialog
        try:
            accepted = dialog.exec() == MigrationDialog.Accepted
        finally:
            self._blocking_dialog = None
        # Closed, so no longer working: result and error collected, then the window
        # (and the work function that captured the password) is destroyed.
        result, error = dialog.take_outcome()
        dialog.deleteLater()
        if accepted and result is not None:
            self._open_session(result.vault)
            self._report_upgrade(result)
        elif isinstance(error, vault_upgrade.UpgradeVerificationError):
            self._unlock_screen.show_error(str(error))
        else:
            self._unlock_screen.show_error(
                "Upgrade not performed: the vault has not been modified.")

    def _report_upgrade(self, result) -> None:
        self._logger.info("Vault upgraded to v4 and opened: %s", result.vault.vault_id)
        self._notify("Vault upgraded",
                     f"Preliminary backup kept: {result.report.backup_path.name}",
                     icon="shield-check", duration=6)
        for warning in result.warnings:
            self._notify("Upgrade", warning, kind="warning", duration=8)
        if result.legacy_plaintext_copies:
            names = ", ".join(p.name for p in result.legacy_plaintext_copies)
            dialogs.alert(
                self, "Old unencrypted copies",
                f"These files, left next to the vault by older versions, are "
                f"NOT encrypted: {names}. They were neither used nor deleted. Delete "
                "them yourself now that the vault has been upgraded.", kind="warning")

    # --- Inactivity, locking -----------------------------------------------------------------

    def _on_activity(self) -> None:
        if self._session is not None:
            self._session.touch()

    def _check_idle(self) -> None:
        if self._session is None:
            return
        if any(isinstance(d, recovery_dialogs.RecoveryKeyDialog) for d in dialogs.open_dialogs()):
            # Key displayed, being copied onto paper: no automatic lock (which would
            # remove it). Manual/session locking unchanged.
            self._session.touch()
        self._update_lock_countdown()
        if self._session.should_lock():
            # Not lock_if_idle(): the automatic backup needs the vault still
            # unlocked; self.lock() locks right after.
            self._logger.info("Auto-lock triggered after %.0fs idle", self._session.idle_seconds())
            seconds = self._session.auto_lock_seconds or 0
            delay = f"{seconds // 60} min" if seconds >= 60 else f"{seconds} s"
            self.lock(f"Locked automatically after {delay} of inactivity.")

    def _update_lock_countdown(self) -> None:
        session, shell = self._session, self._shell
        if session is None or shell is None:
            return
        if session.auto_lock_seconds is None:
            shell.set_countdown("Auto-lock disabled")
            return
        remaining = max(0, int(session.auto_lock_seconds - session.idle_seconds()))
        shell.set_countdown(f"Locking in {remaining // 60:02d}:{remaining % 60:02d}",
                            warn=remaining <= 30)

    def lock(self, message: str = "") -> None:
        """Locks the vault. Nothing that precedes the lock (closing modals, clipboard,
        automatic backup, animation) can prevent it: any error is raised, but only
        AFTER the key has been erased."""
        if self._session is None:
            return
        self._lock_message = message
        self._idle_timer.stop()

        def teardown() -> None:
            shell, self._shell = self._shell, None
            session, self._session = self._session, None
            try:
                if shell is not None:
                    shell.wipe()
                    self._stack.removeWidget(shell)
                    shell.deleteLater()
            finally:
                session.lock_now()  # erases the data key, even if the interface failed
                session.vault.close()
                self._show_locked_state()

        try:
            QApplication.instance().removeEventFilter(self._activity_filter)
            # Closes every open modal, without animation: nothing must remain displayed.
            for dialog in dialogs.open_dialogs():
                if hasattr(dialog, "close_now"):
                    dialog.close_now()
                else:
                    dialog.reject()
            self._clipboard.clear_if_ours()
            self._toasts.clear()
            self._auto_backup()
        finally:
            try:
                # The interface blurs, then fades out over the lock screen.
                effects.protect_transition(self._stack, teardown)
            finally:
                if self._session is not None:  # the animation failed before locking
                    teardown()

    def _auto_backup(self) -> None:
        """Automatic encrypted backup if the vault was modified during the session."""
        session = self._session
        if session is None or session.vault.is_locked or not self._settings.auto_backup:
            return
        if session.vault.connection.total_changes <= self._changes_at_open:
            return
        try:
            directory = backup_directory(self._settings)
            backup.create_backup(session.vault, directory=directory, kind=backup.KIND_AUTO)
            backup.rotate_auto_backups(session.vault.vault_id, directory,
                                       keep=self._settings.auto_backups_kept)
        except Exception as exc:  # noqa: BLE001 - must never prevent locking
            # Logged (type only: no secret) and reported on the lock screen.
            self._logger.error("Automatic backup failed: %s", type(exc).__name__)
            self._lock_message = (self._lock_message + " " if self._lock_message else "") + \
                "The automatic backup failed."

    def _restore_from_locked_state(self) -> None:
        restored = run_restore(self, backup_directory(self._settings))
        if restored is not None:
            self._last_vault_id = restored.vault_id
            self._lock_message = f"Vault restored: \"{restored.vault_name}\"."
            self._show_locked_state()

    def _on_system_lock(self, message: str) -> None:
        if self._settings.lock_on_session_lock:
            self.lock(message)

    # --- Settings ------------------------------------------------------------------------------

    def _apply_settings(self) -> None:
        self._clipboard.clear_after_seconds = self._settings.clipboard_clear_seconds
        effects.set_animations_enabled(self._settings.animations)
        action = self._menus.actions["animations"]
        action.blockSignals(True)
        action.setChecked(self._settings.animations)
        action.blockSignals(False)
        if self._session is not None:
            self._session.auto_lock_seconds = self._settings.auto_lock_seconds
            self._session.touch()
            self._update_lock_countdown()

    def _save_settings(self) -> None:
        try:
            save_settings(self._settings)
        except OSError as exc:
            self._logger.error("Settings could not be saved: %s", type(exc).__name__)

    def update_settings(self, settings: Settings) -> None:
        """Called by the Settings view (automatic saving)."""
        settings.window_geometry = self._settings.window_geometry
        settings.last_vault_id = self._settings.last_vault_id
        self._settings = settings
        self._save_settings()
        self._apply_settings()

    def _toggle_animations(self, enabled: bool) -> None:
        self._settings.animations = enabled
        self._save_settings()
        self._apply_settings()
        if self._shell is not None:
            self._shell.pages["settings"].refresh()

    def open_settings(self) -> None:
        if self._shell is not None:
            self._shell.navigate("settings")

    # --- Vault management ---------------------------------------------------------------------

    def _on_vault_action(self, action: str) -> None:
        if action == "new" and self._session is None:
            self._show_create_screen(False)
            return
        if self._session is None:
            return
        if action == "new":
            self.lock()
            self._show_create_screen(first=False)
        elif action in ("switch", "lock"):
            self.lock()
        elif action == "password":
            self._change_master_password()
        elif action == "recovery":
            recovery_dialogs.create_or_replace(self, self._session.vault, self._clipboard,
                                               self._shell.recovery_changed)
        elif action == "recovery_remove":
            recovery_dialogs.remove(self, self._session.vault, self._shell.recovery_changed)
        elif action == "delete":
            self._delete_current_vault()

    def _change_master_password(self) -> None:
        vault = self._session.vault
        if ChangeMasterPasswordDialog(vault, self).exec() != ChangeMasterPasswordDialog.Accepted:
            return
        detail = ""
        try:  # immediate backup protected by the NEW password
            path = backup.create_backup(vault, directory=backup_directory(self._settings))
            detail = f"New backup: {path.name}"
        except (VaultError, OSError) as exc:
            self._logger.error("Backup after password change failed: %s", type(exc).__name__)
            detail = "The backup after the change failed."
        self._notify("Master password changed", detail, icon="key-round", duration=6)

    def _delete_current_vault(self) -> None:
        vault = self._session.vault
        vault_id, name = vault.vault_id, vault.info.vault_name
        dialog = DeleteVaultDialog(vault_id, name, self)
        if dialog.exec() != DeleteVaultDialog.Accepted:
            return
        password = dialog.entered_password
        dialog.entered_password = ""
        if not vault.verify_master_password(password):
            dialogs.alert(self, "Deletion cancelled", "Wrong master password.")
            return
        self.lock()  # closes the vault (and creates a last backup if it changed)
        try:
            delete_closed_vault(vault_id, password)
        except VaultError as exc:
            dialogs.alert(self, "Deletion impossible", str(exc))
            return
        if self._last_vault_id == vault_id:
            self._last_vault_id = None
        self._lock_message = f"The vault \"{name}\" has been deleted."
        self._show_locked_state()

    # --- Actions, palette, notifications ----------------------------------------------------------

    def _menu_handlers(self) -> dict:
        def shell_call(fn):
            return lambda: fn(self._shell) if self._shell is not None else None

        def vault_page(method: str):
            def run(shell: AppShell) -> None:
                shell.navigate("vault")
                getattr(shell.vault_page, method)()
            return shell_call(run)

        def go(key: str):
            return shell_call(lambda s: s.navigate(key))

        return {
            "go_dashboard": go("dashboard"), "go_vault": go("vault"),
            "go_security": go("security"), "go_history": go("history"),
            "go_trash": go("trash"), "go_backups": go("backups"),
            "settings": self.open_settings,
            "new_entry": shell_call(lambda s: s.navigate("new_entry")),
            "edit_entry": vault_page("edit_entry"),
            "duplicate_entry": vault_page("duplicate_entry"),
            "delete_entry": vault_page("delete_entry"),
            "copy_password": vault_page("copy_selected_password"),
            "copy_username": vault_page("copy_selected_username"),
            "search": shell_call(lambda s: s.focus_search()),
            "palette": self.open_command_palette,
            "generator": shell_call(lambda s: s.open_generator()),
            "import": shell_call(lambda s: (s.navigate("backups"),
                                            s.pages["backups"].import_entries())),
            "export": shell_call(lambda s: (s.navigate("backups"),
                                            s.pages["backups"].export_entries())),
            "backup_now": shell_call(lambda s: (s.navigate("backups"),
                                                s.pages["backups"].create_backup())),
            "restore_backup": lambda: (self._shell.pages["backups"].restore_other()
                                       if self._shell else self._restore_from_locked_state()),
            "open_backups": lambda: open_backup_folder(backup_directory(self._settings)),
            "new_vault": lambda: self._on_vault_action("new"),
            "switch_vault": lambda: self._on_vault_action("switch"),
            "rename_vault": shell_call(lambda s: (s.navigate("settings"),
                                                  s.pages["settings"]._rename())),
            "change_password": lambda: self._on_vault_action("password"),
            "recovery_key": lambda: self._on_vault_action("recovery"),
            "delete_vault": lambda: self._on_vault_action("delete"),
            "lock": lambda: self.lock(),
            "animations": self._toggle_animations,
            "fullscreen": lambda: (self.showNormal() if self.isFullScreen()
                                   else self.showFullScreen()),
            "shortcuts": lambda: ShortcutsDialog(self).exec(),
            "about": lambda: AboutDialog(self).exec(),
            "quit": self.close,
        }

    def _set_vault_open(self, is_open: bool) -> None:
        self._menus.set_vault_open(is_open)

    def _notify(self, title: str, message: str = "", kind: str = "success",
                icon: str | None = None, duration: float = 3.0) -> None:
        self._toasts.show(title, message, kind=kind, icon=icon, duration=duration)

    def _on_copied(self, label: str, sensitive: bool, seconds: int) -> None:
        if sensitive:
            self._toasts.show(f"{label} copied", f"Cleared from the clipboard in {seconds} s",
                              kind="success", icon="copy", countdown=seconds)
        else:
            self._toasts.show(f"{label} copied", kind="success", icon="copy", duration=2.5)

    def command_palette_commands(self) -> list[Command]:
        commands = []
        for key, action in self._menus.actions.items():
            spec = self._menus.specs[key]
            if not action.isEnabled() or spec.checkable or key == "palette":
                continue
            hint = spec.shortcut or spec.shortcut_hint or ""
            commands.append(Command(spec.text, action.trigger, hint, spec.icon, spec.keywords,
                                    group=spec.group))
        shell = self._shell
        if shell is not None:
            for summary in shell.ctx.entries.list_entries():
                keywords = " ".join((summary.username, summary.url, summary.category_name))
                commands.append(Command(
                    summary.service_name,
                    lambda i=summary.id: shell.navigate("vault", entry_id=i),
                    summary.username or summary.category_name, "key-round", keywords,
                    group="Entries"))
                commands.append(Command(
                    f"Copy password — {summary.service_name}",
                    lambda i=summary.id: (shell.navigate("vault", entry_id=i),
                                          shell.vault_page.copy_selected_password()),
                    "", "copy", keywords, group="Copy"))
        return commands

    def open_command_palette(self) -> None:
        CommandPalette(self, self.command_palette_commands()).popup()

    # --- Lifecycle ---------------------------------------------------------------------------

    def bring_to_front(self) -> None:
        """Called when the application is launched again while it is already running."""
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, event) -> None:
        busy = self._blocking_dialog
        if busy is not None and busy.is_busy():
            # Upgrade (or recovery) in progress: closing would wait forever or interrupt
            # the transaction. Refused; the vault stays consistent.
            self._logger.warning("Close refused: vault upgrade in progress")
            event.ignore()
            return
        tasks.wait_for_tasks()
        effects_enabled = effects.animations_enabled()
        effects.set_animations_enabled(False)  # closing: no transition
        self.lock()
        effects.set_animations_enabled(effects_enabled)
        self._clipboard.clear_if_ours()
        self._settings.window_geometry = bytes(self.saveGeometry().toBase64()).decode()
        self._save_settings()
        super().closeEvent(event)
