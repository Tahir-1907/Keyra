"""Fenêtre principale : écrans verrouillés ↔ application (coquille + vues).

C'est le seul endroit de l'UI qui appelle `Vault.create` / `Vault.unlock`
et qui possède la `SessionManager`. Au verrouillage, l'interface se floute
et s'efface sur l'écran de verrouillage ; elle est vidée puis détruite, la
DEK est effacée (`SessionManager.lock_now`) et la connexion fermée : rien du
coffre ne reste affiché ni accessible.
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

APP_DISPLAY_NAME = "Mon Coffre-Fort"
IDLE_CHECK_INTERVAL_MS = 1000
UNLOCK_FEEDBACK_MS = 260  # le cadenas s'ouvre avant la transition vers l'application

# Événements considérés comme une activité de l'utilisateur (auto-verrouillage).
_ACTIVITY_EVENTS = frozenset({
    QEvent.KeyPress, QEvent.MouseButtonPress, QEvent.MouseMove, QEvent.Wheel,
    QEvent.TouchBegin,
})


class _ActivityFilter(QObject):
    """Filtre global : chaque interaction réinitialise le délai d'inactivité."""

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
        # Fenêtre de mise à niveau / récupération ouverte (fermeture refusée pendant le travail).
        self._blocking_dialog = None
        effects.set_animations_enabled(self._settings.animations)

        self.setWindowTitle(APP_DISPLAY_NAME)
        self.setWindowIcon(app_icon())
        self.resize(1320, 820)
        # Assez petit pour l'accrochage sur une moitié d'écran (GNOME : Super+←/→),
        # y compris sur un écran de 1 680 px de large.
        self.setMinimumSize(theme.WINDOW_MIN_WIDTH, theme.WINDOW_MIN_HEIGHT)
        if self._settings.window_geometry:
            self.restoreGeometry(QByteArray.fromBase64(self._settings.window_geometry.encode()))
        self.statusBar().hide()

        self._toasts = ToastManager(self)
        self._clipboard = SecureClipboard(parent=self)
        self._clipboard.copied_item.connect(self._on_copied)
        self._clipboard.cleared.connect(
            lambda: self._toasts.show("Presse-papiers effacé", kind="info", icon="shield-check",
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

    # --- États ---------------------------------------------------------------------------

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
        # Référence pour la sauvegarde automatique : modifications faites *pendant* la session.
        self._changes_at_open = vault.connection.total_changes
        shell = AppShell(self._session, self._clipboard, lambda: self._settings, self._notify,
                         self._on_vault_action, self.update_settings)
        shell.lock_requested.connect(lambda: self.lock())
        self._shell = shell
        self._stack.addWidget(shell)
        # Écran de verrouillage → application : glissement vers la gauche + fondu.
        effects.switch_page(self._stack, shell, 1, effects.theme.DURATION_SLOW)
        self.setWindowTitle(f"{vault.info.vault_name} — {APP_DISPLAY_NAME}")
        self._set_vault_open(True)
        QApplication.instance().installEventFilter(self._activity_filter)
        self._idle_timer.start()
        self._update_lock_countdown()

    # --- Création / déverrouillage (Argon2id en arrière-plan) -------------------------------------

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
        self._notify("Coffre créé", f"« {vault.info.vault_name} » est prêt.", icon="shield-check")
        if recovery_key:
            self._show_recovery_key(vault, recovery_key)

    def _show_recovery_key(self, vault: Vault, key: str, renewed: bool = False) -> None:
        """Affichage unique de la clé (clé supprimée si l'utilisateur ne confirme pas)."""
        shell = self._shell
        recovery_dialogs.show_key(
            self, vault, key, self._clipboard,
            lambda: shell.recovery_changed() if shell is self._shell and shell else None,
            renewed=renewed)

    # --- Mot de passe maître oublié ---------------------------------------------------------------

    def _recover_vault(self, vault_id: str) -> None:
        if self._busy:
            return
        name = next((v.vault_name for v in list_vaults() if v.vault_id == vault_id), vault_id)
        if not vault_has_recovery_key(vault_id):
            dialogs.alert(
                self, "Pas de clé de récupération",
                f"Le coffre « {name} » n'a pas de clé de récupération : sans le mot de passe "
                "maître, personne ne peut l'ouvrir. Si vous vous souvenez d'un ANCIEN mot de "
                "passe, une sauvegarde faite à cette époque s'ouvre avec lui (« Restaurer une "
                "sauvegarde »).", kind="warning")
            return
        try:
            check = vault_upgrade.inspect(vault_id)
        except VaultError as exc:
            dialogs.alert(self, "Récupération impossible", str(exc))
            return
        upgrade_dir = None
        if check.needs_upgrade:
            # Coffre d'une version précédente : la récupération passe par la mise à
            # niveau, confirmée AVANT toute modification.
            if not check.can_upgrade:
                self._refuse_upgrade(vault_id, check)
                return
            upgrade_dir = backup_directory(self._settings)
            confirm = MigrationDialog(check, name, upgrade_dir, None, self)
            confirmed = confirm.exec() == MigrationDialog.Accepted
            confirm.deleteLater()  # confirmation seule : aucune donnée sensible, jamais gardée
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
        self._notify("Nouveau mot de passe maître enregistré",
                     "Notez la nouvelle clé de récupération.", icon="key-round", duration=6)
        self._show_recovery_key(vault, new_key, renewed=True)

    def _show_orphan_recovery_key(self, key: str, message: str) -> None:
        """Récupération faite (nouveau mot de passe, NOUVELLE clé) mais coffre non mis à
        niveau : la clé est montrée sans condition (l'ancienne ne marche plus) et ne peut
        pas être « abandonnée » (elle est déjà enregistrée dans le coffre)."""
        dialog = recovery_dialogs.RecoveryKeyDialog(key, self._clipboard, lambda: None, self,
                                                    renewed=True, kept_if_abandoned=True)
        dialog.exec()
        dialogs.alert(self, "Mise à niveau non effectuée", message, kind="warning")
        self._unlock_screen.show_error(
            "Déverrouillez avec le nouveau mot de passe maître pour réessayer la mise à "
            "niveau.")

    def _on_create_failed(self, exc: Exception) -> None:
        self._busy = False
        self._create_screen.set_busy(False)
        if isinstance(exc, VaultError):  # politique du mot de passe, nom invalide, doublon…
            self._create_screen.show_error(str(exc))
        else:
            self._logger.error("Vault creation failed: %s", type(exc).__name__)
            self._create_screen.show_error("La création du coffre a échoué.")

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
            # Micro-interaction : le cadenas s'ouvre, puis l'application glisse en place.
            self._unlock_screen.show_success()
            QTimer.singleShot(UNLOCK_FEEDBACK_MS, lambda: self._open_session(vault))
        else:
            self._open_session(vault)

    def _on_unlock_failed(self, vault_id: str, exc: Exception, password: str = "") -> None:
        self._busy = False
        if isinstance(exc, VaultMigrationRequiredError) and password:
            # Mot de passe correct (vérifié avant le contrôle de version) : ancien format.
            self._unlock_screen.set_busy(False)
            self._offer_upgrade(vault_id, password)
            return
        if isinstance(exc, WrongMasterPasswordError):
            self._logger.warning("Failed unlock attempt: vault=%s", vault_id)
            message = "Mot de passe maître incorrect."
        elif isinstance(exc, (VaultCorruptedError, UnsupportedVaultVersionError,
                              VaultNotFoundError, VaultMigrationRequiredError)):
            self._logger.error("Unlock failed: vault=%s (%s)", vault_id, type(exc).__name__)
            message = str(exc)
        else:
            self._logger.error("Unlock failed: vault=%s (%s)", vault_id, type(exc).__name__)
            message = "Le déverrouillage a échoué."
        self._unlock_screen.set_busy(False)
        self._unlock_screen.show_error(message)

    # --- Mise à niveau d'un coffre d'une version précédente (v1 à v3 -> v4) ---------------------

    def _refuse_upgrade(self, vault_id: str, check) -> None:
        self._logger.error("Upgrade impossible: vault=%s (%d structure problems)", vault_id,
                           len(check.problems))
        self._unlock_screen.show_error(
            "Ce coffre ne peut pas être mis à niveau : son fichier contient des éléments que "
            "Mon Coffre-Fort n'a pas créés (détail : " + "; ".join(check.problems[:3])
            + "). Il n'a pas été modifié. Une version 1.6, si elle est encore installée, "
            "peut toujours l'ouvrir.")

    def _offer_upgrade(self, vault_id: str, password: str) -> None:
        """Confirmation explicite, mise à niveau en arrière-plan, vérification, session."""
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
        # Fermée, donc plus au travail : résultat et erreur récupérés, puis la fenêtre
        # (et la fonction de travail qui capturait le mot de passe) est détruite.
        result, error = dialog.take_outcome()
        dialog.deleteLater()
        if accepted and result is not None:
            self._open_session(result.vault)
            self._report_upgrade(result)
        elif isinstance(error, vault_upgrade.UpgradeVerificationError):
            self._unlock_screen.show_error(str(error))
        else:
            self._unlock_screen.show_error(
                "Mise à niveau non effectuée : le coffre n'a pas été modifié.")

    def _report_upgrade(self, result) -> None:
        self._logger.info("Vault upgraded to v4 and opened: %s", result.vault.vault_id)
        self._notify("Coffre mis à niveau",
                     f"Sauvegarde préalable conservée : {result.report.backup_path.name}",
                     icon="shield-check", duration=6)
        for warning in result.warnings:
            self._notify("Mise à niveau", warning, kind="warning", duration=8)
        if result.legacy_plaintext_copies:
            names = ", ".join(p.name for p in result.legacy_plaintext_copies)
            dialogs.alert(
                self, "Anciennes copies non chiffrées",
                f"Ces fichiers, laissés par d'anciennes versions à côté du coffre, ne sont "
                f"PAS chiffrés : {names}. Ils n'ont été ni utilisés ni supprimés. Supprimez-"
                "les vous-même maintenant que le coffre est mis à niveau.", kind="warning")

    # --- Inactivité, verrouillage -----------------------------------------------------------------

    def _on_activity(self) -> None:
        if self._session is not None:
            self._session.touch()

    def _check_idle(self) -> None:
        if self._session is None:
            return
        if any(isinstance(d, recovery_dialogs.RecoveryKeyDialog) for d in dialogs.open_dialogs()):
            # Clé affichée, en train d'être recopiée sur papier : pas de verrouillage
            # automatique (qui la supprimerait). Verrouillage manuel/de session inchangés.
            self._session.touch()
        self._update_lock_countdown()
        if self._session.should_lock():
            # Pas lock_if_idle() : la sauvegarde automatique a besoin du coffre
            # encore déverrouillé ; self.lock() verrouille juste après.
            self._logger.info("Auto-lock triggered after %.0fs idle", self._session.idle_seconds())
            seconds = self._session.auto_lock_seconds or 0
            delay = f"{seconds // 60} min" if seconds >= 60 else f"{seconds} s"
            self.lock(f"Verrouillé automatiquement après {delay} d'inactivité.")

    def _update_lock_countdown(self) -> None:
        session, shell = self._session, self._shell
        if session is None or shell is None:
            return
        if session.auto_lock_seconds is None:
            shell.set_countdown("Verrouillage auto désactivé")
            return
        remaining = max(0, int(session.auto_lock_seconds - session.idle_seconds()))
        shell.set_countdown(f"Verrouillage dans {remaining // 60:02d}:{remaining % 60:02d}",
                            warn=remaining <= 30)

    def lock(self, message: str = "") -> None:
        """Verrouille le coffre. Rien de ce qui précède le verrouillage (fermeture des
        modales, presse-papiers, sauvegarde automatique, animation) ne peut l'empêcher :
        une erreur éventuelle remonte, mais seulement APRÈS l'effacement de la clé."""
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
                session.lock_now()  # efface la clé de données, même si l'interface a échoué
                session.vault.close()
                self._show_locked_state()

        try:
            QApplication.instance().removeEventFilter(self._activity_filter)
            # Ferme toute modale ouverte, sans animation : rien ne doit rester affiché.
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
                # L'interface se floute puis s'efface sur l'écran de verrouillage.
                effects.protect_transition(self._stack, teardown)
            finally:
                if self._session is not None:  # l'animation a échoué avant le verrouillage
                    teardown()

    def _auto_backup(self) -> None:
        """Sauvegarde chiffrée automatique si le coffre a été modifié pendant la session."""
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
        except Exception as exc:  # noqa: BLE001 - ne doit jamais empêcher le verrouillage
            # Journalisé (type seulement : aucun secret) et signalé sur l'écran de verrouillage.
            self._logger.error("Automatic backup failed: %s", type(exc).__name__)
            self._lock_message = (self._lock_message + " " if self._lock_message else "") + \
                "La sauvegarde automatique a échoué."

    def _restore_from_locked_state(self) -> None:
        restored = run_restore(self, backup_directory(self._settings))
        if restored is not None:
            self._last_vault_id = restored.vault_id
            self._lock_message = f"Coffre restauré : « {restored.vault_name} »."
            self._show_locked_state()

    def _on_system_lock(self, message: str) -> None:
        if self._settings.lock_on_session_lock:
            self.lock(message)

    # --- Paramètres ------------------------------------------------------------------------------

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
        """Appelé par la vue Paramètres (enregistrement automatique)."""
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

    # --- Gestion des coffres ---------------------------------------------------------------------

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
        try:  # sauvegarde immédiate protégée par le NOUVEAU mot de passe
            path = backup.create_backup(vault, directory=backup_directory(self._settings))
            detail = f"Nouvelle sauvegarde : {path.name}"
        except (VaultError, OSError) as exc:
            self._logger.error("Backup after password change failed: %s", type(exc).__name__)
            detail = "La sauvegarde qui suit le changement a échoué."
        self._notify("Mot de passe maître changé", detail, icon="key-round", duration=6)

    def _delete_current_vault(self) -> None:
        vault = self._session.vault
        vault_id, name = vault.vault_id, vault.info.vault_name
        dialog = DeleteVaultDialog(vault_id, name, self)
        if dialog.exec() != DeleteVaultDialog.Accepted:
            return
        password = dialog.entered_password
        dialog.entered_password = ""
        if not vault.verify_master_password(password):
            dialogs.alert(self, "Suppression annulée", "Mot de passe maître incorrect.")
            return
        self.lock()  # ferme le coffre (et crée une dernière sauvegarde s'il a changé)
        try:
            delete_closed_vault(vault_id, password)
        except VaultError as exc:
            dialogs.alert(self, "Suppression impossible", str(exc))
            return
        if self._last_vault_id == vault_id:
            self._last_vault_id = None
        self._lock_message = f"Le coffre « {name} » a été supprimé."
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
            self._toasts.show(f"{label} copié", f"Effacé du presse-papiers dans {seconds} s",
                              kind="success", icon="copy", countdown=seconds)
        else:
            self._toasts.show(f"{label} copié", kind="success", icon="copy", duration=2.5)

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
                    group="Comptes"))
                commands.append(Command(
                    f"Copier le mot de passe — {summary.service_name}",
                    lambda i=summary.id: (shell.navigate("vault", entry_id=i),
                                          shell.vault_page.copy_selected_password()),
                    "", "copy", keywords, group="Copier"))
        return commands

    def open_command_palette(self) -> None:
        CommandPalette(self, self.command_palette_commands()).popup()

    # --- Cycle de vie ---------------------------------------------------------------------------

    def bring_to_front(self) -> None:
        """Appelé quand l'application est relancée alors qu'elle tourne déjà."""
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, event) -> None:
        busy = self._blocking_dialog
        if busy is not None and busy.is_busy():
            # Mise à niveau (ou récupération) en cours : la fermeture attendrait sans fin
            # ou interromprait la transaction. Refusée ; le coffre reste cohérent.
            self._logger.warning("Close refused: vault upgrade in progress")
            event.ignore()
            return
        tasks.wait_for_tasks()
        effects_enabled = effects.animations_enabled()
        effects.set_animations_enabled(False)  # fermeture : pas de transition
        self.lock()
        effects.set_animations_enabled(effects_enabled)
        self._clipboard.clear_if_ours()
        self._settings.window_geometry = bytes(self.saveGeometry().toBase64()).decode()
        self._save_settings()
        super().closeEvent(event)
