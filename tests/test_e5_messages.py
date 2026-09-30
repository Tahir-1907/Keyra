"""E5.2 and E5.3: exact messages (orphaned recovery key, upgrade).

The texts follow the real behavior, which is not modified: the tests first check the
behavior (key valid or not, vault modified or not), then that the text describes it.
Fixture copies in temporary XDG directories only.
"""

import os
import sqlite3
import unittest.mock

from app.core.exceptions import RecoveryKeyError, VaultError
from app.core.vault import Vault, vault_has_recovery_key
from app.services import vault_upgrade
from app.services.migration_v4 import MigrationError
from tests.test_e3_upgrade import UpgradeUiTestCase, schema_of

NEW_MASTER = "Nouvelle-phrase-de-passe-E5-tres-solide"


def texts(widget) -> str:
    from PySide6.QtWidgets import QLabel

    return " ".join(label.text() for label in widget.findChildren(QLabel))


# --- E5.2: orphaned recovery key -----------------------------------------------------


class TestOrphanRecoveryKey(UpgradeUiTestCase):
    """Recovery succeeded (new password, new key), then the upgrade failed: the new key
    is already saved and stays valid if the user closes its window without writing it
    down."""

    def recover_with_failing_upgrade(self, on_key_dialog):
        from PySide6.QtCore import QTimer

        from app.ui.recovery_dialogs import RecoverVaultDialog, RecoveryKeyDialog

        manifest = self.install()
        errors, seen = [], {}

        def fill():
            dialog = next(d for d in self.open_dialogs() if isinstance(d, RecoverVaultDialog))
            dialog.key.setText(manifest["recovery_key"])
            dialog.new.setText(NEW_MASTER)
            dialog.confirm.setText(NEW_MASTER)
            dialog._submit()

        def key_dialog():
            dialog = next(d for d in self.open_dialogs() if isinstance(d, RecoveryKeyDialog))
            seen["key"] = dialog._key
            on_key_dialog(dialog, seen)

        def confirm():
            self.migration_dialog().start()
            self.later(fill, errors)
            QTimer.singleShot(0, lambda: self.later(key_dialog, errors))

        with unittest.mock.patch.object(vault_upgrade, "migrate_to_v4",
                                        side_effect=MigrationError("simulated failure")), \
                unittest.mock.patch("app.ui.dialogs.alert"):
            self.later(confirm, errors)
            self.window._unlock_screen.forgot.click()
        self.assertEqual(errors, [])
        self.assertTrue(seen.get("key"))
        return manifest, seen

    def test_abandon_message_says_the_key_stays_valid_and_it_does(self):
        def abandon(dialog, seen):
            with unittest.mock.patch("app.ui.dialogs.confirm", return_value=True) as ask:
                dialog.reject()  # close without confirming the key was written down
            seen["message"] = " ".join(str(a) for a in ask.call_args.args[1:3])

        manifest, seen = self.recover_with_failing_upgrade(abandon)
        message = seen["message"].lower()
        self.assertIn("stays valid", message)
        self.assertIn("will not be removed", message)
        self.assertIn("replace it", message)
        self.assertNotIn("will be removed from the vault", message)
        # Real behavior, which the text describes: key still saved and valid.
        vault_id = manifest["vault_id"]
        self.assertTrue(vault_has_recovery_key(vault_id))
        self.assertEqual(schema_of(self.path), 3)  # upgrade not done
        with self.assertRaises(RecoveryKeyError):  # the old key is invalidated
            Vault.recover(vault_id, manifest["recovery_key"], "x-mot-de-passe-de-test-1",
                          allow_legacy=True)
        vault, _ = Vault.recover(vault_id, seen["key"], NEW_MASTER, allow_legacy=True)
        vault.close()

    def test_new_password_then_upgrade_then_key_replacement(self):
        def acknowledge(dialog, _seen):
            dialog.ack.setChecked(True)
            dialog.done_button.click()

        manifest, seen = self.recover_with_failing_upgrade(acknowledge)
        orphan = seen["key"]
        # Opening with the NEW password: upgrade offered, then done.
        errors = self.later(lambda: self.migration_dialog().start())
        self.unlock_with(NEW_MASTER)
        self.assertEqual(errors, [])
        shell = self.window._shell
        self.assertIsNotNone(shell)
        self.assertEqual(schema_of(self.path), 4)
        # Later replacement (Settings -> This vault): the orphaned key stops working,
        # the new one works. Existing logic, not modified.
        replacement = shell.ctx.vault.create_recovery_key(NEW_MASTER)
        self.assertNotEqual(replacement, orphan)
        self.window.lock()
        vault_id = manifest["vault_id"]
        with self.assertRaises(RecoveryKeyError):
            Vault.recover(vault_id, orphan, "x-mot-de-passe-de-test-2")
        vault, _ = Vault.recover(vault_id, replacement, "x-mot-de-passe-de-test-3")
        vault.close()

    def test_normal_abandon_message_is_unchanged(self):
        from app.ui.recovery_dialogs import RecoveryKeyDialog

        abandoned = []
        dialog = RecoveryKeyDialog("0000-0000-0000-0000-0000-0000-0000-0000",
                                   self.window._clipboard, lambda: abandoned.append(1),
                                   self.window)
        self.addCleanup(dialog.deleteLater)
        with unittest.mock.patch("app.ui.dialogs.confirm", return_value=False) as ask:
            dialog.reject()
        self.assertIn("will be removed from the vault", ask.call_args.args[2])
        self.assertEqual(abandoned, [])


# --- E5.3: upgrade messages -----------------------------------------------------------


class TestUpgradeMessages(UpgradeUiTestCase):
    def test_confirmation_explains_backup_irreversibility_and_install(self):
        manifest = self.install()
        seen = {}

        def read_and_cancel():
            dialog = self.migration_dialog()
            seen["text"] = texts(dialog)
            dialog.reject()

        errors = self.later(read_and_cancel)
        self.unlock_with(manifest["master_password"])
        self.assertEqual(errors, [])
        text = seen["text"]
        for fragment in ("before any modification", "encrypted backup", "current format",
                         "current master password", "1.6 will no longer be able to open",
                         "Restore a backup", "new vault", "may replace 1.6",
                         "stays readable"):
            self.assertIn(fragment, text)
        self.assertNotIn("remains usable by 1.6", text)

    def test_backup_failure_names_the_folder_and_the_cause(self):
        manifest = self.install()
        not_a_folder = os.path.join(self._tmpdir.name, "pas-un-dossier")
        with open(not_a_folder, "w", encoding="utf-8") as f:
            f.write("fichier, pas dossier")
        self.window._settings.backup_dir = not_a_folder
        seen = {}

        def start_then_close():
            dialog = self.migration_dialog()
            dialog.start()
            seen["error"] = dialog.error.text()
            seen["retry"] = dialog.ok.text()
            dialog.reject()

        errors = self.later(start_then_close)
        self.unlock_with(manifest["master_password"])
        self.assertEqual(errors, [])
        error = seen["error"]
        self.assertIn("did not complete", error)
        self.assertIn("Preliminary backup impossible", error)
        self.assertIn("has not been modified", error)
        self.assertIn(f"Path: {not_a_folder}", error)
        self.assertIn("Cause:", error)
        self.assertEqual(seen["retry"], "Retry")
        self.assertNotIn(manifest["master_password"], error)
        self.assertEqual(schema_of(self.path), 3)

    def test_unexpected_structure_message_is_understandable(self):
        manifest = self.install()
        conn = sqlite3.connect(self.path)
        conn.execute("CREATE TABLE intrus (x)")
        conn.commit()
        conn.close()
        self.unlock_with(manifest["master_password"])
        message = self.window._unlock_screen.error.text()
        self.assertIn("did not create", message)
        self.assertIn("intrus", message)  # diagnostic detail kept
        self.assertIn("has not been modified", message)
        self.assertIn("1.6", message)
        self.assertNotIn("structure", message.lower())

    def test_security_page_describes_what_the_trash_audit_does(self):
        manifest = self.install()
        errors = self.later(lambda: self.migration_dialog().start())
        self.unlock_with(manifest["master_password"])
        self.assertEqual(errors, [])
        self.window._shell.navigate("security")
        text = texts(self.window._shell.pages["security"])
        self.assertNotIn("The Trash is not analyzed", text)
        self.assertIn("Trash", text)
        self.assertIn("is unreadable are reported", text)


class TestFailureDetails(unittest.TestCase):
    def test_os_error_in_the_chain(self):
        try:
            try:
                raise PermissionError(13, "Permission denied", "/chemin/inexistant/fichier")
            except OSError as exc:
                raise MigrationError("Preliminary backup impossible") from exc
        except MigrationError as error:
            details = vault_upgrade.failure_details(error)
        # File never created and folder missing: the given path is shown as is.
        self.assertEqual(details, ["Path: /chemin/inexistant/fichier",
                                   "Cause: Permission denied"])

    def test_application_error_in_the_chain(self):
        try:
            try:
                raise VaultError("The backup does not decrypt with the key of this vault.")
            except VaultError as exc:
                raise MigrationError("Preliminary backup impossible") from exc
        except MigrationError as error:
            details = vault_upgrade.failure_details(error)
        self.assertEqual(details, ["Cause: The backup does not decrypt with the key "
                                   "of this vault."])

    def test_no_detail_for_an_error_without_cause(self):
        self.assertEqual(vault_upgrade.failure_details(MigrationError("x")), [])
