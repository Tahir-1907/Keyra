"""E5.2 et E5.3 : messages exacts (clé de récupération orpheline, mise à niveau).

Les textes suivent le comportement réel, qui n'est pas modifié : les tests vérifient
d'abord le comportement (clé valide ou non, coffre modifié ou non), puis que le texte
le décrit. Copies de fixtures dans des répertoires XDG temporaires uniquement.
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


# --- E5.2 : clé de récupération orpheline -----------------------------------------------------


class TestOrphanRecoveryKey(UpgradeUiTestCase):
    """Récupération réussie (nouveau mot de passe, nouvelle clé) puis mise à niveau en
    échec : la nouvelle clé est déjà enregistrée et reste valide si l'utilisateur ferme
    sa fenêtre sans l'avoir notée."""

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
                                        side_effect=MigrationError("panne simulée")), \
                unittest.mock.patch("app.ui.dialogs.alert"):
            self.later(confirm, errors)
            self.window._unlock_screen.forgot.click()
        self.assertEqual(errors, [])
        self.assertTrue(seen.get("key"))
        return manifest, seen

    def test_abandon_message_says_the_key_stays_valid_and_it_does(self):
        def abandon(dialog, seen):
            with unittest.mock.patch("app.ui.dialogs.confirm", return_value=True) as ask:
                dialog.reject()  # fermer sans avoir confirmé avoir noté la clé
            seen["message"] = " ".join(str(a) for a in ask.call_args.args[1:3])

        manifest, seen = self.recover_with_failing_upgrade(abandon)
        message = seen["message"].lower()
        self.assertIn("reste valide", message)
        self.assertIn("ne sera pas supprimée", message)
        self.assertIn("remplacez-la", message)
        self.assertNotIn("sera supprimée du coffre", message)
        # Comportement réel, que le texte décrit : clé toujours enregistrée et valide.
        vault_id = manifest["vault_id"]
        self.assertTrue(vault_has_recovery_key(vault_id))
        self.assertEqual(schema_of(self.path), 3)  # mise à niveau non faite
        with self.assertRaises(RecoveryKeyError):  # l'ancienne clé est invalidée
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
        # Ouverture avec le NOUVEAU mot de passe : mise à niveau proposée puis faite.
        errors = self.later(lambda: self.migration_dialog().start())
        self.unlock_with(NEW_MASTER)
        self.assertEqual(errors, [])
        shell = self.window._shell
        self.assertIsNotNone(shell)
        self.assertEqual(schema_of(self.path), 4)
        # Remplacement ultérieur (Paramètres -> Ce coffre) : la clé orpheline cesse de
        # fonctionner, la nouvelle fonctionne. Logique existante, non modifiée.
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
        self.assertIn("sera supprimée du coffre", ask.call_args.args[2])
        self.assertEqual(abandoned, [])


# --- E5.3 : messages de mise à niveau -----------------------------------------------------------


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
        for fragment in ("avant toute modification", "sauvegarde chiffrée", "format actuel",
                         "mot de passe maître actuel", "1.6 ne pourra plus ouvrir",
                         "Restaurer une sauvegarde", "nouveau coffre", "remplacer la 1.6",
                         "historique reste lisible"):
            self.assertIn(fragment, text)
        self.assertNotIn("sauvegarde, elle, reste utilisable par la 1.6", text)

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
        self.assertIn("n'a pas abouti", error)
        self.assertIn("Sauvegarde préalable impossible", error)
        self.assertIn("pas été modifié", error)
        self.assertIn(f"Chemin : {not_a_folder}", error)
        self.assertIn("Cause :", error)
        self.assertEqual(seen["retry"], "Réessayer")
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
        self.assertIn("n'a pas créés", message)
        self.assertIn("intrus", message)  # détail de diagnostic conservé
        self.assertIn("pas été modifié", message)
        self.assertIn("1.6", message)
        self.assertNotIn("structure", message.lower())

    def test_security_page_describes_what_the_trash_audit_does(self):
        manifest = self.install()
        errors = self.later(lambda: self.migration_dialog().start())
        self.unlock_with(manifest["master_password"])
        self.assertEqual(errors, [])
        self.window._shell.navigate("security")
        text = texts(self.window._shell.pages["security"])
        self.assertNotIn("La corbeille n'est pas analysée", text)
        self.assertIn("corbeille", text)
        self.assertIn("illisibles sont signalées", text)


class TestFailureDetails(unittest.TestCase):
    def test_os_error_in_the_chain(self):
        try:
            try:
                raise PermissionError(13, "Permission denied", "/chemin/inexistant/fichier")
            except OSError as exc:
                raise MigrationError("Sauvegarde préalable impossible") from exc
        except MigrationError as error:
            details = vault_upgrade.failure_details(error)
        # Fichier jamais créé et dossier absent : le chemin donné est affiché tel quel.
        self.assertEqual(details, ["Chemin : /chemin/inexistant/fichier",
                                   "Cause : Permission denied"])

    def test_application_error_in_the_chain(self):
        try:
            try:
                raise VaultError("La sauvegarde ne se déchiffre pas avec la clé de ce coffre.")
            except VaultError as exc:
                raise MigrationError("Sauvegarde préalable impossible") from exc
        except MigrationError as error:
            details = vault_upgrade.failure_details(error)
        self.assertEqual(details, ["Cause : La sauvegarde ne se déchiffre pas avec la clé "
                                   "de ce coffre."])

    def test_no_detail_for_an_error_without_cause(self):
        self.assertEqual(vault_upgrade.failure_details(MigrationError("x")), [])
