import json
import os
import secrets
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app.core.entries import Entry
from app.core.exceptions import VaultError, VaultNotFoundError, WrongMasterPasswordError
from app.core.vault import Vault, delete_vault, list_vaults
from app.services import settings as settings_mod
from app.services.settings import Settings, backup_directory, load_settings, save_settings
from tests.test_entries import MASTER, EntryTestCase


class TestSettings(EntryTestCase):
    def test_defaults_when_missing(self):
        self.assertEqual(load_settings(), Settings())

    def test_roundtrip_and_permissions(self):
        s = Settings(auto_lock_seconds=60, clipboard_clear_seconds=10, trash_retention_days=None,
                     auto_backups_kept=3, generator_length=32, passphrase_separator=" ")
        save_settings(s)
        path = settings_mod.settings_path()
        self.assertEqual(oct(path.stat().st_mode & 0o777), "0o600")
        self.assertEqual(load_settings(), s)

    def test_invalid_values_fall_back_to_defaults(self):
        path = settings_mod.settings_path()
        path.write_text(json.dumps({
            "auto_lock_seconds": 7,            # hors liste : pas de délai arbitraire
            "clipboard_clear_seconds": 0,      # désactivation interdite
            "lock_on_session_lock": "non",     # pas un booléen
            "auto_backups_kept": 10_000,
            "backup_dir": "relatif/dossier",
            "generator_length": 3,
            "last_vault_id": "../../etc",
            "inconnu": 42,
            "generator_lowercase": False, "generator_uppercase": False,
            "generator_digits": False, "generator_symbols": False,
        }))
        s = load_settings()
        d = Settings()
        self.assertEqual((s.auto_lock_seconds, s.clipboard_clear_seconds, s.lock_on_session_lock,
                          s.auto_backups_kept, s.backup_dir, s.generator_length, s.last_vault_id),
                         (d.auto_lock_seconds, d.clipboard_clear_seconds, d.lock_on_session_lock,
                          d.auto_backups_kept, d.backup_dir, d.generator_length, d.last_vault_id))
        self.assertTrue(s.generator_lowercase and s.generator_symbols)

    def test_corrupted_file_gives_defaults(self):
        settings_mod.settings_path().write_text("{pas du json")
        self.assertEqual(load_settings(), Settings())

    def test_never_auto_lock_is_allowed_explicitly(self):
        save_settings(Settings(auto_lock_seconds=None))
        self.assertIsNone(load_settings().auto_lock_seconds)

    def test_backup_directory_only_restricts_folders_it_creates(self):
        existing = Path(self._tmpdir.name) / "Nextcloud"
        existing.mkdir(mode=0o755)
        os.chmod(existing, 0o755)
        self.assertEqual(backup_directory(Settings(backup_dir=str(existing))), existing)
        self.assertEqual(oct(existing.stat().st_mode & 0o777), "0o755")
        created = Path(self._tmpdir.name) / "nouveau" / "sauvegardes"
        backup_directory(Settings(backup_dir=str(created)))
        self.assertEqual(oct(created.stat().st_mode & 0o777), "0o700")


class TestVaultManagement(EntryTestCase):
    def test_rename(self):
        self.vault.rename("  Coffre   pro ")
        self.assertEqual(self.vault.info.vault_name, "Coffre pro")
        with self.assertRaises(VaultError):
            self.vault.rename("   ")
        with self.assertRaises(VaultError):
            self.vault.rename("x" * 61)

    def test_create_validates_name(self):
        with self.assertRaises(VaultError):
            Vault.create("autre", "   ", MASTER)

    def test_multiple_vaults_are_independent(self):
        other_pw = secrets.token_urlsafe(16)
        other = Vault.create("travail-1", "Travail", other_pw)
        from app.core.entries import EntryService
        EntryService(other).create_entry(Entry(service_name="Intranet"))
        other.close()
        self.assertEqual(sorted(v.vault_name for v in list_vaults()), ["Test", "Travail"])
        with self.assertRaises(WrongMasterPasswordError):
            Vault.unlock("travail-1", MASTER)  # chaque coffre a son mot de passe
        self.assertEqual(self.entries.list_entries(), [])

    def test_delete_vault_requires_password(self):
        other_pw = secrets.token_urlsafe(16)
        Vault.create("a-supprimer", "Temporaire", other_pw).close()
        with self.assertRaises(WrongMasterPasswordError):
            delete_vault("a-supprimer", "mauvais-mot-de-passe")
        self.assertIn("a-supprimer", [v.vault_id for v in list_vaults()])
        delete_vault("a-supprimer", other_pw)
        self.assertNotIn("a-supprimer", [v.vault_id for v in list_vaults()])

    def test_delete_vault_rejects_path_tricks(self):
        for bad in ("..", "../x", "a/b", ""):
            with self.assertRaises(VaultNotFoundError):
                delete_vault(bad, MASTER)

    def test_duplicate_entry(self):
        a = self.entries.create_entry(Entry(service_name="Banque", password="pw", is_favorite=True))
        b = self.entries.duplicate_entry(a)
        copy = self.entries.get_entry(b)
        self.assertEqual((copy.service_name, copy.password, copy.is_favorite),
                         ("Banque (copie)", "pw", False))


class TestUserEnvironment(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old = {k: os.environ.get(k) for k in ("XDG_DATA_HOME", "XDG_CONFIG_HOME")}
        os.environ["XDG_DATA_HOME"] = os.path.join(self._tmp.name, "data")
        os.environ["XDG_CONFIG_HOME"] = os.path.join(self._tmp.name, "config")

    def tearDown(self):
        for k, v in self._old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._tmp.cleanup()

    def test_ok_for_normal_user(self):
        from app.main import _check_user_environment
        self.assertIsNone(_check_user_environment())

    def test_refuses_root(self):
        from app.main import _check_user_environment
        with mock.patch("os.geteuid", return_value=0):
            self.assertIn("root", _check_user_environment())

    def test_detects_data_owned_by_another_user(self):
        from app.main import _check_user_environment
        os.makedirs(os.path.join(self._tmp.name, "data", "mon-coffre"))
        with mock.patch("os.getuid", return_value=os.getuid() + 4242):
            self.assertIn("n'appartient pas", _check_user_environment())


try:
    from PySide6.QtWidgets import QApplication
except ImportError:  # pragma: no cover
    QApplication = None


@unittest.skipIf(QApplication is None, "PySide6 non installé")
class TestSingleInstance(unittest.TestCase):
    def test_second_launch_asks_first_to_show(self):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtTest import QTest

        from app.ui.single_instance import SingleInstanceServer, notify_running_instance

        app = QApplication.instance() or QApplication([])
        with tempfile.TemporaryDirectory() as runtime:
            os.chmod(runtime, 0o700)
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": runtime}):
                self.assertFalse(notify_running_instance())
                server = SingleInstanceServer()
                shown = []
                server.show_requested.connect(lambda: shown.append(True))
                self.assertTrue(notify_running_instance())
                for _ in range(40):
                    if shown:
                        break
                    QTest.qWait(25)
                self.assertEqual(shown, [True])
                socket = Path(runtime) / "mon-coffre-fort.sock"
                self.assertEqual(oct(socket.stat().st_mode & 0o077), "0o0")  # propriétaire seul
                server.deleteLater()
                app.processEvents()

    def test_too_long_path_disables_single_instance(self):
        from app.ui import single_instance

        long_dir = tempfile.mkdtemp(prefix="x" * 90)
        try:
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": long_dir}), \
                    mock.patch.object(single_instance, "cache_dir", return_value=Path(long_dir)):
                self.assertIsNone(single_instance._socket_path())
                self.assertFalse(single_instance.notify_running_instance())
        finally:
            os.rmdir(long_dir)
