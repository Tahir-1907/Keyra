import gc
import os
import tempfile
import unittest
import uuid
import warnings

from app.core.exceptions import (
    InvalidMasterPasswordPolicyError,
    UnsupportedVaultVersionError,
    VaultAlreadyExistsError,
    VaultCorruptedError,
    VaultNotFoundError,
    WrongMasterPasswordError,
)
from app.core.vault import Vault
from app.database import database
from app.database.repositories import VaultMetaRepository


class VaultTestCase(unittest.TestCase):
    """Isole chaque test dans un répertoire XDG temporaire dédié."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._env_patch = {
            "XDG_DATA_HOME": os.path.join(self._tmpdir.name, "data"),
            "XDG_CONFIG_HOME": os.path.join(self._tmpdir.name, "config"),
            "XDG_CACHE_HOME": os.path.join(self._tmpdir.name, "cache"),
        }
        self._old_env = {k: os.environ.get(k) for k in self._env_patch}
        os.environ.update(self._env_patch)
        self.vault_id = f"test-vault-{uuid.uuid4().hex[:8]}"

    def tearDown(self):
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._tmpdir.cleanup()


class TestVaultCreation(VaultTestCase):
    def test_create_returns_unlocked_vault(self):
        vault = Vault.create(self.vault_id, "Personnel", "mot-de-passe-maitre-solide")
        self.assertFalse(vault.is_locked)
        self.assertEqual(vault.info.vault_name, "Personnel")
        vault.close()

    def test_create_rejects_weak_master_password(self):
        with self.assertRaises(InvalidMasterPasswordPolicyError):
            Vault.create(self.vault_id, "Personnel", "short")

    def test_create_twice_raises_already_exists(self):
        v = Vault.create(self.vault_id, "Personnel", "mot-de-passe-maitre-solide")
        v.close()
        with self.assertRaises(VaultAlreadyExistsError):
            Vault.create(self.vault_id, "Personnel", "mot-de-passe-maitre-solide")


class TestVaultUnlock(VaultTestCase):
    def setUp(self):
        super().setUp()
        v = Vault.create(self.vault_id, "Personnel", "mot-de-passe-maitre-solide")
        v.close()

    def test_unlock_with_correct_password_succeeds(self):
        vault = Vault.unlock(self.vault_id, "mot-de-passe-maitre-solide")
        self.assertFalse(vault.is_locked)
        vault.close()

    def test_unlock_with_wrong_password_raises(self):
        with self.assertRaises(WrongMasterPasswordError):
            Vault.unlock(self.vault_id, "mauvais-mot-de-passe-ici")

    def test_unlock_nonexistent_vault_raises(self):
        with self.assertRaises(VaultNotFoundError):
            Vault.unlock("coffre-qui-n-existe-pas", "peu-importe-le-mdp")

    def test_lock_clears_access(self):
        vault = Vault.unlock(self.vault_id, "mot-de-passe-maitre-solide")
        self.assertFalse(vault.is_locked)
        vault.lock()
        self.assertTrue(vault.is_locked)
        vault.close()

    def test_reunlock_after_lock_works(self):
        vault = Vault.unlock(self.vault_id, "mot-de-passe-maitre-solide")
        vault.lock()
        vault2 = Vault.unlock(self.vault_id, "mot-de-passe-maitre-solide")
        self.assertFalse(vault2.is_locked)
        vault2.close()
        vault.close()


class TestVaultCorruptionDetection(VaultTestCase):
    def setUp(self):
        super().setUp()
        v = Vault.create(self.vault_id, "Personnel", "mot-de-passe-maitre-solide")
        self.db_path = v._db_path  # accès direct pour altérer volontairement le fichier
        v.close()

    def test_detects_corrupted_wrapped_key(self):
        conn = database.connect(self.db_path)
        repo = VaultMetaRepository(conn)
        meta = repo.get()
        # On tronque le blob de clé enveloppée pour simuler une corruption structurelle.
        corrupted = meta.wrapped_key_blob[:3]
        conn.execute(
            "UPDATE vault_meta SET wrapped_key_blob = ? WHERE id = 1;", (corrupted,)
        )
        conn.commit()
        conn.close()

        with self.assertRaises(VaultCorruptedError):
            Vault.unlock(self.vault_id, "mot-de-passe-maitre-solide")

    def test_detects_unsupported_future_format_version(self):
        conn = database.connect(self.db_path)
        conn.execute("UPDATE vault_meta SET format_version = 999 WHERE id = 1;")
        conn.commit()
        conn.close()

        with self.assertRaises(UnsupportedVaultVersionError):
            Vault.unlock(self.vault_id, "mot-de-passe-maitre-solide")

    def test_detects_garbage_database_file(self):
        with open(self.db_path, "wb") as f:
            f.write(b"ceci n'est pas un fichier sqlite valide")

        with self.assertRaises(VaultCorruptedError):
            Vault.unlock(self.vault_id, "mot-de-passe-maitre-solide")

    def test_garbage_database_file_does_not_leak_connection(self):
        # sqlite3.connect() est paresseux : l'erreur n'apparaît qu'au premier
        # PRAGMA. La connexion doit être fermée, pas laissée au ramasse-miettes.
        with open(self.db_path, "wb") as f:
            f.write(b"ceci n'est pas un fichier sqlite valide")

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            with self.assertRaises(VaultCorruptedError):
                Vault.unlock(self.vault_id, "mot-de-passe-maitre-solide")
            gc.collect()
        leaks = [w for w in caught if issubclass(w.category, ResourceWarning)]
        self.assertEqual(leaks, [])


class TestChangeMasterPassword(VaultTestCase):
    def test_change_password_then_unlock_with_new_password(self):
        vault = Vault.create(self.vault_id, "Personnel", "ancien-mot-de-passe-1")
        vault.change_master_password("ancien-mot-de-passe-1", "nouveau-mot-de-passe-2")
        vault.close()

        # L'ancien mot de passe ne doit plus fonctionner.
        with self.assertRaises(WrongMasterPasswordError):
            Vault.unlock(self.vault_id, "ancien-mot-de-passe-1")

        # Le nouveau doit fonctionner.
        vault2 = Vault.unlock(self.vault_id, "nouveau-mot-de-passe-2")
        self.assertFalse(vault2.is_locked)
        vault2.close()

    def test_change_password_with_wrong_current_password_raises(self):
        vault = Vault.create(self.vault_id, "Personnel", "ancien-mot-de-passe-1")
        with self.assertRaises(WrongMasterPasswordError):
            vault.change_master_password("mauvais-mot-de-passe", "nouveau-mot-de-passe-2")
        vault.close()


if __name__ == "__main__":
    unittest.main()
