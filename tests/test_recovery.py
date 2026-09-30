"""Recovery key: format, creation, single use, security."""

import hashlib
import secrets
import shutil
import sqlite3
from pathlib import Path

from app.core import recovery
from app.core.entries import Entry, EntryService
from app.core.exceptions import (
    InvalidMasterPasswordPolicyError,
    NoRecoveryKeyError,
    RecoveryKeyError,
    RecoveryKeyFormatError,
    VaultMigrationRequiredError,
    WrongMasterPasswordError,
)
from app.core.vault import Vault, vault_has_recovery_key
from app.database import database
from app.database.repositories import VaultMetaRepository
from app.utils.paths import vault_path
from tests.test_vault import VaultTestCase


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _password() -> str:
    return secrets.token_urlsafe(16)


class TestRecoveryKeyFormat(VaultTestCase):
    def test_generated_keys_are_well_formed_and_distinct(self):
        keys = {recovery.generate() for _ in range(50)}
        self.assertEqual(len(keys), 50)
        for key in keys:
            groups = key.split("-")
            self.assertEqual([len(g) for g in groups], [4] * 8)
            self.assertTrue(set(key.replace("-", "")) <= set(recovery.ALPHABET))
            self.assertEqual(len(recovery.normalize(key)), recovery.DATA_LENGTH)

    def test_normalize_tolerates_case_spaces_and_confusable_letters(self):
        key = recovery.generate()
        expected = recovery.normalize(key)
        sloppy = " ".join(key.replace("-", "").lower()[i:i + 8] for i in range(0, 32, 8))
        self.assertEqual(recovery.normalize(sloppy), expected)
        zero_one = key.replace("0", "O").replace("1", "l")
        self.assertEqual(recovery.normalize(zero_one), expected)

    def test_typos_are_reported_before_any_derivation(self):
        key = recovery.generate().replace("-", "")
        with self.assertRaises(RecoveryKeyFormatError):
            recovery.normalize(key[:-1])
        with self.assertRaises(RecoveryKeyFormatError):
            recovery.normalize(key[:-1] + "U")  # U is not in the alphabet
        # One character changed: the check detects it (except a collision, 1 in 1024).
        detected = 0
        for position in range(0, 30, 3):
            char = key[position]
            other = recovery.ALPHABET[(recovery.ALPHABET.index(char) + 7) % 32]
            try:
                recovery.normalize(key[:position] + other + key[position + 1:])
            except RecoveryKeyFormatError:
                detected += 1
        self.assertGreaterEqual(detected, 9)


class TestRecoveryKey(VaultTestCase):
    def setUp(self):
        super().setUp()
        self.master = _password()
        self.vault, self.key = Vault.create_with_recovery(self.vault_id, "Perso", self.master)
        self.entries = EntryService(self.vault)
        self.entry_id = self.entries.create_entry(
            Entry(service_name="Banque", password="secret-de-test"))

    def tearDown(self):
        self.vault.close()
        super().tearDown()

    def test_key_is_never_stored(self):
        self.assertTrue(self.vault.has_recovery_key)
        self.vault.close()
        compact = self.key.replace("-", "").encode()
        for path in Path(self.vault._db_path).parent.iterdir():
            data = path.read_bytes()
            self.assertNotIn(compact, data, path.name)
            self.assertNotIn(compact[:30], data, path.name)
            self.assertNotIn(self.key.encode(), data, path.name)
        self.vault = Vault.unlock(self.vault_id, self.master)

    def test_recover_sets_new_password_and_rotates_key(self):
        self.vault.close()
        self.assertTrue(vault_has_recovery_key(self.vault_id))
        new_master = _password()
        vault, new_key = Vault.recover(self.vault_id, self.key.lower(), new_master)
        self.vault = vault
        self.assertFalse(vault.is_locked)
        self.assertNotEqual(new_key, self.key)
        self.assertEqual(EntryService(vault).get_entry(self.entry_id).password, "secret-de-test")
        vault.close()
        # The old password and the old key no longer open anything; the new ones do.
        with self.assertRaises(WrongMasterPasswordError):
            Vault.unlock(self.vault_id, self.master)
        with self.assertRaises(RecoveryKeyError):
            Vault.recover(self.vault_id, self.key, _password())
        self.vault = Vault.unlock(self.vault_id, new_master)
        self.vault.close()
        self.vault, _ = Vault.recover(self.vault_id, new_key, _password())

    def test_wrong_key_is_refused_without_changing_anything(self):
        self.vault.close()
        before = self._envelopes()
        with self.assertRaises(RecoveryKeyError) as ctx:
            Vault.recover(self.vault_id, recovery.generate(), _password())
        self.assertNotIsInstance(ctx.exception, RecoveryKeyFormatError)
        with self.assertRaises(RecoveryKeyFormatError):
            Vault.recover(self.vault_id, "ABCD-EFGH", _password())
        with self.assertRaises(InvalidMasterPasswordPolicyError):
            Vault.recover(self.vault_id, self.key, "court")
        self.assertEqual(self._envelopes(), before)
        self.vault = Vault.unlock(self.vault_id, self.master)

    def test_envelopes_are_not_interchangeable(self):
        # Worst case: the master password IS the secret part of a recovery key,
        # hence the same KEK. Copying the password envelope into the recovery slot
        # must still open nothing: only the (distinct) AES-GCM associated data
        # prevents it.
        key = recovery.generate()
        other_id = self.vault_id + "-aad"
        vault = Vault.create(other_id, "AAD", recovery.normalize(key))
        conn = vault.connection
        with conn:
            conn.execute("INSERT INTO vault_recovery SELECT 1, kdf_params_json, kdf_salt, "
                         "wrapped_key_blob, created_at FROM vault_meta;")
        vault.close()
        with self.assertRaises(RecoveryKeyError) as ctx:
            Vault.recover(other_id, key, _password())
        self.assertNotIsInstance(ctx.exception, RecoveryKeyFormatError)
        Vault.unlock(other_id, recovery.normalize(key)).close()  # nothing changed

    def test_create_replace_and_remove_require_master_password(self):
        with self.assertRaises(WrongMasterPasswordError):
            self.vault.create_recovery_key(_password())
        with self.assertRaises(WrongMasterPasswordError):
            self.vault.remove_recovery_key(_password())
        replaced = self.vault.create_recovery_key(self.master)
        self.assertNotEqual(replaced, self.key)
        self.vault.close()
        with self.assertRaises(RecoveryKeyError):
            Vault.recover(self.vault_id, self.key, _password())  # the old one is revoked
        self.vault = Vault.unlock(self.vault_id, self.master)
        self.vault.remove_recovery_key(self.master)
        self.assertFalse(self.vault.has_recovery_key)
        self.vault.close()
        self.assertFalse(vault_has_recovery_key(self.vault_id))
        with self.assertRaises(NoRecoveryKeyError):
            Vault.recover(self.vault_id, replaced, _password())
        self.vault = Vault.unlock(self.vault_id, self.master)

    def test_change_master_password_keeps_recovery_key_valid(self):
        new_master = _password()
        self.vault.change_master_password(self.master, new_master)
        self.vault.close()
        self.vault, _ = Vault.recover(self.vault_id, self.key, _password())

    def _envelopes(self):
        conn = sqlite3.connect(self.vault._db_path)
        try:
            return (conn.execute("SELECT wrapped_key_blob, kdf_salt FROM vault_meta").fetchone(),
                    conn.execute("SELECT wrapped_key_blob FROM vault_recovery").fetchone())
        finally:
            conn.close()


class TestVaultWithoutRecoveryKey(VaultTestCase):
    def test_plain_vault_and_v2_vault_have_no_key(self):
        master = _password()
        vault = Vault.create(self.vault_id, "Perso", master)
        self.assertFalse(vault.has_recovery_key)
        vault.close()
        self.assertFalse(vault_has_recovery_key(self.vault_id))
        with self.assertRaises(NoRecoveryKeyError):
            Vault.recover(self.vault_id, recovery.generate(), _password())
        # Real v2 vault (app version 1.0.0, no vault_recovery table): no key,
        # and any recovery requires the v4 upgrade first (file not modified).
        fixture = Path(__file__).resolve().parent / "fixtures" / "v2-app-1.0.0" / "vault.db"
        shutil.copyfile(fixture, vault_path("coffre-v2") / "vault.db")
        self.assertFalse(vault_has_recovery_key("coffre-v2"))
        with self.assertRaises(VaultMigrationRequiredError):
            Vault.recover("coffre-v2", recovery.generate(), _password())
        self.assertEqual(sha256_of(vault_path("coffre-v2") / "vault.db"), sha256_of(fixture))
        vault = Vault.unlock(self.vault_id, master)
        self.assertEqual(VaultMetaRepository(vault.connection).get().schema_version,
                         database.SCHEMA_VERSION)
        key = vault.create_recovery_key(master)
        vault.close()
        vault, _ = Vault.recover(self.vault_id, key, _password())
        vault.close()
