"""v4 schema structures: transition (inside the migration) and new v4 vaults.

The additions (vault_meta.vault_uuid, entries.metadata_enc, categories.builtin_key
and name_enc, index, trigger) are applied only by add_v4_structures, which only the
migration calls. These tests check that they change nothing in the v3 behavior, and
that their constraints hold.
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.core import metadata
from app.core.builtin_categories import (
    BUILTIN_CATEGORY_KEYS,
    BUILTIN_CATEGORY_NAMES,
    LEGACY_BUILTIN_NAMES,
    builtin_key_for_v3_row,
    builtin_name,
    legacy_builtin_name,
)
from app.core.categories import BUILTIN_CATEGORIES, CategoryService
from app.core.entries import Entry
from app.core.exceptions import VaultCorruptedError, VaultError
from app.core.vault import Vault
from app.database import database, models
from app.database.models import CategoryRecord, VaultMeta
from app.database.repositories import (
    CategoryRepository,
    EntryRepository,
    VaultMetaRepository,
)
from app.services import backup
from tests.test_entries import MASTER, EntryTestCase
from tests.test_fixtures import FixtureVaultTestCase

UUID = bytes(range(16))
NOW = "2026-09-27T10:00:00+00:00"


def add_structures(vault: Vault) -> None:
    with vault.connection as conn:
        database.add_v4_structures(conn)


class TestBuiltinCategoryMapping(unittest.TestCase):
    def test_display_names_and_order(self):
        self.assertEqual(BUILTIN_CATEGORIES, ("Personal", "Work", "Finance",
                                              "Social", "Email", "Shopping"))
        self.assertEqual(tuple(BUILTIN_CATEGORY_NAMES.values()), BUILTIN_CATEGORIES)

    def test_legacy_names_are_frozen(self):
        # Names stored in plaintext by v1 to v3 vaults: the migration relies on them.
        self.assertEqual(LEGACY_BUILTIN_NAMES, {
            "personal": "Personnel", "work": "Travail", "finance": "Finances",
            "social": "Réseaux sociaux", "email": "Courriel", "shopping": "Achats"})
        self.assertEqual(tuple(LEGACY_BUILTIN_NAMES), BUILTIN_CATEGORY_KEYS)

    def test_keys_are_frozen_generic_ascii(self):
        # Keys stored on disk: never rename them.
        self.assertEqual(BUILTIN_CATEGORY_KEYS,
                         ("personal", "work", "finance", "social", "email", "shopping"))
        for key in BUILTIN_CATEGORY_KEYS:
            self.assertTrue(key.isascii() and key.islower() and key.isidentifier())

    def test_v3_row_mapping(self):
        self.assertEqual(builtin_key_for_v3_row("Travail", is_builtin=True), "work")
        self.assertEqual(builtin_name("social"), "Social")
        self.assertEqual(legacy_builtin_name("social"), "Réseaux sociaux")
        # A custom category with the same name stays custom: no deduction from the name.
        self.assertIsNone(builtin_key_for_v3_row("Travail", is_builtin=False))
        with self.assertRaises(ValueError):
            builtin_key_for_v3_row("Inconnue", is_builtin=True)
        with self.assertRaises(ValueError):  # v3 vaults never stored the English labels
            builtin_key_for_v3_row("Work", is_builtin=True)

    def test_uuid_size_is_consistent(self):
        self.assertEqual(models.VAULT_UUID_SIZE, metadata.VAULT_UUID_SIZE)


class TestNewVaultsAreV4(EntryTestCase):
    """v1.7: a new vault is created directly at the final v4 schema."""

    def test_new_vault_structure(self):
        conn = self.vault.connection
        self.assertEqual(database.SCHEMA_VERSION, 4)
        meta = VaultMetaRepository(conn).get()
        self.assertEqual(meta.schema_version, 4)
        self.assertEqual(len(meta.vault_uuid), 16)
        self.assertEqual(database.structure_problems(conn, 4), [])
        columns = {r[1] for r in conn.execute("PRAGMA table_info(entries)")}
        self.assertEqual(columns, {"id", "metadata_enc", "email_enc", "password_enc",
                                   "notes_enc", "extra_fields_enc"})

    def test_two_vaults_have_different_uuids(self):
        other = Vault.create("autre-coffre", "Autre", MASTER)
        try:
            self.assertNotEqual(VaultMetaRepository(other.connection).get().vault_uuid,
                                VaultMetaRepository(self.vault.connection).get().vault_uuid)
        finally:
            other.close()


class TestVaultUuidLifecycle(EntryTestCase):
    """Immutable end to end, through the real services (D1)."""

    def uuid(self, vault: Vault) -> bytes:
        return VaultMetaRepository(vault.connection).get().vault_uuid

    def test_unchanged_by_rename_password_change_and_recovery(self):
        original = self.uuid(self.vault)
        self.vault.rename("Renommé")
        self.vault.change_master_password(MASTER, "nouveau-mot-de-passe-maitre")
        key = self.vault.create_recovery_key("nouveau-mot-de-passe-maitre")
        self.vault.close()
        self.vault, _ = Vault.recover(self.vault_id, key, "encore-un-mot-de-passe")
        self.assertEqual(self.uuid(self.vault), original)

    def test_metadata_survive_backup_and_restore_with_the_same_uuid(self):
        # D1: creation -> encryption -> backup -> restore -> decryption.
        from app.core.entries import EntryService

        entry_id = self.entries.create_entry(Entry(
            service_name="Banque", url="https://banque.example", username="moi",
            password="secret", is_favorite=True, tags=("Finances",)))
        directory = Path(tempfile.mkdtemp(dir=self._tmpdir.name))
        info = backup.restore_backup(backup.create_backup(self.vault, directory), MASTER)
        self.assertNotEqual(info.vault_id, self.vault_id)  # new folder…
        restored = Vault.unlock(info.vault_id, MASTER)
        try:
            self.assertEqual(self.uuid(restored), self.uuid(self.vault))  # … same identity
            entry = EntryService(restored).get_entry(entry_id)
            self.assertEqual((entry.service_name, entry.url, entry.tags, entry.password),
                             ("Banque", "https://banque.example", ("Finances",), "secret"))
        finally:
            restored.close()


class TestV4StructuresOnTheV3Fixture(FixtureVaultTestCase):
    """Transition phase (inside the migration): additions only, nothing modified."""

    def _install_with_structures(self) -> dict:
        from app.utils.paths import vault_path
        from tests.test_fixtures import logical_dump

        manifest = self.install("v3-app-1.6.0")
        self.db_path = vault_path(manifest["vault_id"]) / "vault.db"
        self.before = logical_dump(self.db_path)
        self.vault = Vault.open_for_migration(manifest["vault_id"], manifest["master_password"])
        add_structures(self.vault)
        add_structures(self.vault)  # idempotent
        return manifest

    def test_existing_rows_are_unchanged(self):
        from tests.test_fixtures import logical_dump

        self._install_with_structures()
        after = logical_dump(self.db_path)
        for table, rows in self.before.items():
            if table == "__schema__":
                continue
            # ADD COLUMN appends the columns at the end of the row (NULL): the rest is identical.
            self.assertEqual([tuple(r[:len(old)]) for r, old in zip(after[table], rows,
                                                                    strict=True)],
                             [tuple(r) for r in rows], table)
        self.assertEqual(VaultMetaRepository(self.vault.connection).get().schema_version, 3)

    def test_no_value_is_generated_or_filled(self):
        self._install_with_structures()
        conn = self.vault.connection
        self.assertIsNone(VaultMetaRepository(conn).get().vault_uuid)
        self.assertTrue(all(blob is None for _, blob in
                            EntryRepository(conn).list_metadata_blobs()))
        self.assertTrue(all(c.builtin_key is None and c.name_enc is None
                            for c in CategoryRepository(conn).list_all_v4()))

    def test_services_refuse_a_v3_vault(self):
        # v1.7: the services NEVER read the plaintext v3 columns anymore.
        from app.core.entries import EntryService

        self._install_with_structures()
        with self.assertRaises(VaultError):
            EntryService(self.vault).list_entries()
        with self.assertRaises(VaultError):
            CategoryService(self.vault).list_categories()

    def test_migration_still_succeeds_afterwards(self):
        from app.services.migration_v4 import migrate_to_v4

        manifest = self._install_with_structures()
        migrate_to_v4(self.vault, Path(self._tmp.name) / "sauvegardes")
        self.assert_matches_manifest(manifest)


class V4TestCase(FixtureVaultTestCase):
    """Copy of the 1.6.0 (v3) vault with the v4 structures added, as in the migration."""

    def setUp(self):
        super().setUp()
        manifest = self.install("v3-app-1.6.0")
        self.vault = Vault.open_for_migration(manifest["vault_id"], manifest["master_password"])
        add_structures(self.vault)
        self.conn = self.vault.connection
        self.meta_repo = VaultMetaRepository(self.conn)

    def set_uuid(self, value: bytes = UUID) -> None:
        with self.conn:
            self.meta_repo.set_vault_uuid(value)


class TestVaultUuid(V4TestCase):
    def test_set_once_and_read_back(self):
        self.set_uuid()
        self.assertEqual(self.meta_repo.get().vault_uuid, UUID)

    def test_immutable_through_the_repository(self):
        self.set_uuid()
        for other in (UUID, bytes(16)):
            with self.subTest(other=other), self.assertRaises(ValueError):
                self.set_uuid(other)
        self.assertEqual(self.meta_repo.get().vault_uuid, UUID)

    def test_immutable_in_sqlite_itself(self):
        self.set_uuid()
        for value in (bytes(16), None):
            with self.subTest(value=value), self.assertRaises(sqlite3.IntegrityError), \
                    self.conn:
                self.conn.execute("UPDATE vault_meta SET vault_uuid = ?", (value,))
        self.assertEqual(self.meta_repo.get().vault_uuid, UUID)

    def test_sqlite_checks_size_and_type(self):
        for value in (b"x" * 15, b"x" * 17, b"", "0123456789abcdef"):
            with self.subTest(value=value), self.assertRaises(sqlite3.IntegrityError), \
                    self.conn:
                self.conn.execute("UPDATE vault_meta SET vault_uuid = ?", (value,))

    def test_repository_refuses_malformed_uuid(self):
        for value in (b"x" * 15, "0" * 16, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.meta_repo.set_vault_uuid(value)

    def test_model_validates_uuid(self):
        meta = self.meta_repo.get()
        for value in (b"x" * 15, "0" * 16, 16):
            with self.subTest(value=value), self.assertRaises(ValueError):
                VaultMeta(**{**{f: getattr(meta, f) for f in meta.__slots__},
                             "vault_uuid": value})

    def test_malformed_uuid_without_sqlite_check_is_corruption(self):
        # Forged file: column added WITHOUT the constraint, 5-byte value.
        import shutil

        from app.utils.paths import vault_path
        from tests.test_fixtures import FIXTURES

        target = vault_path("forge-uuid") / "vault.db"
        shutil.copyfile(FIXTURES / "v3-app-1.6.0" / "vault.db", target)
        conn = sqlite3.connect(target)
        with conn:
            conn.execute("ALTER TABLE vault_meta ADD COLUMN vault_uuid BLOB")
            conn.execute("UPDATE vault_meta SET vault_uuid = x'0102030405'")
        conn.close()
        with self.assertRaises(VaultCorruptedError):
            Vault.open_for_migration("forge-uuid", "fixture-mot-de-passe-maitre-FICTIF")


class TestEntryMetadataColumn(V4TestCase):
    def setUp(self):
        super().setUp()
        self.repo = EntryRepository(self.conn)
        self.ids = [entry_id for entry_id, _ in self.repo.list_metadata_blobs()]

    def test_write_and_list(self):
        with self.conn:
            self.assertTrue(self.repo.set_metadata_blob(2, b"blob-b"))
        listed = dict(self.repo.list_metadata_blobs())
        self.assertEqual(listed[2], b"blob-b")
        self.assertTrue(all(blob is None for i, blob in listed.items() if i != 2))
        self.assertEqual(self.repo.get_metadata_blob(2), b"blob-b")

    def test_trashed_entries_are_listed_too(self):
        trashed = {r.id for r in self.repo.list_deleted()}
        self.assertEqual(len(trashed), 2)
        self.assertLessEqual(trashed, set(self.ids))
        self.assertEqual(self.ids, sorted(self.ids))

    def test_unknown_entry(self):
        with self.conn:
            self.assertFalse(self.repo.set_metadata_blob(999, b"x"))
        with self.assertRaises(KeyError):
            self.repo.get_metadata_blob(999)

    def test_null_or_non_blob_values_are_refused(self):
        for value in (None, b"", "texte", 3):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.repo.set_metadata_blob(1, value)
        with self.assertRaises(sqlite3.IntegrityError), self.conn:
            self.conn.execute("UPDATE entries SET metadata_enc = 'texte' WHERE id = 1")


class TestCategoryColumns(V4TestCase):
    def setUp(self):
        super().setUp()
        self.repo = CategoryRepository(self.conn)
        self.by_name = {c.name: c for c in self.repo.list_all()}
        self.custom = self.by_name["Projets BTS"].id  # custom category of the 1.6.0 vault

    def test_builtin_key_only_on_builtin_rows(self):
        with self.conn:
            self.assertTrue(self.repo.set_builtin_key(self.by_name["Travail"].id, "work"))
            self.assertFalse(self.repo.set_builtin_key(self.custom, "finance"))
        keys = {c.id: c.builtin_key for c in self.repo.list_all_v4()}
        self.assertEqual(keys[self.by_name["Travail"].id], "work")
        self.assertIsNone(keys[self.custom])

    def test_unknown_builtin_key(self):
        with self.assertRaises(ValueError):
            self.repo.set_builtin_key(self.by_name["Travail"].id, "admin")
        with self.assertRaises(sqlite3.IntegrityError), self.conn:
            self.conn.execute("UPDATE categories SET builtin_key = 'admin' WHERE id = ?",
                              (self.by_name["Travail"].id,))

    def test_builtin_key_is_unique(self):
        with self.conn:
            self.repo.set_builtin_key(self.by_name["Travail"].id, "work")
        with self.assertRaises(sqlite3.IntegrityError), self.conn:
            self.conn.execute("UPDATE categories SET builtin_key = 'work' WHERE id = ?",
                              (self.by_name["Achats"].id,))

    def test_name_blob_only_on_custom_rows(self):
        with self.conn:
            self.assertTrue(self.repo.set_name_blob(self.custom, b"nom-chiffre"))
            self.assertFalse(self.repo.set_name_blob(self.by_name["Travail"].id, b"x"))
        blobs = {c.id: c.name_enc for c in self.repo.list_all_v4()}
        self.assertEqual(blobs[self.custom], b"nom-chiffre")
        for value in (None, b"", "texte"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.repo.set_name_blob(self.custom, value)
        with self.assertRaises(sqlite3.IntegrityError), self.conn:
            self.conn.execute("UPDATE categories SET name_enc = 'texte' WHERE id = ?",
                              (self.custom,))

    def test_model_rejects_incoherent_rows(self):
        base = {"id": 1, "name": "X", "is_builtin": True, "created_at": NOW}
        with self.assertRaises(ValueError):
            CategoryRecord(**base, builtin_key="admin")
        with self.assertRaises(ValueError):
            CategoryRecord(**base, builtin_key="work", name_enc=b"x")
        with self.assertRaises(ValueError):
            CategoryRecord(**base, name_enc="texte")
