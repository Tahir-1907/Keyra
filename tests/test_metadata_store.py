"""Cache des métadonnées déchiffrées (Vault.metadata) : cycle de vie et fraîcheur.

Sur des copies MIGRÉES du coffre de référence 1.6.0. L'accent est mis sur les
données périmées : après écriture, ROLLBACK, suppression, restauration, et au
verrouillage, le cache ne doit jamais présenter autre chose que la base.
"""

import dataclasses
import time
from pathlib import Path
from unittest import mock

from app.core.exceptions import (
    EntryDecryptionError,
    EntryNotFoundError,
    EntryValidationError,
    VaultError,
    VaultLockedError,
)
from app.core.metadata import CategoryMetadata, MetadataCipher
from app.core.metadata_store import MetadataStore
from app.core.vault import Vault
from app.database.repositories import EntryRepository
from app.services.migration_v4 import load_v4_view
from tests.test_entries import MASTER, EntryTestCase
from tests.test_fixtures import FixtureVaultTestCase
from tests.test_migration_v4 import V3, MigrationTestCase

NOW = "2026-09-27T12:00:00+00:00"
BANK = 1  # « Banque Exemple » dans le coffre de référence


class StoreTestCase(MigrationTestCase):
    def setUp(self):
        super().setUp()
        self.manifest, _ = self.migrate(V3)
        self.store = self.vault.metadata


class TestLifecycle(StoreTestCase):
    def test_same_store_for_the_whole_session(self):
        self.assertIs(self.vault.metadata, self.store)

    def test_lazy_loading(self):
        self.assertFalse(self.store.is_loaded)
        with mock.patch.object(MetadataCipher, "decrypt_entry",
                               wraps=self.store.cipher.decrypt_entry) as spy:
            self.store.entries()
            first = spy.call_count
            self.store.entries()
            self.store.entry(BANK)
        self.assertEqual(first, 11)  # chaque blob déchiffré une fois…
        self.assertEqual(spy.call_count, 11)  # … et plus jamais ensuite

    def test_content_matches_the_database(self):
        view = load_v4_view(self.vault.connection, self.store.cipher)
        self.assertEqual(dict(self.store.entries()), view.entries)
        self.assertEqual({i: (c.name, c.is_builtin) for i, c in self.store.categories().items()},
                         view.categories)
        self.assertEqual(self.store.category_name(None), "")

    def test_mappings_are_read_only(self):
        with self.assertRaises(TypeError):
            self.store.entries()[BANK] = None
        with self.assertRaises(TypeError):
            self.store.categories()[1] = None

    def test_lock_destroys_the_cache(self):
        self.store.entries()
        self.store.categories()
        self.vault.lock()
        self.assertFalse(self.store.is_loaded)
        for access in (self.store.entries, self.store.categories, lambda: self.store.cipher,
                       lambda: self.store.entry(BANK)):
            with self.assertRaises(VaultLockedError):
                access()
        with self.assertRaises(VaultLockedError):
            _ = self.vault.metadata

    def test_close_destroys_it_too_and_reopening_starts_fresh(self):
        self.store.entries()
        old = self.store
        self.vault.close()
        self.assertFalse(old.is_loaded)
        self.vault = Vault.unlock(self.manifest["vault_id"], self.manifest["master_password"])
        self.assertIsNot(self.vault.metadata, old)
        self.assertEqual(self.vault.metadata.entry(BANK).name, "Banque Exemple")

    def test_nothing_is_written_to_disk(self):
        folder = Path(self.vault._db_path).parent
        before = {p.name: p.stat().st_mtime_ns for p in folder.iterdir()}
        self.store.entries()
        self.store.categories()
        self.assertEqual({p.name: p.stat().st_mtime_ns for p in folder.iterdir()}, before)

    def test_repr_reveals_nothing(self):
        self.store.entries()
        text = repr(self.store) + repr(self.store.categories())
        for secret in ("Banque", "Projets BTS", "banque.example"):
            self.assertNotIn(secret, text)


class TestNotAvailableOutsideV4(FixtureVaultTestCase):
    def test_v3_vault_has_no_metadata_store(self):
        manifest = self.install(V3)
        self.vault = Vault.open_for_migration(manifest["vault_id"], manifest["master_password"])
        with self.assertRaises(VaultError):
            _ = self.vault.metadata


class TestLockedVault(EntryTestCase):
    def test_locked_vault(self):
        self.vault.lock()
        with self.assertRaises(VaultLockedError):
            _ = self.vault.metadata
        self.vault.close()
        self.vault = Vault.unlock(self.vault_id, MASTER)


class TestNoStaleData(StoreTestCase):
    def _renamed(self, name: str):
        return dataclasses.replace(self.store.entry(BANK), name=name, updated_at=NOW)

    def test_write_is_visible_immediately(self):
        self.store.entries()
        generation = self.store.generation
        with self.vault.connection:
            self.store.write_entry(BANK, self._renamed("Nouvelle banque"))
        self.assertEqual(self.store.entry(BANK).name, "Nouvelle banque")
        self.assertGreater(self.store.generation, generation)
        self.assertEqual(load_v4_view(self.vault.connection, self.store.cipher)
                         .entries[BANK].name, "Nouvelle banque")

    def test_rolled_back_write_is_not_kept(self):
        self.store.entries()
        with self.assertRaises(RuntimeError), self.vault.connection:
            self.store.write_entry(BANK, self._renamed("Jamais enregistré"))
            self.assertEqual(self.store.entry(BANK).name, "Jamais enregistré")  # dans la txn
            raise RuntimeError("échec après écriture")
        self.assertEqual(self.store.entry(BANK).name, "Banque Exemple")

    def test_first_load_during_a_rolled_back_transaction(self):
        # Le cache n'a encore rien chargé : le premier chargement a lieu DANS la transaction.
        self.assertFalse(self.store.is_loaded)
        with self.assertRaises(RuntimeError), self.vault.connection:
            self.store.write_entry(BANK, self._renamed("Provisoire"))
            self.assertEqual(self.store.entries()[BANK].name, "Provisoire")
            raise RuntimeError("annulation")
        self.assertEqual(self.store.entries()[BANK].name, "Banque Exemple")

    def test_committed_write_is_kept(self):
        with self.vault.connection:
            self.store.write_entry(BANK, self._renamed("Validée"))
            self.store.entries()  # lue pendant la transaction
        self.assertEqual(self.store.entry(BANK).name, "Validée")
        self.vault.close()
        self.vault = Vault.unlock(self.manifest["vault_id"], self.manifest["master_password"])
        self.assertEqual(self.vault.metadata.entry(BANK).name, "Validée")

    def test_rolled_back_category_rename_is_not_kept(self):
        custom = next(c for c in self.store.categories().values() if not c.is_builtin)
        with self.assertRaises(RuntimeError), self.vault.connection:
            self.store.write_category(custom.id, CategoryMetadata("Provisoire", NOW))
            self.assertEqual(self.store.categories()[custom.id].name, "Provisoire")
            raise RuntimeError("annulation")
        self.assertEqual(self.store.categories()[custom.id].name, custom.name)

    def test_refused_write_changes_nothing(self):
        self.store.entries()
        with self.assertRaises(EntryValidationError):
            self.store.write_entry(BANK, self._renamed(""))
        self.assertEqual(self.store.entry(BANK).name, "Banque Exemple")

    def test_trash_and_restore(self):
        meta = self.store.entry(BANK)
        with self.vault.connection:
            self.store.write_entry(BANK, dataclasses.replace(meta, deleted_at=NOW))
        self.assertEqual(self.store.entry(BANK).deleted_at, NOW)
        with self.vault.connection:
            self.store.write_entry(BANK, dataclasses.replace(meta, deleted_at=None))
        self.assertIsNone(self.store.entry(BANK).deleted_at)

    def test_permanent_deletion(self):
        self.store.entries()
        with self.vault.connection as conn:
            conn.execute("DELETE FROM entries WHERE id = ?", (BANK,))
            self.store.invalidate_entry(BANK)
        self.assertNotIn(BANK, self.store.entries())
        with self.assertRaises(EntryNotFoundError):
            self.store.entry(BANK)

    def test_writing_a_missing_entry_fails_and_caches_nothing(self):
        with self.assertRaises(EntryNotFoundError):
            self.store.write_entry(999, self._renamed("Fantôme"))
        self.assertNotIn(999, self.store.entries())

    def test_categories_are_refreshed(self):
        custom = next(c for c in self.store.categories().values() if not c.is_builtin)
        with self.vault.connection:
            self.store.write_category(custom.id, CategoryMetadata("Renommée", NOW))
        self.assertEqual(self.store.categories()[custom.id].name, "Renommée")
        builtin = next(c for c in self.store.categories().values() if c.is_builtin)
        with self.assertRaises(VaultError), self.vault.connection:
            self.store.write_category(builtin.id, CategoryMetadata("Interdit", NOW))
        self.assertEqual(self.store.categories()[builtin.id].name, builtin.name)

    def test_external_change_needs_invalidate(self):
        # Limite documentée : SQL direct hors du cache -> visible après invalidate().
        self.store.entries()
        cipher = self.store.cipher
        blob = cipher.encrypt_entry(BANK, self._renamed("Changé ailleurs"))
        with self.vault.connection:
            EntryRepository(self.vault.connection).set_metadata_blob(BANK, blob)
        self.assertEqual(self.store.entry(BANK).name, "Banque Exemple")
        self.store.invalidate()
        self.assertEqual(self.store.entry(BANK).name, "Changé ailleurs")


class TestUnreadableEntries(StoreTestCase):
    def test_one_altered_entry_does_not_hide_the_others(self):
        blob = bytearray(EntryRepository(self.vault.connection).get_metadata_blob(BANK))
        blob[-1] ^= 0x01
        with self.vault.connection as conn:
            conn.execute("UPDATE entries SET metadata_enc = ? WHERE id = ?", (bytes(blob), BANK))
        self.store.invalidate()
        self.assertEqual(self.store.unreadable(), frozenset({BANK}))
        self.assertEqual(len(self.store.entries()), 10)
        with self.assertRaises(EntryDecryptionError):
            self.store.entry(BANK)

    def test_swapped_blobs_are_both_unreadable(self):
        repo = EntryRepository(self.vault.connection)
        a, b = repo.get_metadata_blob(1), repo.get_metadata_blob(2)
        with self.vault.connection as conn:
            conn.execute("UPDATE entries SET metadata_enc = ? WHERE id = 1", (b,))
            conn.execute("UPDATE entries SET metadata_enc = ? WHERE id = 2", (a,))
        self.store.invalidate()
        self.assertEqual(self.store.unreadable(), frozenset({1, 2}))

    def test_altered_category_is_an_error(self):
        from app.core.exceptions import CategoryDecryptionError

        with self.vault.connection as conn:
            conn.execute("UPDATE categories SET name_enc = substr(name_enc, 1, 40) "
                         "WHERE builtin_key IS NULL")
        self.store.invalidate()
        with self.assertRaises(CategoryDecryptionError):
            self.store.categories()


class TestPerformance(EntryTestCase):
    def test_2000_entries_load_quickly(self):
        from app.core.entries import Entry

        self.entries.import_entries([Entry(service_name=f"Service {i}", password="x")
                                     for i in range(2000)])
        self.vault.close()
        self.vault = Vault.unlock(self.vault_id, MASTER)  # cache neuf
        started = time.monotonic()
        self.assertEqual(len(self.vault.metadata.entries()), 2000)
        first = time.monotonic() - started
        started = time.monotonic()
        self.vault.metadata.entries()
        cached = time.monotonic() - started
        self.assertLess(first, 2.0)
        self.assertLess(cached, 0.01)


class TestStoreWithoutVault(StoreTestCase):
    def test_store_can_be_built_directly(self):
        # Construction explicite (utile aux services) : même contenu que via le Vault.
        uuid = self.vault.connection.execute("SELECT vault_uuid FROM vault_meta").fetchone()[0]
        store = MetadataStore(self.vault.connection, self.vault._require_unlocked_key(), uuid)
        self.assertEqual(dict(store.entries()), dict(self.store.entries()))
        store.clear()
        with self.assertRaises(VaultLockedError):
            store.entries()
