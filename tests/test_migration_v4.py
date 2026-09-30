"""Migration v1/v2/v3 -> v4 (C2) : conservation, retour arrière, confidentialité.

Toujours sur des COPIES des coffres de référence (tests/fixtures) ou sur des
coffres jetables. La migration n'est appelée par aucun code de l'application.
"""

import json
import os
import sqlite3
import time
from pathlib import Path

from app.core import crypto
from app.core.entries import EntryFilter
from app.core.exceptions import VaultError
from app.core.metadata import MetadataCipher
from app.core.snapshots import parse_snapshot
from app.core.vault import Vault
from app.database import database
from app.database.repositories import HistoryRepository, VaultMetaRepository
from app.services import backup
from app.services.migration_v4 import (
    MigrationError,
    load_v4_view,
    migrate_to_v4,
    summaries_v4,
)
from app.utils.paths import vault_path
from tests.test_fixtures import FIXTURES, FixtureVaultTestCase, logical_dump

V3 = "v3-app-1.6.0"
V2 = "v2-app-1.0.0"
PLAIN_V3_ENTRY_COLUMNS = ("service_name", "url", "username", "entry_type", "category_id",
                          "is_favorite", "is_deleted", "deleted_at", "created_at",
                          "updated_at", "last_used_at", "password_changed_at")


class MigrationTestCase(FixtureVaultTestCase):
    def setUp(self):
        super().setUp()
        self.backup_dir = Path(self._tmp.name) / "sauvegardes"

    def db_path(self, manifest: dict) -> Path:
        return vault_path(manifest["vault_id"]) / "vault.db"

    def install(self, name: str) -> dict:
        manifest = super().install(name)
        # État de référence, avant toute opération sur le coffre.
        self.v3_dump = logical_dump(self.db_path(manifest))
        return manifest

    def migrate(self, name: str, fault=None, prepare=None):
        """Installe une copie, la prépare éventuellement (SQL brut), puis la migre."""
        manifest = self.install(name)
        if prepare is not None:
            conn = sqlite3.connect(self.db_path(manifest))
            prepare(conn)
            conn.commit()
            conn.close()
            self.v3_dump = logical_dump(self.db_path(manifest))
        self.vault = Vault.open_for_migration(manifest["vault_id"], manifest["master_password"])
        return manifest, migrate_to_v4(self.vault, self.backup_dir, _fault=fault)

    def cipher(self) -> MetadataCipher:
        uuid = VaultMetaRepository(self.vault.connection).get().vault_uuid
        return MetadataCipher(self.vault._require_unlocked_key(), uuid)

    def assert_v4_matches_manifest(self, manifest: dict, with_history: bool = True) -> None:
        conn, dek = self.vault.connection, self.vault._require_unlocked_key()
        view = load_v4_view(conn, self.cipher())
        self.assertEqual(sorted((c["id"], c["name"], c["is_builtin"])
                                for c in manifest["categories"]),
                         sorted((cid, name, builtin)
                                for cid, (name, builtin) in view.categories.items()))
        self.assertEqual(sorted(view.entries), sorted(e["id"] for e in manifest["entries"]))
        for expected in manifest["entries"]:
            entry_id, meta = expected["id"], view.entries[expected["id"]]
            secrets = {}
            row = conn.execute("SELECT email_enc, password_enc, notes_enc, extra_fields_enc "
                               "FROM entries WHERE id = ?", (entry_id,)).fetchone()
            for column, blob in zip(("email", "password", "notes", "extra"), row, strict=True):
                secrets[column] = crypto.decrypt_field(
                    dek, blob, f"mon-coffre-fort:entry:{entry_id}:{column}".encode())
            actual = {
                "service_name": meta.name, "url": meta.url, "username": meta.username,
                "entry_type": meta.entry_type, "category_id": meta.category_id,
                "is_favorite": meta.is_favorite, "in_trash": meta.deleted_at is not None,
                "created_at": meta.created_at, "updated_at": meta.updated_at,
                "password_changed_at": meta.password_changed_at,
                "deleted_at": meta.deleted_at or "", "email": secrets["email"],
                "password": secrets["password"], "notes": secrets["notes"],
                "extra": json.loads(secrets["extra"]) if secrets["extra"] else {},
                "tags": meta.tags,
            }
            wanted = {k: expected[k] for k in actual if k != "tags"} | {"tags": ()}
            self.assertEqual(actual, wanted, f"entrée {entry_id}")
            if with_history:
                history = []
                for record in HistoryRepository(conn).list_for_entry(entry_id):
                    content = parse_snapshot(json.loads(crypto.decrypt_field(
                        dek, record.snapshot_enc,
                        f"mon-coffre-fort:history:{entry_id}:{record.id}".encode())))
                    history.append({"service_name": content.service_name, "url": content.url,
                                    "username": content.username,
                                    "password": content.password,
                                    "category_id": content.category_id})
                self.assertEqual(history, expected["history"], f"historique {entry_id}")
        for search in manifest["searches"]:
            self.assertEqual([s.id for s in summaries_v4(view, EntryFilter(**search["filter"]))],
                             search["result"], f"recherche {search['filter']}")

    def assert_intact_v3(self, manifest: dict) -> None:
        """Après un échec : coffre v3 STRICTEMENT identique (schéma et toutes les lignes),
        et toujours migrable avec succès."""
        conn = self.vault.connection
        self.assertEqual(conn.execute("PRAGMA foreign_keys;").fetchone()[0], 1)
        self.assertFalse(conn.in_transaction)
        self.assertEqual(VaultMetaRepository(conn).get().schema_version, 3)
        self.assertFalse(database.has_v4_structures(conn))
        self.assertIsNone(VaultMetaRepository(conn).get().vault_uuid)
        self.vault.close()
        self.assertEqual(logical_dump(self.db_path(manifest)), self.v3_dump)
        self.assertEqual(list(self.db_path(manifest).parent.glob("*.bak")), [])
        self.vault = Vault.open_for_migration(manifest["vault_id"], manifest["master_password"])
        migrate_to_v4(self.vault, self.backup_dir)
        self.assert_v4_matches_manifest(manifest)


class TestSuccessfulMigration(MigrationTestCase):
    def _check_success(self, name: str) -> None:
        manifest, report = self.migrate(name)
        conn = self.vault.connection
        self.assertEqual(VaultMetaRepository(conn).get().schema_version, 4)
        self.assertEqual(database.structure_problems(conn, 4), [])
        self.assertEqual(conn.execute("PRAGMA foreign_key_check;").fetchall(), [])
        self.assertEqual((report.from_version, report.entries, report.categories,
                          report.history_versions, report.tags),
                         (manifest["schema_version"], 11, 8, 3, 0))
        self.assertTrue(report.vacuumed)
        self.assertEqual(report.backup_path.suffix, ".mcfbak")
        self.assertEqual(list(self.db_path(manifest).parent.glob("*.bak")), [])  # jamais de .bak
        self.assert_v4_matches_manifest(manifest)

    def test_v3_vault_made_by_1_6_0(self):
        self._check_success(V3)

    def test_v2_vault_made_by_1_0_0(self):
        self._check_success(V2)

    def test_simulated_v1_vault(self):
        def downgrade_to_v1(conn):
            conn.execute("DROP TABLE entry_history;")
            conn.execute("DROP TABLE vault_recovery;")
            conn.execute("ALTER TABLE entries DROP COLUMN password_changed_at;")
            conn.execute("UPDATE vault_meta SET schema_version = 1;")

        manifest, report = self.migrate(V3, prepare=downgrade_to_v1)
        self.assertEqual((report.from_version, report.history_versions), (1, 0))
        view = load_v4_view(self.vault.connection, self.cipher())
        for expected in manifest["entries"]:
            meta = view.entries[expected["id"]]
            self.assertEqual((meta.name, meta.password_changed_at),
                             (expected["service_name"], meta.updated_at))
        self.assertEqual(database.structure_problems(self.vault.connection, 4), [])

    def test_vault_uuid_is_new_random_and_fixed(self):
        _, _ = self.migrate(V3)
        first = VaultMetaRepository(self.vault.connection).get().vault_uuid
        self.assertEqual(len(first), 16)
        self.vault.close()
        self.vault = None
        _, _ = self.migrate(V3)
        self.assertNotEqual(VaultMetaRepository(self.vault.connection).get().vault_uuid, first)
        with self.assertRaises(sqlite3.IntegrityError), self.vault.connection as conn:
            conn.execute("UPDATE vault_meta SET vault_uuid = ?", (bytes(16),))

    def test_autoincrement_counters_are_preserved(self):
        manifest = self.install(V3)
        conn = sqlite3.connect(self.db_path(manifest))
        before = dict(conn.execute("SELECT name, seq FROM sqlite_sequence"))
        max_category = conn.execute("SELECT MAX(id) FROM categories").fetchone()[0]
        conn.close()
        # La catégorie supprimée du coffre de référence avait le plus grand identifiant.
        self.assertGreater(before["categories"], max_category)
        self.vault = Vault.open_for_migration(manifest["vault_id"], manifest["master_password"])
        migrate_to_v4(self.vault, self.backup_dir)
        after = dict(self.vault.connection.execute("SELECT name, seq FROM sqlite_sequence"))
        for table in ("categories", "entries", "entry_history"):
            self.assertEqual(after[table], before[table], table)
        with self.vault.connection as conn:
            conn.execute("INSERT INTO categories (name_enc) VALUES (x'01')")
        new_id = self.vault.connection.execute("SELECT MAX(id) FROM categories").fetchone()[0]
        self.assertEqual(new_id, before["categories"] + 1)  # identifiant jamais réattribué

    def test_legacy_tags_are_migrated(self):
        def add_tags(conn):
            conn.executemany("INSERT INTO entry_tags (entry_id, tag) VALUES (?, ?)",
                             [(1, "Linux"), (1, "#Travail"), (1, "  BTS   SIO "), (3, "Café")])

        _, report = self.migrate(V3, prepare=add_tags)
        view = load_v4_view(self.vault.connection, self.cipher())
        self.assertEqual(view.entries[1].tags, ("Linux", "Travail", "BTS SIO"))
        self.assertEqual(view.entries[3].tags, ("Café",))
        self.assertEqual(view.entries[2].tags, ())
        self.assertEqual(report.tags, 4)
        tables = {r[0] for r in self.vault.connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'")}
        self.assertNotIn("entry_tags", tables)

    def test_legacy_plaintext_copies_are_reported_not_used_nor_deleted(self):
        manifest = self.install(V3)
        legacy = self.db_path(manifest).with_name("vault.db.avant-schema-v3.bak")
        legacy.write_bytes(b"ancienne copie en clair (fictive)")
        self.vault = Vault.open_for_migration(manifest["vault_id"], manifest["master_password"])
        report = migrate_to_v4(self.vault, self.backup_dir)
        self.assertEqual(report.legacy_plaintext_copies, [legacy])
        self.assertEqual(legacy.read_bytes(), b"ancienne copie en clair (fictive)")
        self.assertEqual(report.backup_path.parent, self.backup_dir)

    def test_already_migrated_vault_is_refused(self):
        manifest, _ = self.migrate(V3)
        with self.assertRaises(MigrationError):
            migrate_to_v4(self.vault, self.backup_dir)
        self.vault.close()
        self.vault = None
        with self.assertRaises(VaultError):
            Vault.open_for_migration(manifest["vault_id"], manifest["master_password"])
        self.vault = Vault.unlock(manifest["vault_id"], manifest["master_password"])
        self.assert_matches_manifest(manifest)  # ouverture normale, services v4


class TestBackups(MigrationTestCase):
    def test_pre_migration_backup_restores_the_original_v3_vault(self):
        manifest, report = self.migrate(V3)
        self.vault.close()
        self.vault = None
        info = backup.restore_backup(report.backup_path, manifest["master_password"])
        restored = vault_path(info.vault_id) / "vault.db"
        self.assertEqual(logical_dump(restored)["entries"], self.v3_dump["entries"])
        # Coffre restauré tel quel (v3), puis migrable comme l'original.
        self.vault = Vault.open_for_migration(info.vault_id, manifest["master_password"])
        self.assertEqual(VaultMetaRepository(self.vault.connection).get().schema_version, 3)
        migrate_to_v4(self.vault, self.backup_dir)
        self.assert_v4_matches_manifest(manifest)

    def test_backup_of_a_migrated_vault(self):
        manifest, _ = self.migrate(V3)
        path = backup.create_backup(self.vault, self.backup_dir)
        backup.verify_backup(path, self.vault._require_unlocked_key())
        self.assertEqual(backup.read_backup_info(path).kind, "manuelle")
        raw = path.read_bytes()
        for plain in (b"Banque Exemple", b"forum.example", b"Projets BTS"):
            self.assertNotIn(plain, raw)
        self.vault.close()
        info = backup.restore_backup(path, manifest["master_password"])
        self.vault = Vault.unlock(info.vault_id, manifest["master_password"])
        self.assertEqual(VaultMetaRepository(self.vault.connection).get().schema_version, 4)
        self.assert_matches_manifest(manifest)

    def test_failed_backup_leaves_the_vault_untouched(self):
        manifest = self.install(V3)
        self.vault = Vault.open_for_migration(manifest["vault_id"], manifest["master_password"])
        blocker = Path(self._tmp.name) / "fichier"
        blocker.write_bytes(b"")  # un fichier à la place du dossier : sauvegarde impossible
        with self.assertRaises(MigrationError):
            migrate_to_v4(self.vault, blocker / "sauvegardes")
        self.assert_intact_v3(manifest)


class TestRollback(MigrationTestCase):
    """Erreur injectée à chaque étape : retour arrière complet, coffre v3 intact."""

    STEPS = (("start", 1), ("structures", 1), ("category", 4), ("tags", 1), ("entry", 6),
             ("history", 2), ("validation", 1), ("rebuild", 1), ("rebuilt", 1),
             ("before_version", 1), ("before_commit", 1))

    def _fault_at(self, target: str, occurrence: int, error=RuntimeError):
        seen = {}

        def fault(step: str) -> None:
            seen[step] = seen.get(step, 0) + 1
            if step == target and seen[step] == occurrence:
                raise error(f"panne simulée : {step}")
        return fault, seen

    def test_every_step(self):
        for step, occurrence in self.STEPS:
            with self.subTest(step=step):
                manifest = self.install(V3)
                self.vault = Vault.open_for_migration(manifest["vault_id"],
                                                      manifest["master_password"])
                fault, seen = self._fault_at(step, occurrence)
                try:
                    with self.assertRaises(MigrationError) as ctx:
                        migrate_to_v4(self.vault, self.backup_dir, _fault=fault)
                    self.assertEqual(seen[step], occurrence)  # l'étape a bien été atteinte
                    self.assertIsInstance(ctx.exception.__cause__, RuntimeError)
                    self.assert_intact_v3(manifest)
                finally:
                    self.vault.close()
                    self.vault = None

    def test_interruption_is_rolled_back_and_propagated(self):
        manifest = self.install(V3)
        self.vault = Vault.open_for_migration(manifest["vault_id"], manifest["master_password"])
        fault, _ = self._fault_at("entry", 3, KeyboardInterrupt)
        with self.assertRaises(KeyboardInterrupt):
            migrate_to_v4(self.vault, self.backup_dir, _fault=fault)
        self.assert_intact_v3(manifest)

    def test_backup_made_before_a_failure_is_kept_and_valid(self):
        manifest = self.install(V3)
        self.vault = Vault.open_for_migration(manifest["vault_id"], manifest["master_password"])
        fault, _ = self._fault_at("rebuilt", 1)
        with self.assertRaises(MigrationError):
            migrate_to_v4(self.vault, self.backup_dir, _fault=fault)
        (path,) = self.backup_dir.glob("*_migration.mcfbak")
        backup.verify_backup(path, self.vault._require_unlocked_key())

    def _assert_refused(self, prepare) -> None:
        manifest = self.install(V3)
        conn = sqlite3.connect(self.db_path(manifest))
        prepare(conn)
        conn.commit()
        conn.close()
        self.vault = Vault.open_for_migration(manifest["vault_id"], manifest["master_password"])
        with self.assertRaises(MigrationError):
            migrate_to_v4(self.vault, self.backup_dir)
        conn = self.vault.connection
        self.assertEqual(VaultMetaRepository(conn).get().schema_version, 3)
        self.assertFalse(database.has_v4_structures(conn))

    def test_real_errors_abort_the_migration(self):
        cases = {
            "version d'historique altérée": lambda c: c.execute(
                "UPDATE entry_history SET snapshot_enc = substr(snapshot_enc, 1, 40) "
                "WHERE id = (SELECT MIN(id) FROM entry_history)"),
            "corbeille incohérente": lambda c: c.execute(
                "UPDATE entries SET is_deleted = 1, deleted_at = NULL WHERE id = 1"),
            "type d'entrée inconnu": lambda c: c.execute(
                "UPDATE entries SET entry_type = 'admin' WHERE id = 1"),
            "secret absent": lambda c: c.execute(
                "UPDATE entries SET password_enc = NULL WHERE id = 1"),
            "secret altéré": lambda c: c.execute(
                "UPDATE entries SET notes_enc = substr(notes_enc, 1, length(notes_enc) - 1) "
                "WHERE id = 2"),
            "tags en double": lambda c: c.executemany(
                "INSERT INTO entry_tags (entry_id, tag) VALUES (?, ?)",
                [(1, "Linux"), (1, "LINUX")]),
            "tag orphelin": lambda c: c.execute(
                "INSERT INTO entry_tags (entry_id, tag) VALUES (999, 'x')"),
            "date sans fuseau": lambda c: c.execute(
                "UPDATE entries SET created_at = '2024-01-01T00:00:00' WHERE id = 1"),
        }
        for label, prepare in cases.items():
            with self.subTest(cas=label):
                try:
                    self._assert_refused(prepare)
                finally:
                    if self.vault is not None:
                        self.vault.close()
                        self.vault = None


class TestConfidentiality(MigrationTestCase):
    """Après migration, les anciennes valeurs en clair ne sont plus dans le fichier."""

    def _raw(self, manifest: dict) -> bytes:
        path = self.db_path(manifest)
        return b"".join(p.read_bytes() for p in (path, Path(f"{path}-wal"), Path(f"{path}-shm"))
                        if p.exists())

    def _plaintext_values(self, manifest: dict, extra_tags=()) -> set[bytes]:
        values = set()
        for e in manifest["entries"]:
            for value in (e["service_name"], e["url"], e["username"]):
                if len(value) >= 4:
                    values.add(value.encode())
        for c in manifest["categories"]:
            if not c["is_builtin"]:
                values.add(c["name"].encode())
        values.add("Catégorie supprimée".encode())  # supprimée avant la génération
        values.update({b"secure_note", b"identity", b"server"})
        values.add(b"2001-01-01T00:00:00+00:00")  # deleted_at de la corbeille ancienne
        values.update(t.encode() for t in extra_tags)
        return values

    def _entry_dates_not_kept_on_purpose(self, manifest: dict) -> set[bytes]:
        """Dates d'entrée, sauf celles qui restent en clair par décision (D3 : dates des
        versions d'historique ; dates du coffre)."""
        conn = self.vault.connection
        public = {r[0] for r in conn.execute("SELECT created_at FROM entry_history")}
        public |= set(conn.execute("SELECT created_at, updated_at FROM vault_meta").fetchone())
        dates = set()
        for e in manifest["entries"]:
            for key in ("created_at", "updated_at", "password_changed_at"):
                if e[key] not in public:
                    dates.add(e[key].encode())
        return dates

    def test_scanner_finds_the_values_before_migration(self):
        # Témoin : dans le coffre v3, ces valeurs sont bien lisibles en clair.
        manifest = self.install(V3)
        raw = self._raw(manifest)
        found = [v for v in self._plaintext_values(manifest) if v in raw]
        self.assertGreaterEqual(len(found), 15)

    def test_no_old_plaintext_left_after_migration(self):
        tags = ("Tag-Tres-Reconnaissable", "Étiquette-Unique")

        def add_tags(conn):
            conn.executemany("INSERT INTO entry_tags (entry_id, tag) VALUES (1, ?)",
                             [(t,) for t in tags])

        manifest, _ = self.migrate(V3, prepare=add_tags)
        sensitive = self._plaintext_values(manifest, tags) | self._entry_dates_not_kept_on_purpose(
            manifest)
        for label, raw in (("coffre ouvert", self._raw(manifest)),):
            leaks = sorted(v for v in sensitive if v in raw)
            self.assertEqual(leaks, [], label)
        self.vault.close()
        self.vault = None
        raw = self._raw(manifest)
        self.assertEqual(sorted(v for v in sensitive if v in raw), [], "coffre fermé")

    def test_schema_keeps_no_plaintext_column_or_index(self):
        _, _ = self.migrate(V3)
        conn = self.vault.connection
        columns = {r[1] for r in conn.execute("PRAGMA table_info(entries)")}
        self.assertEqual(columns, {"id", "metadata_enc", "email_enc", "password_enc",
                                   "notes_enc", "extra_fields_enc"})
        self.assertFalse(columns & set(PLAIN_V3_ENTRY_COLUMNS))
        self.assertEqual({r[1] for r in conn.execute("PRAGMA table_info(categories)")},
                         {"id", "builtin_key", "name_enc"})
        indexes = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL")}
        self.assertEqual(indexes, {"idx_entry_history_entry"})
        self.assertEqual(conn.execute("PRAGMA freelist_count").fetchone()[0], 0)


def add_v3_entries(vault: Vault, count: int, versions: int) -> None:
    """Ajoute des entrées AU FORMAT v3 (colonnes en clair, secrets sous la DEK), comme la
    v1.6 les écrivait : l'application ne sait plus produire de coffre v3."""
    dek, conn, now = vault._require_unlocked_key(), vault.connection, "2026-01-01T00:00:00+00:00"

    def enc(value: str, aad: str) -> bytes:
        return crypto.encrypt_field(dek, value, aad.encode())

    with conn:
        for i in range(count):
            entry_id = conn.execute(
                "INSERT INTO entries (entry_type, service_name, url, username, created_at, "
                "updated_at, password_changed_at) VALUES ('login', ?, ?, ?, ?, ?, ?)",
                (f"Service {i}", f"https://s{i}.example", f"utilisateur{i}", now, now, now),
            ).lastrowid
            blobs = [enc(v, f"mon-coffre-fort:entry:{entry_id}:{c}") for c, v in (
                ("email", ""), ("password", f"pw-{i}"), ("notes", "note " * 20), ("extra", ""))]
            conn.execute(
                "UPDATE entries SET email_enc = ?, password_enc = ?, notes_enc = ?, "
                "extra_fields_enc = ? WHERE id = ?", (*blobs, entry_id))
            if i < versions:
                history_id = conn.execute(
                    "INSERT INTO entry_history (entry_id, created_at) VALUES (?, ?)",
                    (entry_id, now)).lastrowid
                snapshot = json.dumps({
                    "entry_type": "login", "service_name": f"Service {i}", "url": "",
                    "username": "", "email": "", "password": "ancien", "notes": "",
                    "extra": {}, "category_id": None, "updated_at": now,
                    "password_changed_at": now})
                conn.execute("UPDATE entry_history SET snapshot_enc = ? WHERE id = ?",
                             (enc(snapshot, f"mon-coffre-fort:history:{entry_id}:{history_id}"),
                              history_id))


class TestPerformance(MigrationTestCase):
    def test_2000_entries(self):
        manifest = self.install(V3)
        self.vault = Vault.open_for_migration(manifest["vault_id"], manifest["master_password"])
        add_v3_entries(self.vault, 2000, versions=200)
        started = time.monotonic()
        report = migrate_to_v4(self.vault, self.backup_dir)
        elapsed = time.monotonic() - started
        self.assertEqual((report.entries, report.history_versions), (2011, 203))
        self.assertLess(elapsed, 60)  # budget large : la fiabilité prime
        if os.environ.get("MCF_BENCH"):
            print(f"\nmigration de 2011 entrées / 203 versions : {elapsed:.2f} s")


class TestFixturesUntouched(MigrationTestCase):
    def test_reference_files_are_not_modified(self):
        before = {p: p.read_bytes() for p in FIXTURES.glob("*/vault.db")}
        self.migrate(V3)
        self.assertEqual({p: p.read_bytes() for p in FIXTURES.glob("*/vault.db")}, before)
