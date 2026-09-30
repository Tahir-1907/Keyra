"""Préparation de la migration v4 (C1) : rien n'est encore migré.

Étapes v1/v2 -> v3 réutilisables, ouverture sans mise à niveau (donc sans .bak
en clair), sauvegarde de migration vérifiée, schéma v4 définitif et son
contrôle de structure, format des versions d'historique v1/v2.
"""

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.core import crypto, snapshots
from app.core.exceptions import (
    VaultCorruptedError,
    WrongMasterPasswordError,
)
from app.core.snapshots import SnapshotContent, build_snapshot, parse_snapshot
from app.core.vault import Vault
from app.database import database
from app.database.repositories import HistoryRepository, VaultMetaRepository
from app.services import backup
from app.utils.paths import vault_path
from tests.test_entries import MASTER, EntryTestCase
from tests.test_fixtures import FIXTURE_NAMES, FixtureVaultTestCase

NOW = "2026-09-27T10:00:00+00:00"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TestOpenForMigration(FixtureVaultTestCase):
    def test_opens_v2_and_v3_without_upgrading_or_copying(self):
        for name in FIXTURE_NAMES:
            with self.subTest(name=name):
                manifest = self.install(name)
                db_path = vault_path(manifest["vault_id"]) / "vault.db"
                before = sha256(db_path)
                vault = Vault.open_for_migration(manifest["vault_id"],
                                                 manifest["master_password"])
                try:
                    meta = VaultMetaRepository(vault.connection).get()
                    self.assertEqual(meta.schema_version, manifest["schema_version"])
                    self.assertFalse(vault.is_locked)
                finally:
                    vault.close()
                self.assertEqual(sha256(db_path), before)  # fichier inchangé
                self.assertEqual(list(db_path.parent.glob("*.bak")), [])  # aucun .bak

    def test_wrong_password(self):
        manifest = self.install("v3-app-1.6.0")
        with self.assertRaises(WrongMasterPasswordError):
            Vault.open_for_migration(manifest["vault_id"], "mauvais-mot-de-passe")

    def test_unlock_refuses_old_vaults_without_touching_them(self):
        # v1.7 : plus de mise à niveau implicite au déverrouillage (ni copie .bak en clair).
        from app.core.exceptions import VaultMigrationRequiredError
        from tests.test_fixtures import logical_dump

        for name in FIXTURE_NAMES:
            with self.subTest(name=name):
                manifest = self.install(name)
                db_path = vault_path(manifest["vault_id"]) / "vault.db"
                before = logical_dump(db_path)
                with self.assertRaises(VaultMigrationRequiredError):
                    Vault.unlock(manifest["vault_id"], manifest["master_password"])
                with self.assertRaises(WrongMasterPasswordError):  # mot de passe vérifié d'abord
                    Vault.unlock(manifest["vault_id"], "mauvais-mot-de-passe")
                self.assertEqual(logical_dump(db_path), before)
                self.assertEqual(list(db_path.parent.glob("*.bak")), [])


class TestMigrationBackup(EntryTestCase):
    def setUp(self):
        super().setUp()
        from app.core.entries import Entry

        self.entries.create_entry(Entry(service_name="Banque", password="secret"))
        self.dir = Path(tempfile.mkdtemp(dir=self._tmpdir.name))
        self.path = backup.create_backup(self.vault, self.dir, kind=backup.KIND_MIGRATION)
        self.dek = self.vault._require_unlocked_key()

    def test_valid_backup_is_verified(self):
        backup.verify_backup(self.path, self.dek)
        self.assertEqual(backup.read_backup_info(self.path).kind, "migration")

    def test_wrong_key_tampering_and_truncation_are_refused(self):
        with self.assertRaises(backup.BackupError):
            backup.verify_backup(self.path, crypto.generate_key())
        raw = self.path.read_bytes()
        for data in (raw[:-1] + bytes([raw[-1] ^ 1]), raw[:len(raw) // 2], b""):
            self.path.write_bytes(data)
            with self.subTest(size=len(data)), self.assertRaises(backup.BackupError):
                backup.verify_backup(self.path, self.dek)

    def test_migration_backups_are_never_rotated(self):
        for _ in range(3):
            backup.create_backup(self.vault, self.dir, kind=backup.KIND_AUTO)
        backup.rotate_auto_backups(self.vault_id, self.dir, keep=0)
        self.assertEqual([b.kind for b in backup.list_backups(self.dir)], ["migration"])


class V4SchemaTestCase(unittest.TestCase):
    """Base v4 définitive, en mémoire."""

    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute("PRAGMA foreign_keys = ON;")
        for sql in database.v4_tables_sql().values():
            self.conn.execute(sql)
        self.conn.execute(database._RECOVERY_TABLE_SQL)
        for sql in database.V4_POST_REBUILD_SQL:
            self.conn.execute(sql)
        self.conn.execute(
            "INSERT INTO vault_meta VALUES (1, 4, 1, 'argon2id', '{}', x'00', x'00', x'00', "
            "?, 'Coffre', ?, ?)", (bytes(16), NOW, NOW))

    def tearDown(self):
        self.conn.close()

    def assert_refused(self, sql: str, args: tuple = ()) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(sql, args)


class TestV4Schema(V4SchemaTestCase):
    def test_structure_is_valid(self):
        self.assertEqual(database.structure_problems(self.conn, 4), [])

    def test_plaintext_v3_columns_or_entry_tags_are_structure_problems(self):
        self.conn.execute("ALTER TABLE entries ADD COLUMN service_name TEXT")
        self.assertIn("colonnes v3 en clair présentes dans entries",
                      database.structure_problems(self.conn, 4))
        self.conn.execute("CREATE TABLE entry_tags (entry_id INTEGER, tag TEXT)")
        self.assertIn("table entry_tags (v3) présente", database.structure_problems(self.conn, 4))

    def test_entries_require_every_blob(self):
        self.assert_refused("INSERT INTO entries (metadata_enc, email_enc, password_enc, "
                            "notes_enc) VALUES (x'01', x'01', x'01', x'01')")
        self.assert_refused("INSERT INTO entries (metadata_enc, email_enc, password_enc, "
                            "notes_enc, extra_fields_enc) VALUES ('texte', x'01', x'01', x'01', "
                            "x'01')")

    def test_category_is_either_builtin_or_custom(self):
        self.conn.execute("INSERT INTO categories (builtin_key) VALUES ('work')")
        self.conn.execute("INSERT INTO categories (name_enc) VALUES (x'01')")
        for sql in ("INSERT INTO categories (builtin_key, name_enc) VALUES ('finance', x'01')",
                    "INSERT INTO categories (builtin_key, name_enc) VALUES (NULL, NULL)",
                    "INSERT INTO categories (builtin_key) VALUES ('admin')",
                    "INSERT INTO categories (builtin_key) VALUES ('work')",
                    "INSERT INTO categories (name_enc) VALUES ('texte')"):
            with self.subTest(sql=sql):
                self.assert_refused(sql)

    def test_history_requires_snapshot_and_existing_entry(self):
        self.assert_refused("INSERT INTO entry_history (entry_id, snapshot_enc, created_at) "
                            "VALUES (99, x'01', ?)", (NOW,))
        self.conn.execute("INSERT INTO entries VALUES (1, x'01', x'01', x'01', x'01', x'01')")
        self.assert_refused("INSERT INTO entry_history (entry_id, snapshot_enc, created_at) "
                            "VALUES (1, NULL, ?)", (NOW,))

    def test_vault_uuid_is_mandatory_and_immutable(self):
        for value in (bytes(15), None, "0" * 16, bytes(range(16))):
            with self.subTest(value=value), self.assertRaises(sqlite3.IntegrityError):
                self.conn.execute("UPDATE vault_meta SET vault_uuid = ?", (value,))


class TestForgedSchemaNumber(EntryTestCase):
    def test_v4_vault_claiming_to_be_v3_is_refused(self):
        # Structure v4 sous un numéro v3 (rétrogradation forgée) : endommagé, jamais
        # lu comme un v3 ni « re-migré ».
        with self.vault.connection as conn:
            conn.execute("UPDATE vault_meta SET schema_version = 3")
        self.vault.close()
        with self.assertRaises(VaultCorruptedError):
            Vault.unlock(self.vault_id, MASTER)
        with self.assertRaises(VaultCorruptedError):
            Vault.open_for_migration(self.vault_id, MASTER)
        conn = database.connect(Path(self.vault._db_path))
        with conn:
            conn.execute("UPDATE vault_meta SET schema_version = 4")
        conn.close()
        self.vault = Vault.unlock(self.vault_id, MASTER)


def _content(**changes) -> SnapshotContent:
    values = dict(version=2, entry_type="login", service_name="Banque", url="", username="",
                  email="", password="x", notes="", extra={}, category_id=None,
                  updated_at=NOW, password_changed_at=NOW, tags=("Linux",), is_favorite=True)
    values.update(changes)
    return SnapshotContent(**values)


class TestSnapshotFormat(FixtureVaultTestCase):
    def test_every_real_v1_snapshot_of_the_fixtures_is_read(self):
        for name in FIXTURE_NAMES:
            manifest = self.install(name)
            vault = Vault.open_for_migration(manifest["vault_id"], manifest["master_password"])
            try:
                dek = vault._require_unlocked_key()
                records = [r for e in manifest["entries"]
                           for r in HistoryRepository(vault.connection).list_for_entry(e["id"])]
                self.assertEqual(len(records), 3)
                for record in records:
                    data = json.loads(crypto.decrypt_field(
                        dek, record.snapshot_enc,
                        f"mon-coffre-fort:history:{record.entry_id}:{record.id}".encode()))
                    content = parse_snapshot(data)
                    self.assertEqual((content.version, content.tags, content.is_favorite),
                                     (1, (), None))
            finally:
                vault.close()

    def test_v2_round_trip(self):
        content = _content(extra={"ssid": "Box"}, category_id=3)
        self.assertEqual(parse_snapshot(json.loads(json.dumps(build_snapshot(content)))),
                         content)

    def test_malformed_snapshots(self):
        good = build_snapshot(_content())
        v1 = {k: v for k, v in good.items() if k not in ("v", "tags", "is_favorite")}
        self.assertEqual(parse_snapshot(v1).version, 1)
        bad = [
            [1, 2], {k: v for k, v in v1.items() if k != "url"}, {**v1, "inconnu": 1},
            {**v1, "tags": []}, {**good, "v": 3}, {**good, "v": "2"}, {**good, "v": True},
            {**good, "tags": ["Linux", "linux"]}, {**good, "tags": "Linux"},
            {**good, "tags": ["  Linux"]}, {**good, "is_favorite": None},
            {**good, "is_favorite": 1}, {**good, "entry_type": "admin"},
            {**good, "service_name": " "}, {**good, "category_id": True},
            {**good, "category_id": 0}, {**good, "extra": {"k": 1}}, {**good, "password": None},
        ]
        for data in bad:
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse_snapshot(data)

    def test_v2_always_records_the_favourite(self):
        with self.assertRaises(ValueError):
            build_snapshot(_content(is_favorite=None))
        with self.assertRaises(ValueError):
            build_snapshot(_content(tags=("a", "A")))

    def test_repr_never_contains_secrets(self):
        self.assertNotIn("Banque", repr(_content()))
        self.assertEqual(snapshots.SNAPSHOT_VERSION, 2)
