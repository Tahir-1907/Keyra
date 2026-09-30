"""Services v4 (E1) : tags, catégories, audit et import/export sur le vrai runtime.

Coffres jetables (répertoire XDG temporaire) ou copies MIGRÉES du coffre de
référence 1.6.0 : aucun vrai coffre n'est ouvert.
"""

import base64
import csv
import json
import secrets
import sqlite3
import tempfile
from pathlib import Path
from unittest import mock

from app.core import crypto
from app.core.audit import KIND_UNREADABLE, run_audit
from app.core.categories import CategoryService
from app.core.entries import Entry, EntryFilter, EntryService
from app.core.exceptions import EntryDecryptionError, EntryValidationError
from app.core.metadata import MAX_TAGS
from app.core.snapshots import parse_snapshot
from app.core.vault import Vault
from app.database.repositories import CategoryRepository, EntryRepository, HistoryRepository
from app.services import import_export
from tests.test_entries import MASTER, EntryTestCase
from tests.test_migration_v4 import V3, MigrationTestCase

BANK = 1  # « Banque Exemple » (historique au format v1) dans le coffre de référence 1.6.0


def raw_metadata(vault, entry_id: int) -> bytes:
    return EntryRepository(vault.connection).get_metadata_blob(entry_id)


def history_contents(vault, entry_id: int) -> list:
    dek = vault._require_unlocked_key()
    return [parse_snapshot(json.loads(crypto.decrypt_field(
        dek, r.snapshot_enc, f"mon-coffre-fort:history:{entry_id}:{r.id}".encode())))
        for r in HistoryRepository(vault.connection).list_for_entry(entry_id)]


class TestTags(EntryTestCase):
    def create(self, tags, **kwargs):
        return self.entries.create_entry(Entry(service_name="Serveur", password="pw",
                                               tags=tags, **kwargs))

    def test_created_tags_are_canonical(self):
        entry_id = self.create(["  #Linux ", "Écoles   primaires", "perso"])
        self.assertEqual(self.entries.get_entry(entry_id).tags,
                         ("Linux", "Écoles primaires", "perso"))
        self.assertEqual(self.entries.list_entries()[0].tags,
                         ("Linux", "Écoles primaires", "perso"))

    def test_user_case_and_accents_are_kept(self):
        entry_id = self.create(["LiNuX", "Éte"])
        self.assertEqual(self.entries.get_entry(entry_id).tags, ("LiNuX", "Éte"))

    def test_logical_duplicates_are_refused(self):
        for tags in (["Linux", "linux"], ["École", "ecole"], ["#dev", "DEV"]):
            with self.subTest(tags=tags), self.assertRaises(EntryValidationError):
                self.create(tags)
        self.assertEqual(self.entries.list_entries(), [])

    def test_maximum_count_and_length(self):
        entry_id = self.create([f"t{i}" for i in range(MAX_TAGS)])
        self.assertEqual(len(self.entries.get_entry(entry_id).tags), MAX_TAGS)
        with self.assertRaises(EntryValidationError):
            self.create([f"t{i}" for i in range(MAX_TAGS + 1)])
        with self.assertRaises(EntryValidationError):
            self.create(["x" * 33])
        for bad in ("", "  ", "#", "a,b", "a​b", "a\x00b"):
            with self.subTest(tag=bad), self.assertRaises(EntryValidationError):
                self.create([bad])

    def test_modification_and_removal(self):
        entry_id = self.create(["a", "b"])
        entry = self.entries.get_entry(entry_id)
        entry.tags = ("b", "c")
        self.entries.update_entry(entry)
        self.assertEqual(self.entries.get_entry(entry_id).tags, ("b", "c"))
        entry = self.entries.get_entry(entry_id)
        entry.tags = ()
        self.entries.update_entry(entry)
        self.assertEqual(self.entries.get_entry(entry_id).tags, ())

    def test_invalid_modification_changes_nothing(self):
        entry_id = self.create(["a"])
        before = raw_metadata(self.vault, entry_id)
        entry = self.entries.get_entry(entry_id)
        entry.tags = ("x", "X")
        with self.assertRaises(EntryValidationError):
            self.entries.update_entry(entry)
        self.assertEqual(raw_metadata(self.vault, entry_id), before)
        self.assertEqual(self.entries.history_count(entry_id), 0)

    def test_tag_change_creates_a_history_version(self):
        entry_id = self.create(["a"])
        entry = self.entries.get_entry(entry_id)
        entry.tags = ("a", "b")
        self.entries.update_entry(entry)
        versions = self.entries.list_history(entry_id)
        self.assertEqual(len(versions), 1)
        self.assertEqual(versions[0].entry.tags, ("a",))
        self.assertEqual(versions[0].changed, ("Tags",))
        snapshot = history_contents(self.vault, entry_id)[0]
        self.assertEqual((snapshot.version, snapshot.tags), (2, ("a",)))

    def test_case_only_change_is_a_change(self):
        entry_id = self.create(["linux"])
        entry = self.entries.get_entry(entry_id)
        entry.tags = ("Linux",)
        self.entries.update_entry(entry)
        self.assertEqual(self.entries.get_entry(entry_id).tags, ("Linux",))
        self.assertEqual(self.entries.history_count(entry_id), 1)

    def test_other_changes_keep_the_tags(self):
        entry_id = self.create(["a", "b"], category_id=self.category_id("Travail"))
        entry = self.entries.get_entry(entry_id)
        entry.url = "https://serveur.example"
        entry.category_id = self.category_id("Personnel")
        self.entries.update_entry(entry)
        self.entries.set_favorite(entry_id, True)
        self.entries.delete_entry(entry_id)
        self.entries.restore_entry(entry_id)
        got = self.entries.get_entry(entry_id)
        self.assertEqual((got.tags, got.url, got.is_favorite),
                         (("a", "b"), "https://serveur.example", True))
        self.assertEqual(self.entries.list_history(entry_id)[0].entry.tags, ("a", "b"))

    def test_favorite_alone_creates_no_version(self):
        entry_id = self.create(["a"])
        entry = self.entries.get_entry(entry_id)
        entry.is_favorite = True
        self.entries.update_entry(entry)
        self.assertEqual(self.entries.history_count(entry_id), 0)
        self.assertEqual(self.entries.get_entry(entry_id).tags, ("a",))

    def test_restore_version_brings_back_its_tags(self):
        entry_id = self.create(["ancien"])
        entry = self.entries.get_entry(entry_id)
        entry.tags = ("nouveau",)
        entry.password = "pw2"
        self.entries.update_entry(entry)
        old = self.entries.list_history(entry_id)[0]
        self.entries.restore_version(old.id)
        got = self.entries.get_entry(entry_id)
        self.assertEqual((got.tags, got.password), (("ancien",), "pw"))
        self.assertEqual(self.entries.list_history(entry_id)[0].entry.tags, ("nouveau",))

    def test_duplicate_keeps_the_tags(self):
        entry_id = self.create(["a"])
        copy = self.entries.duplicate_entry(entry_id)
        self.assertEqual(self.entries.get_entry(copy).tags, ("a",))

    def test_tags_are_not_in_the_database_in_clear(self):
        self.create(["TagTresSecretZ"])
        self.vault.connection.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        data = self.vault._db_path.read_bytes()
        self.assertNotIn(b"TagTresSecretZ", data)
        self.assertNotIn("TagTresSecretZ".encode("utf-16-le"), data)


class TestTagsOnMigratedVault(MigrationTestCase):
    """Entrée migrée dont l'historique est resté au format v1 (sans tags)."""

    def setUp(self):
        super().setUp()
        self.manifest, _ = self.migrate(V3)
        self.entries = EntryService(self.vault)

    def test_v1_history_stays_readable(self):
        versions = self.entries.list_history(BANK)
        self.assertEqual([v.entry.password for v in versions],
                         [h["password"] for h in self.manifest["entries"][0]["history"]])
        self.assertTrue(all(c.version == 1 for c in history_contents(self.vault, BANK)))

    def test_restoring_a_v1_version_keeps_the_current_tags(self):
        entry = self.entries.get_entry(BANK)
        entry.tags = ("banque",)
        self.entries.update_entry(entry)
        v1 = self.entries.list_history(BANK)[-1]
        # Affichage : une version v1 reprend les tags de la version plus récente (ici aucun).
        self.assertEqual(v1.entry.tags, ())
        self.entries.restore_version(v1.id)
        got = self.entries.get_entry(BANK)
        self.assertEqual((got.tags, got.password), (("banque",), v1.entry.password))
        self.assertTrue(got.is_favorite)
        newest = history_contents(self.vault, BANK)[0]
        self.assertEqual((newest.version, newest.tags), (2, ("banque",)))


class TestCategoryDeletion(EntryTestCase):
    def setUp(self):
        super().setUp()
        self.cat = self.categories.create_category("Projets BTS")
        self.active = self.entries.create_entry(Entry(service_name="Actif", password="a",
                                                      category_id=self.cat, tags=["x"]))
        self.trashed = self.entries.create_entry(Entry(service_name="Jeté", password="b",
                                                       category_id=self.cat))
        self.other = self.entries.create_entry(Entry(service_name="Autre", password="c",
                                                     category_id=self.category_id("Travail")))
        self.entries.delete_entry(self.trashed)

    def test_entries_become_uncategorized_and_are_reencrypted(self):
        before = {i: raw_metadata(self.vault, i) for i in (self.active, self.trashed, self.other)}
        self.categories.delete_category(self.cat)
        self.assertNotIn(self.cat, {c.id for c in self.categories.list_categories()})
        for entry_id in (self.active, self.trashed):
            self.assertNotEqual(raw_metadata(self.vault, entry_id), before[entry_id])
        self.assertEqual(raw_metadata(self.vault, self.other), before[self.other])
        active = self.entries.get_entry(self.active)
        self.assertEqual((active.category_id, active.tags, active.password), (None, ("x",), "a"))
        self.assertIsNone(self.entries.get_entry(self.trashed, include_deleted=True).category_id)
        self.assertEqual(self.entries.history_count(self.active), 0)
        # Relu depuis la base, sans cache.
        self.vault.metadata.invalidate()
        self.assertIsNone(self.vault.metadata.entry(self.active).category_id)
        self.assertEqual(self.categories.overview().uncategorized, 1)

    def test_restored_trash_entry_has_no_dangling_category(self):
        self.categories.delete_category(self.cat)
        self.entries.restore_entry(self.trashed)
        self.assertIsNone(self.entries.get_entry(self.trashed).category_id)

    def test_deleted_category_is_refused_and_never_reused(self):
        self.categories.delete_category(self.cat)
        entry = self.entries.get_entry(self.active)
        entry.category_id = self.cat
        with self.assertRaises(EntryValidationError):
            self.entries.update_entry(entry)
        self.assertGreater(self.categories.create_category("Nouvelle"), self.cat)

    def test_restoring_a_version_of_a_deleted_category(self):
        entry = self.entries.get_entry(self.active)
        entry.password = "a2"
        self.entries.update_entry(entry)
        self.categories.delete_category(self.cat)
        old = self.entries.list_history(self.active)[0]
        self.assertEqual(old.entry.category_id, self.cat)
        self.entries.restore_version(old.id)
        got = self.entries.get_entry(self.active)
        self.assertEqual((got.password, got.category_id), ("a", None))

    def test_failure_rolls_everything_back(self):
        ids = (self.active, self.trashed, self.other)
        before = {i: raw_metadata(self.vault, i) for i in ids}
        rows = self.vault.connection.execute("SELECT * FROM categories").fetchall()
        with mock.patch.object(CategoryRepository, "delete",
                               side_effect=sqlite3.OperationalError("panne simulée")), \
                self.assertRaises(sqlite3.OperationalError):
            self.categories.delete_category(self.cat)
        self.assertEqual({i: raw_metadata(self.vault, i) for i in ids}, before)
        self.assertEqual(self.vault.connection.execute("SELECT * FROM categories").fetchall(),
                         rows)
        # Le cache ne garde pas la valeur annulée.
        self.assertEqual(self.entries.get_entry(self.active).category_id, self.cat)
        self.assertEqual(
            self.entries.get_entry(self.trashed, include_deleted=True).category_id, self.cat)
        self.assertIn(self.cat, {c.id for c in self.categories.list_categories()})


class TestAuditOfAlteredMetadata(EntryTestCase):
    def test_altered_metadata_is_reported_and_never_rebuilt(self):
        ok = self.entries.create_entry(Entry(service_name="OK", password="x" * 20))
        bad = self.entries.create_entry(Entry(service_name="Altérée", password="y" * 20))
        trashed = self.entries.create_entry(Entry(service_name="Jetée", password="z" * 20))
        self.entries.delete_entry(trashed)
        conn = self.vault.connection
        for entry_id in (bad, trashed):
            blob = bytearray(raw_metadata(self.vault, entry_id))
            blob[-1] ^= 0x01
            with conn:
                conn.execute("UPDATE entries SET metadata_enc = ? WHERE id = ?",
                             (bytes(blob), entry_id))
        altered = {i: raw_metadata(self.vault, i) for i in (bad, trashed)}
        self.vault.metadata.invalidate()  # modification faite hors de l'application

        report = run_audit(self.entries)
        self.assertEqual(sorted(f.entry_id for f in report.by_kind(KIND_UNREADABLE)),
                         sorted([bad, trashed]))
        self.assertEqual(report.checked_entries, 3)
        self.assertNotIn("Altérée", repr(report))

        # Rien n'est reconstruit : l'entrée reste illisible, le blob inchangé.
        self.assertEqual([s.id for s in self.entries.list_entries()], [ok])
        self.assertEqual(self.entries.list_entries(EntryFilter(in_trash=True)), [])
        self.assertEqual(self.entries.unreadable_entries(), sorted([bad, trashed]))
        with self.assertRaises(EntryDecryptionError):
            self.entries.get_entry(bad)
        self.assertEqual({i: raw_metadata(self.vault, i) for i in (bad, trashed)}, altered)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0], 3)
        # Ni la purge ni le vidage de la corbeille ne touchent une entrée illisible.
        self.assertEqual((self.entries.purge_trash(0), self.entries.empty_trash()), (0, 0))
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0], 3)


class TestImportExportWithTags(EntryTestCase):
    def setUp(self):
        super().setUp()
        self.dir = Path(tempfile.mkdtemp(dir=self._tmpdir.name))
        self.entries.create_entry(Entry(
            service_name="Serveur", entry_type="server", username="root", password="pw,1",
            notes="note\nsur deux lignes", extra={"hostname": "10.0.0.1", "port": "22"},
            category_id=self.category_id("Travail"), is_favorite=True,
            tags=["Linux", "Écoles primaires", "#prod"]))
        self.entries.create_entry(Entry(service_name="Sans tag", password="p2"))

    def fresh_target(self):
        """Second coffre jetable, pour réimporter."""
        target = Vault.create(f"cible-{secrets.token_hex(4)}", "Cible", MASTER)
        self.addCleanup(target.close)
        categories = CategoryService(target)
        categories.ensure_builtin_categories()
        return EntryService(target), categories

    def imported(self, service):
        return {s.service_name: service.get_entry(s.id) for s in service.list_entries()}

    def assert_same_as_source(self, service):
        got = self.imported(service)
        server = got["Serveur"]
        self.assertEqual(server.tags, ("Linux", "Écoles primaires", "prod"))
        self.assertEqual((server.entry_type, server.username, server.password, server.notes,
                          server.extra, server.is_favorite),
                         ("server", "root", "pw,1", "note\nsur deux lignes",
                          {"hostname": "10.0.0.1", "port": "22"}, True))
        self.assertEqual(got["Sans tag"].tags, ())
        self.assertEqual(got["Sans tag"].password, "p2")

    def test_csv_export_has_a_tags_column_and_roundtrips(self):
        dest = self.dir / "export.csv"
        import_export.export_csv(self.entries, self.vault, MASTER, dest)
        with open(dest, newline="", encoding="utf-8") as f:
            rows = {r["name"]: r for r in csv.DictReader(f)}
        self.assertEqual(rows["Serveur"]["tags"], "Linux, Écoles primaires, prod")
        self.assertEqual(rows["Sans tag"]["tags"], "")
        service, categories = self.fresh_target()
        result = import_export.apply_import(service, categories, import_export.parse_csv(dest))
        self.assertEqual((result.imported, result.invalid), (2, 0))
        self.assert_same_as_source(service)
        server = self.imported(service)["Serveur"]
        self.assertEqual(categories.list_categories()[0].name, "Personnel")
        self.assertEqual(
            next(c.name for c in categories.list_categories() if c.id == server.category_id),
            "Travail")

    def test_encrypted_export_roundtrips_the_tags(self):
        dest = self.dir / "export.mcfexport"
        export_pw = secrets.token_urlsafe(12)
        import_export.export_encrypted(self.entries, self.vault, MASTER, export_pw, dest)
        self.assertNotIn(b"Linux", dest.read_bytes())
        preview = import_export.parse_encrypted_export(dest, export_pw)
        service, categories = self.fresh_target()
        import_export.apply_import(service, categories, preview)
        self.assert_same_as_source(service)

    def write_csv(self, header, rows):
        path = self.dir / f"{secrets.token_hex(4)}.csv"
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(header)
            writer.writerows(rows)
        return path

    def test_old_csv_without_tags_column_is_still_recognized(self):
        path = self.write_csv(
            ["type", "name", "url", "username", "email", "password", "notes", "category",
             "favorite", "extra"],
            [["login", "Ancien", "https://a.example", "al", "", "pw", "n", "Travail", "1", ""]])
        preview = import_export.parse_csv(path)
        self.assertEqual(preview.format_key, "moncoffre")
        import_export.apply_import(self.entries, self.categories, preview)
        got = self.imported(self.entries)["Ancien"]
        self.assertEqual((got.tags, got.password, got.is_favorite, got.category_id),
                         ((), "pw", True, self.category_id("Travail")))

    def test_invalid_tags_are_dropped_without_losing_the_entry(self):
        too_many = ", ".join(f"t{i}" for i in range(MAX_TAGS + 5))
        path = self.write_csv(
            ["type", "name", "url", "username", "email", "password", "notes", "category",
             "favorite", "extra", "tags"],
            [["login", "Doublons", "", "", "", "pw1", "", "", "0", "", "Linux, linux, #LINUX"],
             ["login", "Trop long", "", "", "", "pw2", "", "", "0", "", "ok, " + "x" * 33],
             ["login", "Invisible", "", "", "", "pw3", "", "", "0", "", "a​b, bon"],
             ["login", "Trop", "", "", "", "pw4", "", "", "0", "", too_many],
             ["login", "Vides", "", "", "", "pw5", "", "", "0", "", " , ,#, "]])
        result = import_export.apply_import(self.entries, self.categories,
                                            import_export.parse_csv(path))
        self.assertEqual((result.imported, result.invalid), (5, 0))
        got = self.imported(self.entries)
        self.assertEqual(got["Doublons"].tags, ("Linux",))
        self.assertEqual(got["Trop long"].tags, ("ok",))
        self.assertEqual(got["Invisible"].tags, ("bon",))
        self.assertEqual(got["Trop"].tags, tuple(f"t{i}" for i in range(MAX_TAGS)))
        self.assertEqual(got["Vides"].tags, ())
        self.assertEqual(got["Trop"].password, "pw4")

    def test_malformed_tags_in_an_encrypted_export(self):
        payload = {"entries": [
            {"type": "login", "name": "A", "password": "pa", "tags": "pas-une-liste"},
            {"type": "login", "name": "B", "password": "pb", "tags": [1, None, "ok", "OK"]},
        ]}
        params = crypto.Argon2Params()
        salt = crypto.generate_salt()
        export_pw = secrets.token_urlsafe(12)
        nonce, ciphertext = crypto.aes_gcm_encrypt(
            crypto.derive_key(export_pw, salt, params),
            json.dumps(payload).encode(), import_export._EXPORT_AAD)
        dest = self.dir / "forge.mcfexport"
        dest.write_text(json.dumps({
            "format": "mon-coffre-fort-export", "version": 1, "kdf": "argon2id",
            "kdf_params": params.to_dict(), "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()}))
        preview = import_export.parse_encrypted_export(dest, export_pw)
        tags = {i.entry.service_name: i.entry.tags for i in preview.items}
        self.assertEqual(tags, {"A": (), "B": ("ok",)})


class TestRuntimeIgnoresLegacy(EntryTestCase):
    """Les lecteurs v1 à v3 (colonnes en clair, entry_tags) sont réservés à la migration."""

    LEGACY = ("list_active", "list_deleted", "list_all(", "list_all_v4", "set_builtin_key",
              "set_name_blob(", "count_entries_by_category", "apply_legacy_steps",
              "add_v4_structures", "entry_tags", "is_deleted")
    ALLOWED = frozenset({"app/services/migration_v4.py", "app/database/repositories.py",
                         "app/database/database.py", "app/database/models.py"})

    def test_no_runtime_module_uses_legacy_readers(self):
        root = Path(__file__).resolve().parent.parent
        offenders = []
        for path in sorted((root / "app").rglob("*.py")):
            relative = path.relative_to(root).as_posix()
            if relative in self.ALLOWED:
                continue
            text = path.read_text(encoding="utf-8")
            offenders += [f"{relative}: {name}" for name in self.LEGACY if name in text]
        self.assertEqual(offenders, [])

    def test_v4_vault_has_no_legacy_table_after_use(self):
        entry_id = self.entries.create_entry(Entry(service_name="A", tags=["t"]))
        entry = self.entries.get_entry(entry_id)
        entry.tags = ("u",)
        self.entries.update_entry(entry)
        tables = {r[0] for r in self.vault.connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'")}
        self.assertNotIn("entry_tags", tables)
