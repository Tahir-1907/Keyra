import csv
import dataclasses
import secrets
import sqlite3
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar

from app.core.audit import KIND_OLD, run_audit
from app.core.entries import MAX_HISTORY_VERSIONS, Entry, EntryFilter
from app.core.exceptions import (
    EntryDecryptionError,
    EntryNotFoundError,
    UnsupportedVaultVersionError,
    VaultCorruptedError,
    WrongMasterPasswordError,
)
from app.core.vault import Vault, list_vaults
from app.database import database
from app.services import backup, import_export
from tests.test_entries import MASTER, EntryTestCase


class TestTrash(EntryTestCase):
    def test_delete_moves_to_trash_and_restore(self):
        a = self.entries.create_entry(Entry(service_name="A", password="pa"))
        self.entries.delete_entry(a)
        self.assertEqual(self.entries.list_entries(), [])
        trash = self.entries.list_entries(EntryFilter(in_trash=True))
        self.assertEqual([s.id for s in trash], [a])
        self.assertTrue(trash[0].deleted_at)
        self.assertEqual(self.categories.overview().trash, 1)
        self.entries.restore_entry(a)
        self.assertEqual([s.id for s in self.entries.list_entries()], [a])
        self.assertEqual(self.entries.get_entry(a).password, "pa")

    def test_trashed_entry_readable_only_explicitly(self):
        a = self.entries.create_entry(Entry(service_name="A", password="pa"))
        self.entries.delete_entry(a)
        with self.assertRaises(EntryNotFoundError):
            self.entries.get_entry(a)
        self.assertEqual(self.entries.get_entry(a, include_deleted=True).password, "pa")

    def test_delete_permanently_removes_history_too(self):
        a = self.entries.create_entry(Entry(service_name="A", password="v1"))
        e = self.entries.get_entry(a)
        e.password = "v2"
        self.entries.update_entry(e)
        self.entries.delete_entry(a)
        self.entries.delete_permanently(a)
        conn = self.vault.connection
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0], 0)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM entry_history").fetchone()[0], 0)

    def test_empty_and_purge(self):
        ids = [self.entries.create_entry(Entry(service_name=n)) for n in "ABC"]
        for i in ids:
            self.entries.delete_entry(i)
        old = (datetime.now(UTC) - timedelta(days=45)).isoformat()
        store = self.vault.metadata  # v4: the deletion date is encrypted
        with self.vault.connection:
            store.write_entry(ids[0], dataclasses.replace(store.entry(ids[0]), deleted_at=old))
        self.assertEqual(self.entries.purge_trash(30), 1)
        self.assertEqual(self.entries.trash_count(), 2)
        self.assertEqual(self.entries.empty_trash(), 2)
        self.assertEqual(self.entries.trash_count(), 0)

    def test_trash_excluded_from_audit_and_counts(self):
        a = self.entries.create_entry(Entry(service_name="A", password="azerty"))
        self.entries.delete_entry(a)
        self.assertEqual(run_audit(self.entries).findings, [])
        self.assertEqual(self.categories.overview().total, 0)


class TestHistory(EntryTestCase):
    def test_update_keeps_previous_version(self):
        a = self.entries.create_entry(Entry(service_name="Mail", password="ancien"))
        e = self.entries.get_entry(a)
        e.password = "nouveau"
        e.notes = "note"
        self.entries.update_entry(e)
        versions = self.entries.list_history(a)
        self.assertEqual(len(versions), 1)
        self.assertEqual(versions[0].entry.password, "ancien")
        self.assertEqual(set(versions[0].changed), {"Password", "Notes"})

    def test_no_version_when_nothing_changed(self):
        a = self.entries.create_entry(Entry(service_name="Mail", password="x"))
        e = self.entries.get_entry(a)
        e.is_favorite = True  # the favorite status does not create a version
        self.entries.update_entry(e)
        self.assertEqual(self.entries.history_count(a), 0)
        self.assertTrue(self.entries.get_entry(a).is_favorite)

    def test_restore_version(self):
        a = self.entries.create_entry(Entry(service_name="Mail", password="v1"))
        e = self.entries.get_entry(a)
        e.password = "v2"
        self.entries.update_entry(e)
        old = self.entries.list_history(a)[0]
        self.entries.restore_version(old.id)
        self.assertEqual(self.entries.get_entry(a).password, "v1")
        # The replaced version (v2) is in the history in turn.
        self.assertEqual(self.entries.list_history(a)[0].entry.password, "v2")

    def test_history_is_capped(self):
        a = self.entries.create_entry(Entry(service_name="Mail", password="p0"))
        for i in range(1, MAX_HISTORY_VERSIONS + 5):
            e = self.entries.get_entry(a)
            e.password = f"p{i}"
            self.entries.update_entry(e)
        versions = self.entries.list_history(a)
        self.assertEqual(len(versions), MAX_HISTORY_VERSIONS)
        self.assertEqual(versions[0].entry.password, f"p{MAX_HISTORY_VERSIONS + 3}")

    def test_history_encrypted_and_bound(self):
        a = self.entries.create_entry(Entry(service_name="A", password="secret-histo-1"))
        e = self.entries.get_entry(a)
        e.password = "secret-histo-2"
        self.entries.update_entry(e)
        conn = self.vault.connection
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        raw = Path(self.vault._db_path).read_bytes()
        self.assertNotIn(b"secret-histo-1", raw)
        b = self.entries.create_entry(Entry(service_name="B"))
        with conn:  # moving a version to another entry must be detected
            conn.execute("UPDATE entry_history SET entry_id = ?", (b,))
        with self.assertRaises(EntryDecryptionError):
            self.entries.list_history(b)

    def test_clear_history(self):
        a = self.entries.create_entry(Entry(service_name="A", password="1"))
        e = self.entries.get_entry(a)
        e.password = "2"
        self.entries.update_entry(e)
        self.assertEqual(self.entries.clear_history(a), 1)
        self.assertEqual(self.entries.history_count(a), 0)

    def test_password_changed_at_and_old_password_audit(self):
        a = self.entries.create_entry(Entry(service_name="A", password=secrets.token_urlsafe(20)))
        e = self.entries.get_entry(a)
        created = e.password_changed_at
        e.notes = "modification sans changer le mot de passe"
        self.entries.update_entry(e)
        self.assertEqual(self.entries.get_entry(a).password_changed_at, created)
        far_future = datetime.now().astimezone().date() + timedelta(days=400)
        report = run_audit(self.entries, today=far_future)
        self.assertEqual([f.entry_id for f in report.by_kind(KIND_OLD)], [a])
        e = self.entries.get_entry(a)
        e.password = secrets.token_urlsafe(20)
        self.entries.update_entry(e)
        self.assertNotEqual(self.entries.get_entry(a).password_changed_at, created)


class TestMigration(EntryTestCase):
    def test_old_vault_requires_migration_and_gets_no_plaintext_copy(self):
        # v1.6: a v1/v2 vault was upgraded on unlock WITH a plaintext .bak copy.
        # v1.7: explicit refusal, file intact, no copy; the upgrade goes through the
        # v4 migration (encrypted backup), see test_migration_v4.
        import hashlib
        import shutil

        from app.core.exceptions import VaultMigrationRequiredError
        from app.utils.paths import vault_path

        fixture = Path(__file__).resolve().parent / "fixtures" / "v3-app-1.6.0" / "vault.db"
        target = vault_path("ancien-v1") / "vault.db"
        shutil.copyfile(fixture, target)
        conn = sqlite3.connect(target)
        with conn:  # v1 vault (Phase 1): no history, no recovery key
            conn.execute("DROP TABLE entry_history;")
            conn.execute("DROP TABLE vault_recovery;")
            conn.execute("ALTER TABLE entries DROP COLUMN password_changed_at;")
            conn.execute("UPDATE vault_meta SET schema_version = 1;")
        conn.close()
        before = hashlib.sha256(target.read_bytes()).hexdigest()
        with self.assertRaises(VaultMigrationRequiredError):
            Vault.unlock("ancien-v1", "fixture-mot-de-passe-maitre-FICTIF")
        self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), before)
        self.assertEqual(list(target.parent.glob("*.bak")), [])

    def test_newer_schema_is_refused(self):
        db_path = self.vault._db_path
        with self.vault.connection as conn:
            conn.execute("UPDATE vault_meta SET schema_version = 99;")
        self.vault.close()
        with self.assertRaises(UnsupportedVaultVersionError):
            Vault.unlock(self.vault_id, MASTER)
        # Restore the state for tearDown (which closes self.vault).
        conn = database.connect(db_path)
        with conn:
            conn.execute("UPDATE vault_meta SET schema_version = ?;", (database.SCHEMA_VERSION,))
        conn.close()
        self.vault = Vault.unlock(self.vault_id, MASTER)


class TestBackup(EntryTestCase):
    def setUp(self):
        super().setUp()
        self.backup_dir = Path(tempfile.mkdtemp(dir=self._tmpdir.name))

    def test_roundtrip_creates_new_vault(self):
        a = self.entries.create_entry(Entry(service_name="Banque", password="pw-backup"))
        path = backup.create_backup(self.vault, self.backup_dir)
        self.assertEqual(oct(path.stat().st_mode & 0o777), "0o600")
        raw = path.read_bytes()
        for plain in (b"Banque", b"pw-backup", b"SQLite format"):
            self.assertNotIn(plain, raw)
        info = backup.restore_backup(path, MASTER)
        self.assertNotEqual(info.vault_id, self.vault_id)
        self.assertIn("restored", info.vault_name)
        restored = Vault.unlock(info.vault_id, MASTER)
        from app.core.entries import EntryService
        self.assertEqual(EntryService(restored).get_entry(a).password, "pw-backup")
        restored.close()
        self.assertEqual(len(list_vaults()), 2)

    def test_delete_backups_only_touches_this_vault(self):
        manual = backup.create_backup(self.vault, self.backup_dir)
        autos = [backup.create_backup(self.vault, self.backup_dir, kind=backup.KIND_AUTO)
                 for _ in range(2)]
        other = Vault.create(self.vault_id + "-autre", "Autre", secrets.token_urlsafe(16))
        foreign = backup.create_backup(other, self.backup_dir)
        other.close()
        stray = self.backup_dir / "notes.mcfbak"
        stray.write_bytes(b"pas une sauvegarde")
        with self.assertRaises(backup.BackupError):
            backup.delete_backup(foreign, self.vault_id)  # another vault: refused
        with self.assertRaises(backup.BackupError):
            backup.delete_backup(stray, self.vault_id)    # not a backup: refused
        self.assertEqual(backup.delete_backups(self.vault_id, self.backup_dir,
                                               backup.KIND_AUTO), 2)
        self.assertFalse(any(p.exists() for p in autos))
        self.assertTrue(manual.exists())
        backup.delete_backup(manual, self.vault_id)
        self.assertFalse(manual.exists())
        self.assertTrue(foreign.exists() and stray.exists())
        self.assertEqual(backup.list_backups(self.backup_dir, self.vault_id), [])

    def test_backup_opens_with_password_at_backup_time(self):
        path = backup.create_backup(self.vault, self.backup_dir)
        self.vault.change_master_password(MASTER, "nouveau-mot-de-passe-maitre")
        with self.assertRaises(WrongMasterPasswordError):
            backup.restore_backup(path, "nouveau-mot-de-passe-maitre")
        backup.restore_backup(path, MASTER)

    def test_wrong_password_and_tampering(self):
        path = backup.create_backup(self.vault, self.backup_dir)
        with self.assertRaises(WrongMasterPasswordError):
            backup.restore_backup(path, "mauvais-mot-de-passe")
        data = bytearray(path.read_bytes())
        data[-5] ^= 0xFF
        path.write_bytes(bytes(data))
        with self.assertRaises(VaultCorruptedError):
            backup.restore_backup(path, MASTER)
        self.assertEqual(len(list_vaults()), 1)  # no partial vault left behind

    def test_header_tampering_detected(self):
        path = backup.create_backup(self.vault, self.backup_dir)
        data = path.read_bytes().replace(b'"vault_name": "Test"', b'"vault_name": "Tost"')
        path.write_bytes(data)
        with self.assertRaises(VaultCorruptedError):
            backup.restore_backup(path, MASTER)

    def test_not_a_backup(self):
        path = self.backup_dir / "x.mcfbak"
        path.write_bytes(b"n'importe quoi")
        with self.assertRaises(backup.BackupError):
            backup.restore_backup(path, MASTER)

    def test_list_and_rotate_auto_backups(self):
        for _ in range(4):
            backup.create_backup(self.vault, self.backup_dir, kind=backup.KIND_AUTO,
                                 destination=self.backup_dir / f"{secrets.token_hex(4)}.mcfbak")
        backup.create_backup(self.vault, self.backup_dir)
        self.assertEqual(len(backup.list_backups(self.backup_dir, self.vault_id)), 5)
        self.assertEqual(backup.rotate_auto_backups(self.vault_id, self.backup_dir, keep=2), 2)
        kinds = sorted(i.kind for i in backup.list_backups(self.backup_dir))
        self.assertEqual(kinds, ["auto", "auto", "manuelle"])


class TestImportExport(EntryTestCase):
    def setUp(self):
        super().setUp()
        self.dir = Path(tempfile.mkdtemp(dir=self._tmpdir.name))

    def write_csv(self, name, header, rows):
        path = self.dir / name
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows(rows)
        return path

    def test_bitwarden(self):
        path = self.write_csv("bw.csv",
            ["folder", "favorite", "type", "name", "notes", "fields", "reprompt",
             "login_uri", "login_username", "login_password", "login_totp"],
            [["Travail", "1", "login", "GitLab", "n", "", "0", "https://gitlab.com",
              "alice", "pw1", "JBSWY3DP"],
             ["", "", "note", "Code alarme", "1234", "", "0", "", "", "", ""]])
        preview = import_export.parse_csv(path)
        self.assertEqual(preview.format_key, "bitwarden")
        result = import_export.apply_import(self.entries, self.categories, preview)
        self.assertEqual(result.imported, 2)
        entries = {s.service_name: self.entries.get_entry(s.id)
                   for s in self.entries.list_entries()}
        gitlab = entries["GitLab"]
        self.assertEqual((gitlab.password, gitlab.username, gitlab.is_favorite),
                         ("pw1", "alice", True))
        self.assertIn("TOTP: JBSWY3DP", gitlab.notes)
        self.assertEqual(entries["Code alarme"].entry_type, "secure_note")
        self.assertEqual(self.category_id("Work"), gitlab.category_id)

    def test_keepassxc_creates_categories(self):
        path = self.write_csv("kp.csv",
            ["Group", "Title", "Username", "Password", "URL", "Notes", "TOTP", "Icon",
             "Last Modified", "Created"],
            [["Root/Jeux", "Steam", "bob", "pw2", "https://store.steampowered.com",
              "", "", "0", "", ""]])
        preview = import_export.parse_csv(path)
        self.assertEqual(preview.format_key, "keepassxc")
        result = import_export.apply_import(self.entries, self.categories, preview)
        self.assertEqual(result.categories_created, ["Jeux"])

    def test_chrome_and_firefox_and_duplicates(self):
        chrome = self.write_csv("c.csv", ["name", "url", "username", "password", "note"],
                                [["github.com", "https://github.com/", "al", "pw3", ""]])
        firefox = self.write_csv("f.csv",
            ["url", "username", "password", "httpRealm", "formActionOrigin", "guid",
             "timeCreated", "timeLastUsed", "timePasswordChanged"],
            [["https://www.wikipedia.org", "al", "pw4", "", "", "{x}", "", "", ""]])
        self.assertEqual(import_export.parse_csv(chrome).format_key, "chrome")
        preview = import_export.parse_csv(firefox)
        self.assertEqual(preview.format_key, "firefox")
        self.assertEqual(preview.items[0].entry.service_name, "wikipedia.org")
        import_export.apply_import(self.entries, self.categories, import_export.parse_csv(chrome))
        again = import_export.apply_import(self.entries, self.categories,
                                           import_export.parse_csv(chrome))
        self.assertEqual((again.imported, again.duplicates), (0, 1))

    def test_unknown_csv_is_rejected(self):
        path = self.write_csv("x.csv", ["a", "b"], [["1", "2"]])
        with self.assertRaises(import_export.ImportExportError):
            import_export.parse_csv(path)

    def test_encrypted_export_roundtrip_requires_master_password(self):
        self.entries.create_entry(Entry(service_name="Carte", entry_type="card",
                                        extra={"card_number": "4111", "cvv": "999"},
                                        category_id=self.category_id("Finance")))
        dest = self.dir / "export.mcfexport"
        export_pw = secrets.token_urlsafe(12)
        with self.assertRaises(WrongMasterPasswordError):
            import_export.export_encrypted(self.entries, self.vault, "mauvais-mdp", export_pw, dest)
        self.assertFalse(dest.exists())
        self.assertEqual(import_export.export_encrypted(
            self.entries, self.vault, MASTER, export_pw, dest), 1)
        self.assertEqual(oct(dest.stat().st_mode & 0o777), "0o600")
        self.assertNotIn(b"4111", dest.read_bytes())
        self.assertTrue(import_export.is_encrypted_export(dest))
        with self.assertRaises(WrongMasterPasswordError):
            import_export.parse_encrypted_export(dest, "mauvais-mdp-export")
        preview = import_export.parse_encrypted_export(dest, export_pw)
        item = preview.items[0]
        self.assertEqual((item.entry.extra["cvv"], item.category_name), ("999", "Finance"))

    def test_csv_export_roundtrip(self):
        self.entries.create_entry(Entry(service_name="A", password="p,\"a\"\nb", notes="x"))
        dest = self.dir / "export.csv"
        import_export.export_csv(self.entries, self.vault, MASTER, dest)
        self.assertEqual(oct(dest.stat().st_mode & 0o777), "0o600")
        preview = import_export.parse_csv(dest)
        self.assertEqual(preview.format_key, "moncoffre")
        self.assertEqual(preview.items[0].entry.password, "p,\"a\"\nb")

    def test_invalid_rows_are_skipped(self):
        path = self.write_csv("c.csv", ["name", "url", "username", "password", "note"],
                              [["ok", "", "", "pw", ""], ["x" * 500, "", "", "pw", ""]])
        result = import_export.apply_import(self.entries, self.categories,
                                            import_export.parse_csv(path))
        self.assertEqual((result.imported, result.invalid), (1, 1))


class TestMaliciousFiles(EntryTestCase):
    """Crafted files: oversized Argon2id parameters refused BEFORE any derivation."""

    HUGE: ClassVar[dict[str, int]] = {
        "time_cost": 10**9, "memory_cost": 2**40, "parallelism": 2**20, "hash_len": 32,
    }

    def test_params_bounds(self):
        from app.core import crypto

        crypto.Argon2Params.from_dict(crypto.Argon2Params().to_dict())  # defaults accepted
        for bad in (self.HUGE,
                    {**crypto.Argon2Params().to_dict(), "memory_cost": 2 * 1024 * 1024},
                    {**crypto.Argon2Params().to_dict(), "time_cost": 0},
                    {**crypto.Argon2Params().to_dict(), "hash_len": 16}):
            with self.assertRaises(ValueError):
                crypto.Argon2Params.from_dict(bad)

    def test_tampered_vault_params(self):
        import json as _json

        from app.core import crypto

        with self.vault.connection as conn:
            conn.execute("UPDATE vault_meta SET kdf_params_json = ?", (_json.dumps(self.HUGE),))
        self.vault.close()
        with self.assertRaises(VaultCorruptedError):
            self.vault = Vault.unlock(self.vault_id, MASTER)
        self.assertEqual([v.vault_name for v in list_vaults()], [self.vault_id])  # unreadable
        # Restore the state for tearDown.
        conn = database.connect(Path(self.vault._db_path))
        with conn:
            conn.execute("UPDATE vault_meta SET kdf_params_json = ?",
                         (_json.dumps(crypto.Argon2Params().to_dict()),))
        conn.close()
        self.vault = Vault.unlock(self.vault_id, MASTER)

    def test_tampered_backup_header(self):
        import json as _json
        import struct

        path = backup.create_backup(self.vault, Path(tempfile.mkdtemp(dir=self._tmpdir.name)))
        data = path.read_bytes()
        n = struct.unpack(">I", data[8:12])[0]
        header = _json.loads(data[12:12 + n])
        header["kdf_params"] = self.HUGE
        new = _json.dumps(header).encode()
        path.write_bytes(data[:8] + struct.pack(">I", len(new)) + new + data[12 + n:])
        with self.assertRaises(backup.BackupError):
            backup.restore_backup(path, MASTER)

    def test_tampered_encrypted_export(self):
        import json as _json

        dest = Path(tempfile.mkdtemp(dir=self._tmpdir.name)) / "x.mcfexport"
        import_export.export_encrypted(self.entries, self.vault, MASTER,
                                       secrets.token_urlsafe(12), dest)
        container = _json.loads(dest.read_text())
        container["kdf_params"] = self.HUGE
        dest.write_text(_json.dumps(container))
        with self.assertRaises(import_export.ImportExportError):
            import_export.parse_encrypted_export(dest, "peu-importe")
