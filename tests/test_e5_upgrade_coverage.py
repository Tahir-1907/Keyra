"""E5.4: additional coverage of the upgrade (E3).

* final verification against REAL corruptions of a migrated v4 vault;
* VACUUM: engine failure then successful retry, or double failure (warning);
* real SIGKILL (separate process) while the preliminary backup is written and
  after the COMMIT (before VACUUM, during verification).

The VACUUM failure is injected on the TEST side, through a wrapper around the SQLite
connection that refuses the `VACUUM` statement: the engine (migration_v4) has no
injection point for this step and is not modified. Fixture copies in temporary XDG
directories only.
"""

import os
import signal
import sqlite3
import subprocess
import sys
import time
import unittest.mock
from pathlib import Path

from app.core.exceptions import VaultError
from app.core.vault import Vault
from app.database import database
from app.database.repositories import VaultMetaRepository
from app.services import backup, vault_upgrade
from app.services.migration_v4 import MigrationReport
from app.utils.paths import vault_path
from tests.test_e3_upgrade import ROOT, V3, UpgradeTestCase, schema_of
from tests.test_fixtures import logical_dump


class NoVacuum:
    """SQLite connection whose VACUUM statement fails (simulated full disk)."""

    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, *args):
        if sql.strip().upper().startswith("VACUUM"):
            raise sqlite3.OperationalError("database or disk is full (simulé)")
        return self._conn.execute(sql, *args)

    def __getattr__(self, name):
        return getattr(self._conn, name)


def freelist(path: Path) -> int:
    conn = sqlite3.connect(path)
    try:
        return conn.execute("PRAGMA freelist_count").fetchone()[0]
    finally:
        conn.close()


def flip_last_byte(conn, table: str, column: str, row_id: int) -> None:
    blob = bytearray(conn.execute(f"SELECT {column} FROM {table} WHERE id = ?",  # noqa: S608
                                  (row_id,)).fetchone()[0])
    blob[-1] ^= 1
    conn.execute(f"UPDATE {table} SET {column} = ? WHERE id = ?",  # noqa: S608
                 (bytes(blob), row_id))


# --- E5.4.1: final verification on a really corrupted v4 vault -----------------------------


class TestVerificationOnRealCorruption(UpgradeTestCase):
    def migrated(self):
        manifest = self.install(V3)
        result = self.upgrade(manifest)
        self.vault.close()
        self.vault = None
        return manifest, result.report

    def tamper(self, manifest, action):
        conn = sqlite3.connect(self.db(manifest))
        try:
            action(conn)
            conn.commit()
        finally:
            conn.close()

    def verify(self, manifest, report):
        vault = Vault.unlock(manifest["vault_id"], manifest["master_password"])
        try:
            return vault_upgrade.verify_upgraded(vault, report)
        finally:
            vault.close()

    def test_intact_migrated_vault_passes(self):
        manifest, report = self.migrated()
        self.assertEqual(self.verify(manifest, report), [])

    def test_each_real_corruption_is_refused(self):
        custom_category = 7  # "Projets BTS": custom category (encrypted name)
        cases = {
            "entry metadata": lambda c: flip_last_byte(c, "entries", "metadata_enc", 1),
            "entry secret": lambda c: flip_last_byte(c, "entries", "password_enc", 2),
            "history version": lambda c: flip_last_byte(
                c, "entry_history", "snapshot_enc",
                c.execute("SELECT MIN(id) FROM entry_history").fetchone()[0]),
            "category name": lambda c: flip_last_byte(c, "categories", "name_enc",
                                                      custom_category),
            "missing entry": lambda c: c.execute("DELETE FROM entries WHERE id = 3"),
            "unexpected table": lambda c: c.execute("CREATE TABLE intrus (x)"),
        }
        for label, action in cases.items():
            with self.subTest(corruption=label):
                manifest, report = self.migrated()
                self.tamper(manifest, action)
                with self.assertRaises(VaultError):
                    self.verify(manifest, report)

    def test_damaged_migration_backup_is_refused(self):
        manifest, report = self.migrated()
        data = report.backup_path.read_bytes()
        report.backup_path.write_bytes(data[:-40])
        with self.assertRaises(backup.BackupError):
            self.verify(manifest, report)

    def test_upgrade_reports_a_real_verification_failure(self):
        """Corruption between the migration and the verification: `upgrade` returns no
        open vault and raises UpgradeVerificationError (real mechanism)."""
        manifest = self.install(V3)
        real = vault_upgrade.migrate_to_v4

        def migrate_then_corrupt(vault, backup_dir, _fault=None):
            report = real(vault, backup_dir, _fault=_fault)
            flip_last_byte(vault.connection, "entries", "metadata_enc", 1)
            vault.connection.commit()
            return report

        with unittest.mock.patch.object(vault_upgrade, "migrate_to_v4", migrate_then_corrupt), \
                self.assertRaises(vault_upgrade.UpgradeVerificationError) as ctx:
            self.upgrade(manifest)
        self.assertIsNone(self.vault)
        self.assertEqual(schema_of(self.db(manifest)), 4)
        (path,) = self.backups()
        self.assertEqual(ctx.exception.backup_path, path)
        info = backup.restore_backup(path, manifest["master_password"])
        self.assertEqual(schema_of(vault_path(info.vault_id) / "vault.db"), 3)


# --- E5.4.3 : VACUUM ---------------------------------------------------------------------------


class TestVacuumRetry(UpgradeTestCase):
    def engine_without_vacuum(self, seen):
        real = vault_upgrade.migrate_to_v4

        def engine(vault, backup_dir, _fault=None):
            original = vault._conn
            vault._conn = NoVacuum(original)
            try:
                report = real(vault, backup_dir, _fault=_fault)
            finally:
                vault._conn = original
            seen["engine_vacuumed"] = report.vacuumed
            seen["freelist_after_engine"] = freelist(vault._db_path)
            return report
        return engine

    def test_engine_vacuum_fails_then_the_retry_succeeds(self):
        manifest = self.install(V3)
        seen = {}
        with unittest.mock.patch.object(vault_upgrade, "migrate_to_v4",
                                        self.engine_without_vacuum(seen)):
            result = self.upgrade(manifest)
        self.assertFalse(seen["engine_vacuumed"])  # first attempt (engine) fails
        self.assertGreater(seen["freelist_after_engine"], 0)
        self.assertTrue(result.report.vacuumed)  # second attempt (verification) succeeds
        self.assertEqual(result.warnings, [])
        self.assertEqual(freelist(self.db(manifest)), 0)
        self.assert_matches_manifest(manifest)

    def test_both_attempts_fail_the_vault_stays_verified_with_a_warning(self):
        manifest = self.install(V3)
        seen = {}
        real_unlock = Vault.unlock

        def unlock_without_vacuum(vault_id, password):
            vault = real_unlock(vault_id, password)
            vault._conn = NoVacuum(vault._conn)
            return vault

        with unittest.mock.patch.object(vault_upgrade, "migrate_to_v4",
                                        self.engine_without_vacuum(seen)), \
                unittest.mock.patch.object(Vault, "unlock", side_effect=unlock_without_vacuum):
            result = self.upgrade(manifest)
        self.assertFalse(seen["engine_vacuumed"])
        self.assertFalse(result.report.vacuumed)
        self.assertEqual(len(result.warnings), 1)
        self.assertIn("compaction", result.warnings[0])
        self.assertGreater(freelist(self.db(manifest)), 0)
        # Upgrade committed and verified nonetheless: content intact, can be opened.
        self.assertEqual(schema_of(self.db(manifest)), 4)
        self.assert_matches_manifest(manifest)
        self.vault.close()
        self.vault = Vault.unlock(manifest["vault_id"], manifest["master_password"])
        self.assert_matches_manifest(manifest)


# --- E5.4.5: SIGKILL outside the transaction ---------------------------------------------------


class TestSigkillOutsideTheTransaction(UpgradeTestCase):
    """Complements TestSigkill (E3: entry, rebuilt, before_commit steps, INSIDE the transaction)."""

    def run_and_kill(self, manifest, pause_code: str) -> None:
        marker = Path(self._tmp.name) / "pause-reached"
        marker.unlink(missing_ok=True)
        child = (
            "import sys, time\n"
            f"sys.path.insert(0, {str(ROOT)!r})\n"
            "from pathlib import Path\n"
            f"MARKER = Path({str(marker)!r})\n"
            "def pause():\n"
            "    MARKER.write_text('ok')\n"
            "    time.sleep(120)\n"
            + pause_code +
            "from app.services import vault_upgrade\n"
            f"vault_upgrade.upgrade({manifest['vault_id']!r}, {manifest['master_password']!r},"
            f" Path({str(self.backup_dir)!r}))\n")
        proc = subprocess.Popen([sys.executable, "-c", child], env=os.environ.copy())
        try:
            for _ in range(600):
                if marker.exists() or proc.poll() is not None:
                    break
                time.sleep(0.05)
            self.assertTrue(marker.exists(), "point d'arrêt non atteint")
        finally:
            proc.send_signal(signal.SIGKILL)
            proc.wait()
        self.assertEqual(proc.returncode, -signal.SIGKILL)

    def rebuilt_report(self, manifest) -> MigrationReport:
        (path,) = self.backup_dir.glob("*_migration.mcfbak")
        return MigrationReport(
            from_version=3, backup_path=path, legacy_plaintext_copies=[],
            entries=len(manifest["entries"]),
            history_versions=sum(len(e["history"]) for e in manifest["entries"]),
            vacuumed=True)

    def assert_integrity(self, manifest):
        conn = sqlite3.connect(self.db(manifest))
        try:
            self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        finally:
            conn.close()

    def test_while_writing_the_backup(self):
        """Stop after the complete encrypted write, before the final rename: the vault was
        not touched, the (encrypted) temporary remains, ignored; full retry."""
        manifest = self.install(V3)
        dump = logical_dump(self.db(manifest))
        self.run_and_kill(manifest, (
            "import app.utils.files as files\n"
            "_replace = files.os.replace\n"
            "def replace(src, dst):\n"
            "    if str(dst).endswith('_migration.mcfbak'):\n"
            "        pause()\n"
            "    return _replace(src, dst)\n"
            "files.os.replace = replace\n"))
        self.assertEqual(schema_of(self.db(manifest)), 3)
        self.assertEqual(logical_dump(self.db(manifest)), dump)
        self.assert_integrity(manifest)
        leftovers = sorted(self.backup_dir.glob(".tmp-*"))
        self.assertEqual(len(leftovers), 1)
        self.assertTrue(leftovers[0].read_bytes().startswith(backup.MAGIC))  # encrypted
        self.assertEqual(backup.list_backups(self.backup_dir), [])  # ignored when listing
        self.upgrade(manifest)  # new attempt
        self.assert_matches_manifest(manifest)

    def test_after_commit_before_vacuum(self):
        manifest = self.install(V3)
        self.run_and_kill(manifest, (
            "import sqlite3\n"
            "from app.core.vault import Vault\n"
            "class Paused:\n"
            "    def __init__(self, conn): self._conn = conn\n"
            "    def execute(self, sql, *args):\n"
            "        if sql.strip().upper().startswith('VACUUM'): pause()\n"
            "        return self._conn.execute(sql, *args)\n"
            "    def __getattr__(self, name): return getattr(self._conn, name)\n"
            "_open = Vault.open_for_migration.__func__\n"
            "def open_for_migration(cls, vault_id, password):\n"
            "    vault = _open(cls, vault_id, password)\n"
            "    vault._conn = Paused(vault._conn)\n"
            "    return vault\n"
            "Vault.open_for_migration = classmethod(open_for_migration)\n"))
        self.assert_integrity(manifest)
        self.assertEqual(schema_of(self.db(manifest)), 4)  # COMMIT already done
        self.vault = Vault.unlock(manifest["vault_id"], manifest["master_password"])
        self.assert_matches_manifest(manifest)
        report = self.rebuilt_report(manifest)
        report.vacuumed = False  # the engine's VACUUM did not happen
        self.assertEqual(vault_upgrade.verify_upgraded(self.vault, report), [])
        self.assertTrue(report.vacuumed)  # caught up by the verification
        self.assertEqual(VaultMetaRepository(self.vault.connection).get().schema_version, 4)

    def test_during_the_final_verification(self):
        manifest = self.install(V3)
        self.run_and_kill(manifest, (
            "from app.services import vault_upgrade as _vu\n"
            "def verify(vault, report):\n"
            "    pause()\n"
            "_vu.verify_upgraded = verify\n"))
        self.assert_integrity(manifest)
        self.assertEqual(schema_of(self.db(manifest)), 4)
        self.assertEqual(freelist(self.db(manifest)), 0)  # VACUUM done before the stop
        self.vault = Vault.unlock(manifest["vault_id"], manifest["master_password"])
        self.assert_matches_manifest(manifest)
        self.assertEqual(vault_upgrade.verify_upgraded(self.vault, self.rebuilt_report(manifest)),
                         [])
        conn = self.vault.connection
        self.assertEqual(database.structure_problems(conn, 4), [])
