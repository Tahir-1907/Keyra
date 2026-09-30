"""E3 : mise à niveau des coffres v1/v2/v3 (préflight, migration, vérification, UI).

Uniquement des COPIES des coffres de référence (tests/fixtures) dans des
répertoires XDG temporaires : aucun vrai coffre n'est jamais ouvert.
"""

import hashlib
import io
import json
import os
import signal
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path

from app.core.exceptions import (
    RecoveryKeyError,
    VaultCorruptedError,
    VaultError,
    VaultMigrationRequiredError,
    WrongMasterPasswordError,
)
from app.core.vault import Vault
from app.database import database
from app.database.repositories import VaultMetaRepository
from app.services import backup, vault_upgrade
from app.services.migration_v4 import MigrationError
from app.services.vault_upgrade import (
    RecoveredNotUpgradedError,
    UpgradeRefusedError,
    UpgradeVerificationError,
)
from app.utils.paths import vault_path
from tests.test_fixtures import FixtureVaultTestCase, load_manifest, logical_dump
from tests.test_ui import UiTestCase

V3, V2 = "v3-app-1.6.0", "v2-app-1.0.0"
ROOT = Path(__file__).resolve().parent.parent
NEW_MASTER = "nouveau-mot-de-passe-de-test-E3"
# Tables dont le contenu ne dépend pas du mot de passe (la récupération ne réécrit que
# vault_meta et vault_recovery).
DATA_TABLES = ("categories", "entries", "entry_history", "entry_tags")


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def data_dump(path: Path) -> dict:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return {t: conn.execute(f"SELECT * FROM {t} ORDER BY rowid").fetchall()  # noqa: S608
                for t in DATA_TABLES}
    finally:
        conn.close()


def schema_of(path: Path) -> int:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return conn.execute("SELECT schema_version FROM vault_meta").fetchone()[0]
    finally:
        conn.close()


class UpgradeTestCase(FixtureVaultTestCase):
    def setUp(self):
        super().setUp()
        root = Path(self._tmp.name)
        self.assertTrue(str(vault_path("x")).startswith(str(root)))  # jamais un vrai coffre
        self.backup_dir = root / "sauvegardes"

    def db(self, manifest) -> Path:
        return vault_path(manifest["vault_id"]) / "vault.db"

    def prepared(self, name, prepare):
        manifest = self.install(name)
        conn = sqlite3.connect(self.db(manifest))
        prepare(conn)
        conn.commit()
        conn.close()
        return manifest

    def upgrade(self, manifest, password=None, **kwargs):
        result = vault_upgrade.upgrade(manifest["vault_id"],
                                       password or manifest["master_password"],
                                       self.backup_dir, **kwargs)
        self.vault = result.vault
        return result

    def assert_untouched(self, manifest, sha_before, dump_before):
        self.assertEqual(schema_of(self.db(manifest)), manifest["schema_version"])
        self.assertEqual(logical_dump(self.db(manifest)), dump_before)
        if sha_before is not None:
            self.assertEqual(file_sha(self.db(manifest)), sha_before)

    def backups(self):
        return sorted(self.backup_dir.glob("*.mcfbak")) if self.backup_dir.exists() else []


# --- Réussites ---------------------------------------------------------------------------


class TestSuccessfulUpgrade(UpgradeTestCase):
    def check(self, name):
        manifest = self.install(name)
        result = self.upgrade(manifest)
        self.assertEqual(VaultMetaRepository(self.vault.connection).get().schema_version, 4)
        self.assert_matches_manifest(manifest)
        (path,) = self.backups()
        self.assertEqual(result.report.backup_path, path)
        self.assertEqual(backup.read_backup_info(path).kind, backup.KIND_MIGRATION)
        backup.verify_backup(path, self.vault._require_unlocked_key())
        self.assertTrue(result.report.vacuumed)
        self.assertEqual(result.warnings, [])
        self.vault.close()
        self.vault = Vault.unlock(manifest["vault_id"], manifest["master_password"])
        self.assert_matches_manifest(manifest)
        self.assertEqual(vault_upgrade.inspect(manifest["vault_id"]).needs_upgrade, False)

    def test_v3(self):
        self.check(V3)

    def test_v2(self):
        self.check(V2)

    def test_simulated_v1(self):
        def to_v1(conn):
            conn.execute("DROP TABLE entry_history;")
            conn.execute("DROP TABLE vault_recovery;")
            conn.execute("ALTER TABLE entries DROP COLUMN password_changed_at;")
            conn.execute("UPDATE vault_meta SET schema_version = 1;")

        manifest = self.prepared(V3, to_v1)
        self.assertEqual(vault_upgrade.inspect(manifest["vault_id"]).problems, ())
        result = self.upgrade(manifest)
        self.assertEqual(result.report.from_version, 1)
        self.assertEqual(len(self.vault.metadata.entries()), len(manifest["entries"]))

    def test_legacy_plaintext_copies_are_reported_and_kept(self):
        manifest = self.install(V3)
        copy = self.db(manifest).with_name("vault.db.avant-schema-v3.bak")
        copy.write_bytes(b"ancienne copie en clair (fictive)")
        self.assertEqual(vault_upgrade.inspect(manifest["vault_id"]).legacy_plaintext_copies,
                         (copy,))
        result = self.upgrade(manifest)
        self.assertEqual(result.legacy_plaintext_copies, (copy,))
        self.assertEqual(copy.read_bytes(), b"ancienne copie en clair (fictive)")


# --- Refus et échecs : coffre intact ---------------------------------------------------------


class TestRefusals(UpgradeTestCase):
    def test_wrong_password_never_migrates(self):
        manifest = self.install(V3)
        sha, dump = file_sha(self.db(manifest)), logical_dump(self.db(manifest))
        with self.assertRaises(WrongMasterPasswordError):
            vault_upgrade.upgrade(manifest["vault_id"], "mauvais-mot-de-passe-123",
                                  self.backup_dir)
        self.assert_untouched(manifest, sha, dump)
        self.assertEqual(self.backups(), [])

    def test_corrupted_file_is_refused(self):
        manifest = self.install(V3)
        path = self.db(manifest)
        path.write_bytes(path.read_bytes()[:4096])
        truncated = file_sha(path)
        for call in (lambda: vault_upgrade.inspect(manifest["vault_id"]),
                     lambda: vault_upgrade.upgrade(manifest["vault_id"],
                                                   manifest["master_password"],
                                                   self.backup_dir)):
            with self.assertRaises(VaultCorruptedError):
                call()
        self.assertEqual(file_sha(path), truncated)
        self.assertEqual(self.backups(), [])

    def test_unreadable_history_is_refused_and_kept(self):
        manifest = self.prepared(V3, lambda c: c.execute(
            "UPDATE entry_history SET snapshot_enc = substr(snapshot_enc, 1, 40) "
            "WHERE id = (SELECT MIN(id) FROM entry_history)"))
        dump = logical_dump(self.db(manifest))
        with self.assertRaises(MigrationError) as ctx:
            self.upgrade(manifest)
        self.assertIn("historique", str(ctx.exception))
        self.assert_untouched(manifest, None, dump)
        (path,) = self.backups()  # sauvegarde faite avant la tentative, conservée
        vault = Vault.open_for_migration(manifest["vault_id"], manifest["master_password"])
        try:
            backup.verify_backup(path, vault._require_unlocked_key())
        finally:
            vault.close()

    def test_unexpected_structures_are_refused_never_dropped(self):
        cases = {
            "table inconnue": ("CREATE TABLE intrus (secret TEXT)", "intrus"),
            "vue inconnue": ("CREATE VIEW vue_intruse AS SELECT service_name FROM entries",
                             "vue_intruse"),
            "déclencheur inconnu": (
                "CREATE TRIGGER trg_intrus AFTER UPDATE ON entries BEGIN SELECT 1; END",
                "trg_intrus"),
            "index inattendu": ("CREATE INDEX idx_intrus ON entries(url)", "idx_intrus"),
            "colonne inattendue (table reconstruite)": (
                "ALTER TABLE entries ADD COLUMN commentaire TEXT", "entries.commentaire"),
            "colonne inattendue (table conservée)": (
                "ALTER TABLE vault_recovery ADD COLUMN indice TEXT", "vault_recovery.indice"),
            "table SQLite interne inattendue": ("ANALYZE", "sqlite_stat1"),
            "index légitime absent": ("DROP INDEX idx_entries_category",
                                      "idx_entries_category"),
        }
        for label, (sql, marker) in cases.items():
            with self.subTest(cas=label):
                manifest = self.prepared(V3, lambda c, sql=sql: c.execute(sql))
                sha, dump = file_sha(self.db(manifest)), logical_dump(self.db(manifest))
                check = vault_upgrade.inspect(manifest["vault_id"])
                self.assertFalse(check.can_upgrade)
                self.assertTrue(any(marker in p for p in check.problems), check.problems)
                with self.assertRaises(UpgradeRefusedError) as ctx:
                    self.upgrade(manifest)
                self.assertIn(marker, str(ctx.exception))
                self.assert_untouched(manifest, sha, dump)
                self.assertEqual(self.backups(), [])  # refusé avant la sauvegarde
                if "absent" not in label:  # la structure inconnue est toujours là
                    conn = sqlite3.connect(self.db(manifest))
                    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
                    columns = {f"{t}.{r[1]}" for t in ("entries", "vault_recovery")
                               for r in conn.execute(f"PRAGMA table_info({t})")}
                    conn.close()
                    self.assertIn(marker, names | columns)

    def test_error_during_migration_leaves_a_usable_vault_and_retry_works(self):
        manifest = self.install(V3)
        dump = logical_dump(self.db(manifest))

        def fault(step):
            if step == "entry":
                raise RuntimeError("panne simulée")

        with self.assertRaises(MigrationError):
            self.upgrade(manifest, _fault=fault)
        self.assert_untouched(manifest, None, dump)
        with self.assertRaises(VaultMigrationRequiredError):  # toujours un coffre v3
            Vault.unlock(manifest["vault_id"], manifest["master_password"])
        self.upgrade(manifest)
        self.assert_matches_manifest(manifest)
        self.assertEqual(len(self.backups()), 2)  # une sauvegarde par tentative, conservées

    def test_backup_impossible_leaves_the_vault_unchanged(self):
        manifest = self.install(V3)
        sha, dump = file_sha(self.db(manifest)), logical_dump(self.db(manifest))
        self.backup_dir.parent.mkdir(parents=True, exist_ok=True)
        self.backup_dir.write_text("un fichier, pas un dossier")
        with self.assertRaises(MigrationError) as ctx:
            self.upgrade(manifest)
        self.assertIn("Sauvegarde préalable impossible", str(ctx.exception))
        self.assert_untouched(manifest, sha, dump)

    def test_verification_failure_state(self):
        """Migration validée mais vérification en échec : coffre v4 NON ouvert, sauvegarde
        de migration intacte et restaurable (format d'origine)."""
        manifest = self.install(V3)
        with unittest.mock.patch.object(vault_upgrade, "verify_upgraded",
                                        side_effect=RuntimeError("écart simulé")), \
                self.assertRaises(UpgradeVerificationError) as ctx:
            self.upgrade(manifest)
        self.assertEqual(schema_of(self.db(manifest)), 4)
        (path,) = self.backups()
        self.assertEqual(ctx.exception.backup_path, path)
        self.assertIn(path.name, str(ctx.exception))
        with self.assertRaises(VaultError):  # déjà v4 : pas de seconde migration
            self.upgrade(manifest)
        info = backup.restore_backup(path, manifest["master_password"])
        self.assertEqual(schema_of(vault_path(info.vault_id) / "vault.db"), 3)


class TestSigkill(UpgradeTestCase):
    """Arrêt brutal du processus PENDANT la transaction : coffre d'origine, retentable."""

    def run_and_kill(self, manifest, step):
        marker = Path(self._tmp.name) / f"etape-{step}"
        child = (
            "import sys, time\n"
            f"sys.path.insert(0, {str(ROOT)!r})\n"
            "from pathlib import Path\n"
            "from app.services import vault_upgrade\n"
            "def fault(s):\n"
            f"    if s == {step!r}:\n"
            f"        Path({str(marker)!r}).write_text(s)\n"
            "        time.sleep(120)\n"
            f"vault_upgrade.upgrade({manifest['vault_id']!r}, "
            f"{manifest['master_password']!r}, Path({str(self.backup_dir)!r}), _fault=fault)\n")
        proc = subprocess.Popen([sys.executable, "-c", child], env=os.environ.copy())
        try:
            for _ in range(600):
                if marker.exists() or proc.poll() is not None:
                    break
                time.sleep(0.05)
            self.assertTrue(marker.exists(), "étape non atteinte")
        finally:
            proc.send_signal(signal.SIGKILL)
            proc.wait()
        self.assertEqual(proc.returncode, -signal.SIGKILL)

    def test_sigkill_at_several_steps(self):
        for step in ("entry", "rebuilt", "before_commit"):
            with self.subTest(step=step):
                manifest = self.install(V3)
                dump = logical_dump(self.db(manifest))
                self.run_and_kill(manifest, step)
                self.assert_untouched(manifest, None, dump)
                conn = sqlite3.connect(self.db(manifest))
                self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertFalse(database.has_v4_structures(conn))
                conn.close()
                self.assertEqual(vault_upgrade.inspect(manifest["vault_id"]).problems, ())
                self.upgrade(manifest)  # nouvel essai complet
                self.assert_matches_manifest(manifest)
                self.vault.close()
                self.vault = None


# --- Récupération par clé ----------------------------------------------------------------------


class TestRecoveryUpgrade(UpgradeTestCase):
    def recover(self, manifest, **kwargs):
        result, new_key = vault_upgrade.recover_and_upgrade(
            manifest["vault_id"], manifest["recovery_key"], NEW_MASTER, self.backup_dir,
            **kwargs)
        self.vault = result.vault
        return result, new_key

    def test_recovery_then_upgrade(self):
        manifest = self.install(V3)
        result, new_key = self.recover(manifest)
        self.assertNotEqual(new_key, manifest["recovery_key"])
        self.assert_matches_manifest(manifest)
        self.vault.close()
        self.vault = None
        vault_id = manifest["vault_id"]
        with self.assertRaises(WrongMasterPasswordError):
            Vault.unlock(vault_id, manifest["master_password"])
        with self.assertRaises(RecoveryKeyError):
            Vault.recover(vault_id, manifest["recovery_key"], "autre-mot-de-passe-de-test")
        Vault.unlock(vault_id, NEW_MASTER).close()
        # La sauvegarde de migration (v3) s'ouvre avec le NOUVEAU mot de passe.
        with self.assertRaises(WrongMasterPasswordError):
            backup.restore_backup(result.report.backup_path, manifest["master_password"])
        info = backup.restore_backup(result.report.backup_path, NEW_MASTER)
        self.assertEqual(schema_of(vault_path(info.vault_id) / "vault.db"), 3)
        self.vault, _ = Vault.recover(vault_id, new_key, "encore-un-mot-de-passe-de-test")

    def test_recovery_succeeds_but_migration_fails(self):
        manifest = self.install(V3)
        data = data_dump(self.db(manifest))

        def fault(step):
            if step == "history":
                raise RuntimeError("panne simulée après récupération")

        with self.assertRaises(RecoveredNotUpgradedError) as ctx:
            self.recover(manifest, _fault=fault)
        new_key = ctx.exception.new_recovery_key
        self.assertTrue(new_key)
        self.assertNotEqual(new_key, manifest["recovery_key"])
        self.assertIn("nouveau mot de passe", str(ctx.exception).lower())
        # État exact : format d'origine, données identiques, NOUVELLES enveloppes.
        path = self.db(manifest)
        self.assertEqual(schema_of(path), 3)
        self.assertEqual(data_dump(path), data)
        conn = sqlite3.connect(path)
        self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        self.assertFalse(database.has_v4_structures(conn))
        conn.close()
        vault_id = manifest["vault_id"]
        with self.assertRaises(WrongMasterPasswordError):
            Vault.open_for_migration(vault_id, manifest["master_password"])
        with self.assertRaises(RecoveryKeyError):
            Vault.recover(vault_id, manifest["recovery_key"], "x-mot-de-passe-de-test",
                          allow_legacy=True)
        (kept,) = self.backups()  # sauvegarde faite avant la migration, avec le NOUVEAU mdp
        info = backup.restore_backup(kept, NEW_MASTER)
        self.assertEqual(schema_of(vault_path(info.vault_id) / "vault.db"), 3)
        with self.assertRaises(VaultMigrationRequiredError):  # proposé au déverrouillage
            Vault.unlock(vault_id, NEW_MASTER)
        # Nouvel essai propre : nouveau mot de passe, puis migration normale.
        self.upgrade(manifest, password=NEW_MASTER)
        self.assert_matches_manifest(manifest)
        self.vault.close()
        self.vault, _ = Vault.recover(vault_id, new_key, "dernier-mot-de-passe-de-test")

    def test_structure_problem_is_refused_before_recovery(self):
        manifest = self.prepared(V3, lambda c: c.execute("CREATE TABLE intrus (x)"))
        sha, dump = file_sha(self.db(manifest)), logical_dump(self.db(manifest))
        with self.assertRaises(UpgradeRefusedError):
            self.recover(manifest)
        self.assert_untouched(manifest, sha, dump)  # enveloppes NON réécrites
        vault, _ = Vault.recover(manifest["vault_id"], manifest["recovery_key"],
                                 NEW_MASTER, allow_legacy=True)  # l'ancienne clé marche
        vault.close()

    def test_recover_without_flag_still_refuses_old_vaults(self):
        manifest = self.install(V3)
        sha = file_sha(self.db(manifest))
        with self.assertRaises(VaultMigrationRequiredError):
            Vault.recover(manifest["vault_id"], manifest["recovery_key"], NEW_MASTER)
        self.assertEqual(file_sha(self.db(manifest)), sha)


# --- Anciennes sauvegardes -----------------------------------------------------------------------


class TestOldBackups(UpgradeTestCase):
    def test_restored_old_backup_proposes_the_upgrade(self):
        for name in (V2, V3):
            with self.subTest(fixture=name):
                manifest = self.install(name)
                vault = Vault.open_for_migration(manifest["vault_id"],
                                                 manifest["master_password"])
                path = backup.create_backup(vault, directory=self.backup_dir)
                vault.close()
                info = backup.restore_backup(path, manifest["master_password"])
                with self.assertRaises(VaultMigrationRequiredError):
                    Vault.unlock(info.vault_id, manifest["master_password"])
                check = vault_upgrade.inspect(info.vault_id)
                self.assertTrue(check.can_upgrade)
                self.assertEqual(check.schema_version, manifest["schema_version"])
                result = vault_upgrade.upgrade(info.vault_id, manifest["master_password"],
                                               self.backup_dir)
                self.vault = result.vault
                self.assert_matches_manifest(manifest)
                self.vault.close()
                self.vault = None


class TestCompatibilityWith160(UpgradeTestCase):
    """La sauvegarde faite avant migration se restaure avec le code 1.6.0 (a99f821)."""

    def test_migration_backup_restored_by_1_6_0(self):
        archive = subprocess.run(["git", "-C", str(ROOT), "archive", "--format=tar", "a99f821"],
                                 capture_output=True, check=False)
        if archive.returncode != 0:
            self.skipTest("commit a99f821 indisponible")
        old_code = Path(self._tmp.name) / "code-1.6.0"
        with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tar:
            tar.extractall(old_code, filter="data")
        manifest = self.install(V3)
        result = self.upgrade(manifest)
        path = result.report.backup_path
        self.vault.close()
        self.vault = None
        home = Path(tempfile.mkdtemp(dir=self._tmp.name))
        env = {**os.environ, "HOME": str(home), "XDG_DATA_HOME": str(home / "data"),
               "XDG_CONFIG_HOME": str(home / "config"), "XDG_CACHE_HOME": str(home / "cache")}
        child = (
            "import json, sys\n"
            f"sys.path.insert(0, {str(old_code)!r})\n"
            "from pathlib import Path\n"
            "import app\n"
            "from app.core.entries import EntryFilter, EntryService\n"
            "from app.core.vault import Vault\n"
            "from app.services import backup\n"
            f"info = backup.restore_backup(Path({str(path)!r}), {manifest['master_password']!r})\n"
            f"v = Vault.unlock(info.vault_id, {manifest['master_password']!r})\n"
            "s = EntryService(v)\n"
            "trash = s.list_entries(EntryFilter(in_trash=True))\n"
            "print(json.dumps({'version': app.__version__, 'app_file': app.__file__,\n"
            "  'active': sorted(e.service_name for e in s.list_entries()),\n"
            "  'trash': sorted(e.service_name for e in trash),\n"
            "  'passwords': sorted(s.get_entry(e.id, include_deleted=True).password\n"
            "      for e in s.list_entries() + trash)}))\n")
        out = subprocess.run([sys.executable, "-c", child], env=env, cwd=old_code,
                             capture_output=True, text=True, check=True, timeout=120)
        data = json.loads(out.stdout.strip().splitlines()[-1])
        self.assertEqual(data["version"], "1.6.0")
        self.assertTrue(data["app_file"].startswith(str(old_code)))
        entries = manifest["entries"]
        self.assertEqual(data["active"], sorted(e["service_name"] for e in entries
                                                if not e["in_trash"]))
        self.assertEqual(data["trash"], sorted(e["service_name"] for e in entries
                                               if e["in_trash"]))
        self.assertEqual(data["passwords"], sorted(e["password"] for e in entries))


class TestStructureReference(unittest.TestCase):
    def test_new_v4_vault_matches_the_reference_exactly(self):
        conn = sqlite3.connect(":memory:")
        database.initialize_schema(conn)
        self.assertEqual(vault_upgrade.unexpected_structures(conn, 4), [])
        conn.close()

    def test_fixtures_have_no_unexpected_structure(self):
        for name in (V2, V3):
            with self.subTest(fixture=name):
                path = ROOT / "tests" / "fixtures" / name / "vault.db"
                conn = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
                try:
                    version = load_manifest(name)["schema_version"]
                    self.assertEqual(vault_upgrade.unexpected_structures(conn, version), [])
                finally:
                    conn.close()


# --- Interface ---------------------------------------------------------------------------


class UpgradeUiTestCase(UiTestCase):
    def install(self, name=V3):
        import shutil

        manifest = load_manifest(name)
        shutil.copyfile(ROOT / "tests" / "fixtures" / name / "vault.db",
                        vault_path(manifest["vault_id"]) / "vault.db")
        self.window._last_vault_id = manifest["vault_id"]
        self.window._show_locked_state()
        self.manifest = manifest
        self.path = vault_path(manifest["vault_id"]) / "vault.db"
        return manifest

    def unlock_with(self, password):
        screen = self.window._unlock_screen
        screen.password.setText(password)
        screen._submit()

    def later(self, fn, errors=None):
        """Interagit avec la prochaine fenêtre modale (exec). Toute erreur est notée et
        ferme les fenêtres ouvertes : un échec ne bloque jamais un exec()."""
        from PySide6.QtCore import QTimer

        errors = [] if errors is None else errors

        def run():
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 - remonté après exec()
                errors.append(exc)
                for dialog in self.open_dialogs():
                    dialog._busy = False
                    dialog.close_now()
        QTimer.singleShot(0, run)
        return errors

    @staticmethod
    def open_dialogs():
        from app.ui import dialogs

        return dialogs.open_dialogs()

    def migration_dialog(self):
        from app.ui.migration_dialog import MigrationDialog

        return next(d for d in self.open_dialogs() if isinstance(d, MigrationDialog))

    def backups(self):
        from app.services.settings import backup_directory

        directory = backup_directory(self.window._settings)
        self.assertTrue(str(directory).startswith(self._tmpdir.name))
        return sorted(directory.glob("*.mcfbak")) if directory.exists() else []


class TestUpgradeUi(UpgradeUiTestCase):
    def test_confirmed_upgrade_opens_the_v4_session(self):
        manifest = self.install()
        seen = {}

        def confirm():
            dialog = self.migration_dialog()
            seen["text"] = " ".join(w.text() for w in dialog.findChildren(
                __import__("PySide6.QtWidgets", fromlist=["QLabel"]).QLabel))
            dialog.start()

        errors = self.later(confirm)
        self.unlock_with(manifest["master_password"])
        self.assertEqual(errors, [])
        self.assertIn("1.6 ne pourra plus ouvrir", seen["text"])
        shell = self.window._shell
        self.assertIsNotNone(shell)
        self.assertEqual(schema_of(self.path), 4)
        active = [e for e in manifest["entries"] if not e["in_trash"]]
        self.assertEqual(sorted(s.service_name for s in shell.ctx.entries.list_entries()),
                         sorted(e["service_name"] for e in active))
        (path,) = self.backups()
        self.assertEqual(backup.read_backup_info(path).kind, backup.KIND_MIGRATION)

    def test_cancel_leaves_the_vault_unchanged(self):
        manifest = self.install()
        sha = file_sha(self.path)
        errors = self.later(lambda: self.migration_dialog().reject())
        self.unlock_with(manifest["master_password"])
        self.assertEqual(errors, [])
        self.assertIsNone(self.window._shell)
        self.assertEqual(file_sha(self.path), sha)
        self.assertEqual(self.backups(), [])
        self.assertIn("pas été modifié", self.window._unlock_screen.error.text())

    def test_wrong_password_shows_no_upgrade(self):
        manifest = self.install()
        with unittest.mock.patch.object(vault_upgrade, "upgrade") as upgrade, \
                unittest.mock.patch("app.ui.main_window.MigrationDialog") as dialog:
            self.unlock_with("mauvais-mot-de-passe-123")
        upgrade.assert_not_called()
        dialog.assert_not_called()
        self.assertEqual(schema_of(self.path), manifest["schema_version"])
        self.assertIn("incorrect", self.window._unlock_screen.error.text())

    def test_failure_is_shown_then_retry_succeeds(self):
        manifest = self.install()
        real = vault_upgrade.upgrade
        calls = []

        def flaky(*args, **kwargs):
            calls.append(1)
            if len(calls) == 1:
                def fault(step):
                    if step == "entry":
                        raise RuntimeError("panne simulée")
                return real(*args, _fault=fault, **kwargs)
            return real(*args, **kwargs)

        def interact():
            dialog = self.migration_dialog()
            dialog.start()  # échoue (retour arrière)
            self.assertTrue(dialog.isVisible())
            self.assertTrue(dialog.error.isVisibleTo(dialog))
            self.assertIn("pas été modifié", dialog.error.text())
            self.assertEqual(dialog.ok.text(), "Réessayer")
            self.assertEqual(schema_of(self.path), 3)
            dialog.start()  # nouvel essai

        with unittest.mock.patch.object(vault_upgrade, "upgrade", side_effect=flaky):
            errors = self.later(interact)
            self.unlock_with(manifest["master_password"])
        self.assertEqual(errors, [])
        self.assertEqual(len(calls), 2)
        self.assertIsNotNone(self.window._shell)
        self.assertEqual(schema_of(self.path), 4)

    def test_nothing_can_close_the_dialog_or_the_app_while_busy(self):
        manifest = self.install()

        def interact():
            dialog = self.migration_dialog()
            dialog._set_busy(True)  # état « mise à niveau en cours »
            dialog.reject()
            dialog.close_now()
            self.window.close()
            self.assertTrue(dialog.isVisible())
            self.assertTrue(self.window.isVisible())  # fermeture refusée
            self.window.lock()  # aucun effet : pas de session
            dialog._set_busy(False)
            dialog.reject()

        self.window.show()
        errors = self.later(interact)
        self.unlock_with(manifest["master_password"])
        self.assertEqual(errors, [])
        self.assertFalse(self.window.isHidden())
        self.assertEqual(schema_of(self.path), 3)

    def test_unexpected_structure_is_refused_without_dialog(self):
        manifest = load_manifest(V3)
        self.install()
        conn = sqlite3.connect(self.path)
        conn.execute("CREATE TABLE intrus (x)")
        conn.commit()
        conn.close()
        sha = file_sha(self.path)
        with unittest.mock.patch("app.ui.main_window.MigrationDialog") as dialog:
            self.unlock_with(manifest["master_password"])
        dialog.assert_not_called()
        self.assertIn("intrus", self.window._unlock_screen.error.text())
        self.assertEqual(file_sha(self.path), sha)

    def test_restored_old_backup_proposes_the_upgrade(self):
        manifest = self.install()
        vault = Vault.open_for_migration(manifest["vault_id"], manifest["master_password"])
        path = backup.create_backup(vault, directory=Path(self._tmpdir.name) / "anciennes")
        vault.close()
        info = backup.restore_backup(path, manifest["master_password"])
        self.window._last_vault_id = info.vault_id
        self.window._show_locked_state()
        proposed = []

        def confirm():
            dialog = self.migration_dialog()
            proposed.append(dialog)
            dialog.start()

        errors = self.later(confirm)
        self.unlock_with(manifest["master_password"])
        self.assertEqual(errors, [])
        self.assertEqual(len(proposed), 1)
        self.assertEqual(self.window._shell.ctx.vault.vault_id, info.vault_id)
        self.assertEqual(schema_of(self.path), 3)  # l'original n'a pas été touché


class TestRecoveryUpgradeUi(UpgradeUiTestCase):
    def fill_recovery(self, key, password):
        from app.ui.recovery_dialogs import RecoverVaultDialog

        dialog = next(d for d in self.open_dialogs() if isinstance(d, RecoverVaultDialog))
        dialog.key.setText(key)
        dialog.new.setText(password)
        dialog.confirm.setText(password)
        dialog._submit()

    def test_forgotten_password_on_v3(self):
        manifest = self.install()
        new_master = "Nouvelle-phrase-de-passe-E3-tres-solide"

        errors = []

        def confirm():
            self.migration_dialog().start()  # confirmation seule
            self.later(lambda: self.fill_recovery(manifest["recovery_key"], new_master),
                       errors)

        self.later(confirm, errors)
        self.window._unlock_screen.forgot.click()
        self.assertEqual(errors, [])
        shell = self.window._shell
        self.assertIsNotNone(shell)
        self.assertEqual(schema_of(self.path), 4)
        self.assertEqual(len(shell.ctx.entries.list_entries()),
                         len([e for e in manifest["entries"] if not e["in_trash"]]))
        from app.ui.recovery_dialogs import RecoveryKeyDialog

        renewed = next(d for d in self.open_dialogs() if isinstance(d, RecoveryKeyDialog))
        self.assertNotEqual(renewed._key, manifest["recovery_key"])
        renewed.close_now()

    def test_recovery_ok_but_upgrade_fails_then_retry(self):
        from PySide6.QtCore import QTimer

        from app.ui.recovery_dialogs import RecoveryKeyDialog

        manifest = self.install()
        new_master = "Nouvelle-phrase-de-passe-E3-tres-solide"
        shown = {}

        def acknowledge_key():
            dialog = next(d for d in self.open_dialogs() if isinstance(d, RecoveryKeyDialog))
            shown["key"] = dialog._key
            dialog.ack.setChecked(True)
            dialog.done_button.click()

        errors = []

        def confirm():
            self.migration_dialog().start()
            self.later(lambda: self.fill_recovery(manifest["recovery_key"], new_master),
                       errors)
            QTimer.singleShot(0, lambda: self.later(acknowledge_key, errors))

        with unittest.mock.patch.object(vault_upgrade, "migrate_to_v4",
                                        side_effect=MigrationError("panne simulée")), \
                unittest.mock.patch("app.ui.dialogs.alert") as alert:
            self.later(confirm, errors)
            self.window._unlock_screen.forgot.click()
            self._wait_until(lambda: alert.called)
        self.assertEqual(errors, [])
        self.assertIsNone(self.window._shell)
        self.assertTrue(shown.get("key"))
        self.assertNotEqual(shown["key"], manifest["recovery_key"])
        self.assertIn("nouveau mot de passe", alert.call_args.args[2].lower())
        self.assertIn("nouveau mot de passe", self.window._unlock_screen.error.text())
        self.assertEqual(schema_of(self.path), 3)
        # Nouvel essai : déverrouillage avec le nouveau mot de passe -> mise à niveau.
        errors = self.later(lambda: self.migration_dialog().start())
        self.unlock_with(new_master)
        self.assertEqual(errors, [])
        self.assertIsNotNone(self.window._shell)
        self.assertEqual(schema_of(self.path), 4)
        self.window.lock()
        Vault.recover(manifest["vault_id"], shown["key"], "encore-un-mot-de-passe-E3")[0].close()
