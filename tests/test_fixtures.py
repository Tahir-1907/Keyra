"""Vaults produced by earlier versions (tests/fixtures/): faithful reading.

Each test vault is COPIED to a temporary folder before being opened: the files
in tests/fixtures/ are never modified. The manifest contains the expected data
and the search results computed by the version that produced the vault.

The manifests name the built-in categories with the French names that versions
1.x stored (e.g. "Travail"). The application now displays English labels
("Work"), so `as_displayed()` maps those historical names to their current
labels before comparing; the fixtures themselves stay untouched.
"""

import copy
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"
FIXTURE_NAMES = ("v2-app-1.0.0", "v3-app-1.6.0")


def logical_dump(db_path: Path) -> dict:
    """Complete logical fingerprint of a database: schema and every row, table by table.

    Used to prove that a vault stayed STRICTLY identical (independently of the file
    bytes, which SQLite may reorganize without changing any content).
    """
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        dump = {"__schema__": sorted(conn.execute(
            "SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL").fetchall())}
        for (table,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' "
                                     "ORDER BY name").fetchall():
            sql = f'SELECT * FROM "{table}" ORDER BY rowid'  # noqa: S608 - name read from the schema
            dump[table] = conn.execute(sql).fetchall()
        return dump
    finally:
        conn.close()


def load_manifest(name: str) -> dict:
    return json.loads((FIXTURES / name / "manifest.json").read_text(encoding="utf-8"))


def as_displayed(manifest: dict) -> dict:
    """Copy of `manifest` with built-in categories under their current display label.

    Historical (v1.x) names map to a stable key, then to the label shown today:
    category names, the "category" field of the entries, and search texts that are
    exactly a historical built-in name (a search matches the displayed label).
    """
    from app.core.builtin_categories import builtin_key_for_v3_row, builtin_name
    from app.core.entries import normalize_for_search

    result = copy.deepcopy(manifest)
    renamed = {}
    for category in result["categories"]:
        if category["is_builtin"]:
            label = builtin_name(builtin_key_for_v3_row(category["name"], True))
            renamed[category["name"]] = label
            category["name"] = label
    for entry in result["entries"]:
        entry["category"] = renamed.get(entry["category"], entry["category"])
    by_search = {normalize_for_search(old): new for old, new in renamed.items()}
    for search in result["searches"]:
        text = search["filter"].get("text")
        if text is not None and normalize_for_search(text) in by_search:
            search["filter"]["text"] = by_search[normalize_for_search(text)]
    return result


class FixtureVaultTestCase(unittest.TestCase):
    """Isolated XDG data; `install(name)` copies a test vault and returns its manifest."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old_env = {k: os.environ.get(k) for k in ("XDG_DATA_HOME", "XDG_CONFIG_HOME")}
        os.environ["XDG_DATA_HOME"] = os.path.join(self._tmp.name, "data")
        os.environ["XDG_CONFIG_HOME"] = os.path.join(self._tmp.name, "config")
        self.vault = None

    def tearDown(self):
        if self.vault is not None:
            self.vault.close()
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._tmp.cleanup()

    def install(self, name: str) -> dict:
        from app.utils.paths import vault_path

        manifest = load_manifest(name)
        shutil.copyfile(FIXTURES / name / "vault.db",
                        vault_path(manifest["vault_id"]) / "vault.db")
        return manifest

    def assert_matches_manifest(self, manifest: dict) -> None:
        """The open vault (self.vault) returns exactly the manifest: categories,
        decrypted entries, dates, history and search results."""
        from app.core.categories import CategoryService
        from app.core.entries import EntryFilter, EntryService

        manifest = as_displayed(manifest)
        entries, categories = EntryService(self.vault), CategoryService(self.vault)
        names = {c.id: c.name for c in categories.list_categories()}
        self.assertEqual(
            sorted((c["id"], c["name"], c["is_builtin"]) for c in manifest["categories"]),
            sorted((c.id, c.name, c.is_builtin) for c in categories.list_categories()))
        for expected in manifest["entries"]:
            e = entries.get_entry(expected["id"], include_deleted=True)
            actual = {
                "id": e.id, "entry_type": e.entry_type, "service_name": e.service_name,
                "url": e.url, "username": e.username, "email": e.email,
                "password": e.password, "notes": e.notes, "extra": e.extra,
                "category_id": e.category_id,
                "category": names.get(e.category_id) if e.category_id else None,
                "is_favorite": e.is_favorite, "in_trash": bool(e.deleted_at),
                "created_at": e.created_at, "updated_at": e.updated_at,
                "password_changed_at": e.password_changed_at, "deleted_at": e.deleted_at,
                "history": [
                    {"service_name": v.entry.service_name, "url": v.entry.url,
                     "username": v.entry.username, "password": v.entry.password,
                     "category_id": v.entry.category_id}
                    for v in entries.list_history(e.id)
                ],
            }
            self.assertEqual(actual, expected, f"entry {expected['id']}")
        for search in manifest["searches"]:
            result = [s.id for s in entries.list_entries(EntryFilter(**search["filter"]))]
            self.assertEqual(result, search["result"], f"search {search['filter']}")


class TestFixturesAreFaithfullyRead(FixtureVaultTestCase):
    """Real v1.7 path: v4 migration, then reading through the REAL v4 services."""

    def open_migrated(self, name: str) -> dict:
        from app.core.vault import Vault
        from app.services.migration_v4 import migrate_to_v4

        manifest = self.install(name)
        self.vault = Vault.open_for_migration(manifest["vault_id"], manifest["master_password"])
        migrate_to_v4(self.vault, Path(self._tmp.name) / "backups")
        return manifest

    def _check(self, name: str) -> None:
        manifest = self.open_migrated(name)
        self.assert_matches_manifest(manifest)
        # And after closing, through the application's normal opening.
        from app.core.vault import Vault

        self.vault.close()
        self.vault = Vault.unlock(manifest["vault_id"], manifest["master_password"])
        self.assert_matches_manifest(manifest)

    def test_v2_vault_made_by_app_1_0_0(self):
        self._check("v2-app-1.0.0")

    def test_v3_vault_made_by_app_1_6_0(self):
        self._check("v3-app-1.6.0")

    def test_v3_recovery_key_still_works(self):
        from app.core.vault import Vault

        manifest = self.open_migrated("v3-app-1.6.0")
        self.vault.close()
        self.vault, _new_key = Vault.recover(manifest["vault_id"], manifest["recovery_key"],
                                             "nouveau-mot-de-passe-de-test")
        self.assert_matches_manifest(manifest)

    def test_fixture_files_are_never_modified(self):
        # The tests work on copies: the versioned files stay intact.
        for name in FIXTURE_NAMES:
            self.assertFalse((FIXTURES / name / "vault.db-wal").exists())
            self.assertFalse(any((FIXTURES / name).glob("*.bak")))
