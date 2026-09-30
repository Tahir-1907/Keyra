import os
import tempfile
import unittest
import uuid

from app.core.categories import BUILTIN_CATEGORIES, CategoryService
from app.core.entries import (
    UNCATEGORIZED,
    Entry,
    EntryFilter,
    EntryService,
    normalize_for_search,
)
from app.core.exceptions import (
    CategoryError,
    EntryDecryptionError,
    EntryNotFoundError,
    EntryValidationError,
    VaultLockedError,
)
from app.core.vault import Vault, generate_vault_id, list_vaults

MASTER = "mot-de-passe-maitre-de-test"


class EntryTestCase(unittest.TestCase):
    """New vault in a temporary XDG directory, services ready to use."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._env_patch = {
            "XDG_DATA_HOME": os.path.join(self._tmpdir.name, "data"),
            "XDG_CONFIG_HOME": os.path.join(self._tmpdir.name, "config"),
            "XDG_CACHE_HOME": os.path.join(self._tmpdir.name, "cache"),
        }
        self._old_env = {k: os.environ.get(k) for k in self._env_patch}
        os.environ.update(self._env_patch)
        self.vault_id = f"test-vault-{uuid.uuid4().hex[:8]}"
        self.vault = Vault.create(self.vault_id, "Test", MASTER)
        self.entries = EntryService(self.vault)
        self.categories = CategoryService(self.vault)
        self.categories.ensure_builtin_categories()

    def tearDown(self):
        self.vault.close()
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._tmpdir.cleanup()

    def category_id(self, name):
        return next(c.id for c in self.categories.list_categories() if c.name == name)


class TestEntryCrud(EntryTestCase):
    def test_create_and_get_roundtrip(self):
        entry_id = self.entries.create_entry(
            Entry(
                service_name="  Banque  ",
                url="https://banque.example",
                username="alice",
                email="alice@example.org",
                password="S3cr3t!-éàü",
                notes="Code client dans le coffre",
                category_id=self.category_id("Finance"),
            )
        )
        got = self.entries.get_entry(entry_id)
        self.assertEqual(got.service_name, "Banque")
        self.assertEqual(got.password, "S3cr3t!-éàü")
        self.assertEqual(got.email, "alice@example.org")
        self.assertEqual(got.notes, "Code client dans le coffre")
        self.assertEqual(got.category_id, self.category_id("Finance"))
        self.assertTrue(got.created_at)

    def test_update_keeps_created_at_and_changes_fields(self):
        entry_id = self.entries.create_entry(Entry(service_name="Mail", password="a"))
        before = self.entries.get_entry(entry_id)
        before.password = "b"
        before.service_name = "Mail pro"
        self.entries.update_entry(before)
        after = self.entries.get_entry(entry_id)
        self.assertEqual(after.password, "b")
        self.assertEqual(after.service_name, "Mail pro")
        self.assertEqual(after.created_at, before.created_at)

    def test_type_specific_extra_fields(self):
        entry_id = self.entries.create_entry(
            Entry(
                service_name="Visa",
                entry_type="card",
                extra={"card_number": "4111111111111111", "cvv": "123"},
            )
        )
        got = self.entries.get_entry(entry_id)
        self.assertEqual(got.extra, {"card_number": "4111111111111111", "cvv": "123"})

    def test_unknown_extra_field_rejected(self):
        with self.assertRaises(EntryValidationError):
            self.entries.create_entry(
                Entry(service_name="x", entry_type="login", extra={"cvv": "1"})
            )

    def test_name_is_required(self):
        with self.assertRaises(EntryValidationError):
            self.entries.create_entry(Entry(service_name="   "))

    def test_unknown_type_rejected(self):
        with self.assertRaises(EntryValidationError):
            self.entries.create_entry(Entry(service_name="x", entry_type="nope"))

    def test_delete(self):
        entry_id = self.entries.create_entry(Entry(service_name="Temp"))
        self.entries.delete_entry(entry_id)
        with self.assertRaises(EntryNotFoundError):
            self.entries.get_entry(entry_id)
        self.assertEqual(self.entries.list_entries(), [])

    def test_repr_never_contains_secrets(self):
        e = Entry(service_name="x", password="ne-doit-pas-fuiter", notes="secret-note")
        self.assertNotIn("ne-doit-pas-fuiter", repr(e))
        self.assertNotIn("secret-note", repr(e))

    def test_locked_vault_refuses_access(self):
        entry_id = self.entries.create_entry(Entry(service_name="x", password="p"))
        self.vault.lock()
        with self.assertRaises(VaultLockedError):
            self.entries.get_entry(entry_id)
        with self.assertRaises(VaultLockedError):
            self.entries.list_entries()
        with self.assertRaises(VaultLockedError):
            self.entries.create_entry(Entry(service_name="y"))

    def test_entries_survive_close_and_reunlock(self):
        entry_id = self.entries.create_entry(Entry(service_name="Persist", password="pw-123"))
        self.vault.close()
        self.vault = Vault.unlock(self.vault_id, MASTER)
        got = EntryService(self.vault).get_entry(entry_id)
        self.assertEqual(got.password, "pw-123")


class TestEncryptionAtRest(EntryTestCase):
    def test_sensitive_values_not_in_database_file(self):
        secrets_ = ["MotDePasseUltraSecret42", "note-confidentielle-xyz", "moi@secret.example"]
        # v4: metadata encrypted too (v1.6: plaintext name, URL, username).
        metadata = ["NomDeServiceVisible", "https://url-privee.example", "identifiant-prive",
                    "TagPrive"]
        self.entries.create_entry(
            Entry(
                service_name=metadata[0],
                url=metadata[1],
                username=metadata[2],
                tags=(metadata[3],),
                password=secrets_[0],
                notes=secrets_[1],
                email=secrets_[2],
            )
        )
        self.vault.connection.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        raw = b""
        for suffix in ("", "-wal"):
            path = str(self.vault._db_path) + suffix
            if os.path.exists(path):
                with open(path, "rb") as f:
                    raw += f.read()
        for value in secrets_ + metadata:
            self.assertNotIn(value.encode("utf-8"), raw)

    def test_blob_moved_to_another_entry_is_detected(self):
        a = self.entries.create_entry(Entry(service_name="A", password="password-A"))
        b = self.entries.create_entry(Entry(service_name="B", password="password-B"))
        conn = self.vault.connection
        blob_a = conn.execute("SELECT password_enc FROM entries WHERE id = ?", (a,)).fetchone()[0]
        with conn:
            conn.execute("UPDATE entries SET password_enc = ? WHERE id = ?", (blob_a, b))
        with self.assertRaises(EntryDecryptionError):
            self.entries.get_entry(b)

    def test_blob_moved_to_another_field_is_detected(self):
        a = self.entries.create_entry(Entry(service_name="A", password="password-A"))
        conn = self.vault.connection
        blob = conn.execute("SELECT password_enc FROM entries WHERE id = ?", (a,)).fetchone()[0]
        with conn:
            conn.execute("UPDATE entries SET notes_enc = ? WHERE id = ?", (blob, a))
        with self.assertRaises(EntryDecryptionError):
            self.entries.get_entry(a)

    def test_tampered_blob_is_detected(self):
        a = self.entries.create_entry(Entry(service_name="A", password="password-A"))
        conn = self.vault.connection
        blob = bytearray(
            conn.execute("SELECT password_enc FROM entries WHERE id = ?", (a,)).fetchone()[0]
        )
        blob[-1] ^= 0x01
        with conn:
            conn.execute("UPDATE entries SET password_enc = ? WHERE id = ?", (bytes(blob), a))
        with self.assertRaises(EntryDecryptionError):
            self.entries.get_entry(a)


class TestSearchAndFilters(EntryTestCase):
    def setUp(self):
        super().setUp()
        self.gmail = self.entries.create_entry(
            Entry(service_name="Gmail", username="alice", url="https://mail.google.com",
                  category_id=self.category_id("Email"), is_favorite=True)
        )
        self.bank = self.entries.create_entry(
            Entry(service_name="Société Générale", username="a.dupont",
                  category_id=self.category_id("Finance"))
        )
        self.misc = self.entries.create_entry(Entry(service_name="éditeur", password="zzz"))

    def names(self, **kw):
        return [s.service_name for s in self.entries.list_entries(EntryFilter(**kw))]

    def test_sorted_case_and_accent_insensitive(self):
        self.assertEqual(self.names(), ["éditeur", "Gmail", "Société Générale"])

    def test_search_is_case_and_accent_insensitive(self):
        self.assertEqual(self.names(text="SOCIETE gen"), ["Société Générale"])
        self.assertEqual(self.names(text="editeur"), ["éditeur"])

    def test_search_matches_username_url_and_category(self):
        self.assertEqual(self.names(text="dupont"), ["Société Générale"])
        self.assertEqual(self.names(text="google"), ["Gmail"])
        self.assertEqual(self.names(text="finance"), ["Société Générale"])

    def test_search_never_matches_secret_fields(self):
        self.assertEqual(self.names(text="zzz"), [])

    def test_favorites_filter_and_toggle(self):
        self.assertEqual(self.names(favorites_only=True), ["Gmail"])
        self.entries.set_favorite(self.bank, True)
        self.assertEqual(self.names(favorites_only=True), ["Gmail", "Société Générale"])

    def test_category_filters(self):
        self.assertEqual(self.names(category_id=self.category_id("Finance")),
                         ["Société Générale"])
        self.assertEqual(self.names(category_id=UNCATEGORIZED), ["éditeur"])

    def test_normalize(self):
        self.assertEqual(normalize_for_search("ÉLÉPHANT Œuvre"), "elephant œuvre")


class TestCategories(EntryTestCase):
    def test_builtins_created_once(self):
        self.categories.ensure_builtin_categories()
        names = [c.name for c in self.categories.list_categories()]
        self.assertEqual(names, list(BUILTIN_CATEGORIES))

    def test_create_rename_delete_custom(self):
        cid = self.categories.create_category("  Jeux   vidéo ")
        entry_id = self.entries.create_entry(Entry(service_name="Steam", category_id=cid))
        self.categories.rename_category(cid, "Jeux")
        self.assertIn("Jeux", [c.name for c in self.categories.list_categories()])
        self.categories.delete_category(cid)
        # The entry survives, uncategorized.
        self.assertIsNone(self.entries.get_entry(entry_id).category_id)

    def test_duplicate_names_rejected_case_and_accent_insensitive(self):
        with self.assertRaises(CategoryError):
            self.categories.create_category("sOcIaL")  # built-in category
        self.categories.create_category("Jeux vidéo")
        with self.assertRaises(CategoryError):
            self.categories.create_category("JEUX VIDEO")

    def test_rename_own_case_allowed(self):
        cid = self.categories.create_category("jeux")
        self.categories.rename_category(cid, "Jeux")

    def test_builtin_cannot_be_modified(self):
        with self.assertRaises(CategoryError):
            self.categories.delete_category(self.category_id("Work"))
        with self.assertRaises(CategoryError):
            self.categories.rename_category(self.category_id("Work"), "Boulot")

    def test_overview_counts(self):
        cid = self.category_id("Work")
        self.entries.create_entry(Entry(service_name="a", category_id=cid, is_favorite=True))
        self.entries.create_entry(Entry(service_name="b"))
        ov = self.categories.overview()
        self.assertEqual((ov.total, ov.favorites, ov.uncategorized), (2, 1, 1))
        self.assertEqual(next(c for c in ov.categories if c.id == cid).entry_count, 1)


class TestVaultDiscovery(EntryTestCase):
    def test_list_vaults_returns_created_vault(self):
        infos = list_vaults()
        self.assertEqual([(i.vault_id, i.vault_name) for i in infos], [(self.vault_id, "Test")])

    def test_generate_vault_id_is_filesystem_safe(self):
        vid = generate_vault_id("Coffre Perso / Été ../..")
        self.assertRegex(vid, r"^[a-z0-9-]+$")
        self.assertTrue(vid.startswith("coffre-perso-ete-"))
        self.assertNotEqual(vid, generate_vault_id("Coffre Perso / Été ../.."))


if __name__ == "__main__":
    unittest.main()
