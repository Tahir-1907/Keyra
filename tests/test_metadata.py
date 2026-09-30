"""Chiffrement des métadonnées d'entrée et des noms de catégories (app.core.metadata)."""

import json
import unittest

from app.core import crypto, metadata
from app.core.exceptions import (
    CategoryDecryptionError,
    CategoryError,
    EntryDecryptionError,
    EntryValidationError,
    VaultError,
)
from app.core.metadata import (
    CategoryMetadata,
    EntryMetadata,
    MetadataCipher,
    normalize_tags,
    tag_key,
)

NOW = "2026-09-27T10:00:00+00:00"
UUID_A = bytes(range(16))
UUID_B = bytes(range(1, 17))


def sample(**changes) -> EntryMetadata:
    values = dict(name="Banque Exemple", url="https://banque.example",
                  username="client@example.test", entry_type="login", category_id=3,
                  is_favorite=True, tags=("Finances", "Important"), created_at=NOW,
                  updated_at=NOW, password_changed_at=NOW, deleted_at=None)
    values.update(changes)
    return EntryMetadata(**values)


def valid_payload(**changes) -> dict:
    payload = {"v": 1, "name": "Banque", "url": "", "username": "", "entry_type": "login",
               "category_id": None, "is_favorite": False, "tags": [], "created_at": NOW,
               "updated_at": NOW, "password_changed_at": NOW, "deleted_at": None, "pad": ""}
    payload.update(changes)
    return payload


class CipherTestCase(unittest.TestCase):
    def setUp(self):
        self.dek = crypto.generate_key()
        self.cipher = MetadataCipher(self.dek, UUID_A)

    def forge_entry(self, text: str, entry_id: int = 1, pad: bool = True) -> bytes:
        """Chiffre un texte ARBITRAIRE avec la vraie sous-clé et la vraie AAD."""
        if pad:
            text += " " * (-len(text.encode("utf-8")) % metadata.PAD_BLOCK)
        key = crypto.derive_subkey(self.dek, metadata.ENTRY_METADATA_INFO)
        return crypto.encrypt_field(key, text, self.cipher.entry_aad(entry_id))

    def forge_payload(self, payload: dict, entry_id: int = 1) -> bytes:
        return self.forge_entry(json.dumps(payload, ensure_ascii=False), entry_id)

    def assert_corrupted(self, blob: bytes, entry_id: int = 1) -> None:
        with self.assertRaises(EntryDecryptionError):
            self.cipher.decrypt_entry(entry_id, blob)


class TestEntryRoundTrip(CipherTestCase):
    def test_round_trip(self):
        meta = sample()
        self.assertEqual(self.cipher.decrypt_entry(7, self.cipher.encrypt_entry(7, meta)), meta)

    def test_round_trip_minimal_and_trash(self):
        meta = sample(url="", username="", category_id=None, is_favorite=False, tags=(),
                      entry_type="secure_note", deleted_at="2001-01-01T00:00:00+00:00")
        self.assertEqual(self.cipher.decrypt_entry(1, self.cipher.encrypt_entry(1, meta)), meta)

    def test_unicode_is_preserved(self):
        meta = sample(name="Éléphant Café ☕", tags=("École", "Réseau"))
        self.assertEqual(self.cipher.decrypt_entry(2, self.cipher.encrypt_entry(2, meta)), meta)

    def test_fresh_nonce_every_time(self):
        meta = sample()
        self.assertNotEqual(self.cipher.encrypt_entry(1, meta), self.cipher.encrypt_entry(1, meta))

    def test_nothing_readable_in_the_blob(self):
        blob = self.cipher.encrypt_entry(1, sample())
        for plain in (b"Banque", b"banque.example", b"client@", b"Finances", b"login"):
            self.assertNotIn(plain, blob)


class TestPadding(CipherTestCase):
    def _plaintext(self, blob: bytes, entry_id: int = 1) -> str:
        key = crypto.derive_subkey(self.dek, metadata.ENTRY_METADATA_INFO)
        return crypto.decrypt_field(key, blob, self.cipher.entry_aad(entry_id))

    def test_plaintext_is_a_multiple_of_64_bytes(self):
        for name in ("A", "Nom moyen", "é" * 50, "x" * 300):
            text = self._plaintext(self.cipher.encrypt_entry(1, sample(name=name)))
            self.assertEqual(len(text.encode("utf-8")) % 64, 0, name)

    def test_short_and_medium_names_have_the_same_size(self):
        short = self.cipher.encrypt_entry(1, sample(name="A"))
        medium = self.cipher.encrypt_entry(1, sample(name="Banque Exemple 2"))
        self.assertEqual(len(short), len(medium))

    def test_padding_only_reduces_the_length_leak(self):
        # Documenté : un contenu nettement plus long reste plus gros.
        short = self.cipher.encrypt_entry(1, sample(name="A"))
        long = self.cipher.encrypt_entry(1, sample(name="x" * 500))
        self.assertGreater(len(long), len(short))

    def test_wrong_total_length_is_rejected(self):
        text = json.dumps(valid_payload())
        text += " " * ((1 - len(text.encode("utf-8"))) % 64)  # multiple de 64, plus 1
        self.assertEqual(len(text.encode("utf-8")) % 64, 1)
        self.assert_corrupted(self.forge_entry(text, pad=False))

    def test_non_space_padding_is_rejected(self):
        self.assert_corrupted(self.forge_payload(valid_payload(pad="xx")))


class TestTampering(CipherTestCase):
    def setUp(self):
        super().setUp()
        self.blob = self.cipher.encrypt_entry(5, sample())

    def _flip(self, index: int) -> bytes:
        data = bytearray(self.blob)
        data[index] ^= 0x01
        return bytes(data)

    def test_modified_nonce(self):
        self.assert_corrupted(self._flip(1), 5)

    def test_modified_ciphertext(self):
        self.assert_corrupted(self._flip(1 + crypto.NONCE_SIZE), 5)

    def test_modified_tag(self):
        self.assert_corrupted(self._flip(-1), 5)

    def test_modified_version_byte(self):
        data = bytearray(self.blob)
        data[0] = 2
        self.assert_corrupted(bytes(data), 5)

    def test_truncated_empty_or_missing(self):
        for blob in (self.blob[:20], b"", None, "texte"):
            with self.assertRaises(EntryDecryptionError):
                self.cipher.decrypt_entry(5, blob)


class TestSubstitution(CipherTestCase):
    def test_blob_moved_to_another_entry(self):
        blob = self.cipher.encrypt_entry(1, sample(name="MaBanque"))
        self.assert_corrupted(blob, entry_id=2)

    def test_blobs_swapped_between_two_entries(self):
        bank = self.cipher.encrypt_entry(1, sample(name="MaBanque"))
        forum = self.cipher.encrypt_entry(2, sample(name="Forum"))
        self.assert_corrupted(forum, entry_id=1)
        self.assert_corrupted(bank, entry_id=2)

    def test_other_vault_uuid(self):
        blob = self.cipher.encrypt_entry(1, sample())
        with self.assertRaises(EntryDecryptionError):
            MetadataCipher(self.dek, UUID_B).decrypt_entry(1, blob)

    def test_other_vault_key(self):
        blob = self.cipher.encrypt_entry(1, sample())
        with self.assertRaises(EntryDecryptionError):
            MetadataCipher(crypto.generate_key(), UUID_A).decrypt_entry(1, blob)

    def test_entry_blob_is_not_a_category_and_vice_versa(self):
        entry_blob = self.cipher.encrypt_entry(3, sample())
        category_blob = self.cipher.encrypt_category(3, CategoryMetadata("Perso", NOW))
        with self.assertRaises(CategoryDecryptionError):
            self.cipher.decrypt_category(3, entry_blob)
        self.assert_corrupted(category_blob, entry_id=3)

    def test_secret_field_blob_is_not_metadata(self):
        # Un champ secret (DEK, AAD entry:<id>:password) ne passe pas pour des métadonnées.
        secret = crypto.encrypt_field(self.dek, json.dumps(valid_payload()),
                                      b"mon-coffre-fort:entry:1:password")
        self.assert_corrupted(secret, entry_id=1)

    def test_error_message_reveals_no_content(self):
        blob = self.cipher.encrypt_entry(1, sample(name="MaBanque", url="https://secret.example"))
        with self.assertRaises(EntryDecryptionError) as ctx:
            self.cipher.decrypt_entry(2, blob)
        for secret in ("MaBanque", "secret.example"):
            self.assertNotIn(secret, str(ctx.exception))


class TestStrictParsing(CipherTestCase):
    def test_invalid_json(self):
        self.assert_corrupted(self.forge_entry("{pas du json"))

    def test_not_an_object(self):
        self.assert_corrupted(self.forge_entry(json.dumps([1, 2, 3])))

    def test_missing_field(self):
        payload = valid_payload()
        del payload["url"]
        self.assert_corrupted(self.forge_payload(payload))

    def test_unexpected_field(self):
        self.assert_corrupted(self.forge_payload(valid_payload(secret_supplementaire="x")))

    def test_duplicate_key(self):
        text = json.dumps(valid_payload())[:-1] + ',"name":"Autre"}'
        self.assert_corrupted(self.forge_entry(text))

    def test_unknown_or_invalid_version(self):
        for version in (2, 0, "1", True, None, 1.0):
            self.assert_corrupted(self.forge_payload(valid_payload(v=version)))

    def test_wrong_types(self):
        for changes in (
            {"name": 42}, {"name": ""}, {"name": "   "}, {"url": None}, {"username": 3},
            {"is_favorite": 1}, {"is_favorite": "true"}, {"category_id": "3"},
            {"category_id": True}, {"category_id": 0}, {"category_id": -1},
            {"category_id": 3.0}, {"tags": "Linux"}, {"tags": [1]}, {"tags": None},
        ):
            with self.subTest(changes=changes):
                self.assert_corrupted(self.forge_payload(valid_payload(**changes)))

    def test_unknown_entry_type(self):
        for entry_type in ("admin", "", None, "LOGIN"):
            self.assert_corrupted(self.forge_payload(valid_payload(entry_type=entry_type)))

    def test_invalid_dates(self):
        for field in ("created_at", "updated_at", "password_changed_at"):
            for value in ("hier", "", None, "2024-01-01T00:00:00", 1700000000):
                with self.subTest(field=field, value=value):
                    self.assert_corrupted(self.forge_payload(valid_payload(**{field: value})))
        for value in ("", "2024-13-01T00:00:00+00:00", "2024-01-01", False):
            self.assert_corrupted(self.forge_payload(valid_payload(deleted_at=value)))

    def test_non_canonical_or_invalid_stored_tags(self):
        for tags in (["Linux", "linux"], ["  Linux"], ["#Linux"], [""], ["a" * 33],
                     [f"t{i}" for i in range(21)], ["a,b"]):
            with self.subTest(tags=tags):
                self.assert_corrupted(self.forge_payload(valid_payload(tags=tags)))

    def test_forged_valid_payload_is_accepted(self):
        # Témoin : le même mécanisme accepte un contenu valide (les refus ci-dessus
        # viennent donc bien de la validation, pas du chiffrement).
        meta = self.cipher.decrypt_entry(1, self.forge_payload(valid_payload(tags=["Linux"])))
        self.assertEqual(meta.tags, ("Linux",))


class TestWriteValidation(CipherTestCase):
    """On n'écrit jamais ce qu'on ne saurait pas relire."""

    def test_invalid_metadata_is_refused_before_encryption(self):
        for changes in ({"name": ""}, {"entry_type": "admin"}, {"created_at": "hier"},
                        {"updated_at": "2024-01-01T00:00:00"}, {"tags": ("a", "A")},
                        {"tags": ["liste"]}, {"category_id": 0}, {"is_favorite": None}):
            with self.subTest(changes=changes), self.assertRaises(EntryValidationError):
                self.cipher.encrypt_entry(1, sample(**changes))

    def test_invalid_ids_and_uuid(self):
        for entry_id in (0, -1, True, "1", None):
            with self.subTest(entry_id=entry_id), self.assertRaises(ValueError):
                self.cipher.encrypt_entry(entry_id, sample())
        for uuid in (b"", b"x" * 15, b"x" * 17, "0" * 16, None):
            with self.subTest(uuid=uuid), self.assertRaises(ValueError):
                MetadataCipher(self.dek, uuid)


class TestTags(unittest.TestCase):
    def test_case_and_accents_are_the_same_tag(self):
        self.assertEqual(tag_key("Linux"), tag_key("LINUX"))
        self.assertEqual(tag_key("École"), tag_key("ecole"))
        for tags in (["Linux", "linux"], ["École", "ECOLE"], ["Réseau", "reseau"]):
            with self.subTest(tags=tags), self.assertRaises(EntryValidationError):
                normalize_tags(tags)

    def test_display_form_is_kept(self):
        self.assertEqual(normalize_tags(["Linux", "BTS SIO", "école"]),
                         ("Linux", "BTS SIO", "école"))

    def test_canonical_form(self):
        self.assertEqual(normalize_tags(["  #Travail ", "Serveurs   maison"]),
                         ("Travail", "Serveurs maison"))
        decomposed = "École"  # É en deux points de code
        self.assertEqual(normalize_tags([decomposed]), ("École",))
        with self.assertRaises(EntryValidationError):
            normalize_tags(["École", decomposed])

    def test_limits(self):
        self.assertEqual(len(normalize_tags([f"t{i}" for i in range(20)])), 20)
        self.assertEqual(normalize_tags(["a" * 32]), ("a" * 32,))
        for tags in ([f"t{i}" for i in range(21)], ["a" * 33]):
            with self.subTest(n=len(tags)), self.assertRaises(EntryValidationError):
                normalize_tags(tags)

    def test_invalid_tags(self):
        for tags in ([""], ["   "], ["#"], ["a,b"], ["\u200bzero"], ["bi\u202edi"],
                     ["nul\x00"], [3], [None]):
            with self.subTest(tags=tags), self.assertRaises(EntryValidationError):
                normalize_tags(tags)

    def test_whitespace_is_normalized(self):
        # Tabulation ou retour à la ligne (tag collé) : ramenés à une espace.
        self.assertEqual(normalize_tags(["tab\tulation", "ligne\nnouvelle"]),
                         ("tab ulation", "ligne nouvelle"))


class TestCategories(CipherTestCase):
    def test_round_trip(self):
        meta = CategoryMetadata("Santé & Mutuelle", NOW)
        self.assertEqual(self.cipher.decrypt_category(4, self.cipher.encrypt_category(4, meta)),
                         meta)

    def test_tampered_category_is_detected(self):
        blob = bytearray(self.cipher.encrypt_category(4, CategoryMetadata("Perso", NOW)))
        blob[-1] ^= 0x01
        for value in (bytes(blob), None, b"", bytes(blob[:20])):
            with self.assertRaises(CategoryDecryptionError):
                self.cipher.decrypt_category(4, value)

    def test_categories_swapped(self):
        a = self.cipher.encrypt_category(4, CategoryMetadata("Banque", NOW))
        b = self.cipher.encrypt_category(5, CategoryMetadata("Loisirs", NOW))
        for category_id, blob in ((4, b), (5, a)):
            with self.assertRaises(CategoryDecryptionError):
                self.cipher.decrypt_category(category_id, blob)

    def test_other_vault(self):
        blob = self.cipher.encrypt_category(4, CategoryMetadata("Perso", NOW))
        with self.assertRaises(CategoryDecryptionError):
            MetadataCipher(self.dek, UUID_B).decrypt_category(4, blob)

    def test_invalid_category_metadata(self):
        key = crypto.derive_subkey(self.dek, metadata.CATEGORY_INFO)
        for payload in ({"v": 1, "name": "", "created_at": NOW, "pad": ""},
                        {"v": 1, "name": "X", "created_at": "hier", "pad": ""},
                        {"v": 1, "name": "X", "pad": ""},
                        {"v": 2, "name": "X", "created_at": NOW, "pad": ""}):
            text = json.dumps(payload)
            text += " " * (-len(text.encode()) % 64)
            blob = crypto.encrypt_field(key, text, self.cipher.category_aad(4))
            with self.subTest(payload=payload), self.assertRaises(CategoryDecryptionError):
                self.cipher.decrypt_category(4, blob)
        with self.assertRaises(CategoryError):
            self.cipher.encrypt_category(4, CategoryMetadata("  ", NOW))


class TestConsistency(unittest.TestCase):
    def test_entry_types_match_the_entry_service(self):
        from app.core.entries import ENTRY_TYPES

        self.assertEqual(metadata.ENTRY_TYPE_KEYS, frozenset(ENTRY_TYPES))

    def test_repr_never_contains_content(self):
        cipher = MetadataCipher(crypto.generate_key(), UUID_A)
        for obj in (sample(name="MaBanque", url="https://x.example"),
                    CategoryMetadata("Santé", NOW), cipher):
            self.assertNotIn("MaBanque", repr(obj))
            self.assertNotIn("x.example", repr(obj))
            self.assertNotIn("Santé", repr(obj))

    def test_errors_are_business_errors(self):
        self.assertTrue(issubclass(EntryDecryptionError, VaultError))
        self.assertTrue(issubclass(CategoryDecryptionError, VaultError))

    def test_vault_uuid_is_random_and_16_bytes(self):
        a, b = metadata.new_vault_uuid(), metadata.new_vault_uuid()
        self.assertEqual(len(a), 16)
        self.assertNotEqual(a, b)

    def test_distinct_subkeys(self):
        self.assertNotEqual(metadata.ENTRY_METADATA_INFO, metadata.CATEGORY_INFO)
        self.assertNotIn(b"backup", metadata.ENTRY_METADATA_INFO + metadata.CATEGORY_INFO)
