"""Security tests: tampering, substitutions and error messages.

Complement test_crypto (primitives), test_entries (moving a BLOB) and
test_phase4 (crafted files) with targeted scenarios: every part of an encrypted
value (nonce, ciphertext, tag), substitution between contexts, truncated or
spliced backup files, and no secret in errors.

BLOB format: version (1 B) | nonce (12 B) | ciphertext | GCM tag (16 B).
"""

import logging
import tempfile
import traceback
import uuid
from pathlib import Path

from app.core import crypto
from app.core.entries import Entry
from app.core.exceptions import (
    EntryDecryptionError,
    VaultCorruptedError,
    VaultError,
    WrongMasterPasswordError,
)
from app.core.vault import Vault, list_vaults
from app.services import backup, import_export
from tests.test_entries import MASTER, EntryTestCase

SECRET = "S3cret-Tres-Reconnaissable-42!"
NONCE_START = 1
CIPHERTEXT_START = 1 + crypto.NONCE_SIZE
TAG_LENGTH = 16


class TestFieldTampering(EntryTestCase):
    """Any change to an encrypted field is detected, never "decrypted"."""

    def setUp(self):
        super().setUp()
        self.entry_id = self.entries.create_entry(Entry(service_name="Banque", password=SECRET))

    def _blob(self, column: str = "password_enc", entry_id: int | None = None) -> bytes:
        row = self.vault.connection.execute(
            f"SELECT {column} FROM entries WHERE id = ?",  # noqa: S608 - colonne constante
            (entry_id or self.entry_id,),
        ).fetchone()
        return bytes(row[0])

    def _store(self, blob: bytes, column: str = "password_enc") -> None:
        with self.vault.connection as conn:
            conn.execute(
                f"UPDATE entries SET {column} = ? WHERE id = ?",  # noqa: S608 - colonne constante
                (blob, self.entry_id),
            )

    def _assert_flip_detected(self, index: int) -> None:
        blob = bytearray(self._blob())
        blob[index] ^= 0x01
        self._store(bytes(blob))
        with self.assertRaises(EntryDecryptionError):
            self.entries.get_entry(self.entry_id)

    def test_modified_nonce_is_detected(self):
        self._assert_flip_detected(NONCE_START)

    def test_modified_last_nonce_byte_is_detected(self):
        self._assert_flip_detected(CIPHERTEXT_START - 1)

    def test_modified_ciphertext_is_detected(self):
        self._assert_flip_detected(CIPHERTEXT_START)

    def test_modified_tag_is_detected(self):
        self._assert_flip_detected(-TAG_LENGTH)

    def test_truncated_blob_is_detected(self):
        self._store(self._blob()[:CIPHERTEXT_START - 2])
        with self.assertRaises(EntryDecryptionError):
            self.entries.get_entry(self.entry_id)

    def test_tag_removed_is_detected(self):
        self._store(self._blob()[:-TAG_LENGTH])
        with self.assertRaises(EntryDecryptionError):
            self.entries.get_entry(self.entry_id)

    def test_history_snapshot_cannot_replace_a_field(self):
        entry = self.entries.get_entry(self.entry_id)
        entry.password = "nouveau-mot-de-passe"
        self.entries.update_entry(entry)
        snapshot = self.vault.connection.execute(
            "SELECT snapshot_enc FROM entry_history WHERE entry_id = ?", (self.entry_id,)
        ).fetchone()[0]
        self._store(bytes(snapshot))
        with self.assertRaises(EntryDecryptionError):
            self.entries.get_entry(self.entry_id)

    def test_value_from_another_vault_is_rejected(self):
        # Same entry identifier, same field, but another vault (another DEK).
        other = Vault.create(f"autre-{uuid.uuid4().hex[:8]}", "Autre", MASTER)
        try:
            from app.core.entries import EntryService

            other_entries = EntryService(other)
            other_id = other_entries.create_entry(Entry(service_name="Banque", password="autre"))
            self.assertEqual(other_id, self.entry_id)
            foreign = other.connection.execute(
                "SELECT password_enc FROM entries WHERE id = ?", (other_id,)
            ).fetchone()[0]
        finally:
            other.close()
        self._store(bytes(foreign))
        with self.assertRaises(EntryDecryptionError):
            self.entries.get_entry(self.entry_id)


class TestCorruptedVaultMetadata(EntryTestCase):
    """A vault whose metadata has been tampered with never opens silently."""

    def _tamper_meta(self, column: str, value: bytes) -> None:
        with self.vault.connection as conn:
            conn.execute(
                f"UPDATE vault_meta SET {column} = ?",  # noqa: S608 - colonne constante
                (value,),
            )
        self.vault.close()

    def _reopen(self):
        self.vault = Vault.unlock(self.vault_id, MASTER)
        return self.vault

    def test_modified_verifier_is_detected(self):
        blob = bytearray(self.vault.connection.execute(
            "SELECT verifier_blob FROM vault_meta").fetchone()[0])
        blob[-1] ^= 0x01
        self._tamper_meta("verifier_blob", bytes(blob))
        with self.assertRaises(VaultCorruptedError):
            self._reopen()

    def test_swapped_salt_is_not_accepted(self):
        self._tamper_meta("kdf_salt", crypto.generate_salt())
        with self.assertRaises(WrongMasterPasswordError):
            self._reopen()


class TestCorruptedBackups(EntryTestCase):
    """A tampered backup is never restored, and leaves no partial vault behind."""

    def setUp(self):
        super().setUp()
        self.entries.create_entry(Entry(service_name="Banque", password=SECRET))
        self.backup_dir = Path(tempfile.mkdtemp(dir=self._tmpdir.name))
        self.path = backup.create_backup(self.vault, self.backup_dir)
        self.raw = self.path.read_bytes()
        self.vaults_before = len(list_vaults())

    def _assert_refused(self, data: bytes) -> None:
        self.path.write_bytes(data)
        with self.assertRaises(VaultError):
            backup.restore_backup(self.path, MASTER)
        self.assertEqual(len(list_vaults()), self.vaults_before)

    def _body_offset(self) -> int:
        header_length = int.from_bytes(self.raw[len(backup.MAGIC):len(backup.MAGIC) + 4], "big")
        return len(backup.MAGIC) + 4 + header_length

    def test_empty_file(self):
        self._assert_refused(b"")

    def test_truncated_inside_header(self):
        self._assert_refused(self.raw[:len(backup.MAGIC) + 10])

    def test_truncated_right_after_header(self):
        self._assert_refused(self.raw[:self._body_offset()])

    def test_truncated_body(self):
        self._assert_refused(self.raw[:len(self.raw) - 40])

    def test_modified_body_nonce(self):
        data = bytearray(self.raw)
        data[self._body_offset()] ^= 0x01
        self._assert_refused(bytes(data))

    def test_modified_body_tag(self):
        data = bytearray(self.raw)
        data[-1] ^= 0x01
        self._assert_refused(bytes(data))

    def test_header_of_another_vault_is_rejected(self):
        # (Valid) header of another vault with the same password, spliced onto this body.
        other = Vault.create(f"autre-{uuid.uuid4().hex[:8]}", "Autre", MASTER)
        try:
            other_raw = backup.create_backup(other, self.backup_dir).read_bytes()
        finally:
            other.close()
        self.vaults_before = len(list_vaults())
        other_length = int.from_bytes(other_raw[len(backup.MAGIC):len(backup.MAGIC) + 4], "big")
        other_header = other_raw[:len(backup.MAGIC) + 4 + other_length]
        self._assert_refused(other_header + self.raw[self._body_offset():])


class TestErrorsRevealNoSecret(EntryTestCase):
    """Error messages, tracebacks and logs contain no secret."""

    def _assert_no_secret(self, exc: BaseException, *secrets_: str) -> None:
        text = "".join(traceback.format_exception(exc))  # message, chain of causes
        for secret in secrets_:
            self.assertNotIn(secret, text)
            self.assertNotIn(secret, repr(exc))

    def test_wrong_master_password_is_not_echoed(self):
        attempt = "Tentative-Mot-De-Passe-Unique-987"
        with self.assertLogs("mon_coffre", level=logging.DEBUG) as logs:
            self.assertFalse(self.vault.verify_master_password(attempt))
            with self.assertRaises(WrongMasterPasswordError) as ctx:
                Vault.unlock(self.vault_id, attempt)
        self._assert_no_secret(ctx.exception, attempt, MASTER)
        self.assertNotIn(attempt, "\n".join(logs.output))

    def test_decryption_error_does_not_reveal_the_value(self):
        entry_id = self.entries.create_entry(Entry(service_name="Banque", password=SECRET,
                                                   notes="note " + SECRET))
        blob = bytearray(self.vault.connection.execute(
            "SELECT password_enc FROM entries WHERE id = ?", (entry_id,)).fetchone()[0])
        blob[-1] ^= 0x01
        with self.vault.connection as conn:
            conn.execute("UPDATE entries SET password_enc = ? WHERE id = ?",
                         (bytes(blob), entry_id))
        with self.assertRaises(EntryDecryptionError) as ctx:
            self.entries.get_entry(entry_id)
        self._assert_no_secret(ctx.exception, SECRET, MASTER)

    def test_wrong_export_password_is_not_echoed(self):
        self.entries.create_entry(Entry(service_name="Banque", password=SECRET))
        path = Path(self._tmpdir.name) / "export.mcfexport"
        import_export.export_encrypted(self.entries, self.vault, MASTER,
                                       "mot-de-passe-export", path)
        attempt = "Mauvais-Export-Unique-654"
        with self.assertRaises(WrongMasterPasswordError) as ctx:
            import_export.parse_encrypted_export(path, attempt)
        self._assert_no_secret(ctx.exception, attempt, SECRET, "mot-de-passe-export")

    def test_modified_export_ciphertext_is_detected(self):
        import base64
        import json

        path = Path(self._tmpdir.name) / "export.mcfexport"
        import_export.export_encrypted(self.entries, self.vault, MASTER,
                                       "mot-de-passe-export", path)
        container = json.loads(path.read_text())
        ciphertext = bytearray(base64.b64decode(container["ciphertext"]))
        ciphertext[0] ^= 0x01
        container["ciphertext"] = base64.b64encode(bytes(ciphertext)).decode()
        path.write_text(json.dumps(container))
        with self.assertRaises(WrongMasterPasswordError):
            import_export.parse_encrypted_export(path, "mot-de-passe-export")


class TestMalformedBackupListing(EntryTestCase):
    """A malformed .mcfbak file is ignored when listing, never a raw exception."""

    def test_invalid_header_versions_are_skipped(self):
        import json
        import struct

        directory = Path(tempfile.mkdtemp(dir=self._tmpdir.name))
        valid = backup.create_backup(self.vault, directory)
        for name, version in (("texte", "x"), ("nul", None), ("liste", [1]),
                              ("booleen", True), ("zero", 0), ("chaine-1", "1")):
            header = json.dumps({"format": "mon-coffre-fort-backup", "version": version,
                                 "vault_id": self.vault_id, "kind": "auto"}).encode()
            (directory / f"{name}.mcfbak").write_bytes(
                backup.MAGIC + struct.pack(">I", len(header)) + header)
        self.assertEqual([b.path for b in backup.list_backups(directory)], [valid])
        self.assertEqual(backup.rotate_auto_backups(self.vault_id, directory, keep=0), 0)


class TestMalformedVaultFiles(EntryTestCase):
    """Malformed vault: always VaultCorruptedError, never a raw exception."""

    def _tamper(self, sql: str, args: tuple = ()) -> None:
        with self.vault.connection as conn:
            conn.execute(sql, args)
        self.vault.close()

    def _assert_corrupted(self) -> None:
        from app.core.exceptions import VaultCorruptedError

        with self.assertRaises(VaultCorruptedError):
            self.vault = Vault.unlock(self.vault_id, MASTER)

    def test_empty_salt(self):
        self._tamper("UPDATE vault_meta SET kdf_salt = x''")
        self._assert_corrupted()

    def test_too_short_salt(self):
        self._tamper("UPDATE vault_meta SET kdf_salt = x'01020304'")
        self._assert_corrupted()

    def test_salt_stored_as_text(self):
        self._tamper("UPDATE vault_meta SET kdf_salt = 'abcdefghijklmnop'")
        self._assert_corrupted()

    def test_non_numeric_schema_version(self):
        self._tamper("UPDATE vault_meta SET schema_version = 'abc'")
        self._assert_corrupted()

    def test_zero_format_version(self):
        self._tamper("UPDATE vault_meta SET format_version = 0")
        self._assert_corrupted()

    def test_unknown_kdf(self):
        self._tamper("UPDATE vault_meta SET kdf_name = 'pbkdf2'")
        self._assert_corrupted()

    def test_wrapped_key_version_byte(self):
        blob = bytearray(self.vault.connection.execute(
            "SELECT wrapped_key_blob FROM vault_meta").fetchone()[0])
        blob[0] = 2
        self._tamper("UPDATE vault_meta SET wrapped_key_blob = ?", (bytes(blob),))
        self._assert_corrupted()

    def test_dropped_entries_table(self):
        self._tamper("DROP TABLE entries")
        self._assert_corrupted()

    def test_dropped_history_table(self):
        self._tamper("DROP TABLE entry_history")
        self._assert_corrupted()

    def test_dropped_column(self):
        self._tamper("ALTER TABLE entries DROP COLUMN metadata_enc")
        self._assert_corrupted()

    def test_field_version_byte_is_checked(self):
        entry_id = self.entries.create_entry(Entry(service_name="A", password=SECRET))
        blob = bytearray(self.vault.connection.execute(
            "SELECT password_enc FROM entries WHERE id = ?", (entry_id,)).fetchone()[0])
        blob[0] = 2
        with self.vault.connection as conn:
            conn.execute("UPDATE entries SET password_enc = ? WHERE id = ?",
                         (bytes(blob), entry_id))
        with self.assertRaises(EntryDecryptionError):
            self.entries.get_entry(entry_id)

    def test_valid_vault_still_opens(self):
        self.entries.create_entry(Entry(service_name="A", password=SECRET))
        self.vault.close()
        self.vault = Vault.unlock(self.vault_id, MASTER)
        self.assertEqual(len(self.entries.__class__(self.vault).list_entries()), 1)


class TestMalformedRecoveryEnvelope(EntryTestCase):
    def test_short_recovery_salt(self):
        from app.core.exceptions import VaultCorruptedError

        self.vault.close()
        vault, key = Vault.create_with_recovery(f"rec-{uuid.uuid4().hex[:8]}", "R", MASTER)
        with vault.connection as conn:
            conn.execute("UPDATE vault_recovery SET kdf_salt = x'0102'")
        with self.assertRaises(VaultCorruptedError):
            _ = vault.has_recovery_key
        vault_id = vault.vault_id
        vault.close()
        with self.assertRaises(VaultCorruptedError):
            Vault.recover(vault_id, key, "nouveau-mot-de-passe-solide")
        self.vault = Vault.unlock(self.vault_id, MASTER)


class TestMalformedBackupHeader(EntryTestCase):
    """Malformed backup header: BackupError, no vault created."""

    def setUp(self):
        super().setUp()
        self.directory = Path(tempfile.mkdtemp(dir=self._tmpdir.name))
        self.path = backup.create_backup(self.vault, self.directory)
        raw = self.path.read_bytes()
        start = len(backup.MAGIC) + 4
        length = int.from_bytes(raw[len(backup.MAGIC):start], "big")
        self.header = raw[start:start + length]
        self.body = raw[start + length:]

    def _assert_refused(self, **changes) -> None:
        import json
        import struct

        header = json.loads(self.header)
        header.update(changes)
        data = json.dumps(header).encode()
        self.path.write_bytes(backup.MAGIC + struct.pack(">I", len(data)) + data + self.body)
        before = len(list_vaults())
        with self.assertRaises(backup.BackupError):
            backup.restore_backup(self.path, MASTER)
        self.assertEqual(len(list_vaults()), before)

    def test_short_salt(self):
        import base64

        self._assert_refused(kdf_salt=base64.b64encode(b"1234").decode())

    def test_salt_not_a_string(self):
        self._assert_refused(kdf_salt=5)

    def test_schema_version_as_text(self):
        self._assert_refused(schema_version="3")

    def test_schema_version_as_float(self):
        self._assert_refused(schema_version=3.7)

    def test_format_version_as_bool(self):
        self._assert_refused(format_version=True)

    def test_unknown_kdf(self):
        self._assert_refused(kdf_name="scrypt")


class TestMalformedEncryptedExport(EntryTestCase):
    """Malformed .mcfexport export: ImportExportError before any derivation."""

    def setUp(self):
        super().setUp()
        self.path = Path(self._tmpdir.name) / "export.mcfexport"
        import_export.export_encrypted(self.entries, self.vault, MASTER,
                                       "mot-de-passe-export", self.path)

    def _assert_refused(self, key: str, value: bytes) -> None:
        import base64
        import json

        container = json.loads(self.path.read_text())
        container[key] = base64.b64encode(value).decode()
        self.path.write_text(json.dumps(container))
        with self.assertRaises(import_export.ImportExportError):
            import_export.parse_encrypted_export(self.path, "mot-de-passe-export")

    def test_short_salt(self):
        self._assert_refused("salt", b"1234")

    def test_empty_nonce(self):
        self._assert_refused("nonce", b"")

    def test_oversized_nonce(self):
        self._assert_refused("nonce", b"x" * 16)
