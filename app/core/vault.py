"""The vault: creation, unlocking, locking.

Security model (envelope encryption):

    master password --Argon2id(salt)--> KEK (key encryption key)
    KEK --AES-256-GCM--> decrypts/encrypts the DEK (random data key)
    DEK --AES-256-GCM--> encrypts/decrypts each sensitive field of an entry

The DEK never exists on disk in plaintext. The master password never exists
on disk, not even derived (only its derivation result is used as an
ephemeral KEK, in memory, while the DEK is unwrapped).

Recovery key (optional): a SECOND envelope of the same DEK.

    recovery key --Argon2id(salt)--> recovery KEK
    recovery KEK --AES-256-GCM--> DEK   (vault_recovery table)

It therefore opens the vault on its own. It is never stored (shown once, see
app.core.recovery). After use, it is replaced: the typed key may have been
seen, so it must no longer open anything.

Known and accepted limitation (documented in the README): as with any
password manager based on authenticated encryption, a GCM authentication
failure while unwrapping the DEK is treated as a "wrong master password",
because this case is cryptographically indistinguishable from targeted
corruption of the wrapped key blob. Other forms of corruption (file
structure, format version) are detected and reported separately.
"""

from __future__ import annotations

import re
import secrets
import shutil
import sqlite3
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.core import crypto, recovery
from app.core.exceptions import (
    InvalidMasterPasswordPolicyError,
    NoRecoveryKeyError,
    RecoveryKeyError,
    UnsupportedVaultVersionError,
    VaultAlreadyExistsError,
    VaultCorruptedError,
    VaultError,
    VaultLockedError,
    VaultMigrationRequiredError,
    VaultNotFoundError,
    WrongMasterPasswordError,
)
from app.core.metadata import new_vault_uuid
from app.core.metadata_store import MetadataStore
from app.database import database
from app.database.models import RecoveryRecord, VaultMeta
from app.database.repositories import RecoveryRepository, VaultMetaRepository
from app.utils.logging import get_logger
from app.utils.paths import vault_path, vaults_dir

CURRENT_FORMAT_VERSION = 1
MIN_MASTER_PASSWORD_LENGTH = 8
MAX_VAULT_NAME_LENGTH = 60

# Constant value used only to check, after unwrapping, that the DEK obtained
# is actually usable. It is not a secret.
_VERIFIER_PLAINTEXT = b"MON-COFFRE-FORT-VERIFIER-V1"
_VERIFIER_AAD = b"mon-coffre-fort:verifier"
_WRAPPED_KEY_AAD = b"mon-coffre-fort:wrapped-dek"
# Distinct associated data: one envelope cannot be mistaken for the other.
_RECOVERY_KEY_AAD = b"mon-coffre-fort:recovery-wrapped-dek"

_DB_FILENAME = "vault.db"


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _validate_master_password_policy(password: str) -> None:
    if len(password) < MIN_MASTER_PASSWORD_LENGTH:
        raise InvalidMasterPasswordPolicyError(
            f"The master password must contain at least "
            f"{MIN_MASTER_PASSWORD_LENGTH} characters."
        )


@dataclass(slots=True)
class VaultInfo:
    """Non-sensitive information about a vault, usable while the vault is locked."""

    vault_id: str
    vault_name: str
    format_version: int
    created_at: str
    updated_at: str


def check_supported_versions(meta: VaultMeta) -> None:
    if meta.format_version > CURRENT_FORMAT_VERSION:
        raise UnsupportedVaultVersionError(
            f"This vault uses a newer format "
            f"(v{meta.format_version}) than the one supported by this application "
            f"(v{CURRENT_FORMAT_VERSION})."
        )
    if meta.schema_version > database.SCHEMA_VERSION:
        raise UnsupportedVaultVersionError(
            f"This vault was created by a newer version of the application "
            f"(schema v{meta.schema_version}, supported: v{database.SCHEMA_VERSION})."
        )


def unwrap_data_key(master_password: str, meta: VaultMeta) -> bytes:
    """Derives the KEK and unwraps the DEK described by `meta`.

    Used when unlocking, to re-check the master password (export, password
    change) and to restore a backup (whose header contains the same metadata).
    """
    kek = crypto.derive_key(master_password, meta.kdf_salt, meta.kdf_params)

    try:
        _version, nonce, ciphertext = crypto.unpack_blob(meta.wrapped_key_blob)
    except ValueError as exc:
        raise VaultCorruptedError("Invalid wrapped vault key.") from exc

    try:
        dek = crypto.aes_gcm_decrypt(kek, nonce, ciphertext, _WRAPPED_KEY_AAD)
    except crypto.AuthenticationFailed as exc:
        raise WrongMasterPasswordError("Wrong master password.") from exc
    _check_verifier(dek, meta)
    return dek


def _check_verifier(dek: bytes, meta: VaultMeta) -> None:
    """Defense in depth: the DEK obtained must decrypt the vault verifier."""
    try:
        _v_version, v_nonce, v_ciphertext = crypto.unpack_blob(meta.verifier_blob)
        plaintext = crypto.aes_gcm_decrypt(dek, v_nonce, v_ciphertext, _VERIFIER_AAD)
    except (ValueError, crypto.AuthenticationFailed) as exc:
        raise VaultCorruptedError(
            "The vault integrity check failed after unlocking."
        ) from exc

    if plaintext != _VERIFIER_PLAINTEXT:
        raise VaultCorruptedError("Invalid vault verifier.")


def _wrap_for_password(dek: bytes, password: str) -> dict:
    """New envelope of the DEK for `password` (fresh salt and parameters)."""
    salt = crypto.generate_salt()
    params = crypto.Argon2Params()
    kek = crypto.derive_key(password, salt, params)
    nonce, ciphertext = crypto.aes_gcm_encrypt(kek, dek, _WRAPPED_KEY_AAD)
    v_nonce, v_ciphertext = crypto.aes_gcm_encrypt(dek, _VERIFIER_PLAINTEXT, _VERIFIER_AAD)
    return {"wrapped_key_blob": crypto.pack_blob(nonce, ciphertext),
            "verifier_blob": crypto.pack_blob(v_nonce, v_ciphertext),
            "kdf_salt": salt, "kdf_params": params}


def _new_recovery(dek: bytes) -> tuple[str, RecoveryRecord]:
    """Draws a recovery key and wraps the DEK with it: (displayable key, row)."""
    key = recovery.generate()
    salt = crypto.generate_salt()
    params = crypto.Argon2Params()
    kek = crypto.derive_key(recovery.normalize(key), salt, params)
    nonce, ciphertext = crypto.aes_gcm_encrypt(kek, dek, _RECOVERY_KEY_AAD)
    return key, RecoveryRecord(kdf_params=params, kdf_salt=salt,
                               wrapped_key_blob=crypto.pack_blob(nonce, ciphertext),
                               created_at=_utc_now_iso())


def _unwrap_with_recovery(secret: str, record: RecoveryRecord, meta: VaultMeta) -> bytes:
    kek = crypto.derive_key(secret, record.kdf_salt, record.kdf_params)
    try:
        _version, nonce, ciphertext = crypto.unpack_blob(record.wrapped_key_blob)
    except ValueError as exc:
        raise VaultCorruptedError("Invalid recovery envelope.") from exc
    try:
        dek = crypto.aes_gcm_decrypt(kek, nonce, ciphertext, _RECOVERY_KEY_AAD)
    except crypto.AuthenticationFailed as exc:
        raise RecoveryKeyError("Wrong recovery key for this vault.") from exc
    _check_verifier(dek, meta)
    return dek


def _require_current_schema(meta: VaultMeta) -> None:
    """A v1 to v3 vault must be migrated first (app.services.migration_v4); nothing
    is modified here. No plaintext .bak copy is ever created anymore."""
    if meta.schema_version < database.SCHEMA_VERSION:
        raise VaultMigrationRequiredError(
            f"This vault uses an older format (v{meta.schema_version}): it must be "
            "upgraded to the version 1.7 format before it can be opened. "
            "It has not been modified.")


def _read_recovery(conn: sqlite3.Connection) -> RecoveryRecord | None:
    """Recovery envelope, or None; VaultCorruptedError if it is malformed."""
    try:
        return RecoveryRepository(conn).get()
    except (sqlite3.DatabaseError, ValueError, KeyError, TypeError) as exc:
        raise VaultCorruptedError("The vault recovery envelope is corrupted.") from exc


def _open_existing(vault_id: str) -> tuple[sqlite3.Connection, Path, VaultMeta]:
    """Connects to the file of an existing vault and reads its metadata."""
    db_path = vault_path(vault_id) / _DB_FILENAME
    if not db_path.exists():
        raise VaultNotFoundError(f"The vault \"{vault_id}\" cannot be found.")
    try:
        conn = database.connect(db_path)
    except sqlite3.DatabaseError as exc:
        raise VaultCorruptedError("Cannot open the vault file.") from exc
    try:
        meta = VaultMetaRepository(conn).get()
    except (sqlite3.DatabaseError, ValueError, KeyError, TypeError) as exc:
        conn.close()
        raise VaultCorruptedError("The vault file is corrupted.") from exc
    if meta is None:
        conn.close()
        raise VaultCorruptedError("Vault metadata missing or corrupted.")
    try:
        # A schema newer than every known one cannot be checked here:
        # check_supported_versions will reject it explicitly (unsupported version).
        problems = (database.structure_problems(conn, meta.schema_version)
                    if meta.schema_version <= database.V4_SCHEMA_VERSION else [])
    except sqlite3.DatabaseError:
        problems = ["base illisible"]
    if problems:
        conn.close()
        get_logger().error("Vault structure invalid: %s (%s)", vault_id, "; ".join(problems))
        raise VaultCorruptedError("The structure of the vault file is damaged.")
    return conn, db_path, meta


class Vault:
    """Represents a vault, locked or unlocked.

    This class is not meant to be instantiated directly: use
    `Vault.create(...)` or `Vault.unlock(...)`.
    """

    def __init__(self, vault_id: str, db_path: Path, conn: sqlite3.Connection) -> None:
        self.vault_id = vault_id
        self._db_path = db_path
        self._conn = conn
        self._meta_repo = VaultMetaRepository(conn)
        self._dek: bytearray | None = None  # None => locked
        self._metadata: MetadataStore | None = None  # v4 cache, destroyed on lock
        self._logger = get_logger()

    # --- Properties ----------------------------------------------------------

    @property
    def is_locked(self) -> bool:
        return self._dek is None

    @property
    def info(self) -> VaultInfo:
        meta = self._meta_repo.get()
        if meta is None:
            raise VaultCorruptedError("Vault metadata not found.")
        return VaultInfo(
            vault_id=self.vault_id,
            vault_name=meta.vault_name,
            format_version=meta.format_version,
            created_at=meta.created_at,
            updated_at=meta.updated_at,
        )

    # --- Lifecycle ----------------------------------------------------------

    @classmethod
    def create(cls, vault_id: str, vault_name: str, master_password: str) -> Vault:
        """Creates a new encrypted vault and returns it unlocked."""
        vault_name = validate_vault_name(vault_name)
        _validate_master_password_policy(master_password)

        directory = vault_path(vault_id)
        db_path = directory / _DB_FILENAME
        if db_path.exists():
            raise VaultAlreadyExistsError(f"The vault \"{vault_id}\" already exists.")

        conn = database.connect(db_path)
        database.initialize_schema(conn)

        dek = crypto.generate_key()
        envelope = _wrap_for_password(dek, master_password)

        now = _utc_now_iso()
        meta = VaultMeta(
            schema_version=database.SCHEMA_VERSION,
            format_version=CURRENT_FORMAT_VERSION,
            kdf_name="argon2id",
            **envelope,
            vault_name=vault_name,
            created_at=now,
            updated_at=now,
            vault_uuid=new_vault_uuid(),  # vault identity, immutable (metadata AAD)
        )
        repo = VaultMetaRepository(conn)
        repo.insert(meta)

        vault = cls(vault_id, db_path, conn)
        vault._dek = bytearray(dek)
        vault._logger.info("Vault created: %s", vault_id)
        return vault

    @classmethod
    def create_with_recovery(cls, vault_id: str, vault_name: str,
                             master_password: str) -> tuple[Vault, str]:
        """Creates the vault and its recovery key (returned to be shown once)."""
        vault = cls.create(vault_id, vault_name, master_password)
        try:
            return vault, vault._install_recovery_key(vault._require_unlocked_key())
        except Exception:
            vault.close()
            raise

    @classmethod
    def unlock(cls, vault_id: str, master_password: str) -> Vault:
        """Opens an existing vault. Raises an explicit domain exception on failure."""
        conn, db_path, meta = _open_existing(vault_id)
        try:
            check_supported_versions(meta)
            dek = unwrap_data_key(master_password, meta)
            _require_current_schema(meta)
        except Exception:
            conn.close()
            raise

        vault = cls(vault_id, db_path, conn)
        vault._dek = bytearray(dek)
        vault._logger.info("Vault unlocked: %s", vault_id)
        return vault

    @classmethod
    def open_for_migration(cls, vault_id: str, master_password: str) -> Vault:
        """Opens a v1 to v3 vault WITHOUT automatic upgrade (hence without a .bak copy).

        Reserved for the v4 migration (app.services.migration_v4), which first
        makes an ENCRYPTED backup and then includes the v1/v2 -> v3 steps in its
        own transaction. The file schema is not modified here.
        """
        conn, db_path, meta = _open_existing(vault_id)
        try:
            check_supported_versions(meta)
            if meta.schema_version >= database.V4_SCHEMA_VERSION:
                raise VaultError("This vault is already in the v4 format.")
            dek = unwrap_data_key(master_password, meta)
        except Exception:
            conn.close()
            raise
        vault = cls(vault_id, db_path, conn)
        vault._dek = bytearray(dek)
        vault._logger.info("Vault opened for migration: %s", vault_id)
        return vault

    @property
    def metadata(self) -> MetadataStore:
        """Cache of the decrypted metadata (unlocked v4 vault only).

        Created on first access after unlocking; destroyed by `lock()`.
        """
        dek = self._require_unlocked_key()
        if self._metadata is None:
            meta = self._meta_repo.get()
            if (meta is None or meta.schema_version < database.V4_SCHEMA_VERSION
                    or meta.vault_uuid is None):
                raise VaultError("Encrypted metadata unavailable: vault not migrated (v4).")
            self._metadata = MetadataStore(self._conn, dek, meta.vault_uuid)
        return self._metadata

    def lock(self) -> None:
        """Erases the DEK and the metadata cache (best effort), locks the vault."""
        if self._metadata is not None:
            self._metadata.clear()
            self._metadata = None
        if self._dek is not None:
            crypto.wipe(self._dek)
            self._dek = None
            self._logger.info("Vault locked: %s", self.vault_id)

    def close(self) -> None:
        """Locks the vault and closes the database connection."""
        self.lock()
        self._conn.close()

    # --- Access to the data key (reserved for internal layers) --------------

    def _require_unlocked_key(self) -> bytes:
        if self._dek is None:
            raise VaultLockedError("The vault is locked.")
        return bytes(self._dek)

    @property
    def connection(self) -> sqlite3.Connection:
        """Raw SQLite connection, used by the repositories and services.

        Accessible even when locked, for what the file keeps readable by design
        (`vault_meta`: vault name, derivation parameters; `entry_history.created_at`
        dates, D3). Entry metadata and category names are encrypted (v4): the
        services that read them go through `_require_unlocked_key()` or the
        `metadata` cache.
        """
        return self._conn

    # --- Vault name ---------------------------------------------------------------

    def rename(self, new_name: str) -> None:
        self._require_unlocked_key()
        self._meta_repo.rename_vault(validate_vault_name(new_name), _utc_now_iso())
        self._logger.info("Vault renamed: %s", self.vault_id)

    # --- Master password re-check -----------------------------------

    def verify_master_password(self, password: str, log_failure: bool = True) -> bool:
        """Re-checks the master password independently of the unlocked state.

        Required before sensitive operations (export, password change): a
        session left open is not enough to perform them.
        """
        meta = self._meta_repo.get()
        if meta is None:
            raise VaultCorruptedError("Vault metadata missing.")
        try:
            unwrap_data_key(password, meta)
        except WrongMasterPasswordError:
            if log_failure:  # False: plain comparison (e.g. the password of a PDF)
                self._logger.warning("Master password re-verification failed: %s",
                                     self.vault_id)
            return False
        return True

    # --- Master password change --------------------------------------

    def change_master_password(self, current_password: str, new_password: str) -> None:
        """Re-wraps the existing DEK under a new master password.

        Data already encrypted with the DEK does not need to be touched: only
        the envelope (KEK) changes. This is the point of envelope encryption.
        """
        _validate_master_password_policy(new_password)
        dek = self._require_unlocked_key()

        meta = self._meta_repo.get()
        if meta is None:
            raise VaultCorruptedError("Vault metadata missing.")

        # The old password is re-checked independently of the in-memory unlocked
        # state, so that a session left open does not allow the password to be
        # changed without knowing it.
        if not self.verify_master_password(current_password):
            raise WrongMasterPasswordError("The current master password is wrong.")

        self._meta_repo.update_wrapped_key(**_wrap_for_password(dek, new_password),
                                           updated_at=_utc_now_iso())
        self._logger.info("Master password changed for vault: %s", self.vault_id)

    # --- Recovery key ---------------------------------------------------------

    @property
    def recovery_created_at(self) -> str | None:
        """Creation date of the recovery key (ISO), or None if there is none."""
        record = _read_recovery(self._conn)
        return record.created_at if record else None

    @property
    def has_recovery_key(self) -> bool:
        return self.recovery_created_at is not None

    def create_recovery_key(self, master_password: str) -> str:
        """Creates (or replaces) the recovery key and returns it, to be shown ONCE.

        The master password is required: a session left open must not make it
        possible to forge permanent access to the vault.
        """
        dek = self._require_unlocked_key()
        if not self.verify_master_password(master_password):
            raise WrongMasterPasswordError("Wrong master password.")
        return self._install_recovery_key(dek)

    def _install_recovery_key(self, dek: bytes) -> str:
        key, record = _new_recovery(dek)
        RecoveryRepository(self._conn).set(record)
        self._logger.info("Recovery key created for vault: %s", self.vault_id)
        return key

    def remove_recovery_key(self, master_password: str) -> None:
        self._require_unlocked_key()
        if not self.verify_master_password(master_password):
            raise WrongMasterPasswordError("Wrong master password.")
        RecoveryRepository(self._conn).delete()
        self._logger.info("Recovery key removed for vault: %s", self.vault_id)

    def discard_recovery_key(self) -> None:
        """Removes a key that the user did not confirm writing down.

        No password needed: removing a key only TAKES AWAY an access.
        """
        self._require_unlocked_key()
        RecoveryRepository(self._conn).delete()
        self._logger.info("Unconfirmed recovery key discarded for vault: %s", self.vault_id)

    @classmethod
    def recover(cls, vault_id: str, recovery_key: str,
                new_master_password: str, allow_legacy: bool = False) -> tuple[Vault, str]:
        """Opens the vault with its recovery key and sets a new master password.

        Returns the unlocked vault and the NEW recovery key (the old one no longer
        works). The password envelope and the recovery envelope are replaced in a
        single transaction: never one without the other.

        `allow_legacy`: accepts a v1 to v3 vault, only for the "recovery then
        upgrade" sequence (app.services.vault_upgrade). Only the two envelopes are
        rewritten, as in 1.6; the returned vault is usable only by the migration,
        never by the v4 services.
        """
        _validate_master_password_policy(new_master_password)
        secret = recovery.normalize(recovery_key)  # RecoveryKeyFormatError: typo
        conn, db_path, meta = _open_existing(vault_id)
        try:
            check_supported_versions(meta)
            if not allow_legacy:
                _require_current_schema(meta)
            elif meta.schema_version >= database.SCHEMA_VERSION:
                raise VaultError("This vault is already in the current format.")
            record = _read_recovery(conn)
            if record is None:
                raise NoRecoveryKeyError("This vault has no recovery key.")
            dek = _unwrap_with_recovery(secret, record, meta)
            new_key, new_record = _new_recovery(dek)
            password_envelope = _wrap_for_password(dek, new_master_password)
            with conn:  # a single transaction
                VaultMetaRepository(conn).update_wrapped_key(
                    **password_envelope, updated_at=_utc_now_iso(), commit=False)
                RecoveryRepository(conn).set(new_record, commit=False)
        except Exception:
            conn.close()
            raise
        vault = cls(vault_id, db_path, conn)
        vault._dek = bytearray(dek)
        vault._logger.warning("Vault recovered with its recovery key: %s", vault_id)
        return vault, new_key


# --- Vault discovery (no password) --------------------------------------


def generate_vault_id(vault_name: str) -> str:
    """File-system-safe vault identifier, derived from the name.

    E.g. "My Vault" -> "my-vault-3fa9c1". The random suffix (CSPRNG) avoids
    collisions between vaults with the same name. A name with no usable ASCII
    character falls back to the historical "coffre" prefix.
    """
    ascii_name = (
        unicodedata.normalize("NFKD", vault_name).encode("ascii", "ignore").decode("ascii")
    )
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_name.lower()).strip("-")[:32] or "coffre"
    return f"{slug}-{secrets.token_hex(3)}"


def list_vaults() -> list[VaultInfo]:
    """Lists the vaults present locally, with their non-sensitive metadata.

    An unreadable vault is still listed (under its identifier): an explicit
    error is shown to the user when unlocking it.
    """
    infos: list[VaultInfo] = []
    for directory in sorted(vaults_dir().iterdir()):
        db_path = directory / _DB_FILENAME
        if not directory.is_dir() or not db_path.is_file():
            continue
        vault_id = directory.name
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            try:
                meta = VaultMetaRepository(conn).get()
            finally:
                conn.close()
        except (sqlite3.DatabaseError, ValueError, KeyError, TypeError):
            meta = None
        if meta is None:
            get_logger().warning("Unreadable vault metadata: %s", vault_id)
            infos.append(VaultInfo(vault_id, vault_id, 0, "", ""))
        else:
            infos.append(
                VaultInfo(
                    vault_id=vault_id,
                    vault_name=meta.vault_name,
                    format_version=meta.format_version,
                    created_at=meta.created_at,
                    updated_at=meta.updated_at,
                )
            )
    return infos


def vault_has_recovery_key(vault_id: str) -> bool:
    """Does the vault have a recovery key? (read-only, no password)"""
    db_path = vaults_dir() / vault_id / _DB_FILENAME
    if not re.fullmatch(r"[A-Za-z0-9._-]+", vault_id) or not db_path.is_file():
        return False
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            return RecoveryRepository(conn).get() is not None
        finally:
            conn.close()
    except (sqlite3.DatabaseError, ValueError, KeyError, TypeError):
        return False


def validate_vault_name(name: str) -> str:
    clean = " ".join(name.split())
    if not clean:
        raise VaultError("A vault name is required.")
    if len(clean) > MAX_VAULT_NAME_LENGTH:
        raise VaultError(
            f"The vault name must not exceed {MAX_VAULT_NAME_LENGTH} characters."
        )
    return clean


def delete_vault(vault_id: str, master_password: str) -> None:
    """Permanently deletes a vault (whole directory); the master password is required.

    The vault must not be open. The .mcfbak backups, stored elsewhere, are not
    touched.
    """
    if not re.fullmatch(r"[A-Za-z0-9._-]+", vault_id) or vault_id in (".", ".."):
        raise VaultNotFoundError("Invalid vault identifier.")
    directory = vaults_dir() / vault_id
    db_path = directory / _DB_FILENAME
    if not db_path.is_file():
        raise VaultNotFoundError(f"The vault \"{vault_id}\" cannot be found.")
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        meta = VaultMetaRepository(conn).get()
    except (sqlite3.DatabaseError, ValueError, KeyError, TypeError):
        meta = None
    finally:
        conn.close()
    if meta is None:
        # Unreadable vault: the password cannot be checked, so deletion is refused
        # (deleting the folder manually remains possible, knowingly).
        raise VaultCorruptedError(
            "This vault is unreadable: its deletion cannot be verified."
        )
    unwrap_data_key(master_password, meta)  # WrongMasterPasswordError if wrong
    shutil.rmtree(directory)
    get_logger().info("Vault deleted: %s", vault_id)
