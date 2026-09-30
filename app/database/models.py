"""Data models (typed dataclasses).

These dataclasses mirror the SQLite tables as they are stored: sensitive
fields are opaque encrypted BLOBs there. The "decrypted" objects handled by
the application (Entry, EntrySummary) live in app/core/entries.py, because
only the core layer knows the key.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.builtin_categories import BUILTIN_CATEGORY_KEYS
from app.core.crypto import Argon2Params, check_salt

VAULT_UUID_SIZE = 16  # identical to app.core.metadata.VAULT_UUID_SIZE (checked by a test)


def _check_blob(value: object, what: str) -> None:
    if not isinstance(value, bytes):
        raise ValueError(f"Invalid {what}.")


def _check_version(value: object, what: str) -> None:
    # bool is an int in Python: excluded explicitly.
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"Invalid {what}.")


@dataclass(slots=True)
class RecoveryRecord:
    """Row of `vault_recovery`: the DEK wrapped by the recovery key.

    Contains neither the recovery key nor the plaintext DEK.
    """

    kdf_params: Argon2Params
    kdf_salt: bytes
    wrapped_key_blob: bytes
    created_at: str

    def __post_init__(self) -> None:
        """Values read back from a file: ValueError if they are malformed."""
        check_salt(self.kdf_salt)
        _check_blob(self.wrapped_key_blob, "recovery envelope")


@dataclass(slots=True)
class VaultMeta:
    """In-memory representation of the `vault_meta` table.

    `wrapped_key_blob` and `verifier_blob` are opaque encrypted BLOBs (see
    app.core.crypto.pack_blob): this dataclass never contains a plaintext key.
    """

    schema_version: int
    format_version: int
    kdf_name: str
    kdf_params: Argon2Params
    kdf_salt: bytes
    wrapped_key_blob: bytes
    verifier_blob: bytes
    vault_name: str
    created_at: str
    updated_at: str
    # v4: stable vault identity (metadata AAD). None for a v3 vault:
    # never generated on read, only by the migration or by v4 creation.
    vault_uuid: bytes | None = None

    def __post_init__(self) -> None:
        """Values read back from a file (vault, backup header): ValueError if they
        are malformed, which callers turn into "corrupted vault"."""
        _check_version(self.schema_version, "schema version")
        _check_version(self.format_version, "format version")
        if self.kdf_name != "argon2id":
            raise ValueError("Unknown key derivation function.")
        check_salt(self.kdf_salt)
        _check_blob(self.wrapped_key_blob, "wrapped key")
        _check_blob(self.verifier_blob, "verifier")
        if self.vault_uuid is not None and (
                not isinstance(self.vault_uuid, bytes) or len(self.vault_uuid) != VAULT_UUID_SIZE):
            raise ValueError("Invalid vault identity.")


@dataclass(slots=True)
class EntryRecord:
    """Row of the `entries` table of a v1 to v3 vault (plaintext metadata).

    Legacy: read by the v3 -> v4 migration only; the v4 runtime only handles
    blobs (EntryRepository, v4 methods). The `*_enc` attributes are AES-256-GCM
    BLOBs (see app.core.crypto.pack_blob) or None if the field is empty.
    """

    id: int | None
    entry_type: str
    category_id: int | None
    is_favorite: bool
    service_name: str
    url: str | None
    username: str | None
    email_enc: bytes | None
    password_enc: bytes | None
    notes_enc: bytes | None
    extra_fields_enc: bytes | None
    created_at: str
    updated_at: str
    last_used_at: str | None = None
    password_changed_at: str | None = None
    is_deleted: bool = False
    deleted_at: str | None = None


@dataclass(slots=True)
class CategoryRecord:
    """Row of the `categories` table during the migration (legacy, see EntryRecord).

    v3: plaintext `name`. v4 (added columns): `builtin_key` for a built-in
    category, OR `name_enc` (encrypted name) for a custom category.
    """

    id: int
    name: str
    is_builtin: bool
    created_at: str
    builtin_key: str | None = None
    name_enc: bytes | None = None

    def __post_init__(self) -> None:
        if self.builtin_key is not None and self.builtin_key not in BUILTIN_CATEGORY_KEYS:
            raise ValueError("Unknown built-in category key.")
        if self.name_enc is not None:
            _check_blob(self.name_enc, "encrypted category name")
        if self.builtin_key is not None and self.name_enc is not None:
            raise ValueError("Category is both built-in and custom.")


@dataclass(slots=True)
class HistoryRecord:
    """Row of `entry_history`: an encrypted previous version of an entry."""

    id: int
    entry_id: int
    snapshot_enc: bytes | None
    created_at: str
