"""Encryption of entry metadata and category names (schema v4).

Everything that describes the content or organization of the vault (name,
URL, username, type, category, favorite, tags, dates) is grouped into one
encrypted, authenticated JSON document per entry; the name of a custom
category is handled the same way. This module only assembles existing
primitives from app.core.crypto (derive_subkey, encrypt_field, decrypt_field):

    metadata subkey = HKDF-SHA256(DEK, "mon-coffre-fort:entry-metadata:v1")
    category subkey = HKDF-SHA256(DEK, "mon-coffre-fort:category:v1")
    entry AAD    = "mon-coffre-fort:entry-metadata:<vault_uuid hex>:<entry_id>"
    category AAD = "mon-coffre-fort:category:<vault_uuid hex>:<category_id>"

A blob can therefore be neither modified, nor moved to another entry or
category, nor to another vault, nor mistaken for the other use (different
subkey AND AAD). Secrets (password, notes…) stay encrypted as before,
directly under the DEK: this module does not touch them.

Versioned JSON ("v": 1), strictly validated when read: exact keys, types,
ISO 8601 dates with time zone, canonical tags. Any anomaly raises a
corruption error — never a silent default value.

Padding: the plaintext is padded to a multiple of 64 bytes before encryption.
This REDUCES the length leak (a short name and a medium name give the same
size) without removing it: very long content is still larger, and the number
of entries, categories and versions remains visible in SQLite.
"""

from __future__ import annotations

import json
import secrets
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from app.core import crypto
from app.core.exceptions import (
    CategoryDecryptionError,
    CategoryError,
    EntryDecryptionError,
    EntryValidationError,
)
from app.i18n import tr

ENTRY_METADATA_INFO = b"mon-coffre-fort:entry-metadata:v1"
CATEGORY_INFO = b"mon-coffre-fort:category:v1"
METADATA_VERSION = 1
PAD_BLOCK = 64
VAULT_UUID_SIZE = 16

MAX_TAGS = 20
MAX_TAG_LENGTH = 32
# Must stay identical to the keys of app.core.entries.ENTRY_TYPES (checked by a test;
# no direct import: entries depends on this module).
ENTRY_TYPE_KEYS = frozenset({"login", "secure_note", "card", "identity", "wifi", "server"})

_ENTRY_KEYS = frozenset({
    "v", "name", "url", "username", "entry_type", "category_id", "is_favorite", "tags",
    "created_at", "updated_at", "password_changed_at", "deleted_at", "pad",
})
_CATEGORY_KEYS = frozenset({"v", "name", "created_at", "pad"})


# --- Decrypted objects ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EntryMetadata:
    """Decrypted metadata of an entry (exists only in memory)."""

    name: str
    url: str
    username: str
    entry_type: str
    category_id: int | None
    is_favorite: bool
    tags: tuple[str, ...]
    created_at: str
    updated_at: str
    password_changed_at: str
    deleted_at: str | None = None  # not null = in the Trash

    def __repr__(self) -> str:  # never any content in a repr (logs, tracebacks)
        return (f"EntryMetadata(entry_type={self.entry_type!r}, tags={len(self.tags)}, "
                f"in_trash={self.deleted_at is not None})")


@dataclass(frozen=True, slots=True)
class CategoryMetadata:
    """Decrypted name of a custom category."""

    name: str
    created_at: str

    def __repr__(self) -> str:
        return "CategoryMetadata(…)"


# --- Tags --------------------------------------------------------------------------------


def tag_key(tag: str) -> str:
    """Comparison key: "Linux", "linux" and "LINUX" are the same tag, and so are "Écoles"
    and "ecoles" (case and accents ignored). The displayed form is kept."""
    decomposed = unicodedata.normalize("NFKD", tag)
    return "".join(c for c in decomposed if not unicodedata.combining(c)).casefold()


def normalize_tags(raw: Iterable[str]) -> tuple[str, ...]:
    """Entered tags -> canonical form (order kept). Raises EntryValidationError.

    Canonical form: Unicode NFC, extra whitespace removed, leading "#" removed,
    original case kept. Rejected: empty tag, more than MAX_TAG_LENGTH characters,
    control character or comma, logical duplicate, more than MAX_TAGS tags.
    """
    result: list[str] = []
    seen: set[str] = set()
    for value in raw:
        if not isinstance(value, str):
            raise EntryValidationError(tr("tags.error.text"))
        tag = " ".join(unicodedata.normalize("NFC", value).split()).lstrip("#").strip()
        if not tag:
            raise EntryValidationError(tr("tags.error.empty"))
        if len(tag) > MAX_TAG_LENGTH:
            raise EntryValidationError(tr("tags.error.too_long", max=MAX_TAG_LENGTH))
        if "," in tag or any(unicodedata.category(c).startswith("C") for c in tag):
            raise EntryValidationError(tr("tags.error.character"))
        key = tag_key(tag)
        if key in seen:
            raise EntryValidationError(tr("tags.error.duplicate", tag=tag))
        seen.add(key)
        result.append(tag)
    if len(result) > MAX_TAGS:
        raise EntryValidationError(tr("tags.error.too_many", max=MAX_TAGS))
    return tuple(result)


# --- Shared validation (write: input error; read: corruption) --------------


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_timestamp(value: object, error: type[Exception], what: str) -> str:
    if not isinstance(value, str):
        raise error(f"Invalid date: {what}.")
    try:
        moment = datetime.fromisoformat(value)
    except ValueError as exc:
        raise error(f"Invalid date: {what}.") from exc
    if moment.tzinfo is None:
        raise error(f"Date without a time zone: {what}.")
    return value


def _check_entry(meta: EntryMetadata, error: type[Exception]) -> None:
    if not isinstance(meta.name, str) or not meta.name.strip():
        raise error("Missing or invalid entry name.")
    for what, value in (("URL", meta.url), ("identifiant", meta.username)):
        if not isinstance(value, str):
            raise error(f"Invalid field: {what}.")
    if meta.entry_type not in ENTRY_TYPE_KEYS:
        raise error("Unknown entry type.")
    if meta.category_id is not None and not (_is_int(meta.category_id) and meta.category_id > 0):
        raise error("Invalid category reference.")
    if not isinstance(meta.is_favorite, bool):
        raise error("Invalid \"favorite\" flag.")
    if not isinstance(meta.tags, tuple):
        raise error("Invalid tag list.")
    try:
        canonical = normalize_tags(meta.tags)
    except EntryValidationError as exc:
        raise error("Invalid tag list.") from exc
    if canonical != meta.tags:
        raise error("Non-canonical tag list.")
    for what in ("created_at", "updated_at", "password_changed_at"):
        _check_timestamp(getattr(meta, what), error, what)
    if meta.deleted_at is not None:
        _check_timestamp(meta.deleted_at, error, "deleted_at")


def _check_category(meta: CategoryMetadata, error: type[Exception]) -> None:
    if not isinstance(meta.name, str) or not meta.name.strip():
        raise error("Missing or invalid category name.")
    _check_timestamp(meta.created_at, error, "created_at")


# --- Serialization (versioned JSON + padding) ----------------------------------------


def _serialize(payload: dict) -> str:
    """Compact JSON whose UTF-8 encoding has a length that is a multiple of PAD_BLOCK."""
    payload = {**payload, "v": METADATA_VERSION, "pad": ""}
    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    payload["pad"] = " " * (-len(text.encode("utf-8")) % PAD_BLOCK)
    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return text


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _parse(text: str, keys: frozenset[str], error: type[Exception]) -> dict:
    """JSON read after decryption: length, structure, version, padding."""
    if len(text.encode("utf-8")) % PAD_BLOCK:
        raise error("Inconsistent metadata length.")
    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except ValueError as exc:  # JSONDecodeError inherits from it
        raise error("Unreadable metadata.") from exc
    if not isinstance(data, dict) or set(data) != keys:
        raise error("Invalid metadata structure.")
    if not _is_int(data["v"]):
        raise error("Invalid metadata version.")
    if data["v"] != METADATA_VERSION:
        raise error("Unsupported metadata version.")
    pad = data["pad"]
    if not isinstance(pad, str) or pad.strip(" "):
        raise error("Invalid metadata padding.")
    return data


# --- Encryption ------------------------------------------------------------------------


def new_vault_uuid() -> bytes:
    """Random, immutable identity of a vault (part of the AAD)."""
    return secrets.token_bytes(VAULT_UUID_SIZE)


def _check_id(value: object, what: str) -> int:
    if not (_is_int(value) and value > 0):
        raise ValueError(f"Invalid {what} identifier.")
    return value


class MetadataCipher:
    """Encrypts and decrypts the metadata of ONE vault (subkeys derived once)."""

    __slots__ = ("_category_key", "_entry_key", "_uuid_hex")

    def __init__(self, dek: bytes, vault_uuid: bytes) -> None:
        if not isinstance(vault_uuid, bytes) or len(vault_uuid) != VAULT_UUID_SIZE:
            raise ValueError("Invalid vault identity (vault_uuid).")
        self._uuid_hex = vault_uuid.hex()
        self._entry_key = crypto.derive_subkey(dek, ENTRY_METADATA_INFO)
        self._category_key = crypto.derive_subkey(dek, CATEGORY_INFO)

    def __repr__(self) -> str:
        return "MetadataCipher(…)"

    def entry_aad(self, entry_id: int) -> bytes:
        entry_id = _check_id(entry_id, "entry")
        return f"mon-coffre-fort:entry-metadata:{self._uuid_hex}:{entry_id}".encode("ascii")

    def category_aad(self, category_id: int) -> bytes:
        category_id = _check_id(category_id, "category")
        return f"mon-coffre-fort:category:{self._uuid_hex}:{category_id}".encode("ascii")

    # --- Entries -------------------------------------------------------------------

    def encrypt_entry(self, entry_id: int, meta: EntryMetadata) -> bytes:
        """Raises EntryValidationError if `meta` could not be read back as is."""
        _check_entry(meta, EntryValidationError)
        text = _serialize({
            "name": meta.name, "url": meta.url, "username": meta.username,
            "entry_type": meta.entry_type, "category_id": meta.category_id,
            "is_favorite": meta.is_favorite, "tags": list(meta.tags),
            "created_at": meta.created_at, "updated_at": meta.updated_at,
            "password_changed_at": meta.password_changed_at, "deleted_at": meta.deleted_at,
        })
        return crypto.encrypt_field(self._entry_key, text, self.entry_aad(entry_id))

    def decrypt_entry(self, entry_id: int, blob: object) -> EntryMetadata:
        """Raises EntryDecryptionError on tampering, substitution or inconsistency."""
        aad = self.entry_aad(entry_id)
        error = EntryDecryptionError
        try:
            if not isinstance(blob, bytes):
                raise ValueError("missing metadata")
            text = crypto.decrypt_field(self._entry_key, blob, aad)
        except (ValueError, crypto.AuthenticationFailed) as exc:
            raise error(
                f"The encrypted metadata of entry {entry_id} is corrupted "
                "or has been tampered with.") from exc
        data = _parse(text, _ENTRY_KEYS, error)
        tags = data["tags"]
        if not isinstance(tags, list):
            raise error("Invalid tag list.")
        meta = EntryMetadata(
            name=data["name"], url=data["url"], username=data["username"],
            entry_type=data["entry_type"], category_id=data["category_id"],
            is_favorite=data["is_favorite"], tags=tuple(tags),
            created_at=data["created_at"], updated_at=data["updated_at"],
            password_changed_at=data["password_changed_at"], deleted_at=data["deleted_at"],
        )
        _check_entry(meta, error)
        return meta

    # --- Categories ----------------------------------------------------------------

    def encrypt_category(self, category_id: int, meta: CategoryMetadata) -> bytes:
        _check_category(meta, CategoryError)
        text = _serialize({"name": meta.name, "created_at": meta.created_at})
        return crypto.encrypt_field(self._category_key, text, self.category_aad(category_id))

    def decrypt_category(self, category_id: int, blob: object) -> CategoryMetadata:
        """Raises CategoryDecryptionError on tampering, substitution or inconsistency."""
        aad = self.category_aad(category_id)
        error = CategoryDecryptionError
        try:
            if not isinstance(blob, bytes):
                raise ValueError("missing name")
            text = crypto.decrypt_field(self._category_key, blob, aad)
        except (ValueError, crypto.AuthenticationFailed) as exc:
            raise error(
                f"The encrypted name of category {category_id} is corrupted "
                "or has been tampered with.") from exc
        data = _parse(text, _CATEGORY_KEYS, error)
        meta = CategoryMetadata(name=data["name"], created_at=data["created_at"])
        _check_category(meta, error)
        return meta
