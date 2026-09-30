"""In-memory cache of the decrypted metadata of a v4 vault.

Attached to the `Vault` (shared by every service of a session):

* created on first read, only for an UNLOCKED vault at schema v4;
* lazy loading: nothing is decrypted before the first access, and then each
  blob is decrypted only once;
* every write going through this cache INVALIDATES the affected element,
  which is read back from the database on the next access (never an
  "in advance" update);
* what is read WHILE a transaction is open is provisional: as soon as the
  transaction ends (COMMIT or ROLLBACK), the first access reads everything
  again from the database. The cache therefore never keeps a value cancelled
  by a ROLLBACK;
* `clear()` (called by `Vault.lock()`) empties everything, forgets the
  metadata key and makes the object unusable;
* never persistent: nothing is written to disk apart from the encrypted blobs.

Limitation (shared by the whole program, see README): Python does not
guarantee that strings are erased from memory; clearing the cache drops the
references, and the garbage collector then frees the memory.

A change made to the database WITHOUT going through this cache (another
process, direct SQL) is only seen after `invalidate()`: the application is
single-instance and all of its metadata writes go through here.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from app.core.builtin_categories import builtin_name
from app.core.exceptions import (
    CategoryDecryptionError,
    EntryDecryptionError,
    EntryNotFoundError,
    VaultLockedError,
)
from app.core.metadata import CategoryMetadata, EntryMetadata, MetadataCipher
from app.database.repositories import CategoryRepository, EntryRepository


@dataclass(frozen=True, slots=True)
class CategoryInfo:
    """Decrypted category: built-in (`builtin_key`) or custom (encrypted name)."""

    id: int
    name: str
    builtin_key: str | None = None
    created_at: str = ""

    @property
    def is_builtin(self) -> bool:
        return self.builtin_key is not None

    def __repr__(self) -> str:
        return f"CategoryInfo(id={self.id!r}, builtin_key={self.builtin_key!r})"


class MetadataStore:
    """Decrypted metadata of ONE unlocked v4 vault (see the module)."""

    def __init__(self, conn: sqlite3.Connection, dek: bytes, vault_uuid: bytes) -> None:
        self._conn = conn
        self._cipher: MetadataCipher | None = MetadataCipher(dek, vault_uuid)
        self._entries: dict[int, EntryMetadata] | None = None
        self._unreadable: set[int] = set()
        self._stale: set[int] = set()
        self._entries_provisional = False  # loaded while a transaction was open
        self._categories: dict[int, CategoryInfo] | None = None
        self._categories_provisional = False
        self.generation = 0  # incremented on every invalidation (views to refresh)

    def __repr__(self) -> str:
        return f"MetadataStore(loaded={self._entries is not None}, generation={self.generation})"

    # --- State ----------------------------------------------------------------------

    @property
    def cipher(self) -> MetadataCipher:
        if self._cipher is None:
            raise VaultLockedError("The vault is locked.")
        return self._cipher

    @property
    def is_loaded(self) -> bool:
        return self._entries is not None

    def clear(self) -> None:
        """Lock: everything is forgotten, the object is no longer used."""
        if self._entries is not None:
            self._entries.clear()
        if self._categories is not None:
            self._categories.clear()
        self._entries = self._categories = None
        self._unreadable.clear()
        self._stale.clear()
        self._cipher = None

    # --- Entries -------------------------------------------------------------------

    def entries(self) -> Mapping[int, EntryMetadata]:
        """All READABLE entries (active and in the Trash), read-only."""
        cipher = self.cipher
        in_transaction = self._conn.in_transaction
        if self._entries is None or (self._entries_provisional and not in_transaction):
            self._entries, self._unreadable, self._stale = {}, set(), set()
            for entry_id, blob in EntryRepository(self._conn).list_metadata_blobs():
                self._load_one(cipher, entry_id, blob)
            self._entries_provisional = in_transaction
        elif self._stale:
            repo = EntryRepository(self._conn)
            for entry_id in sorted(self._stale):
                self._entries.pop(entry_id, None)
                self._unreadable.discard(entry_id)
                try:
                    blob = repo.get_metadata_blob(entry_id)
                except KeyError:  # deleted entry
                    continue
                self._load_one(cipher, entry_id, blob)
            self._stale.clear()
            if in_transaction:  # uncommitted values: read everything again after the transaction
                self._entries_provisional = True
        return MappingProxyType(self._entries)

    def _load_one(self, cipher: MetadataCipher, entry_id: int, blob: bytes | None) -> None:
        try:
            self._entries[entry_id] = cipher.decrypt_entry(entry_id, blob)
        except EntryDecryptionError:
            self._unreadable.add(entry_id)  # reported separately, without blocking the others

    def unreadable(self) -> frozenset[int]:
        """Entries whose metadata is tampered with or unreadable."""
        self.entries()
        return frozenset(self._unreadable)

    def entry(self, entry_id: int) -> EntryMetadata:
        entries = self.entries()
        if entry_id in entries:
            return entries[entry_id]
        if entry_id in self._unreadable:
            raise EntryDecryptionError(
                f"The encrypted metadata of entry {entry_id} is corrupted "
                "or has been tampered with.")
        raise EntryNotFoundError(f"Entry {entry_id} not found.")

    def write_entry(self, entry_id: int, meta: EntryMetadata) -> None:
        """Encrypts and writes (no commit: the caller delimits the transaction)."""
        blob = self.cipher.encrypt_entry(entry_id, meta)
        try:
            if not EntryRepository(self._conn).set_metadata_blob(entry_id, blob):
                raise EntryNotFoundError(f"Entry {entry_id} not found.")
        finally:
            self.invalidate_entry(entry_id)  # read back from the database, even after a ROLLBACK

    def invalidate_entry(self, entry_id: int) -> None:
        """To be called after any write or deletion of an entry."""
        if self._entries is not None:
            self._stale.add(entry_id)
        self.generation += 1

    # --- Categories ----------------------------------------------------------------

    def categories(self) -> Mapping[int, CategoryInfo]:
        cipher = self.cipher
        in_transaction = self._conn.in_transaction
        if self._categories is None or (self._categories_provisional and not in_transaction):
            loaded: dict[int, CategoryInfo] = {}
            for category in CategoryRepository(self._conn).list_v4_rows():
                category_id, key, blob = category
                if key is not None:
                    loaded[category_id] = CategoryInfo(category_id, builtin_name(key), key)
                else:
                    meta = cipher.decrypt_category(category_id, blob)  # CategoryDecryptionError
                    loaded[category_id] = CategoryInfo(category_id, meta.name, None,
                                                       meta.created_at)
            self._categories = loaded
            self._categories_provisional = in_transaction
        return MappingProxyType(self._categories)

    def category_name(self, category_id: int | None) -> str:
        if category_id is None:
            return ""
        category = self.categories().get(category_id)
        return category.name if category else ""

    def write_category(self, category_id: int, meta: CategoryMetadata) -> None:
        """Encrypts and writes the name of a custom category (no commit)."""
        blob = self.cipher.encrypt_category(category_id, meta)
        try:
            if not CategoryRepository(self._conn).set_v4_name_blob(category_id, blob):
                raise CategoryDecryptionError(f"Category {category_id} not found.")
        finally:
            self.invalidate_categories()

    def invalidate_categories(self) -> None:
        self._categories = None
        self.generation += 1

    def invalidate(self) -> None:
        """Read everything again on the next access (e.g. after a restore or an import)."""
        self._entries = None
        self._unreadable, self._stale = set(), set()
        self.invalidate_categories()
