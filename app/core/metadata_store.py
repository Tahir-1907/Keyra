"""Cache en mémoire des métadonnées déchiffrées d'un coffre v4.

Rattaché au `Vault` (tous les services d'une session le partagent) :

* créé à la première lecture, coffre DÉVERROUILLÉ et au schéma v4 uniquement ;
* chargement paresseux : rien n'est déchiffré avant le premier accès, puis
  chaque blob n'est déchiffré qu'une fois ;
* toute écriture passant par ce cache INVALIDE l'élément concerné, relu depuis
  la base au prochain accès (jamais de mise à jour « à l'avance ») ;
* ce qui est lu PENDANT une transaction ouverte est provisoire : dès que la
  transaction se termine (COMMIT ou ROLLBACK), le premier accès relit tout depuis
  la base. Le cache ne garde donc jamais une valeur annulée par un ROLLBACK ;
* `clear()` (appelé par `Vault.lock()`) vide tout, oublie la clé de
  métadonnées et rend l'objet inutilisable ;
* jamais persistant : aucune écriture sur disque en dehors des blobs chiffrés.

Limite (commune à tout le programme, voir README) : Python ne garantit pas
l'effacement des chaînes en mémoire ; vider le cache supprime les références,
le ramasse-miettes libère ensuite la mémoire.

Une modification faite dans la base SANS passer par ce cache (autre processus,
SQL direct) n'est vue qu'après `invalidate()` : l'application est mono-instance
et toutes ses écritures de métadonnées passent par ici.
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
    """Catégorie déchiffrée : intégrée (`builtin_key`) ou personnelle (nom chiffré)."""

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
    """Métadonnées déchiffrées d'UN coffre v4 déverrouillé (voir le module)."""

    def __init__(self, conn: sqlite3.Connection, dek: bytes, vault_uuid: bytes) -> None:
        self._conn = conn
        self._cipher: MetadataCipher | None = MetadataCipher(dek, vault_uuid)
        self._entries: dict[int, EntryMetadata] | None = None
        self._unreadable: set[int] = set()
        self._stale: set[int] = set()
        self._entries_provisional = False  # chargées pendant une transaction ouverte
        self._categories: dict[int, CategoryInfo] | None = None
        self._categories_provisional = False
        self.generation = 0  # incrémenté à chaque invalidation (vues à rafraîchir)

    def __repr__(self) -> str:
        return f"MetadataStore(loaded={self._entries is not None}, generation={self.generation})"

    # --- État ----------------------------------------------------------------------

    @property
    def cipher(self) -> MetadataCipher:
        if self._cipher is None:
            raise VaultLockedError("Le coffre est verrouillé.")
        return self._cipher

    @property
    def is_loaded(self) -> bool:
        return self._entries is not None

    def clear(self) -> None:
        """Verrouillage : tout est oublié, l'objet ne sert plus."""
        if self._entries is not None:
            self._entries.clear()
        if self._categories is not None:
            self._categories.clear()
        self._entries = self._categories = None
        self._unreadable.clear()
        self._stale.clear()
        self._cipher = None

    # --- Entrées -------------------------------------------------------------------

    def entries(self) -> Mapping[int, EntryMetadata]:
        """Toutes les entrées LISIBLES (actives et corbeille), en lecture seule."""
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
                except KeyError:  # entrée supprimée
                    continue
                self._load_one(cipher, entry_id, blob)
            self._stale.clear()
            if in_transaction:  # valeurs non validées : tout relire après la transaction
                self._entries_provisional = True
        return MappingProxyType(self._entries)

    def _load_one(self, cipher: MetadataCipher, entry_id: int, blob: bytes | None) -> None:
        try:
            self._entries[entry_id] = cipher.decrypt_entry(entry_id, blob)
        except EntryDecryptionError:
            self._unreadable.add(entry_id)  # signalé à part, sans bloquer les autres

    def unreadable(self) -> frozenset[int]:
        """Entrées dont les métadonnées sont altérées ou illisibles."""
        self.entries()
        return frozenset(self._unreadable)

    def entry(self, entry_id: int) -> EntryMetadata:
        entries = self.entries()
        if entry_id in entries:
            return entries[entry_id]
        if entry_id in self._unreadable:
            raise EntryDecryptionError(
                f"Les métadonnées chiffrées de l'entrée {entry_id} sont corrompues "
                "ou ont été altérées.")
        raise EntryNotFoundError(f"Entrée {entry_id} introuvable.")

    def write_entry(self, entry_id: int, meta: EntryMetadata) -> None:
        """Chiffre et écrit (sans commit : l'appelant délimite la transaction)."""
        blob = self.cipher.encrypt_entry(entry_id, meta)
        try:
            if not EntryRepository(self._conn).set_metadata_blob(entry_id, blob):
                raise EntryNotFoundError(f"Entrée {entry_id} introuvable.")
        finally:
            self.invalidate_entry(entry_id)  # relu depuis la base, même après un ROLLBACK

    def invalidate_entry(self, entry_id: int) -> None:
        """À appeler après toute écriture ou suppression d'une entrée."""
        if self._entries is not None:
            self._stale.add(entry_id)
        self.generation += 1

    # --- Catégories ----------------------------------------------------------------

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
        """Chiffre et écrit le nom d'une catégorie personnelle (sans commit)."""
        blob = self.cipher.encrypt_category(category_id, meta)
        try:
            if not CategoryRepository(self._conn).set_v4_name_blob(category_id, blob):
                raise CategoryDecryptionError(f"Catégorie {category_id} introuvable.")
        finally:
            self.invalidate_categories()

    def invalidate_categories(self) -> None:
        self._categories = None
        self.generation += 1

    def invalidate(self) -> None:
        """Tout relire au prochain accès (ex. après une restauration ou un import)."""
        self._entries = None
        self._unreadable, self._stale = set(), set()
        self.invalidate_categories()
