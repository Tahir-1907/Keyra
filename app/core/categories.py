"""Catégories d'entrées (coffre déverrouillé).

Schéma v4 : une catégorie intégrée n'est identifiée que par sa clé technique
(générique, identique dans tous les coffres) ; le nom d'une catégorie
personnelle est chiffré. La référence d'une entrée à sa catégorie est dans ses
métadonnées chiffrées : unicité des noms, compteurs et filtres se calculent en
mémoire (cache `Vault.metadata`).

Les catégories intégrées (`BUILTIN_CATEGORIES`) sont créées de façon
idempotente à l'ouverture du coffre — y compris pour les coffres créés en
la première version, qui n'en avaient pas — et ne peuvent être ni renommées ni
supprimées. Les catégories personnalisées sont libres ; supprimer une
catégorie ne supprime aucune entrée (elles passent « sans catégorie »).
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

from app.core.builtin_categories import BUILTIN_CATEGORY_KEYS, BUILTIN_CATEGORY_NAMES
from app.core.entries import UNCATEGORIZED, normalize_for_search
from app.core.exceptions import CategoryError
from app.core.metadata import CategoryMetadata
from app.core.vault import Vault, _utc_now_iso
from app.database.repositories import CategoryRepository
from app.utils.logging import get_logger

# Noms des catégories intégrées, dans l'ordre d'affichage (source : builtin_categories).
BUILTIN_CATEGORIES: tuple[str, ...] = tuple(BUILTIN_CATEGORY_NAMES.values())

MAX_CATEGORY_NAME_LENGTH = 60


@dataclass(frozen=True, slots=True)
class Category:
    id: int
    name: str
    is_builtin: bool
    entry_count: int


@dataclass(frozen=True, slots=True)
class CategoryOverview:
    """Compteurs pour la barre latérale."""

    categories: list[Category]
    total: int
    favorites: int
    uncategorized: int
    trash: int = 0


class CategoryService:
    def __init__(self, vault: Vault) -> None:
        self._vault = vault
        self._conn = vault.connection
        self._repo = CategoryRepository(self._conn)
        self._logger = get_logger()

    @property
    def _store(self):
        return self._vault.metadata  # VaultLockedError si le coffre est verrouillé

    def ensure_builtin_categories(self) -> None:
        """Crée les catégories intégrées manquantes. Comme en v1.6, une catégorie
        personnelle homonyme (ancien coffre) empêche la création de l'intégrée."""
        store = self._store
        taken = {normalize_for_search(c.name) for c in store.categories().values()
                 if not c.is_builtin}
        existing = {c.builtin_key for c in store.categories().values() if c.is_builtin}
        with self._conn:
            for key in BUILTIN_CATEGORY_KEYS:
                if key not in existing and normalize_for_search(
                        BUILTIN_CATEGORY_NAMES[key]) not in taken:
                    self._repo.ensure_v4_builtin(key)
        store.invalidate_categories()

    def _active_counts(self) -> dict[int | None, int]:
        """Entrées actives par catégorie (la corbeille n'est pas comptée)."""
        counts: dict[int | None, int] = {}
        for meta in self._store.entries().values():
            if meta.deleted_at is None:
                counts[meta.category_id] = counts.get(meta.category_id, 0) + 1
        return counts

    def list_categories(self) -> list[Category]:
        counts = self._active_counts()
        cats = [Category(c.id, c.name, c.is_builtin, counts.get(c.id, 0))
                for c in self._store.categories().values()]
        # Catégories intégrées d'abord (ordre défini), puis personnalisées (alpha).
        order = {name: i for i, name in enumerate(BUILTIN_CATEGORIES)}
        cats.sort(
            key=lambda c: (
                0 if c.is_builtin else 1,
                order.get(c.name, 0) if c.is_builtin else 0,
                normalize_for_search(c.name),
                c.id,
            )
        )
        return cats

    def overview(self) -> CategoryOverview:
        metas = self._store.entries().values()
        active = [m for m in metas if m.deleted_at is None]
        return CategoryOverview(
            categories=self.list_categories(),
            total=len(active),
            favorites=sum(1 for m in active if m.is_favorite),
            uncategorized=sum(1 for m in active if m.category_id is None),
            trash=len(metas) - len(active),
        )

    def create_category(self, name: str) -> int:
        store = self._store
        clean = self._validate_name(name)
        with self._conn:  # identifiant + nom chiffré : tout ou rien
            category_id = self._repo.insert_v4_custom_placeholder()
            store.write_category(category_id, CategoryMetadata(clean, _utc_now_iso()))
        self._logger.info("Category created: id=%d", category_id)
        return category_id

    def rename_category(self, category_id: int, new_name: str) -> None:
        current = self._require_custom(category_id)
        clean = self._validate_name(new_name, exclude_id=category_id)
        if clean == current.name:
            return
        with self._conn:
            self._store.write_category(category_id, CategoryMetadata(clean, current.created_at))
        self._logger.info("Category renamed: id=%d", category_id)

    def delete_category(self, category_id: int) -> None:
        """Les entrées concernées (corbeille comprise) passent « sans catégorie »."""
        self._require_custom(category_id)
        store = self._store
        affected = [(i, m) for i, m in store.entries().items() if m.category_id == category_id]
        with self._conn:
            for entry_id, meta in affected:
                store.write_entry(entry_id, dataclasses.replace(meta, category_id=None))
            self._repo.delete(category_id)
            store.invalidate_categories()
        self._logger.info("Category deleted: id=%d", category_id)

    # --- Interne ---------------------------------------------------------------

    def _require_custom(self, category_id: int):
        if category_id == UNCATEGORIZED:
            raise CategoryError("Cette vue n'est pas une catégorie modifiable.")
        category = self._store.categories().get(category_id)
        if category is None:
            raise CategoryError("Catégorie introuvable.")
        if category.is_builtin:
            raise CategoryError("Les catégories intégrées ne peuvent pas être modifiées.")
        return category

    def _validate_name(self, name: str, exclude_id: int | None = None) -> str:
        clean = " ".join(name.split())
        if not clean:
            raise CategoryError("Le nom de la catégorie est obligatoire.")
        if len(clean) > MAX_CATEGORY_NAME_LENGTH:
            raise CategoryError(
                f"Le nom de la catégorie ne doit pas dépasser {MAX_CATEGORY_NAME_LENGTH} "
                "caractères."
            )
        # Doublon insensible à la casse et aux accents (« travail » vs « Travail »),
        # catégories intégrées comprises.
        wanted = normalize_for_search(clean)
        for other in self._store.categories().values():
            if other.id != exclude_id and normalize_for_search(other.name) == wanted:
                raise CategoryError(f"La catégorie « {other.name} » existe déjà.")
        return clean
