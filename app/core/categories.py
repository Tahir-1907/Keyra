"""Entry categories (unlocked vault).

Schema v4: a built-in category is identified only by its technical key
(generic, identical in every vault); the name of a custom category is
encrypted. An entry's reference to its category lives in its encrypted
metadata: name uniqueness, counters and filters are computed in memory
(`Vault.metadata` cache).

Built-in categories (`BUILTIN_CATEGORIES`) are created idempotently when the
vault is opened — including for vaults created by the very first version,
which had none — and can be neither renamed nor deleted. Custom categories
are free-form; deleting a category deletes no entry (its entries become
"uncategorized").
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

from app.core.builtin_categories import (
    BUILTIN_CATEGORY_KEYS,
    BUILTIN_CATEGORY_NAMES,
    builtin_names,
)
from app.core.entries import UNCATEGORIZED, normalize_for_search
from app.core.exceptions import CategoryError
from app.core.metadata import CategoryMetadata
from app.core.vault import Vault, _utc_now_iso
from app.database.repositories import CategoryRepository
from app.i18n import tr
from app.utils.logging import get_logger

# Display names of the built-in categories, in display order (source: builtin_categories).
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
    """Counters for the sidebar."""

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
        return self._vault.metadata  # VaultLockedError if the vault is locked

    def ensure_builtin_categories(self) -> None:
        """Creates the missing built-in categories. As in v1.6, a custom category
        with the same name (old vault) prevents the built-in one from being
        created — under its display name or its legacy name."""
        store = self._store
        taken = {normalize_for_search(c.name) for c in store.categories().values()
                 if not c.is_builtin}
        existing = {c.builtin_key for c in store.categories().values() if c.is_builtin}
        with self._conn:
            for key in BUILTIN_CATEGORY_KEYS:
                if key not in existing and not any(
                        normalize_for_search(name) in taken for name in builtin_names(key)):
                    self._repo.ensure_v4_builtin(key)
        store.invalidate_categories()

    def _active_counts(self) -> dict[int | None, int]:
        """Active entries per category (the Trash is not counted)."""
        counts: dict[int | None, int] = {}
        for meta in self._store.entries().values():
            if meta.deleted_at is None:
                counts[meta.category_id] = counts.get(meta.category_id, 0) + 1
        return counts

    def list_categories(self) -> list[Category]:
        counts = self._active_counts()
        cats = [Category(c.id, c.name, c.is_builtin, counts.get(c.id, 0))
                for c in self._store.categories().values()]
        # Built-in categories first (fixed order), then custom ones (alphabetical).
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
        with self._conn:  # identifier + encrypted name: all or nothing
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
        """The affected entries (Trash included) become "uncategorized"."""
        self._require_custom(category_id)
        store = self._store
        affected = [(i, m) for i, m in store.entries().items() if m.category_id == category_id]
        with self._conn:
            for entry_id, meta in affected:
                store.write_entry(entry_id, dataclasses.replace(meta, category_id=None))
            self._repo.delete(category_id)
            store.invalidate_categories()
        self._logger.info("Category deleted: id=%d", category_id)

    # --- Internal ---------------------------------------------------------------

    def _require_custom(self, category_id: int):
        if category_id == UNCATEGORIZED:
            raise CategoryError(tr("categories.error.not_editable"))
        category = self._store.categories().get(category_id)
        if category is None:
            raise CategoryError(tr("categories.error.not_found"))
        if category.is_builtin:
            raise CategoryError(tr("categories.error.builtin"))
        return category

    def _validate_name(self, name: str, exclude_id: int | None = None) -> str:
        clean = " ".join(name.split())
        if not clean:
            raise CategoryError(tr("categories.error.name_required"))
        if len(clean) > MAX_CATEGORY_NAME_LENGTH:
            raise CategoryError(tr("categories.error.name_too_long", max=MAX_CATEGORY_NAME_LENGTH))
        # Duplicate check, case- and accent-insensitive ("work" vs "Work"),
        # built-in categories included.
        wanted = normalize_for_search(clean)
        for other in self._store.categories().values():
            if other.id != exclude_id and normalize_for_search(other.name) == wanted:
                raise CategoryError(tr("categories.error.exists", name=other.name))
        return clean
