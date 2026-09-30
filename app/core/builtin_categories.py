"""Built-in categories: explicit mapping between technical key and display name.

Single source of truth (app.core.categories derives BUILTIN_CATEGORIES from it,
and the v4 schema its CHECK constraint). Dependency-free module, importable
from the database layer without a circular import.

In v4, a built-in category is identified ONLY by its technical key
(`categories.builtin_key`, in plaintext): these keys are generic and identical
in every vault, so they reveal nothing. The name is supplied by the code.
Custom categories have an encrypted name and never a key: a category is NEVER
deduced to be built-in from its name.

Two name tables:
* BUILTIN_CATEGORY_NAMES — English display labels shown by the application;
* LEGACY_BUILTIN_NAMES — the French names that versions 1.x stored in plaintext
  in v1 to v3 vaults. FROZEN: the v3 → v4 migration identifies built-in
  categories by these exact names, and older files (CSV exports, vaults created
  before built-in categories existed) may still contain them.
"""

from __future__ import annotations

# Order = display order. Keys: ASCII, stable, never to be renamed.
BUILTIN_CATEGORY_NAMES: dict[str, str] = {
    "personal": "Personal",
    "work": "Work",
    "finance": "Finance",
    "social": "Social",
    "email": "Email",
    "shopping": "Shopping",
}
BUILTIN_CATEGORY_KEYS: tuple[str, ...] = tuple(BUILTIN_CATEGORY_NAMES)

# Names stored by v1 to v3 vaults (versions 1.x). Never translate or edit.
LEGACY_BUILTIN_NAMES: dict[str, str] = {
    "personal": "Personnel",
    "work": "Travail",
    "finance": "Finances",
    "social": "Réseaux sociaux",
    "email": "Courriel",
    "shopping": "Achats",
}


def builtin_name(key: str) -> str:
    """Display name of a built-in category; KeyError if the key is unknown."""
    return BUILTIN_CATEGORY_NAMES[key]


def legacy_builtin_name(key: str) -> str:
    """Name stored for this built-in category by v1 to v3 vaults; KeyError if unknown."""
    return LEGACY_BUILTIN_NAMES[key]


def legacy_name_for_display(name: str) -> str | None:
    """Legacy (v1.x) name of the built-in category displayed as `name`, or None."""
    for key, display in BUILTIN_CATEGORY_NAMES.items():
        if display == name:
            return LEGACY_BUILTIN_NAMES[key]
    return None


def builtin_names(key: str) -> tuple[str, str]:
    """Every name that designates this built-in category: display, then legacy."""
    return BUILTIN_CATEGORY_NAMES[key], LEGACY_BUILTIN_NAMES[key]


def builtin_key_for_v3_row(name: str, is_builtin: bool) -> str | None:
    """Key of a category of a v3 vault (migration only).

    Only a row flagged as built-in (`is_builtin = 1`) gets a key, based on its
    plaintext v3 name. A custom category that happens to have the same name as
    a built-in one STAYS custom. A row flagged as built-in with an unknown name
    is inconsistent: ValueError (never a silent choice).
    """
    if not is_builtin:
        return None
    for key, legacy in LEGACY_BUILTIN_NAMES.items():
        if legacy == name:
            return key
    raise ValueError("Unknown built-in category in this vault.")
